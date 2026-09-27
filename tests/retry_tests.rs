// End-to-end retry routing tests: drive the real `proxy_handler` against live TLS h2 backends and
// observe, from the backends' own request counters and response bodies, that a retry after a
// retryable failure lands on a *different* backend when one is available, and re-hits the same
// backend when it is the only one. This exercises the full forward path (TCP connect, rustls
// handshake, h2), not just the selection helpers.
#![cfg(feature = "integration_tests")]
// Integration-test crate: unwrap/expect are the idiomatic way to fail a test loudly. The project's
// deny-level restriction lints auto-exempt inline #[cfg(test)] modules but not standalone test crates.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::str_to_string)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use arrayvec::ArrayString;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, Response, StatusCode};
use bytes::Bytes;
use http_body::{Body as HttpBody, Frame};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use quinn::Endpoint;
use reduction::acl::AccessControl;
use reduction::balancer::BackendPool;
use reduction::circuit::CircuitState;
use reduction::config::{
	BackendConfig, CacheConfig, CircuitBreakerConfig, ProxyConfig, RetryConfig, RouteConfig, TimeoutConfig, TransportKind,
};
use reduction::proxy::handler::{ProxyState, ReloadableState, TestProxyStateParams, proxy_handler};
use reduction::proxy::pool::ConnPool;
use reduction::proxy::router::Router;
use reduction::tls::PeerIdentity;
use reduction::transport::ConnectAddr;
use reduction::transport::quic::{QuicStream, STREAM_TYPE_HTTP, build_quic_server_config};
use reduction::tunnel::registry::TunnelRegistry;
use reduction::tunnel::revocation::RevocationSet;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

const E2E_TIMEOUT: Duration = Duration::from_secs(10);

// A live backend: reads its response status from `status` at request time (so a test can flip a
// healthy backend to failing mid-run) and counts every request it actually served in `hits`.
struct Backend {
	addr: SocketAddr,
	status: Arc<AtomicU16>,
	hits: Arc<AtomicUsize>,
	name: &'static str,
}

fn install_crypto() {
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

// Self-signed leaf for "localhost"; the proxy client uses NoVerify, so the exact identity does not
// matter — only that a real TLS handshake completes.
fn backend_server_config() -> Arc<rustls::ServerConfig> {
	let key: rcgen::KeyPair = rcgen::KeyPair::generate().unwrap();
	let params: rcgen::CertificateParams = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
	let cert: rcgen::Certificate = params.self_signed(&key).unwrap();

	let cert_der: CertificateDer<'static> = cert.der().clone();
	let key_der: PrivatePkcs8KeyDer<'static> = PrivatePkcs8KeyDer::from(key.serialize_der());

	let config: rustls::ServerConfig = rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
		.unwrap();
	return Arc::new(config);
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
	fn verify_server_cert(
		&self,
		_: &CertificateDer<'_>,
		_: &[CertificateDer<'_>],
		_: &ServerName<'_>,
		_: &[u8],
		_: UnixTime,
	) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
		return Ok(rustls::client::danger::ServerCertVerified::assertion());
	}
	fn verify_tls12_signature(
		&self,
		_: &[u8],
		_: &CertificateDer<'_>,
		_: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
	}
	fn verify_tls13_signature(
		&self,
		_: &[u8],
		_: &CertificateDer<'_>,
		_: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
	}
	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		return rustls::crypto::aws_lc_rs::default_provider()
			.signature_verification_algorithms
			.supported_schemes();
	}
}

fn client_tls() -> (Arc<rustls::ClientConfig>, TlsConnector) {
	let config: Arc<rustls::ClientConfig> = Arc::new(
		rustls::ClientConfig::builder()
			.dangerous()
			.with_custom_certificate_verifier(Arc::new(NoVerify))
			.with_no_client_auth(),
	);
	let connector: TlsConnector = TlsConnector::from(config.clone());
	return (config, connector);
}

// Spawn a TLS h2 server on an ephemeral port that answers every request with the current `status`
// and body `name`, incrementing `hits` each time.
async fn spawn_backend(name: &'static str, server_config: Arc<rustls::ServerConfig>) -> Backend {
	let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr: SocketAddr = listener.local_addr().unwrap();
	let status: Arc<AtomicU16> = Arc::new(AtomicU16::new(200));
	let hits: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
	let acceptor: TlsAcceptor = TlsAcceptor::from(server_config);

	let status_srv: Arc<AtomicU16> = status.clone();
	let hits_srv: Arc<AtomicUsize> = hits.clone();
	tokio::spawn(async move {
		loop {
			let (tcp, _) = match listener.accept().await {
				Ok(pair) => pair,
				Err(_) => return,
			};
			let acceptor: TlsAcceptor = acceptor.clone();
			let status_conn: Arc<AtomicU16> = status_srv.clone();
			let hits_conn: Arc<AtomicUsize> = hits_srv.clone();
			tokio::spawn(async move {
				let tls = match acceptor.accept(tcp).await {
					Ok(s) => s,
					Err(_) => return,
				};
				let service = service_fn(move |_req| {
					let status_req: Arc<AtomicU16> = status_conn.clone();
					let hits_req: Arc<AtomicUsize> = hits_conn.clone();
					async move {
						hits_req.fetch_add(1, Ordering::SeqCst);
						let code: u16 = status_req.load(Ordering::SeqCst);
						let resp: Response<Full<Bytes>> = Response::builder()
							.status(code)
							.body(Full::new(Bytes::from(name)))
							.unwrap();
						return Ok::<_, Infallible>(resp);
					}
				});
				let _ = http2::Builder::new(TokioExecutor::new())
					.serve_connection(TokioIo::new(tls), service)
					.await;
			});
		}
	});

	return Backend {
		addr,
		status,
		hits,
		name,
	};
}

// Like spawn_backend, but the accept loop and every live connection shut down when `token` is
// cancelled — so a test can kill the backend and observe the proxy's pooled connections close.
async fn spawn_backend_with_shutdown(
	name: &'static str,
	server_config: Arc<rustls::ServerConfig>,
	token: CancellationToken,
) -> Backend {
	let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr: SocketAddr = listener.local_addr().unwrap();
	let hits: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
	let acceptor: TlsAcceptor = TlsAcceptor::from(server_config);

	let hits_srv: Arc<AtomicUsize> = hits.clone();
	tokio::spawn(async move {
		loop {
			let (tcp, _) = tokio::select! {
				_ = token.cancelled() => return,
				accepted = listener.accept() => match accepted {
					Ok(pair) => pair,
					Err(_) => return,
				},
			};
			let acceptor: TlsAcceptor = acceptor.clone();
			let hits_conn: Arc<AtomicUsize> = hits_srv.clone();
			let conn_token: CancellationToken = token.clone();
			tokio::spawn(async move {
				let tls = match acceptor.accept(tcp).await {
					Ok(s) => s,
					Err(_) => return,
				};
				let service = service_fn(move |_req| {
					let hits_req: Arc<AtomicUsize> = hits_conn.clone();
					async move {
						hits_req.fetch_add(1, Ordering::SeqCst);
						let resp: Response<Full<Bytes>> = Response::builder()
							.status(200)
							.body(Full::new(Bytes::from(name)))
							.unwrap();
						return Ok::<_, Infallible>(resp);
					}
				});
				let conn = http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), service);
				// Dropping the serve future on cancel closes the TLS stream, so the proxy's pooled
				// H2 sender observes the close and reports is_closed().
				tokio::select! {
					_ = conn_token.cancelled() => {},
					_ = conn => {},
				}
			});
		}
	});

	return Backend {
		addr,
		status: Arc::new(AtomicU16::new(200)),
		hits,
		name,
	};
}

// Assemble a ProxyState whose single route "/" targets one pool holding `backends`. ACL and rate
// limiting are disabled and the circuit breaker threshold is set high so it never interferes with
// the retry counts under test. Fast, jitter-free retry config keeps runs quick and selection
// deterministic per client IP.
fn build_state(backends: Vec<BackendConfig>, max_retries: u32) -> Arc<ProxyState> {
	let cache_off: CacheConfig = CacheConfig {
		enabled: false,
		..CacheConfig::default()
	};
	return build_state_with_cache(
		backends,
		max_retries,
		cache_off,
		RevocationSet::default(),
		TimeoutConfig::default(),
	);
}

fn build_state_with_cache(
	backends: Vec<BackendConfig>,
	max_retries: u32,
	cache: CacheConfig,
	revocation: RevocationSet,
	timeouts: TimeoutConfig,
) -> Arc<ProxyState> {
	let client_config = client_tls().0;

	let pool: BackendPool = BackendPool::new(backends).unwrap();
	let mut backend_pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();
	backend_pools.insert(ArrayString::from("svc").unwrap(), pool);

	let route: RouteConfig = RouteConfig {
		path_prefix: ArrayString::from("/").unwrap(),
		backend_id: ArrayString::from("svc").unwrap(),
		timeout_secs: None,
	};
	let router: Router = Router::new(&[route]);
	let reloadable: ReloadableState = ReloadableState {
		router,
		backend_pools,
		acl: AccessControl::new(vec![], vec![]),
	};

	// High failure threshold so the breaker never trips during the retry-count assertions; fast,
	// jitter-free retry keeps runs deterministic per client IP. The HTTP handler reads the watches
	// only via borrow(), so for_test dropping its senders is fine (no Box::leak needed).
	let high_threshold: CircuitBreakerConfig = CircuitBreakerConfig {
		failure_threshold: NonZeroU32::new(1000).unwrap(),
		recovery_timeout_secs: 60,
		half_open_max_requests: NonZeroU32::new(1).unwrap(),
	};
	let retry: RetryConfig = RetryConfig {
		max_retries,
		base_delay_ms: 1,
		max_delay_ms: 1,
		jitter_ms: 0,
	};

	return ProxyState::for_test(TestProxyStateParams {
		circuit_breaker_config: high_threshold,
		retry_config: retry,
		cache_config: cache,
		..TestProxyStateParams::new(reloadable, revocation, client_config, timeouts)
	});
}

fn backend(id: &str, addr: SocketAddr) -> BackendConfig {
	return BackendConfig::new(id, addr, 1.0, TransportKind::Tcp).unwrap();
}

fn backend_quic(id: &str, addr: SocketAddr) -> BackendConfig {
	return BackendConfig::new(id, addr, 1.0, TransportKind::Quic).unwrap();
}

// A QUIC backend speaking Reduction's own framing: each request arrives as a fresh bi-stream that
// opens with a one-byte stream type, after which the proxy speaks HTTP/1 over the stream. The
// backend streams a body of `count` chunks of `chunk_size` bytes, so a test can prove the QUIC/H1
// path delivers a large multi-frame body intact — the path PooledBody's removal was not covering.
async fn spawn_quic_streaming_backend(
	chunk_size: usize,
	count: usize,
	server_config: Arc<rustls::ServerConfig>,
) -> Backend {
	let quic_config: quinn::ServerConfig = build_quic_server_config(server_config).unwrap();
	let endpoint: Endpoint = Endpoint::server(quic_config, "127.0.0.1:0".parse().unwrap()).unwrap();
	let addr: SocketAddr = endpoint.local_addr().unwrap();
	let hits: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

	let hits_srv: Arc<AtomicUsize> = hits.clone();
	tokio::spawn(async move {
		while let Some(incoming) = endpoint.accept().await {
			let hits_conn: Arc<AtomicUsize> = hits_srv.clone();
			tokio::spawn(async move {
				let connection: quinn::Connection = match incoming.await {
					Ok(c) => c,
					Err(_) => return,
				};
				loop {
					let (send, mut recv) = match connection.accept_bi().await {
						Ok(pair) => pair,
						Err(_) => return,
					};
					let hits_stream: Arc<AtomicUsize> = hits_conn.clone();
					tokio::spawn(async move {
						// Consume the one-byte stream type the proxy writes before the HTTP bytes.
						let mut type_buf: [u8; 1] = [0u8; 1];
						if recv.read_exact(&mut type_buf).await.is_err() || type_buf[0] != STREAM_TYPE_HTTP {
							return;
						}
						let stream: QuicStream = QuicStream::new(send, recv);
						let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
							let hits_req: Arc<AtomicUsize> = hits_stream.clone();
							async move {
								hits_req.fetch_add(1, Ordering::SeqCst);
								let body: ChunkedStreamBody = ChunkedStreamBody {
									remaining: count,
									chunk: Bytes::from(vec![b'q'; chunk_size]),
								};
								let resp: Response<ChunkedStreamBody> =
									Response::builder().status(200).body(body).unwrap();
								return Ok::<_, Infallible>(resp);
							}
						});
						let _ = http1::Builder::new()
							.serve_connection(TokioIo::new(stream), service)
							.await;
					});
				}
			});
		}
	});

	return Backend {
		addr,
		status: Arc::new(AtomicU16::new(200)),
		hits,
		name: "quic",
	};
}

// Fire one GET "/" through the proxy from `client_ip` as an authenticated device. mTLS is
// mandatory, so a normal proxied request always carries a parseable identity; tests that exercise
// routing/retry (not identity) use this and let send_as cover the identity-specific cases.
async fn send(state: &Arc<ProxyState>, client_ip: &str) -> (StatusCode, String) {
	return send_as(state, client_ip, Some(identity_with_cn("test-client"))).await;
}

// As `send`, but attaches an mTLS peer identity to the connection so the proxy injects and keys on
// it — the way a real device-authenticated request arrives.
async fn send_as(state: &Arc<ProxyState>, client_ip: &str, identity: Option<PeerIdentity>) -> (StatusCode, String) {
	let mut req: Request<Body> = Request::builder().method("GET").uri("/").body(Body::empty()).unwrap();
	let peer: SocketAddr = format!("{client_ip}:40000").parse().unwrap();
	req.extensions_mut().insert(ConnectInfo(ConnectAddr(peer, identity)));

	let resp: Response<Body> = timeout(E2E_TIMEOUT, proxy_handler(State(state.clone()), req))
		.await
		.expect("handler timed out");
	let status: StatusCode = resp.status();
	let bytes: Bytes = resp.into_body().collect().await.unwrap().to_bytes();
	return (status, String::from_utf8_lossy(&bytes).into_owned());
}

// A real PeerIdentity built from an rcgen leaf with the given CN — the same parse path production
// uses, so spki_hex() (the cache key) is genuine and distinct per identity.
fn identity_with_cn(cn: &str) -> PeerIdentity {
	let key: rcgen::KeyPair = rcgen::KeyPair::generate().unwrap();
	let mut params: rcgen::CertificateParams = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
	params
		.distinguished_name
		.push(rcgen::DnType::CommonName, rcgen::DnValue::Utf8String(cn.to_string()));
	let cert: rcgen::Certificate = params.self_signed(&key).unwrap();
	return PeerIdentity::from_leaf_der(cert.der()).unwrap();
}

// A cacheable backend that echoes the identity header the proxy injected (x-reduction-client-id)
// as its body, so a cross-identity cache leak shows up as the wrong device's CN in the response.
async fn spawn_echo_backend(server_config: Arc<rustls::ServerConfig>) -> Backend {
	let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr: SocketAddr = listener.local_addr().unwrap();
	let hits: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
	let acceptor: TlsAcceptor = TlsAcceptor::from(server_config);

	let hits_srv: Arc<AtomicUsize> = hits.clone();
	tokio::spawn(async move {
		loop {
			let (tcp, _) = match listener.accept().await {
				Ok(pair) => pair,
				Err(_) => return,
			};
			let acceptor: TlsAcceptor = acceptor.clone();
			let hits_conn: Arc<AtomicUsize> = hits_srv.clone();
			tokio::spawn(async move {
				let tls = match acceptor.accept(tcp).await {
					Ok(s) => s,
					Err(_) => return,
				};
				let service = service_fn(move |req: Request<hyper::body::Incoming>| {
					let hits_req: Arc<AtomicUsize> = hits_conn.clone();
					let echoed: String = req
						.headers()
						.get("x-reduction-client-id")
						.and_then(|v| v.to_str().ok())
						.unwrap_or("anonymous")
						.to_owned();
					async move {
						hits_req.fetch_add(1, Ordering::SeqCst);
						let resp: Response<Full<Bytes>> = Response::builder()
							.status(200)
							// Shared cache requires an explicit `public` opt-in (RFC 7234 §3.2);
							// max-age alone is not shareable under this proxy's cache contract.
							.header("cache-control", "public, max-age=300")
							.body(Full::new(Bytes::from(echoed)))
							.unwrap();
						return Ok::<_, Infallible>(resp);
					}
				});
				let _ = http2::Builder::new(TokioExecutor::new())
					.serve_connection(TokioIo::new(tls), service)
					.await;
			});
		}
	});

	return Backend {
		addr,
		status: Arc::new(AtomicU16::new(200)),
		hits,
		name: "echo",
	};
}

// A backend that echoes the value of `header` from the request it receives (or "absent") as its
// body, so a test can assert exactly what the proxy injected.
async fn spawn_header_echo_backend(header: &'static str, server_config: Arc<rustls::ServerConfig>) -> Backend {
	let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr: SocketAddr = listener.local_addr().unwrap();
	let hits: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
	let acceptor: TlsAcceptor = TlsAcceptor::from(server_config);

	let hits_srv: Arc<AtomicUsize> = hits.clone();
	tokio::spawn(async move {
		loop {
			let (tcp, _) = match listener.accept().await {
				Ok(pair) => pair,
				Err(_) => return,
			};
			let acceptor: TlsAcceptor = acceptor.clone();
			let hits_conn: Arc<AtomicUsize> = hits_srv.clone();
			tokio::spawn(async move {
				let tls = match acceptor.accept(tcp).await {
					Ok(s) => s,
					Err(_) => return,
				};
				let service = service_fn(move |req: Request<hyper::body::Incoming>| {
					let hits_req: Arc<AtomicUsize> = hits_conn.clone();
					let echoed: String = req
						.headers()
						.get(header)
						.and_then(|v| v.to_str().ok())
						.unwrap_or("absent")
						.to_owned();
					async move {
						hits_req.fetch_add(1, Ordering::SeqCst);
						let resp: Response<Full<Bytes>> = Response::builder()
							.status(200)
							.body(Full::new(Bytes::from(echoed)))
							.unwrap();
						return Ok::<_, Infallible>(resp);
					}
				});
				let _ = http2::Builder::new(TokioExecutor::new())
					.serve_connection(TokioIo::new(tls), service)
					.await;
			});
		}
	});

	return Backend {
		addr,
		status: Arc::new(AtomicU16::new(200)),
		hits,
		name: "hdr-echo",
	};
}

// A response body that emits `remaining` chunks of `chunk`, one per poll — a genuinely streamed
// (multi-DATA-frame) body, unlike Full which hands over everything at once.
struct ChunkedStreamBody {
	remaining: usize,
	chunk: Bytes,
}

impl HttpBody for ChunkedStreamBody {
	type Data = Bytes;
	type Error = Infallible;

	fn poll_frame(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
		if self.remaining == 0 {
			return Poll::Ready(None);
		}
		self.remaining -= 1;
		let chunk: Bytes = self.chunk.clone();
		return Poll::Ready(Some(Ok(Frame::data(chunk))));
	}
}

// A response body that emits `initial` DATA frames then stalls forever — never another frame, never
// end-of-stream. Models a backend that sends headers plus a partial body and then hangs, the exact
// case the response idle timeout must catch.
struct StallingStreamBody {
	initial: usize,
	chunk: Bytes,
}

impl HttpBody for StallingStreamBody {
	type Data = Bytes;
	type Error = Infallible;

	fn poll_frame(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
		if self.initial == 0 {
			// Stall: return Pending without arming a waker, so the stream stays open and idle.
			return Poll::Pending;
		}
		self.initial -= 1;
		let chunk: Bytes = self.chunk.clone();
		return Poll::Ready(Some(Ok(Frame::data(chunk))));
	}
}

// Backend that sends `initial` body chunks then holds the stream open indefinitely without ending it.
async fn spawn_stalling_backend(
	initial: usize,
	chunk_size: usize,
	server_config: Arc<rustls::ServerConfig>,
) -> Backend {
	let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr: SocketAddr = listener.local_addr().unwrap();
	let hits: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
	let acceptor: TlsAcceptor = TlsAcceptor::from(server_config);

	let hits_srv: Arc<AtomicUsize> = hits.clone();
	tokio::spawn(async move {
		loop {
			let (tcp, _) = match listener.accept().await {
				Ok(pair) => pair,
				Err(_) => return,
			};
			let acceptor: TlsAcceptor = acceptor.clone();
			let hits_conn: Arc<AtomicUsize> = hits_srv.clone();
			tokio::spawn(async move {
				let tls = match acceptor.accept(tcp).await {
					Ok(s) => s,
					Err(_) => return,
				};
				let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
					let hits_req: Arc<AtomicUsize> = hits_conn.clone();
					async move {
						hits_req.fetch_add(1, Ordering::SeqCst);
						let body: StallingStreamBody = StallingStreamBody {
							initial,
							chunk: Bytes::from(vec![b'z'; chunk_size]),
						};
						let resp: Response<StallingStreamBody> = Response::builder().status(200).body(body).unwrap();
						return Ok::<_, Infallible>(resp);
					}
				});
				let _ = http2::Builder::new(TokioExecutor::new())
					.serve_connection(TokioIo::new(tls), service)
					.await;
			});
		}
	});

	return Backend {
		addr,
		status: Arc::new(AtomicU16::new(200)),
		hits,
		name: "stall",
	};
}

// A backend that streams a body of `count` chunks of `chunk_size` bytes across many DATA frames, so
// a test can prove the whole body reaches the client even when the proxy drops its request sender
// mid-stream. Total size deliberately exceeds the default 2 MB H2 stream window to exercise
// flow-control / WINDOW_UPDATE — which only works while the connection driver is alive.
async fn spawn_streaming_backend(chunk_size: usize, count: usize, server_config: Arc<rustls::ServerConfig>) -> Backend {
	let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr: SocketAddr = listener.local_addr().unwrap();
	let hits: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
	let acceptor: TlsAcceptor = TlsAcceptor::from(server_config);

	let hits_srv: Arc<AtomicUsize> = hits.clone();
	tokio::spawn(async move {
		loop {
			let (tcp, _) = match listener.accept().await {
				Ok(pair) => pair,
				Err(_) => return,
			};
			let acceptor: TlsAcceptor = acceptor.clone();
			let hits_conn: Arc<AtomicUsize> = hits_srv.clone();
			tokio::spawn(async move {
				let tls = match acceptor.accept(tcp).await {
					Ok(s) => s,
					Err(_) => return,
				};
				let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
					let hits_req: Arc<AtomicUsize> = hits_conn.clone();
					async move {
						hits_req.fetch_add(1, Ordering::SeqCst);
						let body: ChunkedStreamBody = ChunkedStreamBody {
							remaining: count,
							chunk: Bytes::from(vec![b'z'; chunk_size]),
						};
						let resp: Response<ChunkedStreamBody> = Response::builder().status(200).body(body).unwrap();
						return Ok::<_, Infallible>(resp);
					}
				});
				let _ = http2::Builder::new(TokioExecutor::new())
					.serve_connection(TokioIo::new(tls), service)
					.await;
			});
		}
	});

	return Backend {
		addr,
		status: Arc::new(AtomicU16::new(200)),
		hits,
		name: "stream",
	};
}

const fn enabled_cache() -> CacheConfig {
	return CacheConfig {
		enabled: true,
		max_entries: NonZeroUsize::new(100).unwrap(),
		max_entry_bytes: NonZeroUsize::new(1024 * 1024).unwrap(),
		default_ttl_secs: NonZeroU64::new(300).unwrap(),
	};
}

#[tokio::test]
async fn retry_moves_to_a_different_backend_after_retryable_status() {
	install_crypto();
	let server_config: Arc<rustls::ServerConfig> = backend_server_config();
	let s1: Backend = spawn_backend("b1", server_config.clone()).await;
	let s2: Backend = spawn_backend("b2", server_config).await;

	let state: Arc<ProxyState> = build_state(vec![backend("b1", s1.addr), backend("b2", s2.addr)], 2);

	// Probe (both healthy) to learn which backend this client IP selects first.
	let client_ip: &str = "10.9.8.7";
	let (probe_status, first_name) = send(&state, client_ip).await;
	assert_eq!(probe_status, StatusCode::OK, "probe should succeed");
	assert!(
		first_name == "b1" || first_name == "b2",
		"unexpected body: {first_name}"
	);

	// Flip the first-selected backend to a retryable failure; the other stays healthy.
	let (failing, healthy): (&Backend, &Backend) = if first_name == "b1" { (&s1, &s2) } else { (&s2, &s1) };
	failing.status.store(503, Ordering::SeqCst);

	let failing_hits_before: usize = failing.hits.load(Ordering::SeqCst);
	let healthy_hits_before: usize = healthy.hits.load(Ordering::SeqCst);

	// Same client IP: the first pick now 503s, so the retry must land on the other backend.
	let (status, body) = send(&state, client_ip).await;

	assert_eq!(
		status,
		StatusCode::OK,
		"retry should have produced a success from the healthy backend"
	);
	assert_eq!(
		body, healthy.name,
		"response body must come from the healthy backend, not the failing one"
	);
	assert!(
		failing.hits.load(Ordering::SeqCst) > failing_hits_before,
		"failing backend should have been tried first",
	);
	assert!(
		healthy.hits.load(Ordering::SeqCst) > healthy_hits_before,
		"healthy backend should have received the retry",
	);
}

#[tokio::test]
async fn single_backend_retries_the_same_backend() {
	install_crypto();
	let server_config: Arc<rustls::ServerConfig> = backend_server_config();
	let only: Backend = spawn_backend("solo", server_config).await;
	only.status.store(503, Ordering::SeqCst);

	// One backend, 2 retries -> 3 attempts total. With no alternative, every attempt must re-hit
	// the same backend (proving exclusion is a preference, not a hard drop).
	let state: Arc<ProxyState> = build_state(vec![backend("solo", only.addr)], 2);

	let (status, body) = send(&state, "10.1.2.3").await;

	assert_eq!(
		status,
		StatusCode::SERVICE_UNAVAILABLE,
		"final status is the backend's 503"
	);
	assert_eq!(body, "solo");
	assert_eq!(
		only.hits.load(Ordering::SeqCst),
		3,
		"single backend must be retried on every one of the 3 attempts",
	);
}

#[tokio::test]
async fn anonymous_request_without_identity_is_rejected() {
	install_crypto();
	let server_config: Arc<rustls::ServerConfig> = backend_server_config();
	let only: Backend = spawn_backend("solo", server_config).await;
	let hits_before: usize = only.hits.load(Ordering::SeqCst);

	let state: Arc<ProxyState> = build_state(vec![backend("solo", only.addr)], 2);

	// mTLS is mandatory on every listener, so a request with no parseable identity is an
	// authenticated-but-unnameable peer. It must be refused before routing — never forwarded
	// anonymously (which would also collapse onto one shared empty-identity cache partition).
	let (status, _body) = send_as(&state, "10.4.4.4", None).await;

	assert_eq!(
		status,
		StatusCode::FORBIDDEN,
		"anonymous request must be rejected with 403"
	);
	assert_eq!(
		only.hits.load(Ordering::SeqCst),
		hits_before,
		"a rejected anonymous request must never reach a backend",
	);
}

#[tokio::test]
async fn cache_does_not_leak_across_identities() {
	install_crypto();
	let echo: Backend = spawn_echo_backend(backend_server_config()).await;
	let state: Arc<ProxyState> = build_state_with_cache(
		vec![backend("svc", echo.addr)],
		0,
		enabled_cache(),
		RevocationSet::default(),
		TimeoutConfig::default(),
	);

	let device_a: PeerIdentity = identity_with_cn("device-a");
	let device_b: PeerIdentity = identity_with_cn("device-b");

	// Device A's first request forwards and caches its own response.
	let (status_a1, body_a1) = send_as(&state, "10.0.0.1", Some(device_a)).await;
	assert_eq!(status_a1, StatusCode::OK);
	assert_eq!(body_a1, "device-a");
	assert_eq!(echo.hits.load(Ordering::SeqCst), 1, "first request must forward");

	// Device A repeats: served from cache, no new forward.
	let (_status_a2, body_a2) = send_as(&state, "10.0.0.1", Some(device_a)).await;
	assert_eq!(body_a2, "device-a");
	assert_eq!(
		echo.hits.load(Ordering::SeqCst),
		1,
		"repeat for same identity must hit the cache"
	);

	// Device B, same URL: must NOT receive device A's cached body — it forwards and gets its own.
	let (status_b, body_b) = send_as(&state, "10.0.0.2", Some(device_b)).await;
	assert_eq!(status_b, StatusCode::OK);
	assert_eq!(
		body_b, "device-b",
		"device B must not be served device A's cached response"
	);
	assert_eq!(
		echo.hits.load(Ordering::SeqCst),
		2,
		"different identity must miss the cache and forward"
	);
}

#[tokio::test]
async fn revoked_identity_gets_403_and_never_reaches_backend() {
	install_crypto();
	let echo: Backend = spawn_echo_backend(backend_server_config()).await;

	let revoked: PeerIdentity = identity_with_cn("device-bad");
	let allowed: PeerIdentity = identity_with_cn("device-good");

	// Revocation set naming exactly the bad device's key SPKI.
	let toml: String = format!("[[revoked]]\nspki = \"{}\"\nreason = \"clone\"\n", revoked.spki_hex());
	let revocation: RevocationSet = RevocationSet::parse(&toml).unwrap();

	let cache_off: CacheConfig = CacheConfig {
		enabled: false,
		..CacheConfig::default()
	};
	let state: Arc<ProxyState> = build_state_with_cache(
		vec![backend("svc", echo.addr)],
		0,
		cache_off,
		revocation,
		TimeoutConfig::default(),
	);

	// Revoked identity → 403 with the "revoked" body, and the backend is never touched.
	let (status, body) = send_as(&state, "10.0.0.1", Some(revoked)).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert_eq!(body, "revoked");
	assert_eq!(
		echo.hits.load(Ordering::SeqCst),
		0,
		"revoked request must never reach the backend"
	);

	// Un-revoked identity on the SAME config → 200 and the backend is hit. Nothing but the identity
	// differs, so the diff proves the revocation set is what produced the 403.
	let (status2, _body2) = send_as(&state, "10.0.0.2", Some(allowed)).await;
	assert_eq!(status2, StatusCode::OK);
	assert_eq!(
		echo.hits.load(Ordering::SeqCst),
		1,
		"un-revoked request on the same config must forward"
	);
}

#[tokio::test]
async fn h2_pool_caps_and_evicts_dead_connections() {
	install_crypto();
	let token: CancellationToken = CancellationToken::new();
	let srv: Backend = spawn_backend_with_shutdown("pool", backend_server_config(), token.clone()).await;
	let cfg: BackendConfig = backend("pool", srv.addr);

	const CAP: usize = 3;
	const STREAM_WINDOW: u32 = 2 * 1024 * 1024;
	const CONN_WINDOW: u32 = 4 * 1024 * 1024;
	let conn_pool: ConnPool =
		ConnPool::new().with_pool_config(u32::try_from(CAP).unwrap(), 16, STREAM_WINDOW, CONN_WINDOW);
	let (client_config, connector) = client_tls();
	let ct: Duration = Duration::from_secs(5);
	let ht: Duration = Duration::from_secs(5);

	// Concurrent cold acquires: several race to connect before any pooled connection is ready, so
	// connect_tcp_h2's request-path cap guard is exercised. It must never store more than CAP.
	let acquire = || conn_pool.acquire(&cfg, &connector, &client_config, ct, ht);
	let _ = tokio::join!(
		acquire(),
		acquire(),
		acquire(),
		acquire(),
		acquire(),
		acquire(),
		acquire(),
		acquire(),
	);
	let after_race: usize = conn_pool.pooled_h2_conns(&srv.addr);
	assert!(
		after_race > 0,
		"concurrent acquires should have pooled at least one connection"
	);
	assert!(
		after_race <= CAP,
		"pool exceeded the cap under concurrent connects: {after_race} > {CAP}"
	);

	// warm_up tops the pool up to exactly CAP, and repeating it must not push past the cap.
	conn_pool
		.warm_up(std::slice::from_ref(&cfg), &connector, &client_config, ct, ht)
		.await;
	assert_eq!(
		conn_pool.pooled_h2_conns(&srv.addr),
		CAP,
		"warm_up should fill to the cap"
	);
	conn_pool
		.warm_up(std::slice::from_ref(&cfg), &connector, &client_config, ct, ht)
		.await;
	assert_eq!(
		conn_pool.pooled_h2_conns(&srv.addr),
		CAP,
		"repeat warm_up must not exceed the cap"
	);

	// Kill the backend: its connections close and the proxy's pooled senders become is_closed().
	token.cancel();
	// Each acquire prunes dead senders (retain !is_closed) then redials — which now fails. Poll
	// until every dead sender has been evicted (bounded so a hang fails loudly rather than spins).
	let mut evicted: bool = false;
	for _ in 0..100 {
		let _ = conn_pool.acquire(&cfg, &connector, &client_config, ct, ht).await;
		if conn_pool.pooled_h2_conns(&srv.addr) == 0 {
			evicted = true;
			break;
		}
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	assert!(
		evicted,
		"dead H2 senders must be evicted from the pool after the backend dies"
	);
}

#[tokio::test]
async fn forwarded_for_carries_client_ip() {
	install_crypto();
	let echo: Backend = spawn_header_echo_backend("x-forwarded-for", backend_server_config()).await;
	let state: Arc<ProxyState> = build_state(vec![backend("svc", echo.addr)], 0);

	// A request from a known client IP must reach the backend with that IP in X-Forwarded-For.
	let (status, body) = send_as(&state, "198.51.100.23", Some(identity_with_cn("device-x"))).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		body, "198.51.100.23",
		"backend must receive the client IP in X-Forwarded-For"
	);
}

#[tokio::test]
async fn streamed_response_body_arrives_intact() {
	// The proxy drops its per-request sender handle as soon as the response headers arrive; this
	// proves a large multi-frame body still reaches the client in full afterward, because the spawned
	// connection driver — not the sender handle — owns the stream. Total size exceeds the 2 MB H2
	// stream window, so completing it requires live flow control from that driver.
	install_crypto();
	const CHUNK: usize = 64 * 1024;
	const COUNT: usize = 64; // 4 MB
	let srv: Backend = spawn_streaming_backend(CHUNK, COUNT, backend_server_config()).await;
	let state: Arc<ProxyState> = build_state(vec![backend("svc", srv.addr)], 0);

	let mut req: Request<Body> = Request::builder().method("GET").uri("/").body(Body::empty()).unwrap();
	let peer: SocketAddr = "10.0.0.1:40000".parse().unwrap();
	req.extensions_mut()
		.insert(ConnectInfo(ConnectAddr(peer, Some(identity_with_cn("device-s")))));

	let resp: Response<Body> = timeout(E2E_TIMEOUT, proxy_handler(State(state.clone()), req))
		.await
		.expect("handler timed out");
	assert_eq!(resp.status(), StatusCode::OK);
	let bytes: Bytes = resp.into_body().collect().await.unwrap().to_bytes();
	assert_eq!(
		bytes.len(),
		CHUNK * COUNT,
		"full streamed body must reach the client without truncation"
	);
	assert!(bytes.iter().all(|&b| b == b'z'), "streamed body content must be intact");
}

#[tokio::test]
async fn stalled_response_body_is_aborted_by_idle_timeout() {
	// The request timeout only bounds time-to-headers. A backend that sends headers plus a partial
	// body and then hangs must not stream forever: the response idle timeout has to abort it, which
	// also releases the connection permit, queue slot, and gauges the stalled body was holding.
	install_crypto();
	const INITIAL_CHUNKS: usize = 1;
	const CHUNK: usize = 16 * 1024;
	let srv: Backend = spawn_stalling_backend(INITIAL_CHUNKS, CHUNK, backend_server_config()).await;

	// Short idle timeout so the stall trips quickly; everything else default.
	let timeouts: TimeoutConfig = TimeoutConfig {
		response_idle_secs: NonZeroU64::new(1).unwrap(),
		..TimeoutConfig::default()
	};
	let cache_off: CacheConfig = CacheConfig {
		enabled: false,
		..CacheConfig::default()
	};
	let state: Arc<ProxyState> = build_state_with_cache(
		vec![backend("svc", srv.addr)],
		0,
		cache_off,
		RevocationSet::default(),
		timeouts,
	);

	let mut req: Request<Body> = Request::builder().method("GET").uri("/").body(Body::empty()).unwrap();
	let peer: SocketAddr = "10.0.0.9:40000".parse().unwrap();
	req.extensions_mut()
		.insert(ConnectInfo(ConnectAddr(peer, Some(identity_with_cn("device-stall")))));

	// Headers arrive promptly — send_request resolves at TTFB regardless of the body stall.
	let resp: Response<Body> = timeout(E2E_TIMEOUT, proxy_handler(State(state.clone()), req))
		.await
		.expect("handler timed out");
	assert_eq!(resp.status(), StatusCode::OK);

	// Reading the body must terminate with an error at ~idle timeout, not hang. Before this fix the
	// handler applied no body timeout, so this collect would block until E2E_TIMEOUT — the inner
	// timeout below (well under E2E_TIMEOUT) is the regression guard for that hang.
	let result: Result<_, _> = timeout(Duration::from_secs(5), resp.into_body().collect())
		.await
		.expect("body read hung past the idle timeout — GuardedBody did not abort the stall");
	assert!(
		result.is_err(),
		"a stalled response body must surface as a stream error, not a clean end"
	);
	assert_eq!(
		srv.hits.load(Ordering::SeqCst),
		1,
		"the stalling backend must have served the request"
	);
}

#[tokio::test]
async fn quic_streamed_response_body_arrives_intact() {
	// The QUIC backend forwards over HTTP/1 (per Reduction's QUIC framing). This exercises the H1
	// path that the TCP/H2 streaming test cannot reach, confirming the same invariant there: the
	// per-request sender drops early yet the full multi-frame body still reaches the client.
	install_crypto();
	const CHUNK: usize = 64 * 1024;
	const COUNT: usize = 64; // 4 MB
	let srv: Backend = spawn_quic_streaming_backend(CHUNK, COUNT, backend_server_config()).await;
	let state: Arc<ProxyState> = build_state(vec![backend_quic("svc", srv.addr)], 0);

	let mut req: Request<Body> = Request::builder().method("GET").uri("/").body(Body::empty()).unwrap();
	let peer: SocketAddr = "10.0.0.2:40000".parse().unwrap();
	req.extensions_mut()
		.insert(ConnectInfo(ConnectAddr(peer, Some(identity_with_cn("device-q")))));

	let resp: Response<Body> = timeout(E2E_TIMEOUT, proxy_handler(State(state.clone()), req))
		.await
		.expect("handler timed out");
	assert_eq!(resp.status(), StatusCode::OK);
	let bytes: Bytes = resp.into_body().collect().await.unwrap().to_bytes();
	assert_eq!(
		bytes.len(),
		CHUNK * COUNT,
		"full QUIC-streamed body must reach the client without truncation"
	);
	assert!(
		bytes.iter().all(|&b| b == b'q'),
		"QUIC-streamed body content must be intact"
	);
	assert_eq!(
		srv.hits.load(Ordering::SeqCst),
		1,
		"the QUIC backend must have served the request"
	);
}

#[tokio::test]
async fn forwarded_for_replaces_client_supplied_value() {
	install_crypto();
	let echo: Backend = spawn_header_echo_backend("x-forwarded-for", backend_server_config()).await;
	let state: Arc<ProxyState> = build_state(vec![backend("svc", echo.addr)], 0);

	// The client spoofs X-Forwarded-For; the proxy must overwrite it with the real peer IP.
	let mut req: Request<Body> = Request::builder()
		.method("GET")
		.uri("/")
		.header("x-forwarded-for", "1.2.3.4")
		.body(Body::empty())
		.unwrap();
	let peer: SocketAddr = "198.51.100.77:40000".parse().unwrap();
	req.extensions_mut()
		.insert(ConnectInfo(ConnectAddr(peer, Some(identity_with_cn("device-y")))));

	let resp: Response<Body> = timeout(E2E_TIMEOUT, proxy_handler(State(state.clone()), req))
		.await
		.expect("handler timed out");
	assert_eq!(resp.status(), StatusCode::OK);
	let bytes: Bytes = resp.into_body().collect().await.unwrap().to_bytes();
	assert_eq!(
		String::from_utf8_lossy(&bytes),
		"198.51.100.77",
		"spoofed X-Forwarded-For must be overwritten"
	);
}

// ── F1 assembled one-trip gate ───────────────────────────────────────────────────────────────────

// A free loopback address, released so a wakeable backend can be left cold and brought up later.
fn reserve_addr() -> SocketAddr {
	let listener: std::net::TcpListener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	let addr: SocketAddr = listener.local_addr().unwrap();
	drop(listener);
	return addr;
}

// Like spawn_backend, but binds a caller-chosen (pre-reserved) address, so a test can bring the
// server up mid-request to model a woken service. Always answers 200 with `name`.
async fn spawn_backend_at(addr: SocketAddr, name: &'static str, server_config: Arc<rustls::ServerConfig>) {
	let listener: TcpListener = TcpListener::bind(addr).await.unwrap();
	let acceptor: TlsAcceptor = TlsAcceptor::from(server_config);
	tokio::spawn(async move {
		loop {
			let (tcp, _) = match listener.accept().await {
				Ok(pair) => pair,
				Err(_) => return,
			};
			let acceptor: TlsAcceptor = acceptor.clone();
			tokio::spawn(async move {
				let tls = match acceptor.accept(tcp).await {
					Ok(s) => s,
					Err(_) => return,
				};
				let service = service_fn(move |_req| async move {
					return Ok::<_, Infallible>(Response::builder().status(200).body(Full::new(Bytes::from(name))).unwrap());
				});
				let _ = http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), service).await;
			});
		}
	});
}

// Build a proxy state routing "/" → a single wakeable backend, with a chosen wake timeout.
fn build_state_wake(backends: Vec<BackendConfig>, max_retries: u32, wake_secs: u64) -> Arc<ProxyState> {
	let client_config = client_tls().0;
	let pool: BackendPool = BackendPool::new(backends).unwrap();
	let mut backend_pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();
	backend_pools.insert(ArrayString::from("svc").unwrap(), pool);
	let route: RouteConfig = RouteConfig {
		path_prefix: ArrayString::from("/").unwrap(),
		backend_id: ArrayString::from("svc").unwrap(),
		timeout_secs: None,
	};
	let reloadable: ReloadableState = ReloadableState {
		router: Router::new(&[route]),
		backend_pools,
		acl: AccessControl::new(vec![], vec![]),
	};
	let high_threshold: CircuitBreakerConfig = CircuitBreakerConfig {
		failure_threshold: NonZeroU32::new(1000).unwrap(),
		recovery_timeout_secs: 60,
		half_open_max_requests: NonZeroU32::new(1).unwrap(),
	};
	let retry: RetryConfig = RetryConfig { max_retries, base_delay_ms: 1, max_delay_ms: 1, jitter_ms: 0 };
	let proxy_config: ProxyConfig = ProxyConfig { wake_timeout_secs: NonZeroU64::new(wake_secs).unwrap(), ..ProxyConfig::default() };
	let cache_off: CacheConfig = CacheConfig { enabled: false, ..CacheConfig::default() };
	return ProxyState::for_test(TestProxyStateParams {
		circuit_breaker_config: high_threshold,
		retry_config: retry,
		cache_config: cache_off,
		proxy_config,
		..TestProxyStateParams::new(reloadable, RevocationSet::default(), client_config, TimeoutConfig::default())
	});
}

// The headline Phase 2 gate: a single request to a COLD wakeable backend parks (connect refused),
// then — once the backend is brought up mid-park (as a wake would) — releases and returns 200 in one
// client round trip, with the breaker never tripped.
#[tokio::test]
async fn wakeable_cold_request_parks_then_returns_200_when_woken() {
	install_crypto();
	let addr: SocketAddr = reserve_addr();
	let state: Arc<ProxyState> = build_state_wake(vec![backend("svc", addr).with_wakeable(true)], 3, 20);

	let request_state: Arc<ProxyState> = state.clone();
	let request = tokio::spawn(async move { send(&request_state, "10.0.0.1").await });

	// Let the request park on the cold backend, then wake it.
	tokio::time::sleep(Duration::from_millis(400)).await;
	spawn_backend_at(addr, "svc", backend_server_config()).await;

	let (status, body) = request.await.unwrap();
	assert_eq!(status, StatusCode::OK, "a woken cold backend returns 200 in one round trip");
	assert_eq!(body, "svc");
	assert_eq!(state.circuit_breakers.state("svc"), CircuitState::Closed, "the cold miss must not trip the breaker");
}

// The other side of the gate: a wake that never completes returns 503 at the deadline, not 502.
#[tokio::test]
async fn wakeable_cold_request_503s_when_wake_times_out() {
	install_crypto();
	let addr: SocketAddr = reserve_addr();
	let state: Arc<ProxyState> = build_state_wake(vec![backend("svc", addr).with_wakeable(true)], 3, 1);

	let (status, _body) = send(&state, "10.0.0.2").await;

	assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "a wake that never completes 503s at the deadline");
	assert_eq!(state.circuit_breakers.state("svc"), CircuitState::Closed, "a timed-out wake still does not trip the breaker");
}

// Like build_state_wake, but injects a tunnel registry into the proxy's conn pool so a control peer's
// refusal (`registry.note_refusal`) can abort a parked request.
fn build_state_wake_reg(backends: Vec<BackendConfig>, max_retries: u32, wake_secs: u64, registry: Arc<TunnelRegistry>) -> Arc<ProxyState> {
	let client_config = client_tls().0;
	let pool: BackendPool = BackendPool::new(backends).unwrap();
	let mut backend_pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();
	backend_pools.insert(ArrayString::from("svc").unwrap(), pool);
	let route: RouteConfig = RouteConfig {
		path_prefix: ArrayString::from("/").unwrap(),
		backend_id: ArrayString::from("svc").unwrap(),
		timeout_secs: None,
	};
	let reloadable: ReloadableState = ReloadableState {
		router: Router::new(&[route]),
		backend_pools,
		acl: AccessControl::new(vec![], vec![]),
	};
	let high_threshold: CircuitBreakerConfig = CircuitBreakerConfig {
		failure_threshold: NonZeroU32::new(1000).unwrap(),
		recovery_timeout_secs: 60,
		half_open_max_requests: NonZeroU32::new(1).unwrap(),
	};
	let retry: RetryConfig = RetryConfig { max_retries, base_delay_ms: 1, max_delay_ms: 1, jitter_ms: 0 };
	let proxy_config: ProxyConfig = ProxyConfig { wake_timeout_secs: NonZeroU64::new(wake_secs).unwrap(), ..ProxyConfig::default() };
	let cache_off: CacheConfig = CacheConfig { enabled: false, ..CacheConfig::default() };
	return ProxyState::for_test(TestProxyStateParams {
		circuit_breaker_config: high_threshold,
		retry_config: retry,
		cache_config: cache_off,
		proxy_config,
		tunnel_registry: Some(registry),
		..TestProxyStateParams::new(reloadable, RevocationSet::default(), client_config, TimeoutConfig::default())
	});
}

// F1 budget-refusal: a control peer that refuses the wake makes the parked request 503 AT ONCE (the
// abort-park path), long before the wake deadline — the sub-100ms case in the Phase 2 gate.
#[tokio::test]
async fn wakeable_cold_request_503s_promptly_on_refusal() {
	install_crypto();
	let addr: SocketAddr = reserve_addr();
	let registry: Arc<TunnelRegistry> = Arc::new(TunnelRegistry::new(8));
	// A long wake timeout: only the refusal, not the deadline, can end the park quickly.
	let state: Arc<ProxyState> = build_state_wake_reg(vec![backend("svc", addr).with_wakeable(true)], 3, 300, registry.clone());

	let request_state: Arc<ProxyState> = state.clone();
	let started = std::time::Instant::now();
	let request = tokio::spawn(async move { send(&request_state, "10.0.0.3").await });

	// Let the request reach the park, then refuse. The refusal must end the request in a couple of
	// seconds — the abort-park path — rather than waiting out the 300s wake deadline.
	tokio::time::sleep(Duration::from_millis(500)).await;
	registry.note_refusal("svc");
	let (status, _body) = request.await.unwrap();
	let elapsed = started.elapsed();

	assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "a refused wake 503s");
	assert!(elapsed < Duration::from_secs(5), "refusal must abort the park, not wait the 300s deadline; took {elapsed:?}");
	assert_eq!(state.circuit_breakers.state("svc"), CircuitState::Closed, "a refused wake does not trip the breaker");
}
