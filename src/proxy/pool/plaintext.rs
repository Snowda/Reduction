use std::time::Duration;

use axum::body::Body;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use super::{ConnPool, HttpSender};
use crate::config::BackendConfig;
use crate::error::{ReductionError, Result};

impl ConnPool {
	// Cleartext HTTP/1.1 to a plain-HTTP backend (scheme = http): a raw TCP connection, no TLS handshake,
	// driven by an http1 connection task. Not pooled — like the tunnel H1 path, a fresh connection is
	// dialed per acquire (the backend hop is a trusted private network, and H1 keep-alive pooling would
	// need idle-connection readiness tracking the H2 pool has but H1 does not). The connection driver is
	// spawned so the returned sender can drop after the request without truncating the in-flight body.
	pub(super) async fn acquire_tcp_plaintext(
		&self,
		backend: &BackendConfig,
		connect_timeout: Duration,
		handshake_timeout: Duration,
	) -> Result<HttpSender> {
		let tcp_stream: TcpStream = timeout(connect_timeout, TcpStream::connect(backend.address))
			.await
			.map_err(|_| ReductionError::Forward("connect: timed out".to_owned()))?
			.map_err(|e| ReductionError::Forward(format!("connect {}: {e}", backend.address)))?;

		let io: TokioIo<TcpStream> = TokioIo::new(tcp_stream);

		let (sender, conn): (http1::SendRequest<Body>, _) = timeout(handshake_timeout, http1::handshake(io))
			.await
			.map_err(|_| ReductionError::Forward("http1 handshake: timed out".to_owned()))?
			.map_err(|e| ReductionError::Forward(format!("http1 handshake: {e}")))?;

		tokio::spawn(async move {
			if let Err(e) = conn.await {
				debug!(error = %e, "cleartext HTTP/1.1 connection driver ended");
			}
		});

		return Ok(HttpSender::H1(sender));
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;
	use std::convert::Infallible;
	use std::net::SocketAddr;
	use std::sync::Arc;
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::time::Duration;

	use axum::body::Body;
	use axum::http::{Request, Response, StatusCode};
	use bytes::Bytes;
	use http_body_util::Full;
	use hyper::server::conn::http1 as server_http1;
	use hyper::service::service_fn;
	use hyper_util::rt::TokioIo;
	use tokio::net::TcpListener;

	use super::super::testutil::NoVerify;
	use super::super::HttpSender;
	use crate::acl::AccessControl;
	use crate::config::{BackendConfig, BackendScheme, TimeoutConfig, TransportKind};
	use crate::proxy::handler::{ProxyState, ReloadableState, TestProxyStateParams};
	use crate::proxy::router::Router;
	use crate::tunnel::revocation::RevocationSet;

	// A minimal ProxyState for the cleartext dial tests — the TLS connector it carries is never used on
	// the plaintext path, so a no-verify client config stands in.
	fn make_test_state() -> Arc<ProxyState> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let client_config: Arc<rustls::ClientConfig> = Arc::new(
			rustls::ClientConfig::builder()
				.dangerous()
				.with_custom_certificate_verifier(Arc::new(NoVerify))
				.with_no_client_auth(),
		);
		let reloadable: ReloadableState = ReloadableState {
			router: Router::new(&[]),
			backend_pools: HashMap::new(),
			acl: AccessControl::new(vec![], vec![]),
		};
		return ProxyState::for_test(TestProxyStateParams::new(
			reloadable,
			RevocationSet::default(),
			client_config,
			TimeoutConfig::default(),
		));
	}

	// A plain HTTP/1.1 server over raw TCP (no TLS), answering 200 "ok" and counting requests — the
	// blog:8080-style backend the cleartext scheme dials.
	async fn spawn_h1_plaintext_backend() -> (SocketAddr, Arc<AtomicUsize>) {
		let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr: SocketAddr = listener.local_addr().unwrap();
		let hits: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

		let hits_srv: Arc<AtomicUsize> = hits.clone();
		tokio::spawn(async move {
			loop {
				let (tcp, _) = match listener.accept().await {
					Ok(pair) => pair,
					Err(_) => return,
				};
				let hits_conn: Arc<AtomicUsize> = hits_srv.clone();
				tokio::spawn(async move {
					let service = service_fn(move |_req| {
						let hits_req: Arc<AtomicUsize> = hits_conn.clone();
						async move {
							hits_req.fetch_add(1, Ordering::SeqCst);
							let resp: Response<Full<Bytes>> = Response::builder()
								.status(StatusCode::OK)
								.body(Full::new(Bytes::from("ok")))
								.unwrap();
							return Ok::<_, Infallible>(resp);
						}
					});
					let _ = server_http1::Builder::new()
						.serve_connection(TokioIo::new(tcp), service)
						.await;
				});
			}
		});
		return (addr, hits);
	}

	// Cleartext scheme = http: acquire dials a raw TCP + HTTP/1.1 connection (no TLS) and the request
	// reaches the plaintext backend. The functional inverse below proves the default https path instead
	// attempts TLS against the same server and fails — so the scheme genuinely changes the dial.
	#[tokio::test]
	async fn test_acquire_plaintext_tcp_connects_and_sends() {
		let (addr, hits) = spawn_h1_plaintext_backend().await;
		let state = make_test_state();
		let backend: BackendConfig = BackendConfig::new("blog", addr, 1.0, TransportKind::Tcp)
			.unwrap()
			.with_scheme(BackendScheme::Http);
		let ct: Duration = Duration::from_secs(5);

		let mut sender = state
			.conn_pool
			.acquire(&backend, &state.tls_connector, &state.client_tls_config, ct, ct)
			.await
			.expect("cleartext acquire should connect to the plaintext backend");
		assert!(
			matches!(sender, HttpSender::H1(_)),
			"a plaintext backend must yield an H1 sender, not an H2 one"
		);
		// Cleartext H1 is intentionally not pooled in the H2 map.
		assert_eq!(state.conn_pool.pooled_h2_conns(&addr), 0, "cleartext H1 must not be pooled");

		let req: Request<Body> = Request::builder().uri("/").body(Body::empty()).unwrap();
		let resp = sender.send_request(req).await.expect("request should reach the plaintext backend");
		assert_eq!(resp.status(), StatusCode::OK);
		assert_eq!(hits.load(Ordering::SeqCst), 1);
	}

	#[tokio::test]
	async fn test_acquire_https_against_plaintext_backend_fails() {
		// Default scheme (https) against a cleartext backend must fail: the TLS handshake finds no TLS
		// server. This is the on/off diff — the ONLY difference from the test above is the scheme.
		let (addr, _hits) = spawn_h1_plaintext_backend().await;
		let state = make_test_state();
		let backend: BackendConfig = BackendConfig::new("blog", addr, 1.0, TransportKind::Tcp).unwrap();
		assert_eq!(backend.scheme, BackendScheme::Https, "default scheme must be https");
		let ct: Duration = Duration::from_secs(5);

		let result = state
			.conn_pool
			.acquire(&backend, &state.tls_connector, &state.client_tls_config, ct, ct)
			.await;
		assert!(
			result.is_err(),
			"the default TLS path must fail against a cleartext backend, proving the scheme changes the dial"
		);
	}
}
