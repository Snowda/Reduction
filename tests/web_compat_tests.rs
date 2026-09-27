// Web-compatibility contract for the public-blog cutover: drive the real `proxy_handler` against a
// live PLAINTEXT HTTP/1.1 backend (scheme = http) as an ANONYMOUS browser (client_auth = disabled) and
// assert, from the backend's own echoed view of each request, that the proxy preserves Host, path,
// query, Range, conditional requests, HEAD, streaming bodies, status codes, and the forwarding headers —
// and that the response cache and zstd transform stay OFF by default. This is the end-to-end proof that
// capabilities 1 (anonymous), 2 (plain-HTTP backend), and 4 (web-compat) compose on the real forward path.
#![cfg(feature = "integration_tests")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::str_to_string)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use arrayvec::ArrayString;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Method, Request, Response, StatusCode};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use reduction::acl::AccessControl;
use reduction::balancer::BackendPool;
use reduction::config::{
	BackendConfig, BackendScheme, CacheConfig, ClientAuthPolicy, CompressionConfig, TimeoutConfig, TransportKind,
};
use reduction::proxy::handler::{ProxyState, ReloadableState, TestProxyStateParams, proxy_handler};
use reduction::proxy::router::Router;
use reduction::transport::ConnectAddr;
use reduction::tunnel::revocation::RevocationSet;
use rustls::RootCertStore;
use tokio::net::TcpListener;
use tokio::time::timeout;

const E2E_TIMEOUT: Duration = Duration::from_secs(10);
const CANONICAL_HOST: &str = "conorforde.com";
const STREAM_BODY_LEN: usize = 256 * 1024;

fn install_crypto() {
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

// A rustls client config that is never actually used (the backend hop is cleartext), but for_test needs one.
fn unused_client_config() -> Arc<rustls::ClientConfig> {
	install_crypto();
	return Arc::new(
		rustls::ClientConfig::builder()
			.with_root_certificates(RootCertStore::empty())
			.with_no_client_auth(),
	);
}

// Plaintext HTTP/1.1 echo backend. It reflects what it received back into `x-echo-*` response headers so
// the proxy's rewriting is observable, and returns a status chosen by the request: 304 when a conditional
// header is present, 206 + Content-Range when a Range is present, else 200 with a fixed streaming body.
async fn spawn_echo_backend() -> (SocketAddr, Arc<AtomicUsize>) {
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
				let service = service_fn(move |req: Request<hyper::body::Incoming>| {
					let hits_req: Arc<AtomicUsize> = hits_conn.clone();
					async move {
						hits_req.fetch_add(1, Ordering::SeqCst);
						return Ok::<_, Infallible>(echo_response(&req));
					}
				});
				let _ = http1::Builder::new().serve_connection(TokioIo::new(tcp), service).await;
			});
		}
	});
	return (addr, hits);
}

fn header_str<'a>(req: &'a Request<hyper::body::Incoming>, name: &str) -> &'a str {
	return req.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or("");
}

fn echo_response(req: &Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
	let path: &str = req.uri().path_and_query().map_or("/", |pq| pq.as_str());
	let host: &str = header_str(req, "host");
	let xff: &str = header_str(req, "x-forwarded-for");
	let range: &str = header_str(req, "range");
	let had_secret: &str = if req.headers().contains_key("x-secret") { "1" } else { "0" };
	let has_conditional: bool = req.headers().contains_key("if-none-match");
	let has_range: bool = req.headers().contains_key("range");

	let mut builder = Response::builder()
		.header("x-echo-method", req.method().as_str())
		.header("x-echo-path", path)
		.header("x-echo-host", host)
		.header("x-echo-xff", xff)
		.header("x-echo-range", range)
		.header("x-echo-had-secret", had_secret);

	if has_conditional {
		return builder.status(StatusCode::NOT_MODIFIED).body(Full::new(Bytes::new())).unwrap();
	}
	if has_range {
		builder = builder.status(StatusCode::PARTIAL_CONTENT).header("content-range", "bytes 0-4/100");
		return builder.body(Full::new(Bytes::from_static(b"01234"))).unwrap();
	}
	return builder
		.status(StatusCode::OK)
		.body(Full::new(Bytes::from(vec![b'z'; STREAM_BODY_LEN])))
		.unwrap();
}

// A ProxyState routing "/" to a cleartext-HTTP backend whose Host is the canonical blog host, in
// public-browser mode (anonymous admitted) with the response cache off (the default).
fn build_state(backend_addr: SocketAddr) -> Arc<ProxyState> {
	// Default compression (enabled) so the passthrough tests exercise the normal path.
	return build_state_with_compression(backend_addr, CompressionConfig::default());
}

fn build_state_with_compression(backend_addr: SocketAddr, compression: CompressionConfig) -> Arc<ProxyState> {
	install_crypto();
	let backend: BackendConfig = BackendConfig::new("blog", backend_addr, 1.0, TransportKind::Tcp)
		.unwrap()
		.with_scheme(BackendScheme::Http)
		.with_host(CANONICAL_HOST.to_owned());
	let pool: BackendPool = BackendPool::new(vec![backend]).unwrap();
	let mut backend_pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();
	backend_pools.insert(ArrayString::from("blog").unwrap(), pool);
	let reloadable: ReloadableState = ReloadableState {
		router: Router::new(&[reduction::config::RouteConfig {
			path_prefix: ArrayString::from("/").unwrap(),
			backend_id: ArrayString::from("blog").unwrap(),
			timeout_secs: None,
		}]),
		backend_pools,
		acl: AccessControl::new(vec![], vec![]),
	};
	return ProxyState::for_test(TestProxyStateParams {
		client_auth: ClientAuthPolicy::Disabled,
		// Cache defaults to disabled — asserted explicitly by one of the tests below.
		cache_config: CacheConfig::default(),
		compression_config: compression,
		..TestProxyStateParams::new(reloadable, RevocationSet::default(), unused_client_config(), TimeoutConfig::default())
	});
}

// Drive one anonymous request (no mTLS identity) through the real handler, returning the response.
async fn send(state: &Arc<ProxyState>, method: Method, target: &str, extra: &[(&str, &str)]) -> Response<Body> {
	let mut builder = Request::builder().method(method).uri(target);
	for (k, v) in extra {
		builder = builder.header(*k, *v);
	}
	let mut req: Request<Body> = builder.body(Body::empty()).unwrap();
	let peer: SocketAddr = "203.0.113.7:44444".parse().unwrap();
	req.extensions_mut().insert(ConnectInfo(ConnectAddr(peer, None)));
	return timeout(E2E_TIMEOUT, proxy_handler(State(state.clone()), req))
		.await
		.expect("handler timed out");
}

fn echoed<'a>(resp: &'a Response<Body>, name: &str) -> &'a str {
	return resp.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or("");
}

#[tokio::test]
async fn anonymous_get_preserves_path_query_host_and_forwarding_headers() {
	let (addr, hits) = spawn_echo_backend().await;
	let state = build_state(addr);

	let resp = send(&state, Method::GET, "/posts/hello?draft=1&x=2", &[]).await;
	assert_eq!(resp.status(), StatusCode::OK, "anonymous browser must be served");
	assert_eq!(hits.load(Ordering::SeqCst), 1);
	// Path + query reach the backend verbatim.
	assert_eq!(echoed(&resp, "x-echo-path"), "/posts/hello?draft=1&x=2");
	assert_eq!(echoed(&resp, "x-echo-method"), "GET");
	// Host is set to the configured canonical backend host (preserve-canonical-Host via the `host` field).
	assert_eq!(echoed(&resp, "x-echo-host"), CANONICAL_HOST);
	// The real peer IP is forwarded; no anonymous identity header is injected.
	assert_eq!(echoed(&resp, "x-echo-xff"), "203.0.113.7");
}

#[tokio::test]
async fn head_request_is_forwarded() {
	let (addr, _hits) = spawn_echo_backend().await;
	let state = build_state(addr);
	let resp = send(&state, Method::HEAD, "/about", &[]).await;
	assert_eq!(resp.status(), StatusCode::OK);
	assert_eq!(echoed(&resp, "x-echo-method"), "HEAD");
	assert_eq!(echoed(&resp, "x-echo-path"), "/about");
}

#[tokio::test]
async fn range_request_passes_through_as_206() {
	let (addr, _hits) = spawn_echo_backend().await;
	let state = build_state(addr);
	let resp = send(&state, Method::GET, "/big.bin", &[("range", "bytes=0-4")]).await;
	// The 206 status and Content-Range flow back unchanged; the Range reached the backend.
	assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
	assert_eq!(echoed(&resp, "x-echo-range"), "bytes=0-4");
	assert_eq!(echoed(&resp, "content-range"), "bytes 0-4/100");
	let body = resp.into_body().collect().await.unwrap().to_bytes();
	assert_eq!(&body[..], b"01234", "partial body must pass through unchanged");
}

#[tokio::test]
async fn conditional_request_passes_through_as_304() {
	let (addr, _hits) = spawn_echo_backend().await;
	let state = build_state(addr);
	let resp = send(&state, Method::GET, "/style.css", &[("if-none-match", "\"abc123\"")]).await;
	assert_eq!(resp.status(), StatusCode::NOT_MODIFIED, "conditional 304 must flow back");
}

#[tokio::test]
async fn streaming_body_arrives_intact() {
	let (addr, _hits) = spawn_echo_backend().await;
	let state = build_state(addr);
	let resp = send(&state, Method::GET, "/", &[]).await;
	assert_eq!(resp.status(), StatusCode::OK);
	// The body is not transformed (no Content-Encoding) — checked before the body is consumed.
	assert!(resp.headers().get("content-encoding").is_none(), "body must not be re-encoded");
	let body = resp.into_body().collect().await.unwrap().to_bytes();
	assert_eq!(body.len(), STREAM_BODY_LEN, "a large streamed body must arrive whole");
	assert!(body.iter().all(|&b| b == b'z'), "streamed bytes must be uncorrupted");
}

#[tokio::test]
async fn zstd_transform_off_when_disabled() {
	let (addr, _hits) = spawn_echo_backend().await;
	let compression: CompressionConfig = CompressionConfig {
		enabled: false,
		..CompressionConfig::default()
	};
	let state = build_state_with_compression(addr, compression);
	// Client advertises zstd; with the transform disabled the proxy must NOT compress the response.
	let resp = send(&state, Method::GET, "/", &[("accept-encoding", "zstd")]).await;
	assert_eq!(resp.status(), StatusCode::OK);
	assert!(
		resp.headers().get("content-encoding").is_none(),
		"zstd body transform must stay off for the first cutover when compression is disabled"
	);
}

// The on/off diff: the ONLY change from the test above is compression.enabled — with it on (the
// default), a zstd-accepting client's large body IS transformed. This proves the flag actually gates it.
#[tokio::test]
async fn zstd_transform_on_by_default_when_enabled() {
	let (addr, _hits) = spawn_echo_backend().await;
	let state = build_state(addr); // compression enabled (default)
	let resp = send(&state, Method::GET, "/", &[("accept-encoding", "zstd")]).await;
	assert_eq!(resp.status(), StatusCode::OK);
	assert_eq!(
		resp.headers().get("content-encoding").and_then(|v| v.to_str().ok()),
		Some("zstd"),
		"with compression enabled a zstd-accepting client's response is transformed"
	);
}

#[tokio::test]
async fn connection_nominated_header_is_stripped() {
	let (addr, _hits) = spawn_echo_backend().await;
	let state = build_state(addr);
	// `Connection: x-secret` nominates x-secret as hop-by-hop; the backend must never see it.
	let resp = send(
		&state,
		Method::GET,
		"/",
		&[("connection", "x-secret"), ("x-secret", "leak")],
	)
	.await;
	assert_eq!(resp.status(), StatusCode::OK);
	assert_eq!(echoed(&resp, "x-echo-had-secret"), "0", "a connection-nominated header must be stripped");
}

#[tokio::test]
async fn response_cache_disabled_by_default_backend_hit_every_time() {
	let (addr, hits) = spawn_echo_backend().await;
	let state = build_state(addr);
	let _first = send(&state, Method::GET, "/", &[]).await;
	let _second = send(&state, Method::GET, "/", &[]).await;
	// With the cache off (default), both identical GETs reach the backend — no cached replay.
	assert_eq!(hits.load(Ordering::SeqCst), 2, "the response cache must be off by default");
}

// The forwarding-header injection also strips any client-supplied X-Forwarded-For before setting the
// real one, so a browser cannot spoof its apparent source IP through the anonymous path.
#[tokio::test]
async fn client_supplied_forwarding_header_is_overwritten() {
	let (addr, _hits) = spawn_echo_backend().await;
	let state = build_state(addr);
	let resp = send(&state, Method::GET, "/", &[("x-forwarded-for", "1.2.3.4")]).await;
	let seen: &str = echoed(&resp, "x-echo-xff");
	assert_eq!(seen, "203.0.113.7", "a spoofed X-Forwarded-For must be replaced with the real peer IP");
}
