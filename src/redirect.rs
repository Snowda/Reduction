use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::LOCATION;
use axum::http::{HeaderValue, Request, Response, StatusCode};
use axum::routing::any;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::HttpRedirectConfig;
use crate::error::Result;

// 308 (not 301) preserves method and body semantics for the permanent redirect.
const REDIRECT_STATUS: StatusCode = StatusCode::PERMANENT_REDIRECT;
// Path used when a request somehow carries no path/query (defensive; origin-form requests always have one).
const DEFAULT_PATH: &str = "/";

// The canonical HTTPS host every redirect points at, shared by the listener's handler.
#[derive(Debug, Clone)]
struct RedirectTarget {
	host: String,
}

// Build the absolute HTTPS Location from the trusted config host and the request's path+query. The
// incoming Host header is deliberately ignored — trusting it would be an open redirect.
fn redirect_location(host: &str, path_and_query: &str) -> String {
	return format!("https://{host}{path_and_query}");
}

// Turn one request into its redirect response; a path+query that cannot form a header value yields 400.
fn build_redirect(host: &str, path_and_query: &str) -> Response<Body> {
	let location: String = redirect_location(host, path_and_query);
	let mut response: Response<Body> = Response::new(Body::empty());
	match HeaderValue::from_str(&location) {
		Ok(value) => {
			*response.status_mut() = REDIRECT_STATUS;
			response.headers_mut().insert(LOCATION, value);
		}
		Err(_) => {
			*response.status_mut() = StatusCode::BAD_REQUEST;
		}
	}
	return response;
}

// Fallback handler: preserve path and query, ignore body and Host, never touch a backend.
async fn redirect_handler(State(target): State<Arc<RedirectTarget>>, req: Request<Body>) -> Response<Body> {
	let path_and_query: &str = req.uri().path_and_query().map_or(DEFAULT_PATH, |pq| pq.as_str());
	return build_redirect(&target.host, path_and_query);
}

// Bind the cleartext port-80 listener (synchronously, fail-fast) and spawn its serve loop until shutdown.
// A no-op when the redirect is disabled.
pub async fn spawn_http_redirect(config: &HttpRedirectConfig, shutdown: CancellationToken) -> Result<()> {
	if !config.enabled {
		return Ok(());
	}

	let listener: TcpListener = TcpListener::bind(config.listen).await?;
	let local_addr = listener.local_addr()?;
	let target: Arc<RedirectTarget> = Arc::new(RedirectTarget {
		host: config.to_host.clone(),
	});

	let app = axum::Router::new().fallback(any(redirect_handler)).with_state(target);

	info!(listen = %local_addr, to_host = %config.to_host, "HTTP→HTTPS redirect listener bound");

	tokio::spawn(async move {
		let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
			shutdown.cancelled().await;
			info!("HTTP redirect listener shutting down");
		});
		if let Err(e) = serve.await {
			error!(error = %e, "HTTP redirect listener failed");
		}
	});

	if config.to_host.is_empty() {
		// Defensive: validate() rejects this, but never emit https:/// if it ever slipped through.
		warn!("HTTP redirect enabled with an empty to_host; redirects will be malformed");
	}
	return Ok(());
}

#[cfg(test)]
mod tests {
	use std::net::SocketAddr;
	use std::time::Duration;

	use axum::http::Method;
	use http_body_util::BodyExt;
	use hyper::client::conn::http1;
	use hyper_util::rt::TokioIo;
	use tokio::net::TcpStream;

	use super::*;

	#[test]
	fn redirect_location_preserves_path_and_query() {
		assert_eq!(
			redirect_location("conorforde.com", "/posts/hello?draft=1"),
			"https://conorforde.com/posts/hello?draft=1"
		);
	}

	#[test]
	fn redirect_location_root() {
		assert_eq!(redirect_location("example.test", "/"), "https://example.test/");
	}

	#[test]
	fn build_redirect_is_permanent_with_location() {
		let response: Response<Body> = build_redirect("example.test", "/a?b=c");
		assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
		assert_eq!(
			response.headers().get(LOCATION).unwrap(),
			"https://example.test/a?b=c"
		);
	}

	#[test]
	fn build_redirect_rejects_unencodable_location() {
		// A control char cannot form a header value → 400, never a malformed Location header.
		let response: Response<Body> = build_redirect("example.test", "/\u{0}bad");
		assert_eq!(response.status(), StatusCode::BAD_REQUEST);
		assert!(response.headers().get(LOCATION).is_none());
	}

	// Issue one plaintext HTTP/1.1 request to `addr` and return the response (headers + collected body).
	async fn http1_get(addr: SocketAddr, method: Method, target: &str) -> (StatusCode, Option<String>, Vec<u8>) {
		let stream: TcpStream = TcpStream::connect(addr).await.unwrap();
		let (mut sender, conn) = http1::handshake::<_, Body>(TokioIo::new(stream)).await.unwrap();
		tokio::spawn(async move {
			let _ = conn.await;
		});
		let req: Request<Body> = Request::builder()
			.method(method)
			.uri(target)
			.header("host", "browser-sent-host.example")
			.body(Body::empty())
			.unwrap();
		let resp = sender.send_request(req).await.unwrap();
		let status: StatusCode = resp.status();
		let location: Option<String> = resp
			.headers()
			.get(LOCATION)
			.and_then(|v| v.to_str().ok())
			.map(str::to_owned);
		let body: Vec<u8> = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
		return (status, location, body);
	}

	async fn spawn_redirect(to_host: &str) -> SocketAddr {
		let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr: SocketAddr = listener.local_addr().unwrap();
		let target: Arc<RedirectTarget> = Arc::new(RedirectTarget { host: to_host.to_owned() });
		let app = axum::Router::new().fallback(any(redirect_handler)).with_state(target);
		tokio::spawn(async move {
			let _ = axum::serve(listener, app).await;
		});
		// Give the accept loop a moment to be ready.
		tokio::time::sleep(Duration::from_millis(50)).await;
		return addr;
	}

	#[tokio::test]
	async fn redirects_get_to_https_preserving_path_and_query() {
		let addr: SocketAddr = spawn_redirect("conorforde.com").await;
		let (status, location, body) = http1_get(addr, Method::GET, "/posts/hello?draft=1").await;
		assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
		assert_eq!(location.as_deref(), Some("https://conorforde.com/posts/hello?draft=1"));
		// It must NOT proxy content — the redirect body is empty.
		assert!(body.is_empty(), "a redirect must not return backend content");
	}

	#[tokio::test]
	async fn redirects_head_request_too() {
		let addr: SocketAddr = spawn_redirect("conorforde.com").await;
		let (status, location, _body) = http1_get(addr, Method::HEAD, "/").await;
		assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
		assert_eq!(location.as_deref(), Some("https://conorforde.com/"));
	}

	#[tokio::test]
	async fn ignores_client_host_header_using_canonical_host() {
		// The client sent Host: browser-sent-host.example, but the Location must use the CONFIGURED host,
		// not the client's — closing the open-redirect vector.
		let addr: SocketAddr = spawn_redirect("conorforde.com").await;
		let (_status, location, _body) = http1_get(addr, Method::GET, "/x").await;
		assert_eq!(location.as_deref(), Some("https://conorforde.com/x"));
	}

	// Grab a free loopback port by binding then dropping, since the spawn path binds config.listen itself.
	async fn free_port() -> SocketAddr {
		let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr: SocketAddr = listener.local_addr().unwrap();
		drop(listener);
		return addr;
	}

	#[tokio::test]
	async fn spawn_disabled_is_a_noop() {
		// A disabled redirect binds nothing and returns Ok, so its listen address is never touched.
		let config = HttpRedirectConfig::default();
		assert!(!config.enabled);
		let result = spawn_http_redirect(&config, CancellationToken::new()).await;
		assert!(result.is_ok(), "a disabled redirect must be a successful no-op");
	}

	#[tokio::test]
	async fn spawn_enabled_binds_and_serves_redirects() {
		let addr: SocketAddr = free_port().await;
		let config = HttpRedirectConfig {
			enabled: true,
			listen: addr,
			to_host: "conorforde.com".to_owned(),
		};
		let shutdown = CancellationToken::new();
		spawn_http_redirect(&config, shutdown.clone()).await.unwrap();
		// Give the spawned serve loop a moment to start accepting.
		tokio::time::sleep(Duration::from_millis(50)).await;

		let (status, location, body) = http1_get(addr, Method::GET, "/a?b=c").await;
		assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
		assert_eq!(location.as_deref(), Some("https://conorforde.com/a?b=c"));
		assert!(body.is_empty());

		// Cancelling drives the serve loop's graceful-shutdown branch.
		shutdown.cancel();
	}
}
