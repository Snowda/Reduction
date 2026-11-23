//! The `upstream_send` target: one request straight through the connection pool to one of the three echo
//! backends. It acquires a sender, sends with the HTTP/1.1 resend path, and reads the leased body to its end.

use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, HOST, TE, TRAILER, UPGRADE};
use http::{HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::BodyExt;
use reduction::body::Body;
use reduction::config::BackendConfig;
use reduction::proxy::pool::UpstreamBody;
use reduction::proxy::{ConnPool, HttpSender, ProxyState};
use tokio::time::timeout;

use crate::fixture::echo_of;
use crate::request::DEFAULT_PATH;

// Each pool step has a 2 s timeout of its own; past this bound a step hung.
const EXCHANGE_BOUND: Duration = Duration::from_secs(30);
// Hop-by-hop headers that the proxy strips before a forward, so the pool never sees them.
const HOP_BY_HOP: [&str; 3] = ["keep-alive", "proxy-connection", "proxy-authorization"];

/// The backend's answer: its status and the whole body.
#[derive(Debug)]
pub struct Exchange {
	pub status: StatusCode,
	pub body: Bytes,
}

/// The body the echo backend must return for `req`. HEAD and CONNECT answers carry no body.
#[must_use]
pub fn expected_echo(req: &Request<Bytes>) -> Vec<u8> {
	if req.method() == Method::HEAD || req.method() == Method::CONNECT {
		return Vec::new();
	}
	return echo_of(req.method(), &origin_target(req.uri()), req.body());
}

// The origin-form target the backend reads: never an empty path, and the root path in front of a bare `?q`.
fn origin_target(uri: &Uri) -> String {
	let path: &str = if uri.path().is_empty() { DEFAULT_PATH } else { uri.path() };
	return uri.query().map_or_else(|| return path.to_owned(), |query: &str| return format!("{path}?{query}"));
}

/// Acquire a sender for `backend`, send `req` as a forward does, and read the body to its end.
pub async fn exchange(state: &ProxyState, backend: &BackendConfig, req: Request<Body>) -> Result<Exchange, String> {
	let connect: Duration = Duration::from_secs(state.timeouts.connect_secs.get());
	let handshake: Duration = Duration::from_secs(state.timeouts.handshake_secs.get());
	let pool: &ConnPool = &state.conn_pool;
	let acquired = ConnPool::acquire(pool, backend, &state.tls_connector, &state.client_tls_config, connect, handshake);
	let mut sender: HttpSender = bounded(acquired).await?.map_err(|e| format!("acquire: {e}"))?;
	let sent = ConnPool::send_request(pool, &mut sender, as_forwarded(req, backend)?, backend, &state.tls_connector, connect, handshake);
	let response: Response<UpstreamBody> = bounded(sent).await?.map_err(|e| format!("send: {e}"))?;
	let (parts, body) = response.into_parts();
	let body: Bytes = bounded(HttpSender::into_body(sender, body).collect())
		.await?
		.map_err(|e| format!("body: {e}"))?
		.to_bytes();
	return Ok(Exchange {
		status: parts.status,
		body,
	});
}

async fn bounded<F: Future>(step: F) -> Result<F::Output, String> {
	return timeout(EXCHANGE_BOUND, step)
		.await
		.map_err(|_| return String::from("a pool step did not end within the bound"));
}

// The head a forward hands the pool: no hop-by-hop headers, and the backend's own Host.
fn as_forwarded(req: Request<Body>, backend: &BackendConfig) -> Result<Request<Body>, String> {
	let (mut parts, body) = req.into_parts();
	[CONNECTION, TE, TRAILER, UPGRADE].iter().for_each(|name| {
		parts.headers.remove(name);
	});
	HOP_BY_HOP.iter().for_each(|name| {
		parts.headers.remove(*name);
	});
	let host: HeaderValue = HeaderValue::from_str(&backend.host).map_err(|e| format!("backend host: {e}"))?;
	parts.headers.insert(HOST, host);
	return Ok(Request::from_parts(parts, body));
}

/// The invariant: a completed exchange is a 200, and its body is exactly the echo of the request.
/// So the pool kept the method, the target and the body. A transport error is a refusal, not a bug.
pub fn check(expected: &[u8], exchange: &Result<Exchange, String>) -> Result<(), String> {
	let Ok(exchange) = exchange else {
		return Ok(());
	};
	if exchange.status != StatusCode::OK {
		return Err(format!("the echo backend answered {}: {:?}", exchange.status, exchange.body));
	}
	if exchange.body.as_ref() != expected {
		return Err(format!("echo {:?} is not the request sent, {:?}", exchange.body, Bytes::copy_from_slice(expected)));
	}
	return Ok(());
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::fixture::{self, Fixture};
	use crate::request;

	fn exchanged(status: StatusCode, body: &[u8]) -> Result<Exchange, String> {
		return Ok(Exchange {
			status,
			body: Bytes::copy_from_slice(body),
		});
	}

	#[test]
	fn an_exact_echo_or_a_refusal_passes() {
		let expected: Vec<u8> = echo_of(&Method::POST, "/api/echo", b"hello");
		assert!(check(&expected, &exchanged(StatusCode::OK, &expected)).is_ok(), "exact echo");
		assert!(check(&expected, &Err(String::from("send: reset"))).is_ok(), "transport refusal");
	}

	#[test]
	fn a_changed_echo_or_status_fails() {
		let expected: Vec<u8> = echo_of(&Method::POST, "/api/echo", b"hello");
		let other_body: Vec<u8> = echo_of(&Method::POST, "/api/echo", b"hellp");
		let other_target: Vec<u8> = echo_of(&Method::POST, "/api/echo?", b"hello");
		assert!(check(&expected, &exchanged(StatusCode::OK, &other_body)).is_err(), "body changed");
		assert!(check(&expected, &exchanged(StatusCode::OK, &other_target)).is_err(), "target changed");
		assert!(check(&expected, &exchanged(StatusCode::INTERNAL_SERVER_ERROR, b"")).is_err(), "backend 500");
	}

	#[test]
	fn head_expects_no_body() -> Result<(), String> {
		let head: Request<Bytes> = request::parse(b"HEAD /x HTTP/1.1\r\n\r\n").ok_or("HEAD did not parse")?;
		assert!(expected_echo(&head).is_empty(), "a HEAD answer has no body");
		return Ok(());
	}

	#[test]
	fn the_expected_target_is_origin_form() -> Result<(), String> {
		let targets: Vec<String> = ["SPOT ://hx?1", "GET /a?b", "GET /a?", "GET /a", "GET http://h", "POST h:80"]
			.iter()
			.map(|line: &&str| {
				let req: Request<Bytes> = request::parse(format!("{line} HTTP/1.1\r\n\r\n").as_bytes()).ok_or(*line)?;
				return Ok(origin_target(req.uri()));
			})
			.collect::<Result<_, &str>>()?;
		assert_eq!(targets, ["/?1", "/a?b", "/a?", "/a", "/", "/"]);
		return Ok(());
	}

	// regressions/upstream_send/crash-74a6…: an absolute target with no path. Each backend reads it as `/?1`.
	#[test]
	fn every_backend_reads_an_empty_path_as_the_root() -> Result<(), String> {
		let fixture: &Fixture = fixture::get()?;
		return (0..3).try_for_each(|selector: u8| {
			let req: Request<Bytes> = request::parse(b"SPOT ://hx?1 HTTP/1.1\r\n\nhello").ok_or("SPOT did not parse")?;
			let expected: Vec<u8> = expected_echo(&req);
			let backend: &BackendConfig = fixture.backend(selector);
			let exchange: Result<Exchange, String> = fixture.block_on(exchange(fixture.state, backend, req.map(Body::from)));
			assert!(exchange.is_ok(), "backend {} refused: {exchange:?}", backend.id);
			return check(&expected, &exchange).map_err(|e| return format!("backend {}: {e}", backend.id));
		});
	}

	// Positive control: each of the three backends completes a POST with an exact echo, so no path is vacuous.
	#[test]
	fn every_backend_echoes_a_post_exactly() -> Result<(), String> {
		let fixture: &Fixture = fixture::get()?;
		let raw: &[u8] = b"POST /api/echo?x=1 HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
		return (0..3).try_for_each(|selector: u8| {
			let req: Request<Bytes> = request::parse(raw).ok_or("POST did not parse")?;
			let expected: Vec<u8> = expected_echo(&req);
			let backend: &BackendConfig = fixture.backend(selector);
			let exchange: Exchange = fixture.block_on(exchange(fixture.state, backend, req.map(Body::from)))?;
			assert_eq!(exchange.status, StatusCode::OK, "backend {}", backend.id);
			assert_eq!(exchange.body.as_ref(), expected.as_slice(), "backend {}", backend.id);
			return Ok(());
		});
	}
}
