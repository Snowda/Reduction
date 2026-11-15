//! The `proxy_request` target. One request goes through all of the proxy to the cleartext echo backend:
//! admission, the router, the replay body, the retry loop and the forward step.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use http::header::CONTENT_ENCODING;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::BodyExt;
use reduction::body::Body;
use reduction::proxy::{ProxyState, proxy_request};
use reduction::transport::ConnectAddr;
use tokio::time::timeout;

use crate::fixture::ECHO_MARKER;

const CLIENT_PORT: u16 = 40_000;
// The proxy's own timeouts are 2 s each; past this bound the proxy never answered.
const ANSWER_BOUND: Duration = Duration::from_secs(30);

/// What the client saw: the status, the content encoding, and the whole body or the error that stopped it.
#[derive(Debug)]
pub struct Answer {
	pub status: StatusCode,
	pub content_encoding: Option<HeaderValue>,
	pub body: Result<Bytes, String>,
}

/// The whole answer to `req` from a loopback peer with no name. Each step must end within ANSWER_BOUND.
pub async fn answer(state: &'static ProxyState, req: Request<Body>) -> Result<Answer, String> {
	let peer: ConnectAddr = ConnectAddr(SocketAddr::from((Ipv4Addr::LOCALHOST, CLIENT_PORT)), None);
	let response: Response<Body> = timeout(ANSWER_BOUND, proxy_request(state, Some(peer), None, req))
		.await
		.map_err(|_| return String::from("the proxy sent no response head within the bound"))?;
	let (parts, body) = response.into_parts();
	let body: Result<Bytes, String> = match timeout(ANSWER_BOUND, body.collect()).await {
		Ok(Ok(collected)) => Ok(collected.to_bytes()),
		Ok(Err(e)) => Err(format!("response body: {e}")),
		Err(_) => Err(String::from("the response body did not end within the bound")),
	};
	return Ok(Answer {
		status: parts.status,
		content_encoding: parts.headers.get(CONTENT_ENCODING).cloned(),
		body,
	});
}

/// The invariant: the proxy answers within the bound. A 200 holds the unencoded echo, so it came from the
/// backend. Every other answer is a 4xx or 5xx that the proxy made.
pub fn check(is_bodiless: bool, answer: &Result<Answer, String>) -> Result<(), String> {
	let answer: &Answer = answer.as_ref()?;
	if answer.status.is_client_error() || answer.status.is_server_error() {
		return Ok(());
	}
	if answer.status != StatusCode::OK {
		return Err(format!("{} is not an answer the proxy or the echo backend gives", answer.status));
	}
	// The echo sends no encoding and the proxy applies none, so any encoding is forged.
	if let Some(encoding) = answer.content_encoding.as_ref() {
		return Err(format!("content-encoding {encoding:?} that neither the proxy nor the echo applies"));
	}
	return check_echo(is_bodiless, answer.body.as_ref()?);
}

// A HEAD or CONNECT answer may be empty; the hyper server drops any body it carries.
fn check_echo(is_bodiless: bool, body: &[u8]) -> Result<(), String> {
	let is_empty_allowed: bool = is_bodiless && body.is_empty();
	return match is_empty_allowed || body.starts_with(ECHO_MARKER) {
		true => Ok(()),
		false => Err(format!("a 200 whose body the echo backend did not write: {:?}", Bytes::copy_from_slice(body))),
	};
}

#[cfg(test)]
mod tests {
	use http::Method;

	use super::*;
	use crate::fixture::{self, Fixture, echo_of};

	fn answered(status: StatusCode, encoding: Option<&'static str>, body: &[u8]) -> Result<Answer, String> {
		return Ok(Answer {
			status,
			content_encoding: encoding.map(HeaderValue::from_static),
			body: Ok(Bytes::copy_from_slice(body)),
		});
	}

	#[test]
	fn echoes_and_proxy_errors_pass() -> Result<(), String> {
		let echo: Vec<u8> = echo_of(&Method::GET, "/", b"");
		check(false, &answered(StatusCode::OK, None, &echo))?;
		check(true, &answered(StatusCode::OK, None, b""))?;
		check(false, &answered(StatusCode::BAD_GATEWAY, None, b"bad gateway"))?;
		return Ok(());
	}

	#[test]
	fn answers_the_backend_never_wrote_fail() {
		assert!(check(false, &answered(StatusCode::OK, None, b"forged")).is_err(), "200 without the echo");
		assert!(check(false, &answered(StatusCode::FOUND, None, b"")).is_err(), "302 nobody sends");
		assert!(check(false, &answered(StatusCode::NOT_MODIFIED, None, b"")).is_err(), "304 only the cache sent");
		let echo: Vec<u8> = echo_of(&Method::GET, "/", b"");
		assert!(check(false, &answered(StatusCode::OK, Some("zstd"), &echo)).is_err(), "encoding nobody applies");
		assert!(check(true, &answered(StatusCode::OK, None, b"x")).is_err(), "HEAD with a forged body");
		assert!(check(false, &answered(StatusCode::OK, None, b"")).is_err(), "GET with an empty body");
		assert!(check(false, &Err(String::from("hung"))).is_err(), "no answer in the bound");
	}

	// Positive control: the live pipeline answers a plain GET with the echo, so the harness is not vacuous.
	#[test]
	fn a_plain_get_reaches_the_echo_backend() -> Result<(), String> {
		let fixture: &Fixture = fixture::get()?;
		let req: Request<Body> = Request::get("/fuzz").body(Body::empty()).map_err(|e| format!("GET: {e}"))?;
		let answer: Result<Answer, String> = fixture.block_on(answer(fixture.state, req));
		let body: &Bytes = answer.as_ref()?.body.as_ref()?;
		assert_eq!(answer.as_ref()?.status, StatusCode::OK, "body: {body:?}");
		assert_eq!(body.as_ref(), echo_of(&Method::GET, "/fuzz", b"").as_slice());
		return Ok(());
	}
}
