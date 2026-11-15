//! The `health_route` target: raw bytes on a TCP connection to the liveness and readiness endpoint.

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use httparse::{EMPTY_HEADER, Header, Response, Status};

use crate::request;

const MAX_RESPONSE_HEADERS: usize = 16;
// hyper-util's auto server reads these bytes as an HTTP/2 connection, which this check does not decode.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const LIVEZ_PATH: &str = "/livez";
const READYZ_PATH: &str = "/readyz";
// The fixture sets readiness to Ready, so both probes answer 200 with a five-byte body.
const LIVEZ_BODY: &[u8] = b"alive";
const READYZ_BODY: &[u8] = b"ready";
const PROBE_LENGTH: &[u8] = b"5";
const EMPTY_LENGTH: &[u8] = b"0";
const ALLOWED_METHODS: &[u8] = b"GET,HEAD";
const CONTENT_LENGTH: &str = "content-length";
const ALLOW: &str = "allow";

/// The status `route` gives `request` while readiness is Ready: the exact path first, then the method.
#[must_use]
pub fn expected_status(request: &Request<Bytes>) -> StatusCode {
	let is_probe: bool = matches!(request.uri().path(), LIVEZ_PATH | READYZ_PATH);
	if !is_probe {
		return StatusCode::NOT_FOUND;
	}
	return match *request.method() {
		Method::GET | Method::HEAD => StatusCode::OK,
		_ => StatusCode::METHOD_NOT_ALLOWED,
	};
}

/// The invariant: the endpoint closes within the bound. Its first answer is a hyper refusal (4xx or 5xx) or
/// one of route's three answers in its exact shape. For a request that hyper frames, the status is exact too.
/// Readiness is Ready, so a 503 is always a bug.
pub fn check(data: &[u8], response: &Result<Vec<u8>, String>) -> Result<(), String> {
	let response: &[u8] = response.as_ref()?;
	if response.is_empty() || data.starts_with(H2_PREFACE) {
		return Ok(());
	}
	let mut headers: [Header<'_>; MAX_RESPONSE_HEADERS] = [EMPTY_HEADER; MAX_RESPONSE_HEADERS];
	let mut head: Response<'_, '_> = Response::new(&mut headers);
	let Ok(Status::Complete(head_len)) = head.parse(response) else {
		return Err(format!("not an HTTP/1.1 response head: {:?}", Bytes::copy_from_slice(response)));
	};
	let status: StatusCode = head
		.code
		.and_then(|code| return StatusCode::from_u16(code).ok())
		.ok_or("a response head with no status")?;
	let request: Option<Request<Bytes>> = request::parse(data);
	let body: &[u8] = response.get(head_len..).unwrap_or_default();
	return match status {
		StatusCode::SERVICE_UNAVAILABLE => Err(String::from("readiness is Ready, so no probe may answer 503")),
		StatusCode::OK | StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED => {
			check_exact(status, request.as_ref())?;
			check_shape(status, head.headers, body, request.as_ref())
		}
		_ if status.is_client_error() || status.is_server_error() => Ok(()),
		_ => Err(format!("the health endpoint answered {status}")),
	};
}

// A request that hyper frames gets exactly the status route gives it.
fn check_exact(status: StatusCode, request: Option<&Request<Bytes>>) -> Result<(), String> {
	let Some(request) = request else {
		return Ok(());
	};
	let expected: StatusCode = expected_status(request);
	if status != expected {
		return Err(format!("{} {} answered {status}, not {expected}", request.method(), request.uri()));
	}
	return Ok(());
}

// Each answer from route states its length. A 405 names the allowed methods. A GET probe carries its label.
fn check_shape(status: StatusCode, headers: &[Header<'_>], body: &[u8], request: Option<&Request<Bytes>>) -> Result<(), String> {
	let length: Option<&[u8]> = header(headers, CONTENT_LENGTH);
	if status == StatusCode::METHOD_NOT_ALLOWED && header(headers, ALLOW) != Some(ALLOWED_METHODS) {
		return Err(String::from("a 405 without Allow: GET,HEAD"));
	}
	let want_length: &[u8] = if status == StatusCode::OK { PROBE_LENGTH } else { EMPTY_LENGTH };
	if length != Some(want_length) {
		return Err(format!("a {status} with Content-Length {:?}", length.map(Bytes::copy_from_slice)));
	}
	let Some(request) = request.filter(|request| return request.method() == Method::GET && status == StatusCode::OK) else {
		return Ok(());
	};
	let label: &[u8] = if request.uri().path() == LIVEZ_PATH { LIVEZ_BODY } else { READYZ_BODY };
	if !body.starts_with(label) {
		return Err(format!("GET {} body {:?}", request.uri(), Bytes::copy_from_slice(body)));
	}
	return Ok(());
}

fn header<'a>(headers: &[Header<'a>], name: &str) -> Option<&'a [u8]> {
	return headers
		.iter()
		.find(|header| return header.name.eq_ignore_ascii_case(name))
		.map(|header| return header.value);
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::fixture::{self, Fixture};
	use crate::redirected::exchange;

	const GET_LIVEZ: &[u8] = b"GET /livez HTTP/1.1\r\nHost: probe\r\n\r\n";
	const HEAD_READYZ: &[u8] = b"HEAD /readyz HTTP/1.1\r\nHost: probe\r\n\r\n";
	const POST_LIVEZ: &[u8] = b"POST /livez HTTP/1.1\r\nHost: probe\r\n\r\n";
	const GET_NOPE: &[u8] = b"GET /nope HTTP/1.1\r\nHost: probe\r\n\r\n";
	const ALIVE: &str = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nalive";
	const NOT_ALLOWED: &str = "HTTP/1.1 405 Method Not Allowed\r\nallow: GET,HEAD\r\ncontent-length: 0\r\n\r\n";
	const NOT_FOUND: &str = "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n";

	fn replied(text: &str) -> Result<Vec<u8>, String> {
		return Ok(text.as_bytes().to_vec());
	}

	#[test]
	fn route_answers_in_their_exact_shape_pass() {
		assert!(check(GET_LIVEZ, &replied(ALIVE)).is_ok(), "GET /livez");
		assert!(check(HEAD_READYZ, &replied("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\n")).is_ok(), "HEAD /readyz");
		assert!(check(POST_LIVEZ, &replied(NOT_ALLOWED)).is_ok(), "POST /livez");
		assert!(check(GET_NOPE, &replied(NOT_FOUND)).is_ok(), "GET /nope");
		assert!(check(b"not http", &replied(ALIVE)).is_ok(), "an unframed request is held to the shape only");
	}

	#[test]
	fn refusals_silence_and_h2_pass() {
		assert!(check(GET_LIVEZ, &replied("HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")).is_ok(), "400");
		assert!(check(GET_LIVEZ, &replied("")).is_ok(), "closed without an answer");
		assert!(check(H2_PREFACE, &replied("\0\0\x06\x04")).is_ok(), "an h2 connection is not decoded");
	}

	#[test]
	fn a_wrong_status_for_a_framed_request_fails() {
		assert!(check(GET_NOPE, &replied(ALIVE)).is_err(), "an unknown path answered 200");
		assert!(check(GET_LIVEZ, &replied(NOT_FOUND)).is_err(), "a probe path answered 404");
		assert!(check(GET_LIVEZ, &replied(NOT_ALLOWED)).is_err(), "GET answered 405");
		assert!(check(POST_LIVEZ, &replied(ALIVE)).is_err(), "POST answered 200");
	}

	#[test]
	fn a_wrong_shape_fails() {
		let no_allow: &str = "HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n";
		let long_404: &str = "HTTP/1.1 404 Not Found\r\ncontent-length: 4\r\n\r\nnope";
		let wrong_label: &str = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nready";
		assert!(check(POST_LIVEZ, &replied(no_allow)).is_err(), "a 405 without Allow");
		assert!(check(GET_NOPE, &replied(long_404)).is_err(), "a 404 with a body");
		assert!(check(GET_LIVEZ, &replied(wrong_label)).is_err(), "/livez answered the readiness label");
	}

	#[test]
	fn a_503_hangs_and_garbage_fail() {
		let unavailable: &str = "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 8\r\n\r\nstarting";
		assert!(check(b"not http", &replied(unavailable)).is_err(), "a 503 while Ready");
		assert!(check(GET_LIVEZ, &replied("HTTP/1.1 302 Found\r\ncontent-length: 0\r\n\r\n")).is_err(), "a 302");
		assert!(check(GET_LIVEZ, &replied("garbage")).is_err(), "not a response head");
		assert!(check(GET_LIVEZ, &replied("HTTP/1.1 999 X\r\n\r\n")).is_err(), "a status http cannot name");
		assert!(check(GET_LIVEZ, &Err(String::from("hung"))).is_err(), "no close in the bound");
	}

	// Positive control: the live endpoint answers each probe exactly as health_endpoint's golden test records.
	#[test]
	fn the_live_endpoint_answers_each_probe_exactly() -> Result<(), String> {
		let fixture: &Fixture = fixture::get()?;
		let cases: [(&[u8], &str); 4] = [
			(GET_LIVEZ, "HTTP/1.1 200 OK\r\n"),
			(b"GET /readyz HTTP/1.1\r\nHost: probe\r\n\r\n", "HTTP/1.1 200 OK\r\n"),
			(POST_LIVEZ, "HTTP/1.1 405 Method Not Allowed\r\n"),
			(GET_NOPE, "HTTP/1.1 404 Not Found\r\n"),
		];
		cases.iter().try_for_each(|(data, status_line)| {
			let response: Result<Vec<u8>, String> = fixture.block_on(exchange(fixture.health, data));
			let text: String = String::from_utf8_lossy(response.as_ref()?).into_owned();
			assert!(text.starts_with(status_line), "{text}");
			return check(data, &response);
		})?;
		return Ok(());
	}
}
