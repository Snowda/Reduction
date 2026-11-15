//! Fuzz harnesses for Reduction's untrusted boundaries. Each takes raw bytes and asserts the boundary's
//! invariant. The libFuzzer targets (fuzz_targets/) and the replay test (src/replay.rs) call them.

pub mod fastlane;
pub mod fixture;
pub mod oracle;
pub mod probed;
pub mod proxied;
pub mod redirected;
#[cfg(test)]
mod replay;
pub mod request;
pub mod tunneled;
pub mod upstream;

use std::time::Duration;

use http::Method;
use reduction::body::Body;
use reduction::error::ReductionError;
use reduction::ingress::protocol::{self, Envelope};
use reduction::proxy::ProxyState;

use crate::fixture::Fixture;

/// Any input is refused with an Err or decodes to an Envelope that round-trips exactly; a panic or abort is the bug.
pub fn envelope_decode(data: &[u8]) {
	let Ok(envelope) = protocol::decode(data) else {
		return;
	};
	// An encode error means the envelope broke the frame cap; a decode error means its frame did not parse back.
	let again: Result<Envelope, ReductionError> = protocol::encode(&envelope).and_then(|frame| protocol::decode(&frame));
	assert!(
		again.as_ref().is_ok_and(|again| *again == envelope),
		"decode -> encode -> decode must be the identity: {again:?}"
	);
}

/// A raw HTTP/1.1 request through the whole proxy; `proxied::check` states the invariant.
pub fn proxy_request(data: &[u8]) {
	let Some(req) = request::parse(data) else {
		return;
	};
	let Some(fixture) = started() else {
		return;
	};
	let is_bodiless: bool = req.method() == Method::HEAD || req.method() == Method::CONNECT;
	let answer: Result<proxied::Answer, String> = fixture.block_on(proxied::answer(fixture.state, req.map(Body::from)));
	let verdict: Result<(), String> = proxied::check(is_bodiless, &answer);
	assert!(verdict.is_ok(), "proxy_request: {verdict:?}");
}

/// The first byte picks a backend protocol; the rest is a raw request through the pool; see `upstream::check`.
pub fn upstream_send(data: &[u8]) {
	let Some((&selector, raw)) = data.split_first() else {
		return;
	};
	let Some(req) = request::parse(raw) else {
		return;
	};
	let Some(fixture) = started() else {
		return;
	};
	let expected: Vec<u8> = upstream::expected_echo(&req);
	let exchange = upstream::exchange(fixture.state, fixture.backend(selector), req.map(Body::from));
	let verdict: Result<(), String> = upstream::check(&expected, &fixture.block_on(exchange));
	assert!(verdict.is_ok(), "upstream_send: {verdict:?}");
}

/// Raw bytes on a connection to the HTTP to HTTPS redirect listener; `redirected::check` states the invariant.
pub fn redirect(data: &[u8]) {
	let Some(fixture) = started() else {
		return;
	};
	let response: Result<Vec<u8>, String> = fixture.block_on(redirected::exchange(fixture.redirect, data));
	let verdict: Result<(), String> = redirected::check(data, &response);
	assert!(verdict.is_ok(), "redirect: {verdict:?}");
}

/// Raw bytes on a connection to the Ready health endpoint; `probed::check` states the invariant.
pub fn health_route(data: &[u8]) {
	let Some(fixture) = started() else {
		return;
	};
	let response: Result<Vec<u8>, String> = fixture.block_on(redirected::exchange(fixture.health, data));
	let verdict: Result<(), String> = probed::check(data, &response);
	assert!(verdict.is_ok(), "health_route: {verdict:?}");
}

/// Raw bytes on a connection to the egress gateway. `$PORT` names the echo port. `tunneled::check` states the invariant.
pub fn egress_connect(data: &[u8]) {
	let Some(fixture) = started() else {
		return;
	};
	let sent: Vec<u8> = tunneled::with_port(data, fixture.egress.echo_port);
	let wait: Duration = tunneled::answer_wait(&sent);
	let response: Result<Vec<u8>, String> =
		fixture.block_on(redirected::exchange_waiting(fixture.egress.gateway, &sent, wait));
	let verdict: Result<(), String> = tunneled::check(&sent, fixture.egress.echo_port, &response);
	assert!(verdict.is_ok(), "egress_connect: {verdict:?}");
}

/// Raw chunked body bytes through fastlane's ChunkedDecoder; `fastlane::chunked::check` states the invariant.
pub fn fastlane_chunked(data: &[u8]) {
	let verdict: Result<(), String> = fastlane::chunked::check(data);
	assert!(verdict.is_ok(), "fastlane_chunked: {verdict:?}");
}

/// Raw backend bytes through fastlane's response-head parser; `fastlane::response::check` states the invariant.
pub fn fastlane_response(data: &[u8]) {
	let verdict: Result<(), String> = fastlane::response::check(data);
	assert!(verdict.is_ok(), "fastlane_response: {verdict:?}");
}

/// The first byte picks the HTTP/1.1 or HTTP/2 plane; the rest is a raw client head. See `fastlane::classify::check`.
pub fn fastlane_classify(data: &[u8]) {
	let Some((&selector, client)) = data.split_first() else {
		return;
	};
	let Some(fixture) = started() else {
		return;
	};
	let state: &ProxyState = if selector & 1 == 0 { fixture.raw.h1 } else { fixture.raw.h2 };
	let verdict: Result<(), String> = fastlane::classify::check(state, client);
	assert!(verdict.is_ok(), "fastlane_classify: {verdict:?}");
}

// A fixture that cannot start is a harness fault, not a pass, so it fails the run.
// Because of the assert, no caller gets None. Their None arms stay uncovered by design.
fn started() -> Option<&'static Fixture> {
	let fixture: Result<&'static Fixture, &'static str> = fixture::get();
	assert!(fixture.is_ok(), "the fuzz fixture must start: {:?}", fixture.as_ref().err());
	return fixture.ok();
}

#[cfg(test)]
mod tests {
	use super::*;

	// Bytes that hyper refuses to frame: no request line, and a body shorter than its Content-Length.
	const UNFRAMED: [&[u8]; 2] = [b"not http\r\n\r\n", b"POST / HTTP/1.1\r\nContent-Length: 9\r\n\r\nshort"];

	#[test]
	fn proxy_request_refuses_bytes_that_frame_no_request() {
		UNFRAMED.iter().for_each(|data| {
			assert!(request::parse(data).is_none(), "the input must be one the decoder refuses");
			proxy_request(data);
		});
	}

	#[test]
	fn upstream_send_refuses_empty_input_and_unframed_bytes() {
		upstream_send(b"");
		UNFRAMED.iter().for_each(|data| {
			assert!(request::parse(data).is_none(), "the input must be one the decoder refuses");
			upstream_send(&[&[0_u8][..], data].concat());
		});
	}
}
