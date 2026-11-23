//! The `egress_connect` target: raw bytes on a TCP connection to the egress CONNECT gateway.
//! The oracle reads the policy from the request bytes alone. It never calls the gateway's own parsers.

use std::str::{self, FromStr};
use std::time::Duration;

use bytes::Bytes;
use http::{StatusCode, Uri};
use httparse::{EMPTY_HEADER, Header, Request, Response, Status};

use crate::fixture::{EGRESS_CONNECT_TIMEOUT_SECS, EGRESS_HOST, EGRESS_INTERNAL_HOST};
use crate::redirected::MAX_RESPONSE_BYTES;

/// Inputs write the echo port as this token, because the fixture picks the port at start.
pub const PORT_TOKEN: &[u8] = b"$PORT";
const MAX_REQUEST_HEADERS: usize = 64;
// Time past the dial limit for the refusal to reach the client on loopback.
const DIAL_MARGIN_SECS: u64 = 1;
// The same idle as `redirected::exchange`: on loopback a partial head gets no answer at all.
const PARTIAL_HEAD_IDLE: Duration = Duration::from_millis(100);
const MAX_RESPONSE_HEADERS: usize = 16;
const CONNECT: &str = "CONNECT";
const ALLOW: &str = "allow";
const CONTENT_LENGTH: &str = "content-length";
const TRANSFER_ENCODING: &str = "transfer-encoding";

// docs/egress.md, "Order of checks": each refusal the gateway can answer with, in check order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
	ClientNotAllowed,
	RateLimited,
	MethodNotAllowed,
	Malformed,
	HostNotAllowed,
	PortNotAllowed,
	AtCapacity,
	ResolveFailed,
	PrivateAddress,
	ConnectFailed,
	ConnectTimeout,
}

impl Refusal {
	const ALL: [Self; 11] = [
		Self::ClientNotAllowed,
		Self::RateLimited,
		Self::MethodNotAllowed,
		Self::Malformed,
		Self::HostNotAllowed,
		Self::PortNotAllowed,
		Self::AtCapacity,
		Self::ResolveFailed,
		Self::PrivateAddress,
		Self::ConnectFailed,
		Self::ConnectTimeout,
	];

	// The body a refusal carries.
	const fn label(self) -> &'static str {
		return match self {
			Self::ClientNotAllowed => "client_not_allowed",
			Self::RateLimited => "rate_limited",
			Self::MethodNotAllowed => "method_not_allowed",
			Self::Malformed => "malformed",
			Self::HostNotAllowed => "host_not_allowed",
			Self::PortNotAllowed => "port_not_allowed",
			Self::AtCapacity => "at_capacity",
			Self::ResolveFailed => "resolve_failed",
			Self::PrivateAddress => "private_address",
			Self::ConnectFailed => "connect_failed",
			Self::ConnectTimeout => "connect_timeout",
		};
	}

	const fn status(self) -> StatusCode {
		return match self {
			Self::ClientNotAllowed | Self::HostNotAllowed | Self::PortNotAllowed | Self::PrivateAddress => StatusCode::FORBIDDEN,
			Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
			Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
			Self::Malformed => StatusCode::BAD_REQUEST,
			Self::AtCapacity => StatusCode::SERVICE_UNAVAILABLE,
			Self::ResolveFailed | Self::ConnectFailed => StatusCode::BAD_GATEWAY,
			Self::ConnectTimeout => StatusCode::GATEWAY_TIMEOUT,
		};
	}

	// Whether a target the policy classes as `expected` can get this refusal.
	const fn can_reach(self, expected: Expected) -> bool {
		return match expected {
			// An allowed target fails only on capacity and network faults.
			Expected::Tunnel => matches!(self, Self::AtCapacity | Self::ResolveFailed | Self::ConnectFailed | Self::ConnectTimeout),
			// An allowlisted internal literal resolves without DNS, so only the slot check comes before the internal check.
			Expected::Internal => matches!(self, Self::AtCapacity | Self::PrivateAddress),
			// A refused target never gets past the checks before the slot, resolve and dial.
			Expected::Refused => matches!(
				self,
				Self::ClientNotAllowed
					| Self::RateLimited | Self::MethodNotAllowed
					| Self::Malformed | Self::HostNotAllowed
					| Self::PortNotAllowed
			),
		};
	}

	fn from_body(body: &[u8]) -> Option<Self> {
		return Self::ALL.into_iter().find(|refusal: &Self| return refusal.label().as_bytes() == body);
	}
}

/// What the policy says about a request, from its bytes alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected {
	/// CONNECT to the allowlisted, exempt host on the allowed port: the gateway can open a tunnel.
	Tunnel,
	/// CONNECT to the allowlisted internal literal on the allowed port: the internal check must refuse it.
	Internal,
	/// Any other request: the gateway must not open a tunnel.
	Refused,
}

// The first request head in the input: what the policy says, where the head ends, and whether a body follows.
struct Asked {
	expected: Expected,
	head_len: usize,
	has_body_framing: bool,
}

/// How long the first answer can take. After a whole request head the gateway can dial before it answers.
/// Without one, it waits for more bytes, so a short idle ends the exchange.
#[must_use]
pub fn answer_wait(data: &[u8]) -> Duration {
	let mut headers: [Header<'_>; MAX_REQUEST_HEADERS] = [EMPTY_HEADER; MAX_REQUEST_HEADERS];
	return match Request::new(&mut headers).parse(data) {
		Ok(Status::Complete(_)) => Duration::from_secs(EGRESS_CONNECT_TIMEOUT_SECS + DIAL_MARGIN_SECS),
		_ => PARTIAL_HEAD_IDLE,
	};
}

/// `data` with every PORT_TOKEN replaced by the decimal echo port.
#[must_use]
pub fn with_port(data: &[u8], echo_port: u16) -> Vec<u8> {
	let port: String = echo_port.to_string();
	let mut out: Vec<u8> = Vec::with_capacity(data.len());
	let mut rest: &[u8] = data;
	while !rest.is_empty() {
		if rest.starts_with(PORT_TOKEN) {
			out.extend_from_slice(port.as_bytes());
			rest = &rest[PORT_TOKEN.len()..];
		} else {
			out.push(rest[0]);
			rest = &rest[1..];
		}
	}
	return out;
}

/// The invariant: the gateway closes within the bound, and its first answer follows the policy.
/// A 200 only for an allowed target, with the bytes after the head echoed back unchanged. An allowed target
/// never gets a policy refusal, the internal literal gets only the internal refusal, and each refusal label
/// carries its documented status. A 405 names CONNECT in Allow.
pub fn check(data: &[u8], echo_port: u16, response: &Result<Vec<u8>, String>) -> Result<(), String> {
	let response: &[u8] = response.as_ref()?;
	if response.is_empty() {
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
	let asked: Option<Asked> = asked(data, echo_port);
	let expected: Expected = asked.as_ref().map_or(Expected::Refused, |asked| return asked.expected);
	let after_head: &[u8] = &response[head_len..];
	if status == StatusCode::OK {
		return check_tunnel(data, asked.as_ref(), after_head, response.len());
	}
	if status.is_informational() {
		return Ok(());
	}
	if !status.is_client_error() && !status.is_server_error() {
		return Err(format!("the gateway answered {status}"));
	}
	let Some(refusal) = refusal_of(head.headers, after_head) else {
		return Ok(());
	};
	return check_refusal(refusal, status, head.headers, expected);
}

// A 200 is a tunnel: only an allowed target gets one, and the echo returns the bytes sent after the head.
fn check_tunnel(data: &[u8], asked: Option<&Asked>, echoed: &[u8], response_len: usize) -> Result<(), String> {
	let Some(asked) = asked.filter(|asked| return asked.expected == Expected::Tunnel) else {
		return Err(format!("a tunnel opened for a target the policy refuses: {:?}", Bytes::copy_from_slice(data)));
	};
	if asked.has_body_framing {
		return Ok(());
	}
	let sent: &[u8] = &data[asked.head_len..];
	let is_capped: bool = u64::try_from(response_len).unwrap_or(MAX_RESPONSE_BYTES) >= MAX_RESPONSE_BYTES;
	let is_faithful: bool = echoed == sent || (is_capped && sent.starts_with(echoed));
	if !is_faithful {
		return Err(format!(
			"the tunnel changed the bytes: sent {:?}, got {:?}",
			Bytes::copy_from_slice(sent),
			Bytes::copy_from_slice(echoed)
		));
	}
	return Ok(());
}

fn check_refusal(refusal: Refusal, status: StatusCode, headers: &[Header<'_>], expected: Expected) -> Result<(), String> {
	let label: &str = refusal.label();
	if refusal.status() != status {
		return Err(format!("refusal {label} answered {status}, documented as {}", refusal.status()));
	}
	if refusal == Refusal::MethodNotAllowed && header(headers, ALLOW) != Some(CONNECT.as_bytes()) {
		return Err(String::from("a 405 without Allow: CONNECT"));
	}
	if !refusal.can_reach(expected) {
		return Err(format!("a {expected:?} target got the refusal {label}"));
	}
	return Ok(());
}

// The refusal a body names: the body, cut at its Content-Length, must be one documented label.
fn refusal_of(headers: &[Header<'_>], after_head: &[u8]) -> Option<Refusal> {
	let length: usize = header(headers, CONTENT_LENGTH)
		.and_then(|value| return str::from_utf8(value).ok())
		.and_then(|value| return value.parse::<usize>().ok())?;
	return Refusal::from_body(after_head.get(..length)?);
}

// Parse the first request head with httparse and classify its target against the fixture's policy.
fn asked(data: &[u8], echo_port: u16) -> Option<Asked> {
	let mut headers: [Header<'_>; MAX_REQUEST_HEADERS] = [EMPTY_HEADER; MAX_REQUEST_HEADERS];
	let mut request: Request<'_, '_> = Request::new(&mut headers);
	let Ok(Status::Complete(head_len)) = request.parse(data) else {
		return None;
	};
	let has_body_framing: bool = request
		.headers
		.iter()
		.any(|header| return header.name.eq_ignore_ascii_case(CONTENT_LENGTH) || header.name.eq_ignore_ascii_case(TRANSFER_ENCODING));
	let expected: Expected = match (request.method, request.path) {
		(Some(CONNECT), Some(path)) => classify(path, echo_port),
		_ => Expected::Refused,
	};
	return Some(Asked { expected, head_len, has_body_framing });
}

// The host compares without case, and one dot at its end is removed. A userinfo part or any other port refuses.
fn classify(target: &str, echo_port: u16) -> Expected {
	let Some(authority) = Uri::from_str(target).ok().and_then(|uri| return uri.authority().cloned()) else {
		return Expected::Refused;
	};
	if authority.as_str().contains('@') || authority.port_u16() != Some(echo_port) {
		return Expected::Refused;
	}
	let host: String = authority.host().to_ascii_lowercase();
	return match host.strip_suffix('.').unwrap_or(&host) {
		EGRESS_HOST => Expected::Tunnel,
		EGRESS_INTERNAL_HOST => Expected::Internal,
		_ => Expected::Refused,
	};
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

	const PORT: u16 = 4321;
	const OPEN: &str = "HTTP/1.1 200 OK\r\n\r\n";

	fn replied(text: &str) -> Result<Vec<u8>, String> {
		return Ok(text.as_bytes().to_vec());
	}

	fn refusal(status: &str, label: &str) -> String {
		return format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\n\r\n{label}", label.len());
	}

	// docs/egress.md, "Order of checks": the labels, their statuses, and which targets can get each one.
	#[test]
	fn each_refusal_has_its_documented_label_status_and_targets() {
		let documented: [(&str, u16, &[Expected]); 11] = [
			("client_not_allowed", 403, &[Expected::Refused]),
			("rate_limited", 429, &[Expected::Refused]),
			("method_not_allowed", 405, &[Expected::Refused]),
			("malformed", 400, &[Expected::Refused]),
			("host_not_allowed", 403, &[Expected::Refused]),
			("port_not_allowed", 403, &[Expected::Refused]),
			("at_capacity", 503, &[Expected::Tunnel, Expected::Internal]),
			("resolve_failed", 502, &[Expected::Tunnel]),
			("private_address", 403, &[Expected::Internal]),
			("connect_failed", 502, &[Expected::Tunnel]),
			("connect_timeout", 504, &[Expected::Tunnel]),
		];
		let targets: [Expected; 3] = [Expected::Tunnel, Expected::Internal, Expected::Refused];
		Refusal::ALL.iter().zip(documented).for_each(|(refusal, (label, status, reachable))| {
			assert_eq!(refusal.label(), label);
			assert_eq!(refusal.status().as_u16(), status, "{label}");
			assert_eq!(Refusal::from_body(label.as_bytes()), Some(*refusal));
			targets.iter().for_each(|target| {
				assert_eq!(refusal.can_reach(*target), reachable.contains(target), "{label} for {target:?}");
			});
		});
		assert_eq!(Refusal::from_body(b"not_a_label"), None);
	}

	#[test]
	fn the_port_token_becomes_the_echo_port() {
		assert_eq!(with_port(b"CONNECT localhost:$PORT x$PORT$", PORT), b"CONNECT localhost:4321 x4321$".to_vec());
	}

	#[test]
	fn the_oracle_classifies_targets_by_host_and_port() {
		let cases: [(&str, Expected); 8] = [
			("localhost:4321", Expected::Tunnel),
			("LocalHost.:4321", Expected::Tunnel),
			("127.0.0.2:4321", Expected::Internal),
			("localhost:22", Expected::Refused),
			("localhost..:4321", Expected::Refused),
			("user@localhost:4321", Expected::Refused),
			("example.com:4321", Expected::Refused),
			("localhost", Expected::Refused),
		];
		cases.iter().for_each(|(target, expected)| {
			assert_eq!(classify(target, PORT), *expected, "{target}");
		});
	}

	#[test]
	fn a_faithful_tunnel_and_documented_refusals_pass() {
		let tunnel: &[u8] = b"CONNECT localhost:4321 HTTP/1.1\r\n\r\nping";
		assert!(check(tunnel, PORT, &replied(&format!("{OPEN}ping"))).is_ok(), "faithful tunnel");
		let off_list: &[u8] = b"CONNECT example.com:4321 HTTP/1.1\r\n\r\n";
		assert!(check(off_list, PORT, &replied(&refusal("403 Forbidden", "host_not_allowed"))).is_ok(), "403");
		let internal: &[u8] = b"CONNECT 127.0.0.2:4321 HTTP/1.1\r\n\r\n";
		assert!(check(internal, PORT, &replied(&refusal("403 Forbidden", "private_address"))).is_ok(), "private");
		let get: &[u8] = b"GET / HTTP/1.1\r\n\r\n";
		let refused_get: String = "HTTP/1.1 405 Method Not Allowed\r\nallow: CONNECT\r\ncontent-length: 18\r\n\r\nmethod_not_allowed".to_owned();
		assert!(check(get, PORT, &replied(&refused_get)).is_ok(), "405");
		assert!(check(b"garbage", PORT, &replied("")).is_ok(), "closed without an answer");
	}

	#[test]
	fn a_tunnel_or_refusal_against_the_policy_fails() {
		let off_list: &[u8] = b"CONNECT example.com:4321 HTTP/1.1\r\n\r\n";
		assert!(check(off_list, PORT, &replied(OPEN)).is_err(), "tunnel to a host off the list");
		let tunnel: &[u8] = b"CONNECT localhost:4321 HTTP/1.1\r\n\r\nping";
		assert!(check(tunnel, PORT, &replied(&format!("{OPEN}pong"))).is_err(), "changed bytes");
		assert!(check(tunnel, PORT, &replied(&refusal("403 Forbidden", "host_not_allowed"))).is_err(), "allowed host refused");
		let internal: &[u8] = b"CONNECT 127.0.0.2:4321 HTTP/1.1\r\n\r\n";
		assert!(check(internal, PORT, &replied(OPEN)).is_err(), "tunnel to an internal address");
		assert!(check(internal, PORT, &replied(&refusal("502 Bad Gateway", "connect_failed"))).is_err(), "dialed an internal address");
		assert!(check(off_list, PORT, &replied(&refusal("400 Bad Request", "host_not_allowed"))).is_err(), "wrong status");
		assert!(check(off_list, PORT, &replied(&refusal("504 Gateway Timeout", "connect_timeout"))).is_err(), "dialed off list");
		let get: &[u8] = b"GET / HTTP/1.1\r\n\r\n";
		assert!(check(get, PORT, &replied(&refusal("405 Method Not Allowed", "method_not_allowed"))).is_err(), "no Allow");
		assert!(check(get, PORT, &replied("HTTP/1.1 302 Found\r\n\r\n")).is_err(), "a redirect");
		assert!(check(get, PORT, &replied("garbage")).is_err(), "not a response head");
		assert!(check(get, PORT, &Err(String::from("hung"))).is_err(), "no close in the bound");
	}

	// Positive control: the live gateway tunnels to the echo and refuses a host off the list.
	#[test]
	fn the_live_gateway_tunnels_to_the_echo_and_refuses_off_list() -> Result<(), String> {
		let fixture: &Fixture = fixture::get()?;
		let port: u16 = fixture.egress.echo_port;
		let tunnel: Vec<u8> = with_port(b"CONNECT localhost:$PORT HTTP/1.1\r\nHost: localhost\r\n\r\nthrough", port);
		let opened: Result<Vec<u8>, String> = fixture.block_on(exchange(fixture.egress.gateway, &tunnel));
		let text: String = String::from_utf8_lossy(opened.as_ref()?).into_owned();
		assert!(text.starts_with("HTTP/1.1 200") && text.ends_with("\r\n\r\nthrough"), "{text}");
		check(&tunnel, port, &opened)?;
		let off_list: Vec<u8> = with_port(b"CONNECT example.com:$PORT HTTP/1.1\r\n\r\n", port);
		let refused: Result<Vec<u8>, String> = fixture.block_on(exchange(fixture.egress.gateway, &off_list));
		let text: String = String::from_utf8_lossy(refused.as_ref()?).into_owned();
		assert!(text.starts_with("HTTP/1.1 403") && text.ends_with("host_not_allowed"), "{text}");
		return check(&off_list, port, &refused);
	}
}
