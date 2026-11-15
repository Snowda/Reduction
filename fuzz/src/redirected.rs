//! The `redirect` target: raw bytes on a TCP connection to the HTTP to HTTPS redirect listener.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, StatusCode};
use httparse::{EMPTY_HEADER, Header, Response, Status};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::fixture::REDIRECT_HOST;
use crate::request::{self, path_and_query};

// The listener answers at once and closes at EOF; past this bound it hung.
const EXCHANGE_BOUND: Duration = Duration::from_secs(10);
// More than any first response head; the read stops here so a long pipeline cannot grow the buffer.
pub const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
const MAX_RESPONSE_HEADERS: usize = 16;
// On loopback the listener answers a whole request in well under this; past it, it waits for more input.
const READ_IDLE: Duration = Duration::from_millis(100);
// hyper-util's auto server reads these bytes as an HTTP/2 connection, which this check does not decode.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const LOCATION: &str = "location";
const CONTENT_LENGTH: &str = "content-length";
const EMPTY_LENGTH: &[u8] = b"0";

/// The bytes a listener sends for `data` until it closes. The write side closes after the first answer.
pub async fn exchange(addr: SocketAddr, data: &[u8]) -> Result<Vec<u8>, String> {
	return exchange_waiting(addr, data, READ_IDLE).await;
}

/// As `exchange`, but the first answer can take up to `idle` between bytes before the write side closes.
pub async fn exchange_waiting(addr: SocketAddr, data: &[u8], idle: Duration) -> Result<Vec<u8>, String> {
	let talk = async {
		let mut stream: TcpStream = TcpStream::connect(addr).await?;
		// The listener may answer and close before it reads all of `data`; the reply still counts.
		let _ = stream.write_all(data).await;
		let mut response: Vec<u8> = Vec::new();
		// hyper drops a connection at a read EOF before it writes the answer, so the write side stays open until then.
		await_first_head(&mut stream, &mut response, idle).await;
		let _ = stream.shutdown().await;
		let rest: u64 = MAX_RESPONSE_BYTES.saturating_sub(u64::try_from(response.len()).unwrap_or(MAX_RESPONSE_BYTES));
		let _ = (&mut stream).take(rest).read_to_end(&mut response).await;
		return Ok::<Vec<u8>, io::Error>(response);
	};
	return match timeout(EXCHANGE_BOUND, talk).await {
		Ok(Ok(response)) => Ok(response),
		Ok(Err(e)) => Err(format!("connect to the listener: {e}")),
		Err(_) => Err(String::from("the listener did not close within the bound")),
	};
}

// Read until a whole response head is in `response`, the stream ends, or no byte comes for `idle`.
async fn await_first_head(stream: &mut TcpStream, response: &mut Vec<u8>, idle: Duration) {
	loop {
		let is_full: bool = u64::try_from(response.len()).unwrap_or(MAX_RESPONSE_BYTES) >= MAX_RESPONSE_BYTES;
		if is_full || has_head(response) {
			return;
		}
		match timeout(idle, stream.read_buf(response)).await {
			Ok(Ok(read)) if read > 0 => continue,
			_ => return,
		}
	}
}

// True once `response` starts with a whole head, or with bytes that no further read can make into one.
fn has_head(response: &[u8]) -> bool {
	let mut headers: [Header<'_>; MAX_RESPONSE_HEADERS] = [EMPTY_HEADER; MAX_RESPONSE_HEADERS];
	return !matches!(Response::new(&mut headers).parse(response), Ok(Status::Partial));
}

/// The invariant: the listener closes within the bound. Its first answer is a 4xx or 5xx, or a bodiless 308.
/// The Location of a 308 is `https://` + REDIRECT_HOST + the path and query of the request.
pub fn check(data: &[u8], response: &Result<Vec<u8>, String>) -> Result<(), String> {
	let response: &[u8] = response.as_ref()?;
	if response.is_empty() || data.starts_with(H2_PREFACE) {
		return Ok(());
	}
	let mut headers: [Header<'_>; MAX_RESPONSE_HEADERS] = [EMPTY_HEADER; MAX_RESPONSE_HEADERS];
	let mut head: Response<'_, '_> = Response::new(&mut headers);
	if !matches!(head.parse(response), Ok(Status::Complete(_))) {
		return Err(format!("not an HTTP/1.1 response head: {:?}", Bytes::copy_from_slice(response)));
	}
	let status: StatusCode = head
		.code
		.and_then(|code| return StatusCode::from_u16(code).ok())
		.ok_or("a response head with no status")?;
	if status.is_client_error() || status.is_server_error() {
		return Ok(());
	}
	if status != StatusCode::PERMANENT_REDIRECT {
		return Err(format!("the redirect listener answered {status}"));
	}
	if header(head.headers, CONTENT_LENGTH) != Some(EMPTY_LENGTH) {
		return Err(String::from("a 308 without Content-Length: 0"));
	}
	let location: &[u8] = header(head.headers, LOCATION).ok_or("a 308 without a Location")?;
	return check_location(location, request::parse(data).as_ref());
}

fn header<'a>(headers: &[Header<'a>], name: &str) -> Option<&'a [u8]> {
	return headers
		.iter()
		.find(|header| return header.name.eq_ignore_ascii_case(name))
		.map(|header| return header.value);
}

// With a parsed request the Location is exact; without one it must still point at the canonical host.
fn check_location(location: &[u8], request: Option<&Request<Bytes>>) -> Result<(), String> {
	let origin: String = format!("https://{REDIRECT_HOST}");
	let is_exact: bool = match request {
		Some(request) => location == format!("{origin}{}", path_and_query(request.uri())).as_bytes(),
		None => location.starts_with(origin.as_bytes()),
	};
	return match is_exact {
		true => Ok(()),
		false => Err(format!("Location {:?} for request {request:?}", Bytes::copy_from_slice(location))),
	};
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::fixture::{self, Fixture};

	const GET: &[u8] = b"GET /posts/hello?draft=1 HTTP/1.1\r\nHost: browser-sent-host.example\r\n\r\n";

	fn replied(text: &str) -> Result<Vec<u8>, String> {
		return Ok(text.as_bytes().to_vec());
	}

	#[test]
	fn exact_redirects_refusals_and_silence_pass() {
		let exact: &str =
			"HTTP/1.1 308 Permanent Redirect\r\ncontent-length: 0\r\nlocation: https://fuzz.example/posts/hello?draft=1\r\n\r\n";
		assert!(check(GET, &replied(exact)).is_ok(), "exact 308");
		assert!(check(GET, &replied("HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")).is_ok(), "400");
		assert!(check(GET, &replied("")).is_ok(), "closed without an answer");
	}

	#[test]
	fn off_host_or_malformed_redirects_fail() {
		let client_host: &str =
			"HTTP/1.1 308 Permanent Redirect\r\ncontent-length: 0\r\nlocation: https://browser-sent-host.example/posts/hello?draft=1\r\n\r\n";
		let lost_query: &str =
			"HTTP/1.1 308 Permanent Redirect\r\ncontent-length: 0\r\nlocation: https://fuzz.example/posts/hello\r\n\r\n";
		let with_body: &str =
			"HTTP/1.1 308 Permanent Redirect\r\ncontent-length: 4\r\nlocation: https://fuzz.example/posts/hello?draft=1\r\n\r\nbody";
		assert!(check(GET, &replied(client_host)).is_err(), "the client's Host header leaked into Location");
		assert!(check(GET, &replied(lost_query)).is_err(), "the query was dropped");
		assert!(check(GET, &replied(with_body)).is_err(), "a 308 with a body");
		assert!(check(GET, &replied("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")).is_err(), "a 200");
		assert!(check(GET, &replied("garbage")).is_err(), "not a response head");
		assert!(check(GET, &Err(String::from("hung"))).is_err(), "no close in the bound");
	}

	// Positive control: the live listener redirects a GET exactly as its own tests record.
	#[test]
	fn the_live_listener_redirects_a_get_exactly() -> Result<(), String> {
		let fixture: &Fixture = fixture::get()?;
		let response: Result<Vec<u8>, String> = fixture.block_on(exchange(fixture.redirect, GET));
		let text: String = String::from_utf8_lossy(response.as_ref()?).into_owned();
		assert!(text.starts_with("HTTP/1.1 308"), "{text}");
		assert!(text.contains("location: https://fuzz.example/posts/hello?draft=1\r\n"), "{text}");
		return check(GET, &response);
	}
}
