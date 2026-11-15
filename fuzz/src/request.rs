//! Turns raw HTTP/1.1 bytes into the `http::Request` that a hyper server gives the proxy. httparse reads the head.
//! Content-Length sets the body, as in hyper; with no length, the body is empty.

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, HeaderName, HeaderValue, TRANSFER_ENCODING};
use http::request::Builder;
use http::{Method, Request, Uri, Version};
use httparse::{EMPTY_HEADER, Header, Status};

// Past this many headers the decoder refuses the input; hyper's server also has a cap.
const MAX_HEADERS: usize = 64;
// httparse reports HTTP/1.x as the minor digit.
const HTTP_10_MINOR: u8 = 0;
// The redirect handler answers this path when a request target has no path and query.
pub const DEFAULT_PATH: &str = "/";

/// The request in `data`, or None when hyper would refuse to frame it (bad head, chunked, short body).
#[must_use]
pub fn parse(data: &[u8]) -> Option<Request<Bytes>> {
	let mut headers: [Header<'_>; MAX_HEADERS] = [EMPTY_HEADER; MAX_HEADERS];
	let mut head: httparse::Request<'_, '_> = httparse::Request::new(&mut headers);
	let Ok(Status::Complete(head_len)) = head.parse(data) else {
		return None;
	};
	let version: Version = match head.version? {
		HTTP_10_MINOR => Version::HTTP_10,
		_ => Version::HTTP_11,
	};
	let mut builder: Builder = Request::builder()
		.method(Method::from_bytes(head.method?.as_bytes()).ok()?)
		.uri(Uri::try_from(head.path?).ok()?)
		.version(version);
	for header in head.headers.iter() {
		let name: HeaderName = HeaderName::from_bytes(header.name.as_bytes()).ok()?;
		builder = builder.header(name, HeaderValue::from_bytes(header.value).ok()?);
	}
	let request: Request<()> = builder.body(()).ok()?;
	let body: Bytes = framed_body(&request, data.get(head_len..)?)?;
	return Some(request.map(|()| return body));
}

// The body that Content-Length frames. A chunked body or two lengths get hyper's own 400, so refuse them.
fn framed_body(request: &Request<()>, rest: &[u8]) -> Option<Bytes> {
	if request.headers().contains_key(TRANSFER_ENCODING) {
		return None;
	}
	let mut lengths = request.headers().get_all(CONTENT_LENGTH).iter();
	let Some(length) = lengths.next() else {
		return Some(Bytes::new());
	};
	if lengths.next().is_some() {
		return None;
	}
	// usize::from_str takes a '+' sign, but hyper refuses one with a 400. So only digits pass.
	let digits: &[u8] = length.as_bytes();
	if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
		return None;
	}
	let length: usize = length.to_str().ok()?.parse().ok()?;
	return rest.get(..length).map(Bytes::copy_from_slice);
}

/// The path and query a handler sees for `uri`, as the redirect handler reads it.
#[must_use]
pub fn path_and_query(uri: &Uri) -> &str {
	return uri.path_and_query().map_or(DEFAULT_PATH, |pq| return pq.as_str());
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::oracle;

	#[test]
	fn a_get_has_an_empty_body_and_keeps_its_target() -> Result<(), String> {
		let request: Request<Bytes> =
			parse(b"GET /posts/hello?draft=1 HTTP/1.1\r\nHost: a\r\n\r\n").ok_or("GET did not parse")?;
		assert_eq!(request.method(), Method::GET);
		assert_eq!(path_and_query(request.uri()), "/posts/hello?draft=1");
		assert!(request.body().is_empty(), "no Content-Length frames an empty body");
		return Ok(());
	}

	#[test]
	fn content_length_frames_the_body_and_leaves_the_rest() -> Result<(), String> {
		let request: Request<Bytes> =
			parse(b"POST /api/echo HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloEXTRA").ok_or("POST did not parse")?;
		assert_eq!(request.body().as_ref(), b"hello");
		return Ok(());
	}

	#[test]
	fn hyper_framed_refusals_are_none() {
		assert!(parse(b"POST / HTTP/1.1\r\nContent-Length: 9\r\n\r\nshort").is_none(), "short body");
		assert!(parse(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").is_none(), "chunked");
		assert!(parse(b"GET / HTTP/1.1\r\nHost: a\r\n").is_none(), "unfinished head");
		assert!(parse(b"\xff / HTTP/1.1\r\n\r\n").is_none(), "bad method");
	}

	// regressions/upstream_send/crash-e007…: a signed length reached the echo backend, which answered 400.
	#[test]
	fn a_length_hyper_refuses_is_none() -> Result<(), String> {
		const SIGNED: &[u8] = b"POST / HTTP/1.1\r\nContent-Length: +0\r\n\r\n";
		assert!(oracle::server_read(SIGNED)?.is_none(), "hyper's server must refuse the signed length");
		assert!(parse(SIGNED).is_none(), "the decoder must refuse what hyper refuses");
		assert!(parse(b"POST / HTTP/1.1\r\nContent-Length: \r\n\r\n").is_none(), "empty length");
		return Ok(());
	}
}
