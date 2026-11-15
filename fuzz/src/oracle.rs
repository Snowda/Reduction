//! hyper 1.x as the oracle for the fastlane parsers. Each call runs one hyper connection over an in-memory pipe
//! on a per-thread runtime, so it needs no fixture and no sockets.

use std::convert::Infallible;
use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use http::header::HOST;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body as _, Incoming};
use hyper::client::conn::http1::{self as client_conn, SendRequest};
use hyper::server::conn::http1 as server_conn;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, copy, duplex, sink, split};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::time::timeout;

// Larger than any fuzz input, so neither side of the pipe blocks on a full buffer.
const PIPE_BYTES: usize = 1024 * 1024;
// One in-memory exchange ends in microseconds; past this bound hyper hung, which is a harness fault.
const EXCHANGE_BOUND: Duration = Duration::from_secs(10);
const ORACLE_HOST: &str = "fuzz.oracle";
// The oracle's request has no body, so its head ends the request.
const HEAD_END: &[u8] = b"\r\n\r\n";
const READ_CHUNK: usize = 4096;

thread_local! {
	static RUNTIME: Result<Runtime, String> =
		Builder::new_current_thread().enable_all().build().map_err(|e| format!("oracle runtime: {e}"));
}

/// A response as hyper's client reads it: the final status and the whole body.
#[derive(Debug, PartialEq, Eq)]
pub struct ClientRead {
	pub status: StatusCode,
	pub body: Bytes,
}

/// The first request head hyper's server parsed, with the body length its decoder framed.
#[derive(Debug)]
pub struct ServerRead {
	pub method: Method,
	pub target: String,
	pub version: Version,
	pub headers: HeaderMap,
	pub body_len: Option<u64>,
}

// Run `future` on this thread's runtime, bounded; Err is a harness fault the caller must not read as a verdict.
fn run<F: Future>(future: F) -> Result<F::Output, String> {
	return RUNTIME.with(|runtime: &Result<Runtime, String>| {
		let runtime: &Runtime = runtime.as_ref().map_err(String::clone)?;
		// timeout() reads the runtime's timer at creation, so create it inside block_on.
		return runtime
			.block_on(async { return timeout(EXCHANGE_BOUND, future).await })
			.map_err(|_| return String::from("a hyper exchange did not end within the bound"));
	});
}

// Write `bytes` and close the write side, then keep the read side open until the peer drops its end.
fn feed(end: DuplexStream, bytes: Vec<u8>) {
	let (mut reader, mut writer) = split(end);
	tokio::spawn(async move {
		let _ = writer.write_all(&bytes).await;
		let _ = writer.shutdown().await;
		let _ = copy(&mut reader, &mut sink()).await;
	});
}

// Act as a backend: read the request head, then answer with `bytes` and close the write side.
// hyper's client cancels the request when bytes arrive before it sends one, so the answer must wait.
fn answer(end: DuplexStream, bytes: Vec<u8>) {
	tokio::spawn(async move {
		let mut end: DuplexStream = end;
		let mut seen: Vec<u8> = Vec::new();
		let mut chunk: [u8; READ_CHUNK] = [0; READ_CHUNK];
		while !seen.windows(HEAD_END.len()).any(|window: &[u8]| return window == HEAD_END) {
			match end.read(&mut chunk).await {
				Ok(0) | Err(_) => return,
				Ok(n) => seen.extend_from_slice(&chunk[..n]),
			}
		}
		feed(end, bytes);
	});
}

/// What hyper's client reads when a backend sends `backend` in answer to a `method` request and then closes.
/// The outer Err is a harness fault; the inner Err is hyper refusing the response.
pub fn client_read(method: &Method, backend: &[u8]) -> Result<Result<ClientRead, String>, String> {
	let (client, server) = duplex(PIPE_BYTES);
	let method: Method = method.clone();
	let backend: Vec<u8> = backend.to_vec();
	return run(async move {
		answer(server, backend);
		let (mut sender, conn): (SendRequest<Empty<Bytes>>, _) =
			client_conn::handshake(TokioIo::new(client)).await.map_err(|e| format!("handshake: {e}"))?;
		tokio::spawn(conn);
		let req: Request<Empty<Bytes>> = Request::builder()
			.method(method)
			.uri("/")
			.header(HOST, HeaderValue::from_static(ORACLE_HOST))
			.body(Empty::new())
			.map_err(|e| format!("request: {e}"))?;
		let response: Response<Incoming> = sender.send_request(req).await.map_err(|e| format!("head: {e}"))?;
		let status: StatusCode = response.status();
		let body: Bytes = response
			.into_body()
			.collect()
			.await
			.map_err(|e| format!("body: {e}"))?
			.to_bytes();
		return Ok(ClientRead { status, body });
	});
}

/// The first request hyper's server parses from `client` (sent, then the write side closed), or None if it refused.
pub fn server_read(client: &[u8]) -> Result<Option<ServerRead>, String> {
	let (peer, server) = duplex(PIPE_BYTES);
	let client: Vec<u8> = client.to_vec();
	return run(async move {
		feed(peer, client);
		let (sent, mut received): (UnboundedSender<ServerRead>, UnboundedReceiver<ServerRead>) = unbounded_channel();
		let service = service_fn(move |req: Request<Incoming>| {
			let hint: Option<u64> = req.body().size_hint().exact();
			let (parts, _) = req.into_parts();
			let _ = sent.send(ServerRead {
				method: parts.method,
				target: parts.uri.path_and_query().map_or_else(String::new, |pq| return pq.as_str().to_owned()),
				version: parts.version,
				headers: parts.headers,
				body_len: hint,
			});
			return async { return Ok::<Response<Empty<Bytes>>, Infallible>(Response::new(Empty::new())) };
		});
		let _ = server_conn::Builder::new()
			.half_close(true)
			.serve_connection(TokioIo::new(server), service)
			.await;
		return received.try_recv().ok();
	});
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_client_oracle_reads_a_sized_body_and_refuses_a_short_one() -> Result<(), String> {
		let read: ClientRead = client_read(&Method::GET, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")??;
		assert_eq!(read, ClientRead { status: StatusCode::OK, body: Bytes::from_static(b"hi") });
		assert!(client_read(&Method::GET, b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhi")?.is_err(), "EOF mid-body");
		assert!(client_read(&Method::GET, b"not http")?.is_err(), "no status line");
		return Ok(());
	}

	#[test]
	fn the_server_oracle_reports_the_head_and_its_body_length() -> Result<(), String> {
		let read: ServerRead =
			server_read(b"POST /a?b HTTP/1.1\r\nContent-Length: 3\r\nX-K: v\r\n\r\nabc")?.ok_or("hyper refused a valid POST")?;
		assert_eq!((read.method, read.target.as_str(), read.version), (Method::POST, "/a?b", Version::HTTP_11));
		assert_eq!(read.body_len, Some(3));
		assert_eq!(read.headers.get("x-k").map(HeaderValue::as_bytes), Some(&b"v"[..]));
		assert!(server_read(b"GET / HTTP/1.1\r\nContent-Length: +1\r\n\r\n")?.is_none(), "hyper refuses a signed length");
		assert!(server_read(b"GET / HTTP/1.1\r\nHost: a\r\n")?.is_none(), "an unfinished head never reaches the service");
		return Ok(());
	}
}
