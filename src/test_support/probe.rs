// Plaintext HTTP probes for the golden tests of the small servers: one request per connection, then the reply's observable parts.
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper::header::{ALLOW, CONTENT_LENGTH, DATE, HOST, HeaderName, LOCATION};
use hyper::{Error as HyperError, HeaderMap, Method, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use core_utils::ctx::Ctx;
use tokio::net::TcpStream;

// Stands in for a body that is not UTF-8, so a golden comparison fails visibly.
const NON_UTF8_BODY: &str = "<non-utf8 body>";

// What a client saw: the head and body, moved out of the response.
#[derive(Debug)]
pub struct Reply {
	pub status: u16,
	pub headers: HeaderMap,
	pub body: Bytes,
}

// The fields a hand-routed server must reproduce exactly, borrowed from a Reply or written as a golden value.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Fields<'a> {
	pub status: u16,
	pub content_length: Option<&'a str>,
	pub allow: Option<&'a str>,
	pub location: Option<&'a str>,
	pub body: &'a str,
	// Names of all other headers. If a server adds a header such as content-type, the golden test fails.
	pub others: Vec<&'a str>,
}

impl Reply {
	#[must_use]
	pub fn fields(&self) -> Fields<'_> {
		let header = |name: HeaderName| -> Option<&str> { return self.headers.get(name).and_then(|v| v.to_str().ok()) };
		return Fields {
			status: self.status,
			content_length: header(CONTENT_LENGTH),
			allow: header(ALLOW),
			location: header(LOCATION),
			body: str::from_utf8(&self.body).unwrap_or(NON_UTF8_BODY),
			others: other_headers(&self.headers),
		};
	}
}

fn other_headers(headers: &HeaderMap) -> Vec<&str> {
	let recorded: [HeaderName; 4] = [CONTENT_LENGTH, ALLOW, LOCATION, DATE];
	let mut others: Vec<&str> = headers.keys().filter(|name| !recorded.contains(name)).map(HeaderName::as_str).collect();
	others.sort_unstable();
	return others;
}

async fn reply(response: Response<Incoming>) -> Result<Reply, String> {
	let (parts, body) = response.into_parts();
	let body: Bytes = match body.collect().await {
		Ok(collected) => collected.to_bytes(),
		Err(err) => return Err(format!("collect body: {err:?}")),
	};
	return Ok(Reply {
		status: parts.status.as_u16(),
		headers: parts.headers,
		body,
	});
}

async fn connect(addr: SocketAddr) -> Result<TcpStream, String> {
	return TcpStream::connect(addr).await.ctx(&format!("connect {addr}"));
}

async fn h1_send(tcp: TcpStream, req: Request<Empty<Bytes>>) -> Result<Response<Incoming>, HyperError> {
	let (mut sender, conn) = http1::handshake(TokioIo::new(tcp)).await?;
	tokio::spawn(conn);
	return sender.send_request(req).await;
}

async fn h2_send(tcp: TcpStream, req: Request<Empty<Bytes>>) -> Result<Response<Incoming>, HyperError> {
	let (mut sender, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(tcp)).await?;
	tokio::spawn(conn);
	return sender.send_request(req).await;
}

// One HTTP/1.1 request for `target` with the given Host header.
pub async fn h1(addr: SocketAddr, method: Method, target: &str, host: &str) -> Result<Reply, String> {
	let tcp: TcpStream = connect(addr).await?;
	let req: Request<Empty<Bytes>> = Request::builder()
		.method(method)
		.uri(target)
		.header(HOST, host)
		.body(Empty::new())
		.ctx(&format!("build h1 {target}"))?;
	let response: Response<Incoming> = h1_send(tcp, req).await.ctx(&format!("h1 {target}"))?;
	return reply(response).await;
}

// One HTTP/2 prior-knowledge request for `path`.
pub async fn h2(addr: SocketAddr, method: Method, path: &str) -> Result<Reply, String> {
	let tcp: TcpStream = connect(addr).await?;
	let req: Request<Empty<Bytes>> = Request::builder()
		.method(method)
		.uri(format!("http://localhost{path}"))
		.body(Empty::new())
		.ctx(&format!("build h2 {path}"))?;
	let response: Response<Incoming> = h2_send(tcp, req).await.ctx(&format!("h2 {path}"))?;
	return reply(response).await;
}
