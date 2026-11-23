// Plaintext test backends on serve_with. `text` answers as an axum `&str`/`String` handler did: 200 with a
// text/plain content type.
use std::future::{Future, pending};
use std::net::SocketAddr;

use http::header::CONTENT_TYPE;
use http::{HeaderValue, Request, Response};
use hyper::body::Incoming;
use tokio::net::{TcpListener, TcpStream};

use crate::body::Body;
use crate::proxy::server::serve_with;

pub const TEXT_PLAIN: &str = "text/plain; charset=utf-8";

#[must_use]
pub fn text(body: impl Into<Body>) -> Response<Body> {
	let mut response: Response<Body> = Response::new(body.into());
	response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(TEXT_PLAIN));
	return response;
}

// Serve `handler` on a fresh loopback port for the rest of the test; returns the address.
pub async fn serve_plain<H, Fut>(handler: H) -> Result<SocketAddr, String>
where
	H: Fn(Request<Incoming>) -> Fut + Clone + Send + 'static,
	Fut: Future<Output = Response<Body>> + Send + 'static,
{
	let listener: TcpListener = TcpListener::bind("127.0.0.1:0")
		.await
		.map_err(|err| format!("bind backend: {err:?}"))?;
	let addr: SocketAddr = listener.local_addr().map_err(|err| format!("backend local_addr: {err:?}"))?;
	let make_handler = move |_: &TcpStream, _: SocketAddr| handler.clone();
	tokio::spawn(serve_with(listener, make_handler, pending::<()>()));
	return Ok(addr);
}

#[cfg(test)]
mod tests {
	use std::future::ready;

	use http::header::CONTENT_TYPE;
	use http::{Method, Request, Response};
	use hyper::body::Incoming;

	use super::{TEXT_PLAIN, serve_plain, text};
	use crate::body::Body;
	use crate::test_support::probe::{Fields, Reply, h1};

	#[tokio::test]
	async fn a_backend_answers_every_request_with_its_handler() -> Result<(), String> {
		let addr = serve_plain(|req: Request<Incoming>| ready(text(req.uri().path().to_owned()))).await?;
		let reply: Reply = h1(addr, Method::GET, "/some/path", "localhost").await?;
		let seen: Fields<'_> = reply.fields();
		assert_eq!(seen.status, 200);
		assert_eq!(seen.body, "/some/path", "the handler sees the request");
		assert_eq!(seen.others, ["content-type"], "text adds only its content type");
		let response: Response<Body> = text("x");
		assert_eq!(response.headers().get(CONTENT_TYPE).map(|v| v.as_bytes()), Some(TEXT_PLAIN.as_bytes()));
		return Ok(());
	}
}
