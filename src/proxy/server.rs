// Plain-hyper servers: each accepted stream is one hyper connection, and no router or tower layer runs on a
// request. `serve` answers with `proxy_request` directly; `serve_with` runs the small servers.
use std::convert::Infallible;
use std::fmt::Display;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::{Builder, UpgradeableConnection};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tracing::trace;

use crate::body::Body;
use crate::config::H1DataPlane;
use crate::proxy::handler::fastlane::{self, Served};
use crate::proxy::handler::{ProxyState, proxy_request};
use crate::proxy::pool::Shard;
use crate::proxy::router::ListenerScope;
use crate::transport::listener::Listener;
use crate::transport::placement::{Seat, Seating};
use crate::transport::{ConnectAddr, PeerStream};

// One connection's part in the graceful drain. `signal` closes when shutdown begins; the server then waits
// until no connection holds a `Drain`. It also holds the connection's seat on its per-core worker.
pub struct Drain {
	signal: watch::Sender<()>,
	_open: watch::Receiver<()>,
	_seat: Seat,
}

// Serve the proxy on `listener` until `signal` fires, then stop new accepts and wait for every connection to
// finish its in-flight requests. The wait has no deadline of its own: callers bound it with their drain timeout.
pub async fn serve<L, F>(listener: L, state: &'static ProxyState, scope: Option<ListenerScope>, signal: F) -> io::Result<()>
where
	L: Listener,
	L::Io: PeerStream,
	F: Future<Output = ()> + Send + 'static,
{
	return serve_on(listener, state, scope, signal, (Shard::FIRST, None)).await;
}

// `serve` for one data-plane worker. Its connections use the worker's share of the raw upstream pool. Each
// connection leaves the worker's live count when it ends.
pub async fn serve_on<L, F>(
	listener: L,
	state: &'static ProxyState,
	scope: Option<ListenerScope>,
	signal: F,
	(shard, seating): (Shard, Option<Seating>),
) -> io::Result<()>
where
	L: Listener,
	L::Io: PeerStream,
	F: Future<Output = ()> + Send + 'static,
{
	return accept_until(listener, signal, seating, |io: L::Io, remote: SocketAddr, drain: Drain| {
		let peer: ConnectAddr = io.connect_addr(remote);
		tokio::spawn(drive_connection(io, peer, state, (scope, shard), drain));
	})
	.await;
}

// The HTTP versions one hyper connection speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocols {
	// h1 or h2, picked by the client preface.
	#[default]
	Auto,
	// h1 only: an h2 preface reads as a bad h1 head. The head bounds below are h1 bounds, so no h2 client skips them.
	Http1,
}

// Bounds on the request head of one hyper connection, and its HTTP versions. None keeps hyper's default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HeadLimits {
	// The connection closes with no response if an h1 head is not read in full in this time. The clock starts
	// when hyper waits for a head, so it also limits keep-alive idle time.
	pub timeout: Option<Duration>,
	// The largest h1 read buffer. A head that does not fit gets 431. Hyper refuses a value under 8192.
	pub max_buf: Option<usize>,
	pub protocols: Protocols,
}

// Serve `listener` until `signal` fires, with the same drain as `serve`. `make_handler` runs once per
// connection and builds the function that answers each of its requests.
pub async fn serve_with<L, M, H, Fut, F>(listener: L, make_handler: M, signal: F) -> io::Result<()>
where
	L: Listener,
	M: FnMut(&L::Io, SocketAddr) -> H,
	H: Fn(Request<Incoming>) -> Fut + Send + 'static,
	Fut: Future<Output = Response<Body>> + Send + 'static,
	F: Future<Output = ()> + Send + 'static,
{
	return serve_bounded(listener, make_handler, signal, HeadLimits::default()).await;
}

// `serve_with` with `limits` on each connection's request head.
pub async fn serve_bounded<L, M, H, Fut, F>(listener: L, mut make_handler: M, signal: F, limits: HeadLimits) -> io::Result<()>
where
	L: Listener,
	M: FnMut(&L::Io, SocketAddr) -> H,
	H: Fn(Request<Incoming>) -> Fut + Send + 'static,
	Fut: Future<Output = Response<Body>> + Send + 'static,
	F: Future<Output = ()> + Send + 'static,
{
	return accept_until(listener, signal, None, |io: L::Io, remote: SocketAddr, drain: Drain| {
		let handler: H = make_handler(&io, remote);
		let service = move |req: Request<Incoming>| {
			let response: Fut = handler(req);
			return async move { Ok::<Response<Body>, Infallible>(response.await) };
		};
		tokio::spawn(drive_hyper(io, service, drain, limits));
	})
	.await;
}

// Hand each accepted stream to `on_conn` until `signal` fires. Then drop the listener and wait for every Drain.
async fn accept_until<L, F, C>(mut listener: L, signal: F, seating: Option<Seating>, mut on_conn: C) -> io::Result<()>
where
	L: Listener,
	F: Future<Output = ()> + Send + 'static,
	C: FnMut(L::Io, SocketAddr, Drain),
{
	// `signal_rx` drops when `signal` fires, which wakes every `signal_tx.closed()`. Each connection holds an
	// `open_rx` clone, so `open_tx.closed()` resolves when the last connection ends.
	let (signal_tx, signal_rx): (watch::Sender<()>, watch::Receiver<()>) = watch::channel(());
	tokio::spawn(async move {
		signal.await;
		drop(signal_rx);
	});
	let (open_tx, open_rx): (watch::Sender<()>, watch::Receiver<()>) = watch::channel(());
	loop {
		let (io, remote): (L::Io, SocketAddr) = tokio::select! {
			conn = listener.accept() => conn,
			() = signal_tx.closed() => break,
		};
		trace!(%remote, "connection accepted");
		on_conn(
			io,
			remote,
			Drain {
				signal: signal_tx.clone(),
				_open: open_rx.clone(),
				_seat: seating.as_ref().map_or_else(Seat::empty, Seating::adopt),
			},
		);
	}
	drop(open_rx);
	drop(listener);
	open_tx.closed().await;
	return Ok(());
}

// The raw HTTP/1.1 plane serves the connection first unless configured off; hyper takes whatever it hands back.
async fn drive_connection<IO>(
	io: IO,
	peer: ConnectAddr,
	state: &'static ProxyState,
	(scope, shard): (Option<ListenerScope>, Shard),
	drain: Drain,
) where
	IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	let service = move |req: Request<Incoming>| {
		let response = proxy_request(state, Some(peer), scope, req.map(Body::new));
		return async move { Ok::<Response<Body>, Infallible>(response.await) };
	};
	// The route is not known until the head parses, so the global request timeout bounds the head read.
	let limits: HeadLimits = HeadLimits {
		timeout: Some(Duration::from_secs(state.timeouts.request_secs.get())),
		max_buf: None,
		protocols: Protocols::Auto,
	};
	if state.proxy_config.h1_data_plane == H1DataPlane::Hyper {
		return drive_hyper(io, service, drain, limits).await;
	}
	match fastlane::serve(io, peer, state, scope, &drain.signal, shard).await {
		Served::Done => drop(drain),
		Served::Handoff(io) => drive_hyper(io, service, drain, limits).await,
	}
}

// One hyper connection (upgrades allowed, versions as `limits.protocols` says) that answers each request with
// `service`. On the shutdown signal it finishes in-flight requests and closes. `drain` drops when it ends.
async fn drive_hyper<IO, S, Fut>(io: IO, service: S, drain: Drain, limits: HeadLimits)
where
	IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	S: Fn(Request<Incoming>) -> Fut + Send + 'static,
	Fut: Future<Output = Result<Response<Body>, Infallible>> + Send + 'static,
{
	let io: TokioIo<IO> = TokioIo::new(io);
	if limits.protocols == Protocols::Http1 {
		// The auto builder ignores http1_only on an upgradeable connection, so h1 alone uses hyper's own builder.
		let mut builder: http1::Builder = http1::Builder::new();
		builder.timer(TokioTimer::new()).header_read_timeout(limits.timeout);
		if let Some(max_buf) = limits.max_buf {
			builder.max_buf_size(max_buf);
		}
		let shutdown = |conn: Pin<&mut _>| http1::UpgradeableConnection::graceful_shutdown(conn);
		return until_drained(builder.serve_connection(io, service_fn(service)).with_upgrades(), shutdown, &drain).await;
	}
	let mut builder: Builder<TokioExecutor> = Builder::new(TokioExecutor::new());
	builder.http1().timer(TokioTimer::new()).header_read_timeout(limits.timeout);
	if let Some(max_buf) = limits.max_buf {
		builder.http1().max_buf_size(max_buf);
	}
	builder.http2().enable_connect_protocol();
	let shutdown = |conn: Pin<&mut _>| UpgradeableConnection::graceful_shutdown(conn);
	return until_drained(builder.serve_connection_with_upgrades(io, service_fn(service)), shutdown, &drain).await;
}

// Run `conn` to its end. When shutdown begins first, ask it to close with `shutdown` and let in-flight requests finish.
async fn until_drained<C, E>(conn: C, shutdown: impl FnOnce(Pin<&mut C>), drain: &Drain)
where
	C: Future<Output = Result<(), E>>,
	E: Display,
{
	tokio::pin!(conn);
	let signal_closed = drain.signal.closed();
	tokio::pin!(signal_closed);
	tokio::select! {
		result = conn.as_mut() => {
			if let Err(e) = result {
				trace!(error = %e, "failed to serve connection");
			}
			return;
		}
		() = &mut signal_closed => shutdown(conn.as_mut()),
	}
	if let Err(e) = conn.await {
		trace!(error = %e, "failed to serve connection during drain");
	}
}

#[cfg(test)]
mod tests {
	use std::io::{self, ErrorKind};
	use std::net::SocketAddr;
	use std::num::NonZeroU64;
	use std::time::{Duration, Instant};

	use arrayvec::ArrayString;
	use bytes::Bytes;
	use http::{HeaderMap, HeaderValue, Method};
	use http_body_util::{BodyExt, Empty};
	use hyper::body::Incoming;
	use hyper::client::conn::{http1, http2};
	use hyper::header::CONTENT_LENGTH;
	use hyper::{Request, Response};
	use hyper_util::rt::{TokioExecutor, TokioIo};
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::{TcpListener, TcpStream};
	use tokio::sync::{mpsc, oneshot};
	use tokio::task::JoinHandle;
	use tokio::time::{sleep, timeout};

	use crate::fast_hash::FastMap;
	use super::serve;
	use crate::acl::AccessControl;
	use crate::balancer::BackendPool;
	use crate::config::{H1DataPlane, MAX_BACKEND_ID_LEN, ProxyConfig, RouteConfig, Stickiness, TimeoutConfig};
	use crate::proxy::handler::{ProxyState, ReloadableState, TestProxyStateParams};
	use crate::proxy::listeners::testutil::{id, single_member_pools, tls_pair};
	use crate::proxy::router::Router;
	use crate::test_support::backend::{serve_plain, text};
	use crate::tls::PeerIdentity;
	use crate::transport::{ConnectAddr, PeerStream};
	use crate::tunnel::revocation::RevocationSet;

	const DEVICE_ID: &str = "dev-7";
	const TEST_SPKI: [u8; 32] = [7; 32];
	const SLOW_PATH: &str = "/api/slow";
	const SLOW_DELAY: Duration = Duration::from_millis(300);
	const STEP_TIMEOUT: Duration = Duration::from_secs(10);
	const SHORT_REQUEST_SECS: NonZeroU64 = NonZeroU64::MIN.saturating_add(1);
	// Sent a byte per gap, this head outlasts STEP_TIMEOUT, so only the proxy's deadline can end it.
	const TRICKLE_HEAD: &[u8] = b"GET /api/x HTTP/1.1\r\nhost: localhost\r\nx-trickle: one byte at a time\r\n\r\n";
	const TRICKLE_GAP: Duration = Duration::from_millis(250);
	// The close can come this much after the deadline: one gap plus timer jitter.
	const TRICKLE_SLACK: Duration = Duration::from_secs(1);

	// Plain TCP stands in for TLS: every test peer presents the same handshake identity.
	fn test_identity() -> Option<PeerIdentity> {
		return PeerIdentity::from_cn_for_test(DEVICE_ID, TEST_SPKI).ok();
	}

	impl PeerStream for TcpStream {
		fn connect_addr(&self, remote: SocketAddr) -> ConnectAddr {
			return ConnectAddr(remote, test_identity());
		}
	}

	// What a client saw, moved out of the response.
	#[derive(Debug)]
	struct Reply {
		status: u16,
		content_length: Option<HeaderValue>,
		body: Bytes,
	}

	// The parts of a response the server must keep as recorded, borrowed from a Reply or written as a golden value.
	#[derive(Debug, PartialEq, Eq)]
	struct Recorded<'a> {
		status: u16,
		content_length: Option<&'a str>,
		body: &'a [u8],
	}

	impl Reply {
		fn recorded(&self) -> Recorded<'_> {
			return Recorded {
				status: self.status,
				content_length: self.content_length.as_ref().and_then(|v| v.to_str().ok()),
				body: &self.body,
			};
		}
	}

	// A backend that echoes the identity and client-IP headers it received; SLOW_PATH answers after SLOW_DELAY
	// and reports its arrival on `arrived`.
	async fn spawn_echo_backend(arrived: mpsc::UnboundedSender<()>) -> Result<SocketAddr, String> {
		return serve_plain(move |req: Request<Incoming>| {
			let arrived: mpsc::UnboundedSender<()> = arrived.clone();
			return async move {
				if req.uri().path() == SLOW_PATH {
					let _ = arrived.send(());
					sleep(SLOW_DELAY).await;
				}
				return text(echo(req.headers()));
			};
		})
		.await;
	}

	fn echo(headers: &HeaderMap) -> String {
		let get = |name: &str| -> &str { headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("-") };
		return format!(
			"id={} xff={}",
			get("x-reduction-client-id"),
			get("x-forwarded-for")
		);
	}

	fn proxy_state(backend: SocketAddr) -> Result<&'static ProxyState, String> {
		return proxy_state_with(backend, TimeoutConfig::default(), ProxyConfig::default());
	}

	fn proxy_state_with(
		backend: SocketAddr,
		timeouts: TimeoutConfig,
		proxy_config: ProxyConfig,
	) -> Result<&'static ProxyState, String> {
		let backend_pools: FastMap<ArrayString<MAX_BACKEND_ID_LEN>, BackendPool> = single_member_pools(&[("echo", backend)])?;
		let route: RouteConfig = RouteConfig {
			path_prefix: id("/api")?,
			backend_id: Some(id("echo")?),
			timeout_secs: None,
			is_wakeable: false,
			stickiness: Stickiness::Identity,
			allows_spill_on_exhaustion: false,
			split: Vec::new(),
		};
		let reloadable: ReloadableState = ReloadableState {
			router: Router::new(&[route]),
			backend_pools,
			acl: AccessControl::new(vec![], vec![]),
		};
		let (_server, client) = tls_pair()?;
		return ProxyState::for_test(TestProxyStateParams {
			proxy_config,
			..TestProxyStateParams::new(reloadable, RevocationSet::default(), client, timeouts)
		})
		.map_err(|err| format!("ProxyState::for_test: {err}"));
	}

	// Start the proxy on a fresh loopback port; it serves until `stop` fires or is dropped.
	async fn start(state: &'static ProxyState) -> Result<(SocketAddr, oneshot::Sender<()>, JoinHandle<io::Result<()>>), String> {
		let listener: TcpListener = match TcpListener::bind("127.0.0.1:0").await {
			Ok(value) => value,
			Err(err) => return Err(format!("bind proxy: {err:?}")),
		};
		let addr: SocketAddr = match listener.local_addr() {
			Ok(value) => value,
			Err(err) => return Err(format!("proxy local_addr: {err:?}")),
		};
		let (stop, stopped): (oneshot::Sender<()>, oneshot::Receiver<()>) = oneshot::channel();
		let signal = async move {
			let _ = stopped.await;
		};
		let handle: JoinHandle<io::Result<()>> = tokio::spawn(serve(listener, state, None, signal));
		return Ok((addr, stop, handle));
	}

	async fn reply(response: Response<hyper::body::Incoming>) -> Result<Reply, String> {
		let (mut parts, body) = response.into_parts();
		let body: Bytes = match body.collect().await {
			Ok(collected) => collected.to_bytes(),
			Err(err) => return Err(format!("collect body: {err:?}")),
		};
		return Ok(Reply {
			status: parts.status.as_u16(),
			content_length: parts.headers.remove(CONTENT_LENGTH),
			body,
		});
	}

	fn request(method: Method, path: &str) -> Result<Request<Empty<Bytes>>, String> {
		return Request::builder()
			.method(method)
			.uri(path)
			.header("host", "localhost")
			.body(Empty::new())
			.map_err(|err| format!("build {path}: {err:?}"));
	}

	async fn h1(addr: SocketAddr, method: Method, path: &str) -> Result<Reply, String> {
		let tcp: TcpStream = TcpStream::connect(addr).await.map_err(|err| format!("connect: {err:?}"))?;
		let (mut sender, conn) = http1::handshake(TokioIo::new(tcp))
			.await
			.map_err(|err| format!("h1 handshake: {err:?}"))?;
		tokio::spawn(conn);
		let response = sender
			.send_request(request(method, path)?)
			.await
			.map_err(|err| format!("h1 send {path}: {err:?}"))?;
		return reply(response).await;
	}

	async fn h2(addr: SocketAddr, path: &str) -> Result<Reply, String> {
		let tcp: TcpStream = TcpStream::connect(addr).await.map_err(|err| format!("connect: {err:?}"))?;
		let (mut sender, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
			.await
			.map_err(|err| format!("h2 handshake: {err:?}"))?;
		tokio::spawn(conn);
		let req: Request<Empty<Bytes>> = Request::builder()
			.uri(format!("http://localhost{path}"))
			.body(Empty::new())
			.map_err(|err| format!("build h2 {path}: {err:?}"))?;
		let response = sender
			.send_request(req)
			.await
			.map_err(|err| format!("h2 send {path}: {err:?}"))?;
		return reply(response).await;
	}

	fn reply_of<'a>(status: u16, content_length: &'a str, body: &'a str) -> Recorded<'a> {
		return Recorded {
			status,
			content_length: Some(content_length),
			body: body.as_bytes(),
		};
	}

	// Golden replies, recorded when this server was checked against the axum app it replaced: h1 GET, the
	// unrouted 404, HEAD, and h2 GET.
	#[tokio::test]
	async fn the_server_answers_exactly_as_recorded() -> Result<(), String> {
		let (arrived, _arrivals) = mpsc::unbounded_channel();
		let backend: SocketAddr = spawn_echo_backend(arrived).await?;
		let (addr, _stop, _handle) = start(proxy_state(backend)?).await?;
		let echoed: String = format!("id={DEVICE_ID} xff=127.0.0.1");
		let length: String = echoed.len().to_string();
		assert_eq!(
			h1(addr, Method::GET, "/api/x").await?.recorded(),
			reply_of(200, &length, &echoed),
			"the connection's identity and IP reach the backend"
		);
		assert_eq!(
			h1(addr, Method::GET, "/nowhere").await?.recorded(),
			reply_of(404, "16", "no route matched"),
			"an unrouted path is the proxy's own exact-size 404"
		);
		assert_eq!(
			h1(addr, Method::HEAD, "/api/x").await?.recorded(),
			reply_of(200, &length, ""),
			"HEAD keeps the GET length and has no body"
		);
		assert_eq!(
			h2(addr, "/api/x").await?.recorded(),
			reply_of(200, &length, &echoed),
			"h2 prior knowledge is detected by preface and carries the same peer facts"
		);
		return Ok(());
	}

	// The client sends one head byte in each gap, so no single read stalls. hyper's header read timeout, sized
	// from the request timeout, closes the connection with no response.
	#[tokio::test]
	async fn hyper_closes_a_head_trickled_past_the_request_timeout() -> Result<(), String> {
		let (arrived, _arrivals) = mpsc::unbounded_channel();
		let backend: SocketAddr = spawn_echo_backend(arrived).await?;
		let timeouts: TimeoutConfig = TimeoutConfig {
			request_secs: SHORT_REQUEST_SECS,
			..TimeoutConfig::default()
		};
		let hyper_only: ProxyConfig = ProxyConfig {
			h1_data_plane: H1DataPlane::Hyper,
			..ProxyConfig::default()
		};
		let (addr, _stop, _handle) = start(proxy_state_with(backend, timeouts, hyper_only)?).await?;
		let limit: Duration = Duration::from_secs(SHORT_REQUEST_SECS.get());
		// Taken before connect: hyper's clock starts once it first polls the accepted connection.
		let started: Instant = Instant::now();
		let tcp: TcpStream = TcpStream::connect(addr).await.map_err(|err| format!("connect: {err:?}"))?;
		let (mut reader, mut writer) = tcp.into_split();
		let trickle: JoinHandle<usize> = tokio::spawn(async move {
			let mut sent: usize = 0;
			while sent < TRICKLE_HEAD.len() && writer.write_all(&TRICKLE_HEAD[sent..=sent]).await.is_ok() {
				sent += 1;
				sleep(TRICKLE_GAP).await;
			}
			return sent;
		});
		let mut got: Vec<u8> = Vec::new();
		let read: io::Result<usize> = timeout(STEP_TIMEOUT, reader.read_to_end(&mut got))
			.await
			.map_err(|_| "a trickled head held the connection past its deadline".to_owned())?;
		let elapsed: Duration = started.elapsed();
		trickle.abort();
		match read {
			Ok(_) => {}
			// A close with a client byte still unread is a reset on some stacks: still a close.
			Err(err) if matches!(err.kind(), ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted) => {}
			Err(err) => return Err(format!("read: {err:?}")),
		}
		assert!(got.is_empty(), "hyper answers nothing on its header timeout: {}", String::from_utf8_lossy(&got));
		assert!(elapsed >= limit, "the deadline covers the whole head, not one read: {elapsed:?}");
		assert!(elapsed < limit + TRICKLE_SLACK, "the close comes at the deadline: {elapsed:?}");
		return Ok(());
	}

	#[tokio::test]
	async fn shutdown_finishes_in_flight_requests_then_stops_accepting() -> Result<(), String> {
		let (arrived, mut arrivals) = mpsc::unbounded_channel();
		let backend: SocketAddr = spawn_echo_backend(arrived).await?;
		let (addr, stop, handle) = start(proxy_state(backend)?).await?;

		let in_flight: JoinHandle<Result<Reply, String>> = tokio::spawn(h1(addr, Method::GET, SLOW_PATH));
		match timeout(STEP_TIMEOUT, arrivals.recv()).await {
			Ok(Some(())) => {}
			other => return Err(format!("slow request never reached the backend: {other:?}")),
		}
		let _ = stop.send(());

		let finished: Reply = match timeout(STEP_TIMEOUT, in_flight).await {
			Ok(Ok(Ok(value))) => value,
			other => return Err(format!("in-flight request: {other:?}")),
		};
		assert_eq!(finished.status, 200, "a request in flight at shutdown completes");
		match timeout(STEP_TIMEOUT, handle).await {
			Ok(Ok(Ok(()))) => {}
			other => return Err(format!("serve must return once its connections end: {other:?}")),
		}
		assert!(
			TcpStream::connect(addr).await.is_err(),
			"the listener is dropped after shutdown"
		);
		return Ok(());
	}
}
