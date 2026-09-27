use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, IdleTimeout, Incoming, RecvStream, SendStream, ServerConfig, TransportConfig, VarInt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::{ReductionError, Result};
use crate::tls::PeerIdentity;
use crate::transport::quic::{QuicStream, STREAM_TYPE_HTTP, STREAM_TYPE_RAW};

const STREAM_TYPE_READ_TIMEOUT_SECS: u64 = 5;
const DEFAULT_CHANNEL_CAPACITY: usize = 256;

// Cap on the initial QUIC handshake: a peer that stalls mid-handshake is dropped instead of
// pinning its task until quinn's idle machinery notices.
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;
// Global bound on connections simultaneously inside that handshake window. At the cap, further
// incomings are ignored (nothing sent back — no amplification) rather than each spawning a task.
// Mirrors the tunnel listener's pending-registration semaphore.
const MAX_CONCURRENT_PENDING_HANDSHAKES: usize = 256;

// Explicit transport contract for the data listener. The idle timeout and bidi-stream cap restate
// quinn's defaults so they are visible and pinned; the connection receive window replaces quinn's
// unbounded default (VarInt::MAX, verified in quinn-proto 0.11 config/transport.rs) with a bound
// on what one connection may buffer toward us.
const DATA_IDLE_TIMEOUT_SECS: u64 = 30;
const DATA_MAX_BIDI_STREAMS: u32 = 100;
const DATA_UNI_STREAMS: u32 = 0;
const DATA_RECEIVE_WINDOW_BYTES: u32 = 8 * 1024 * 1024;

// Per-connection ceiling on streams simultaneously awaiting their 1-byte type prefix. A well-behaved
// client sends the type byte immediately, so its streams hold a permit for microseconds and never
// approach this bound; a slowloris that opens streams and withholds the byte is capped to this many 5s
// holds per connection — further streams are reset cheaply (no task, no timer) instead of each pinning a
// task and its buffers for the full read timeout.
const MAX_CONCURRENT_PENDING_STREAM_READS: usize = 64;

pub struct QuicListener {
	stream_rx: mpsc::Receiver<(QuicStream, SocketAddr)>,
	raw_stream_rx: Option<mpsc::Receiver<(QuicStream, SocketAddr)>>,
	local_addr: SocketAddr,
}

impl QuicListener {
	pub fn bind(addr: SocketAddr, server_config: ServerConfig) -> Result<Self> {
		return Self::bind_with_token(addr, server_config, CancellationToken::new(), DEFAULT_CHANNEL_CAPACITY);
	}

	pub fn bind_with_token(
		addr: SocketAddr,
		server_config: ServerConfig,
		shutdown: CancellationToken,
		channel_capacity: usize,
	) -> Result<Self> {
		let endpoint: Endpoint =
			Endpoint::server(server_config, addr).map_err(|e| ReductionError::Transport(format!("QUIC bind: {e}")))?;

		let local_addr: SocketAddr = endpoint
			.local_addr()
			.map_err(|e| ReductionError::Transport(format!("QUIC local addr: {e}")))?;

		info!(%addr, "QUIC listener bound");

		let (stream_tx, stream_rx) = mpsc::channel(channel_capacity);
		let (raw_tx, raw_rx) = mpsc::channel(channel_capacity);
		tokio::spawn(accept_connections(endpoint, stream_tx, raw_tx, shutdown));

		return Ok(Self {
			stream_rx,
			raw_stream_rx: Some(raw_rx),
			local_addr,
		});
	}

	pub const fn take_raw_stream_receiver(&mut self) -> Option<mpsc::Receiver<(QuicStream, SocketAddr)>> {
		return self.raw_stream_rx.take();
	}

	pub const fn local_addr(&self) -> io::Result<SocketAddr> {
		return Ok(self.local_addr);
	}
}

// The tokio::select! accept loop inflates cognitive complexity via macro expansion; its accept and
// shutdown arms are a cohesive set that must share one select.
#[allow(clippy::cognitive_complexity)]
async fn accept_connections(
	endpoint: Endpoint,
	stream_tx: mpsc::Sender<(QuicStream, SocketAddr)>,
	raw_stream_tx: mpsc::Sender<(QuicStream, SocketAddr)>,
	shutdown: CancellationToken,
) {
	let pending_handshakes: Arc<Semaphore> = Arc::new(Semaphore::new(MAX_CONCURRENT_PENDING_HANDSHAKES));
	loop {
		tokio::select! {
			incoming = endpoint.accept() => {
				let Some(incoming) = incoming else {
					break;
				};
				let remote_addr: SocketAddr = incoming.remote_address();

				// Bound concurrent handshakes before spawning. At the cap, ignore() sends nothing
				// back, so a handshake-stall flood is shed cheaply and cannot amplify.
				let handshake_permit: OwnedSemaphorePermit = match Arc::clone(&pending_handshakes).try_acquire_owned() {
					Ok(permit) => permit,
					Err(_) => {
						warn!(%remote_addr, "pending QUIC handshakes at cap; ignoring connection");
						incoming.ignore();
						continue;
					}
				};

				let tx: mpsc::Sender<(QuicStream, SocketAddr)> = stream_tx.clone();
				let raw_tx: mpsc::Sender<(QuicStream, SocketAddr)> = raw_stream_tx.clone();

				tokio::spawn(async move {
					handle_connection(incoming, remote_addr, tx, raw_tx, handshake_permit).await;
				});
			}
			_ = shutdown.cancelled() => {
				info!("shutdown signal received, closing QUIC endpoint");
				endpoint.close(0u32.into(), b"shutdown");
				break;
			}
		}
	}
	debug!("QUIC endpoint closed, connection acceptor stopping");
}

async fn handle_connection(
	incoming: Incoming,
	remote_addr: SocketAddr,
	stream_tx: mpsc::Sender<(QuicStream, SocketAddr)>,
	raw_stream_tx: mpsc::Sender<(QuicStream, SocketAddr)>,
	handshake_permit: OwnedSemaphorePermit,
) {
	let Some((connection, peer_identity)) = establish_connection(incoming, remote_addr, handshake_permit).await else {
		return;
	};

	// Bound streams concurrently awaiting their type byte, per connection, so a slowloris that opens
	// streams and never sends the prefix can't pin an unbounded pile of tasks for the read timeout.
	let pending_reads: Arc<Semaphore> = Arc::new(Semaphore::new(MAX_CONCURRENT_PENDING_STREAM_READS));

	loop {
		match connection.accept_bi().await {
			Ok((send, recv)) => {
				// Reserve a pending-read slot before spawning. At the cap, drop this stream now (send/recv
				// fall out of scope, resetting it) rather than holding a task for the full read timeout.
				let permit: OwnedSemaphorePermit = match Arc::clone(&pending_reads).try_acquire_owned() {
					Ok(permit) => permit,
					Err(_) => {
						debug!(%remote_addr, "pending stream-type reads at cap; resetting excess stream");
						continue;
					}
				};

				let tx: mpsc::Sender<(QuicStream, SocketAddr)> = stream_tx.clone();
				let raw_tx: mpsc::Sender<(QuicStream, SocketAddr)> = raw_stream_tx.clone();
				let addr: SocketAddr = remote_addr;
				let identity: Option<PeerIdentity> = peer_identity;

				tokio::spawn(handle_bi_stream(send, recv, addr, identity, tx, raw_tx, permit));
			}
			Err(quinn::ConnectionError::ApplicationClosed(_)) => {
				debug!(%remote_addr, "QUIC connection closed by peer");
				return;
			}
			Err(e) => {
				debug!(error = %e, %remote_addr, "QUIC connection ended");
				return;
			}
		}
	}
}

// Await the QUIC handshake under a timeout and extract the per-connection mTLS identity. None means the
// handshake failed or timed out (already logged). A returned connection with identity None means the leaf
// CN was unparseable — the handler rejects such requests rather than forwarding anonymously.
// cognitive_complexity here is the two result-matching arms plus their log macros, not branching logic.
#[allow(clippy::cognitive_complexity)]
async fn establish_connection(
	incoming: Incoming,
	remote_addr: SocketAddr,
	handshake_permit: OwnedSemaphorePermit,
) -> Option<(quinn::Connection, Option<PeerIdentity>)> {
	let connection: quinn::Connection =
		match tokio::time::timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), incoming).await {
			Ok(Ok(conn)) => conn,
			Ok(Err(e)) => {
				error!(error = %e, %remote_addr, "QUIC connection handshake failed");
				return None;
			}
			Err(_) => {
				warn!(%remote_addr, timeout_secs = HANDSHAKE_TIMEOUT_SECS, "QUIC handshake timed out");
				return None;
			}
		};
	// The handshake budget guards only pre-connection work; an established connection is governed by the
	// transport idle timeout and per-connection stream caps instead.
	drop(handshake_permit);

	debug!(%remote_addr, "QUIC connection established");

	// Extract the mTLS identity once per connection; every stream inherits it.
	let peer_identity: Option<PeerIdentity> = match PeerIdentity::from_quic_connection(&connection) {
		Ok(id) => Some(id),
		Err(e) => {
			warn!(error = %e, %remote_addr, "failed to extract peer identity from QUIC connection");
			None
		}
	};

	return Some((connection, peer_identity));
}

// One accepted bidirectional stream: read its 1-byte type prefix under a timeout, then route the stream
// to the HTTP or raw channel by that byte (an unknown byte drops it). Split out of handle_connection's
// accept loop so the read/route matches stay isolated. Holds `permit` only until routing completes or
// the read times out, freeing the pending-read slot for the next stream on this connection.
// cognitive_complexity here is the timeout/type-byte match arms plus their log macros, not branching.
#[allow(clippy::cognitive_complexity)]
async fn handle_bi_stream(
	send: SendStream,
	mut recv: RecvStream,
	addr: SocketAddr,
	identity: Option<PeerIdentity>,
	stream_tx: mpsc::Sender<(QuicStream, SocketAddr)>,
	raw_stream_tx: mpsc::Sender<(QuicStream, SocketAddr)>,
	permit: OwnedSemaphorePermit,
) {
	// Held for the whole type-byte read; released the moment routing completes or the read times out.
	let _permit: OwnedSemaphorePermit = permit;
	let mut type_buf: [u8; 1] = [0u8; 1];
	match tokio::time::timeout(
		Duration::from_secs(STREAM_TYPE_READ_TIMEOUT_SECS),
		tokio::io::AsyncReadExt::read_exact(&mut recv, &mut type_buf),
	)
	.await
	{
		Ok(Ok(_)) => {}
		Ok(Err(e)) => {
			debug!(error = %e, %addr, "failed to read stream type byte");
			return;
		}
		Err(_) => {
			debug!(%addr, "stream type byte read timed out");
			return;
		}
	}

	let stream: QuicStream = QuicStream::new(send, recv).with_peer_identity(identity);
	match type_buf[0] {
		STREAM_TYPE_HTTP => {
			let _ = stream_tx.send((stream, addr)).await;
		}
		STREAM_TYPE_RAW => {
			let _ = raw_stream_tx.send((stream, addr)).await;
		}
		unknown => {
			debug!(%addr, unknown, "unknown stream type byte, dropping stream");
		}
	}
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, QuicListener>> for super::ConnectAddr {
	fn connect_info(target: axum::serve::IncomingStream<'_, QuicListener>) -> Self {
		return Self(*target.remote_addr(), target.io().peer_identity());
	}
}

impl axum::serve::Listener for QuicListener {
	type Io = QuicStream;
	type Addr = SocketAddr;

	async fn accept(&mut self) -> (Self::Io, Self::Addr) {
		match self.stream_rx.recv().await {
			Some(stream) => return stream,
			None => {
				error!("QUIC acceptor task stopped, waiting for graceful shutdown");
				return std::future::pending::<(Self::Io, Self::Addr)>().await;
			}
		}
	}

	fn local_addr(&self) -> io::Result<Self::Addr> {
		return Ok(self.local_addr);
	}
}

pub fn build_quic_server_config(rustls_config: Arc<rustls::ServerConfig>) -> Result<ServerConfig> {
	let quic_crypto: QuicServerConfig = QuicServerConfig::try_from(rustls_config)
		.map_err(|e| ReductionError::Config(format!("QUIC crypto config: {e}")))?;

	let idle: IdleTimeout = IdleTimeout::try_from(Duration::from_secs(DATA_IDLE_TIMEOUT_SECS))
		.map_err(|_| ReductionError::Config(format!("QUIC idle timeout out of range: {DATA_IDLE_TIMEOUT_SECS}s")))?;
	let mut transport: TransportConfig = TransportConfig::default();
	transport.max_idle_timeout(Some(idle));
	transport.max_concurrent_bidi_streams(VarInt::from_u32(DATA_MAX_BIDI_STREAMS));
	transport.max_concurrent_uni_streams(VarInt::from_u32(DATA_UNI_STREAMS));
	transport.receive_window(VarInt::from_u32(DATA_RECEIVE_WINDOW_BYTES));

	let mut quic_config: ServerConfig = ServerConfig::with_crypto(Arc::new(quic_crypto));
	quic_config.transport_config(Arc::new(transport));
	return Ok(quic_config);
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_support::{generate_ca, generate_localhost_cert, write_pem};
	use crate::tls::certs::build_server_config;

	fn make_server_rustls_config() -> Arc<rustls::ServerConfig> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let leaf = generate_localhost_cert(&ca);

		let ca_file = write_pem(&ca.cert.pem());
		let cert_file = write_pem(&leaf.cert.pem());
		let key_file = write_pem(&leaf.signing_key.serialize_pem());

		let (config, _resolver) = build_server_config(cert_file.path(), key_file.path(), ca_file.path()).unwrap();
		return Arc::new(config);
	}

	#[test]
	fn test_build_quic_server_config_valid() {
		let rustls_config = make_server_rustls_config();
		let result = build_quic_server_config(rustls_config);
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_quic_listener_bind_and_local_addr() {
		let rustls_config = make_server_rustls_config();
		let quic_config = build_quic_server_config(rustls_config).unwrap();
		let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
		let listener = QuicListener::bind(addr, quic_config).unwrap();
		let local = listener.local_addr().unwrap();
		assert_eq!(local.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
		assert_ne!(local.port(), 0);
	}

	#[tokio::test]
	async fn test_quic_listener_local_addr_via_listener_trait() {
		let rustls_config = make_server_rustls_config();
		let quic_config = build_quic_server_config(rustls_config).unwrap();
		let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
		let listener = QuicListener::bind(addr, quic_config).unwrap();
		let local: SocketAddr = axum::serve::Listener::local_addr(&listener).unwrap();
		assert_eq!(local.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
	}

	#[test]
	fn test_connect_addr_from_quic_stream() {
		let addr = super::super::ConnectAddr("10.0.0.1:5000".parse().unwrap(), None);
		assert_eq!(*addr, "10.0.0.1:5000".parse::<SocketAddr>().unwrap());
	}

	// The pending-read gate: acquisition succeeds up to the cap, is refused beyond it (the branch that
	// resets an excess stream instead of pinning a task), and recovers the moment a permit is released.
	#[test]
	fn test_pending_read_cap_admits_to_limit_then_refuses() {
		let sem: Arc<Semaphore> = Arc::new(Semaphore::new(MAX_CONCURRENT_PENDING_STREAM_READS));
		let mut permits: Vec<OwnedSemaphorePermit> = Vec::new();
		for _ in 0..MAX_CONCURRENT_PENDING_STREAM_READS {
			permits.push(
				Arc::clone(&sem)
					.try_acquire_owned()
					.expect("acquisition under the cap must succeed"),
			);
		}
		// At the cap the next pending read is refused — excess streams are reset, not queued.
		assert!(
			Arc::clone(&sem).try_acquire_owned().is_err(),
			"beyond the cap a pending-read slot must be refused",
		);
		// Releasing one (a completed type-byte read) frees a slot again.
		permits.pop();
		assert!(
			Arc::clone(&sem).try_acquire_owned().is_ok(),
			"a freed slot must admit the next pending read",
		);
	}

	// ── End-to-end QUIC tests (real mTLS handshake + real streams) ──

	use std::net::IpAddr;

	use quinn::crypto::rustls::QuicClientConfig;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::time::timeout;

	use crate::tls::certs::build_client_config;

	const E2E_TIMEOUT: Duration = Duration::from_secs(10);

	fn generate_client_cert(ca: &rcgen::CertifiedKey<rcgen::KeyPair>, cn: &str) -> rcgen::CertifiedKey<rcgen::KeyPair> {
		let key = rcgen::KeyPair::generate().unwrap();
		let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
		params
			.distinguished_name
			.push(rcgen::DnType::CommonName, rcgen::DnValue::Utf8String(cn.to_string()));
		let issuer = rcgen::Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key).unwrap();
		let cert = params.signed_by(&key, &issuer).unwrap();
		return rcgen::CertifiedKey { cert, signing_key: key };
	}

	// Bind a real QuicListener and return it alongside a connected mTLS client (cert CN `client_cn`),
	// its endpoint (kept alive by the caller), and the listener's shutdown token.
	async fn e2e_setup(client_cn: &str) -> (QuicListener, quinn::Connection, Endpoint, CancellationToken) {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let server_leaf = generate_localhost_cert(&ca); // CN + SAN "localhost"
		let client_leaf = generate_client_cert(&ca, client_cn);

		let ca_file = write_pem(&ca.cert.pem());
		let server_cert_file = write_pem(&server_leaf.cert.pem());
		let server_key_file = write_pem(&server_leaf.signing_key.serialize_pem());
		let client_cert_file = write_pem(&client_leaf.cert.pem());
		let client_key_file = write_pem(&client_leaf.signing_key.serialize_pem());

		let (server_rustls, _r1) =
			build_server_config(server_cert_file.path(), server_key_file.path(), ca_file.path()).unwrap();
		let quic_config = build_quic_server_config(Arc::new(server_rustls)).unwrap();
		let token = CancellationToken::new();
		let listener = QuicListener::bind_with_token(
			"127.0.0.1:0".parse().unwrap(),
			quic_config,
			token.clone(),
			DEFAULT_CHANNEL_CAPACITY,
		)
		.unwrap();
		let addr = listener.local_addr().unwrap();

		let (client_rustls, _r2, _v2) =
			build_client_config(client_cert_file.path(), client_key_file.path(), ca_file.path()).unwrap();
		let quic_client_crypto = QuicClientConfig::try_from(Arc::new(client_rustls)).unwrap();
		let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
		client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_crypto)));
		let connection = client_endpoint.connect(addr, "localhost").unwrap().await.unwrap();

		return (listener, connection, client_endpoint, token);
	}

	#[tokio::test]
	async fn test_http_stream_round_trip_and_identity() {
		let (mut listener, connection, _client_ep, _token) = e2e_setup("device-42").await;

		// Client opens an HTTP-typed stream and sends a request payload.
		let (mut send, mut recv) = connection.open_bi().await.unwrap();
		send.write_all(&[STREAM_TYPE_HTTP]).await.unwrap();
		send.write_all(b"hello").await.unwrap();
		send.flush().await.unwrap();

		// Listener surfaces the stream with the peer's identity attached.
		let (mut stream, addr) = timeout(E2E_TIMEOUT, axum::serve::Listener::accept(&mut listener))
			.await
			.unwrap();
		assert_eq!(addr.ip(), IpAddr::from([127, 0, 0, 1]));
		let identity = stream.peer_identity().expect("identity attached");
		assert_eq!(identity.common_name.as_str(), "device-42");

		// poll_read: read the request payload off the stream.
		let mut buf = [0u8; 5];
		stream.read_exact(&mut buf).await.unwrap();
		assert_eq!(&buf, b"hello");

		// poll_write + poll_flush: write a response the client reads back.
		stream.write_all(b"world").await.unwrap();
		stream.flush().await.unwrap();
		let mut rbuf = [0u8; 5];
		recv.read_exact(&mut rbuf).await.unwrap();
		assert_eq!(&rbuf, b"world");

		// poll_shutdown + finish: both terminate the send side cleanly.
		stream.shutdown().await.unwrap();
		stream.finish();
	}

	#[tokio::test]
	async fn test_many_sequential_streams_release_permits() {
		// Regression for the pending-read semaphore: each routed HTTP stream must release its permit, so
		// more streams than the cap can be served over one connection. If a permit leaked, the (cap+1)th
		// stream would never be surfaced and the accept below would time out.
		let (mut listener, connection, _client_ep, _token) = e2e_setup("device-1").await;
		let total: usize = MAX_CONCURRENT_PENDING_STREAM_READS + 16;
		for i in 0..total {
			let (mut send, _recv) = connection.open_bi().await.unwrap();
			send.write_all(&[STREAM_TYPE_HTTP]).await.unwrap();
			send.write_all(b"hi").await.unwrap();
			send.flush().await.unwrap();

			let (mut stream, _addr) = match timeout(E2E_TIMEOUT, axum::serve::Listener::accept(&mut listener)).await {
				Ok(pair) => pair,
				Err(_) => panic!("stream {i} was not surfaced — a leaked permit likely wedged the connection"),
			};
			let mut buf = [0u8; 2];
			stream.read_exact(&mut buf).await.unwrap();
			assert_eq!(&buf, b"hi");
		}
	}

	#[tokio::test]
	async fn test_raw_stream_routed_to_raw_receiver() {
		let (mut listener, connection, _client_ep, _token) = e2e_setup("device-1").await;
		let mut raw_rx = listener.take_raw_stream_receiver().expect("raw receiver present");

		let (mut send, _recv) = connection.open_bi().await.unwrap();
		send.write_all(&[STREAM_TYPE_RAW]).await.unwrap();
		send.write_all(b"raw").await.unwrap();
		send.flush().await.unwrap();

		let (mut stream, _addr) = timeout(E2E_TIMEOUT, raw_rx.recv()).await.unwrap().expect("raw stream");
		let mut buf = [0u8; 3];
		stream.read_exact(&mut buf).await.unwrap();
		assert_eq!(&buf, b"raw");
	}

	#[tokio::test]
	async fn test_unknown_stream_type_is_dropped() {
		let (mut listener, connection, _client_ep, _token) = e2e_setup("device-1").await;

		let (mut send, _recv) = connection.open_bi().await.unwrap();
		send.write_all(&[0xFF]).await.unwrap();
		send.flush().await.unwrap();

		// An unknown type byte routes to neither channel; accept must not yield anything.
		let res = timeout(Duration::from_millis(500), axum::serve::Listener::accept(&mut listener)).await;
		assert!(res.is_err(), "unknown stream type should be dropped, not surfaced");
	}

	#[tokio::test]
	async fn test_shutdown_stops_acceptor() {
		let rustls_config = make_server_rustls_config();
		let quic_config = build_quic_server_config(rustls_config).unwrap();
		let token = CancellationToken::new();
		let mut listener = QuicListener::bind_with_token(
			"127.0.0.1:0".parse().unwrap(),
			quic_config,
			token.clone(),
			DEFAULT_CHANNEL_CAPACITY,
		)
		.unwrap();

		// Cancelling closes the endpoint; the acceptor exits and drops the stream sender, so accept()
		// enters its "acceptor stopped" branch and pends (never yields).
		token.cancel();
		let res = timeout(Duration::from_millis(500), axum::serve::Listener::accept(&mut listener)).await;
		assert!(res.is_err(), "accept should pend once the acceptor has shut down");
	}

	#[tokio::test]
	async fn test_untrusted_client_cert_handshake_fails() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		// Server trusts CA-A; client presents a cert from CA-B → server rejects it at handshake.
		let server_ca = generate_ca();
		let other_ca = generate_ca();
		let server_leaf = generate_localhost_cert(&server_ca);
		let bad_client_leaf = generate_client_cert(&other_ca, "impostor");

		let server_ca_file = write_pem(&server_ca.cert.pem());
		let server_cert_file = write_pem(&server_leaf.cert.pem());
		let server_key_file = write_pem(&server_leaf.signing_key.serialize_pem());
		let bad_client_cert_file = write_pem(&bad_client_leaf.cert.pem());
		let bad_client_key_file = write_pem(&bad_client_leaf.signing_key.serialize_pem());

		let (server_rustls, _r1) =
			build_server_config(server_cert_file.path(), server_key_file.path(), server_ca_file.path()).unwrap();
		let quic_config = build_quic_server_config(Arc::new(server_rustls)).unwrap();
		let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap(), quic_config).unwrap();
		let addr = listener.local_addr().unwrap();

		// Client trusts the server's CA (validates the server) but its own cert is from CA-B.
		let (client_rustls, _r2, _v2) = build_client_config(
			bad_client_cert_file.path(),
			bad_client_key_file.path(),
			server_ca_file.path(),
		)
		.unwrap();
		let quic_client_crypto = QuicClientConfig::try_from(Arc::new(client_rustls)).unwrap();
		let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
		client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_crypto)));

		// Under TLS 1.3/QUIC the client may finish before the server validates its cert, so connect()
		// can return Ok; the server's rejection then surfaces as the connection being closed.
		match client_endpoint.connect(addr, "localhost").unwrap().await {
			Err(_) => {}
			Ok(conn) => {
				let closed = timeout(E2E_TIMEOUT, conn.closed()).await;
				assert!(
					closed.is_ok(),
					"untrusted client connection should be closed by the server"
				);
			}
		}
	}
}
