use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use arrayvec::ArrayString;
use axum::body::Body;
use axum::http::{Request, Response};
use dashmap::DashMap;
use dashmap::mapref::one::RefMut as MapRefMut;
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use quinn::{Connection, Endpoint};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::{OnceCell, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::{debug, error, warn};

use crate::config::{BackendConfig, TransportKind};
use crate::error::{ReductionError, Result};
use crate::transport::quic::QuicStream;
use crate::tunnel::registry::TunnelRegistry;

// QUIC connection pooling and dialing (take/put/acquire_quic/acquire_raw_stream) lives in a submodule.
mod quic;
// Cleartext HTTP/1.1 dialing (acquire_tcp_plaintext) for plain-HTTP backends lives in a submodule.
mod plaintext;

const MAX_IDLE_PER_HOST: u32 = 16;
const READY_TIMEOUT: Duration = Duration::from_millis(50);
const H2_CONNS_PER_BACKEND: u32 = 4;
const H2_STREAM_WINDOW: u32 = 2 * 1024 * 1024;
const H2_CONN_WINDOW: u32 = 4 * 1024 * 1024;
const QUIC_BIND_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

pub enum HttpSender {
	H1(http1::SendRequest<Body>),
	H2(http2::SendRequest<Body>),
}

impl HttpSender {
	pub async fn send_request(&mut self, req: Request<Body>) -> std::result::Result<Response<Incoming>, hyper::Error> {
		return match self {
			Self::H1(s) => s.send_request(req).await,
			Self::H2(s) => s.send_request(req).await,
		};
	}
}

pub struct ConnPool {
	// Keyed by (address, host): connections are pooled per socket address AND per TLS server name.
	// A connection authenticated for one hostname must never be reused for a request targeting a
	// different hostname at the same address, so the verified SNI host is part of the pool identity.
	tcp_h2: DashMap<SocketAddr, HashMap<String, Vec<http2::SendRequest<Body>>>>,
	tcp_h2_rr: AtomicUsize,
	quic_idle: DashMap<SocketAddr, Mutex<HashMap<String, VecDeque<Connection>>>>,
	quic_endpoint: OnceCell<Endpoint>,
	conn_limits: DashMap<ArrayString<256>, Arc<Semaphore>>,
	h2_conns_per_backend: u32,
	max_idle_quic_per_host: u32,
	h2_stream_window: u32,
	h2_conn_window: u32,
	tunnel_registry: Option<Arc<TunnelRegistry>>,
}

impl Default for ConnPool {
	fn default() -> Self {
		return Self::new();
	}
}

impl ConnPool {
	#[must_use]
	pub fn new() -> Self {
		return Self {
			tcp_h2: DashMap::new(),
			tcp_h2_rr: AtomicUsize::new(0),
			quic_idle: DashMap::new(),
			quic_endpoint: OnceCell::new(),
			conn_limits: DashMap::new(),
			h2_conns_per_backend: H2_CONNS_PER_BACKEND,
			max_idle_quic_per_host: MAX_IDLE_PER_HOST,
			h2_stream_window: H2_STREAM_WINDOW,
			h2_conn_window: H2_CONN_WINDOW,
			tunnel_registry: None,
		};
	}

	pub fn with_tunnel_registry(mut self, registry: Arc<TunnelRegistry>) -> Self {
		self.tunnel_registry = Some(registry);
		return self;
	}

	// The tunnel registry, if this pool has one — used by the F1 park path to await a session.
	#[must_use]
	pub const fn tunnel_registry(&self) -> Option<&Arc<TunnelRegistry>> {
		return self.tunnel_registry.as_ref();
	}

	pub const fn with_pool_config(
		mut self,
		h2_conns: u32,
		max_idle_quic: u32,
		h2_stream_window: u32,
		h2_conn_window: u32,
	) -> Self {
		self.h2_conns_per_backend = h2_conns;
		self.max_idle_quic_per_host = max_idle_quic;
		self.h2_stream_window = h2_stream_window;
		self.h2_conn_window = h2_conn_window;
		return self;
	}

	pub fn try_acquire_conn_permit(
		&self,
		backend: &BackendConfig,
	) -> std::result::Result<OwnedSemaphorePermit, ReductionError> {
		let sem: Arc<Semaphore> = self
			.conn_limits
			.entry(backend.id)
			.or_insert_with(|| {
				Arc::new(Semaphore::new(
					usize::try_from(backend.max_connections).unwrap_or(usize::MAX),
				))
			})
			.clone();
		return sem.try_acquire_owned().map_err(|_| ReductionError::BackendUnavailable);
	}

	pub fn connection_pressure(&self, backend_id: &str, max_connections: u32) -> f64 {
		let max: usize = usize::try_from(max_connections).unwrap_or(usize::MAX);
		if max == 0 {
			return 1.0;
		}
		let available: usize = self
			.conn_limits
			.get(backend_id)
			.map(|sem| sem.available_permits())
			.unwrap_or(max);
		let in_use: usize = max.saturating_sub(available);
		// Both operands are bounded by max_connections (u32), so exactly representable in f64.
		#[allow(clippy::as_conversions)]
		return in_use as f64 / max as f64;
	}

	// Observability accessor for the pooled H2 sender count (integration tests assert it stays capped and
	// sheds dead conns). Reports the stored count as-is; closed senders are pruned lazily on next acquire.
	#[must_use]
	pub fn pooled_h2_conns(&self, addr: &SocketAddr) -> usize {
		return self
			.tcp_h2
			.get(addr)
			.map(|entry| entry.value().values().map(Vec::len).sum())
			.unwrap_or(0);
	}

	#[tracing::instrument(skip_all, fields(backend = %backend.id))]
	pub async fn acquire(
		&self,
		backend: &BackendConfig,
		tls_connector: &TlsConnector,
		client_tls_config: &Arc<rustls::ClientConfig>,
		connect_timeout: Duration,
		handshake_timeout: Duration,
	) -> Result<HttpSender> {
		if let Some(registry) = &self.tunnel_registry
			&& registry.is_tunnel_backend(&backend.id)
		{
			return self.acquire_tunnel(registry, backend, handshake_timeout).await;
		}
		return match backend.transport {
			// Cleartext HTTP/1.1 (scheme = http) skips TLS entirely; the default https path is TLS + H2.
			TransportKind::Tcp if backend.scheme.is_plaintext() => {
				self.acquire_tcp_plaintext(backend, connect_timeout, handshake_timeout)
					.await
			}
			TransportKind::Tcp => {
				self.acquire_tcp(backend, tls_connector, connect_timeout, handshake_timeout)
					.await
			}
			TransportKind::Quic => {
				self.acquire_quic(backend, client_tls_config, connect_timeout, handshake_timeout)
					.await
			}
		};
	}

	async fn acquire_tunnel(
		&self,
		registry: &Arc<TunnelRegistry>,
		backend: &BackendConfig,
		handshake_timeout: Duration,
	) -> Result<HttpSender> {
		let stream: QuicStream = registry.acquire_stream(&backend.id).await?;
		let io: TokioIo<QuicStream> = TokioIo::new(stream);

		let (sender, conn_driver): (http1::SendRequest<Body>, _) = timeout(handshake_timeout, http1::handshake(io))
			.await
			.map_err(|_| ReductionError::Forward("tunnel http handshake: timed out".to_owned()))?
			.map_err(|e| ReductionError::Forward(format!("tunnel http handshake: {e}")))?;

		tokio::spawn(async move {
			if let Err(e) = conn_driver.await {
				debug!(error = %e, "tunnel stream HTTP driver ended");
			}
		});

		return Ok(HttpSender::H1(sender));
	}

	async fn acquire_tcp(
		&self,
		backend: &BackendConfig,
		tls_connector: &TlsConnector,
		connect_timeout: Duration,
		handshake_timeout: Duration,
	) -> Result<HttpSender> {
		if let Some(sender) = self.reuse_pooled_h2(&backend.address, &backend.host).await {
			debug!(backend = %backend.id, "reusing pooled HTTP/2 connection");
			return Ok(HttpSender::H2(sender));
		}
		return self
			.connect_tcp_h2(backend, tls_connector, connect_timeout, handshake_timeout)
			.await;
	}

	// Return a live, ready pooled H2 sender for `addr`, evicting any whose connection has closed
	// (e.g. after a backend restart). Without eviction, dead senders accumulate in the pool Vec and
	// the round-robin keeps selecting them, each paying a full READY_TIMEOUT probe before a redial.
	async fn reuse_pooled_h2(&self, addr: &SocketAddr, host: &str) -> Option<http2::SendRequest<Body>> {
		// Under the shard lock: drop closed senders, then prefer one already reporting ready so the
		// hot path skips the probe. Clone the chosen handle (cheap) and release the lock before any
		// await — a DashMap guard must never be held across `.await`. Only senders whose connection
		// was TLS-verified for `host` are eligible; a different host at the same address is a miss.
		let (candidate, ready_hint): (http2::SendRequest<Body>, bool) = {
			let mut entry: MapRefMut<'_, SocketAddr, HashMap<String, Vec<http2::SendRequest<Body>>>> =
				self.tcp_h2.get_mut(addr)?;
			let senders: &mut Vec<http2::SendRequest<Body>> = entry.value_mut().get_mut(host)?;
			senders.retain(|s| !s.is_closed());
			let count: usize = senders.len();
			if count == 0 {
				return None;
			}
			let start: usize = self.tcp_h2_rr.fetch_add(1, Ordering::Relaxed);
			match (0..count)
				.map(|offset| (start + offset) % count)
				.find(|&i| senders[i].is_ready())
			{
				Some(i) => (senders[i].clone(), true),
				None => (senders[start % count].clone(), false),
			}
		};

		if ready_hint {
			return Some(candidate);
		}

		// No pooled connection reported ready — probe the round-robin pick, bounded so one stuck
		// connection can't delay the redial. A genuinely dead one is pruned on the next acquire.
		let mut candidate: http2::SendRequest<Body> = candidate;
		return match timeout(READY_TIMEOUT, candidate.ready()).await {
			Ok(Ok(_)) => Some(candidate),
			_ => None,
		};
	}

	async fn connect_tcp_h2(
		&self,
		backend: &BackendConfig,
		tls_connector: &TlsConnector,
		connect_timeout: Duration,
		handshake_timeout: Duration,
	) -> Result<HttpSender> {
		let tcp_stream: TcpStream = timeout(connect_timeout, TcpStream::connect(backend.address))
			.await
			.map_err(|_| ReductionError::Forward("connect: timed out".to_owned()))?
			.map_err(|e| ReductionError::Forward(format!("connect {}: {e}", backend.address)))?;

		let server_name: ServerName<'static> = ServerName::try_from(backend.host.as_str())
			.map_err(|e| ReductionError::Forward(format!("invalid server name: {e}")))?
			.to_owned();

		let tls_stream: TlsStream<TcpStream> =
			timeout(handshake_timeout, tls_connector.connect(server_name, tcp_stream))
				.await
				.map_err(|_| ReductionError::Forward("tls handshake: timed out".to_owned()))?
				.map_err(|e| ReductionError::Forward(format!("tls handshake: {e}")))?;

		let io: TokioIo<TlsStream<TcpStream>> = TokioIo::new(tls_stream);

		let (sender, conn) = timeout(
			handshake_timeout,
			http2::Builder::new(TokioExecutor::new())
				.initial_stream_window_size(self.h2_stream_window)
				.initial_connection_window_size(self.h2_conn_window)
				.handshake(io),
		)
		.await
		.map_err(|_| ReductionError::Forward("http2 handshake: timed out".to_owned()))?
		.map_err(|e| ReductionError::Forward(format!("http2 handshake: {e}")))?;

		tokio::spawn(async move {
			if let Err(e) = conn.await {
				error!(error = %e, "HTTP/2 connection driver error");
			}
		});

		// Pool the new connection, but prune closed senders and cap the pooled count at
		// h2_conns_per_backend so redial churn or backend restarts can't grow the Vec without bound.
		// At cap the fresh connection is still returned for this request, just not pooled.
		{
			let mut entry: MapRefMut<'_, SocketAddr, HashMap<String, Vec<http2::SendRequest<Body>>>> =
				self.tcp_h2.entry(backend.address).or_default();
			let senders: &mut Vec<http2::SendRequest<Body>> =
				entry.value_mut().entry(backend.host.clone()).or_default();
			senders.retain(|s| !s.is_closed());
			if senders.len() < usize::try_from(self.h2_conns_per_backend).unwrap_or(usize::MAX) {
				senders.push(sender.clone());
			}
		}

		return Ok(HttpSender::H2(sender));
	}

	pub fn drain_backends(&self, addrs: &[SocketAddr]) {
		for addr in addrs {
			self.tcp_h2.remove(addr);
			if let Some((_, mutex)) = self.quic_idle.remove(addr) {
				for conn in mutex.lock().values_mut().flat_map(|q| q.drain(..)) {
					conn.close(0u32.into(), b"draining");
				}
			}
		}
	}

	pub fn drain(&self) {
		self.tcp_h2.clear();

		for entry in self.quic_idle.iter() {
			for conn in entry.value().lock().values_mut().flat_map(|q| q.drain(..)) {
				conn.close(0u32.into(), b"shutdown");
			}
		}
		self.quic_idle.clear();

		if let Some(endpoint) = self.quic_endpoint.get() {
			endpoint.close(0u32.into(), b"shutdown");
		}
	}

	pub async fn warm_up(
		&self,
		backends: &[BackendConfig],
		tls_connector: &TlsConnector,
		client_tls_config: &Arc<rustls::ClientConfig>,
		connect_timeout: Duration,
		handshake_timeout: Duration,
	) {
		for backend in backends {
			// Cleartext H1 backends are not pooled (a fresh connection is dialed per request), so there
			// is nothing to pre-warm — skip them rather than opening a connection we would immediately drop.
			if backend.transport == TransportKind::Tcp && backend.scheme.is_plaintext() {
				debug!(backend = %backend.id, "cleartext HTTP/1.1 backend is not pooled; skipping pre-warm");
				continue;
			}
			match backend.transport {
				TransportKind::Tcp => {
					self.warm_up_tcp(backend, tls_connector, connect_timeout, handshake_timeout)
						.await;
				}
				TransportKind::Quic => {
					self.warm_up_quic(
						backend,
						tls_connector,
						client_tls_config,
						connect_timeout,
						handshake_timeout,
					)
					.await;
				}
			}
		}
	}

	// Pre-open H2 connections up to the per-backend cap. A failed dial stops warming this backend — the
	// live path retries on demand — rather than hammering an unreachable host through the whole loop.
	async fn warm_up_tcp(
		&self,
		backend: &BackendConfig,
		tls_connector: &TlsConnector,
		connect_timeout: Duration,
		handshake_timeout: Duration,
	) {
		let existing: usize = self
			.tcp_h2
			.get(&backend.address)
			.and_then(|e| e.value().get(&backend.host).map(Vec::len))
			.unwrap_or(0);
		for i in existing..usize::try_from(self.h2_conns_per_backend).unwrap_or(usize::MAX) {
			match self
				.connect_tcp_h2(backend, tls_connector, connect_timeout, handshake_timeout)
				.await
			{
				Ok(_sender) => {
					debug!(backend = %backend.id, conn = i, "pre-warmed H2 connection");
				}
				Err(e) => {
					warn!(backend = %backend.id, conn = i, error = %e, "failed to pre-warm H2 connection");
					break;
				}
			}
		}
	}

	// Pre-open a single QUIC connection; a failure is logged and left for the live path to retry.
	async fn warm_up_quic(
		&self,
		backend: &BackendConfig,
		tls_connector: &TlsConnector,
		client_tls_config: &Arc<rustls::ClientConfig>,
		connect_timeout: Duration,
		handshake_timeout: Duration,
	) {
		match self
			.acquire(
				backend,
				tls_connector,
				client_tls_config,
				connect_timeout,
				handshake_timeout,
			)
			.await
		{
			Ok(_sender) => {
				debug!(backend = %backend.id, "pre-warmed QUIC connection");
			}
			Err(e) => {
				warn!(backend = %backend.id, error = %e, "failed to pre-warm QUIC connection");
			}
		}
	}
}

// Test fixtures shared between this module's tests and the `quic` submodule's tests.
#[cfg(test)]
mod testutil {
	use rustls::pki_types::ServerName;

	// A rustls verifier that accepts any server certificate — for loopback test backends only.
	#[derive(Debug)]
	pub struct NoVerify;

	impl rustls::client::danger::ServerCertVerifier for NoVerify {
		fn verify_server_cert(
			&self,
			_: &rustls::pki_types::CertificateDer<'_>,
			_: &[rustls::pki_types::CertificateDer<'_>],
			_: &ServerName<'_>,
			_: &[u8],
			_: rustls::pki_types::UnixTime,
		) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
			return Ok(rustls::client::danger::ServerCertVerified::assertion());
		}

		fn verify_tls12_signature(
			&self,
			_: &[u8],
			_: &rustls::pki_types::CertificateDer<'_>,
			_: &rustls::DigitallySignedStruct,
		) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
			return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
		}

		fn verify_tls13_signature(
			&self,
			_: &[u8],
			_: &rustls::pki_types::CertificateDer<'_>,
			_: &rustls::DigitallySignedStruct,
		) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
			return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
		}

		fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
			return vec![
				rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
				rustls::SignatureScheme::RSA_PSS_SHA256,
			];
		}
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;
	use std::convert::Infallible;
	use std::sync::atomic::AtomicUsize;

	use axum::http::StatusCode;
	use bytes::Bytes;
	use http_body_util::Full;
	use hyper::server::conn::http2 as server_http2;
	use hyper::service::service_fn;
	use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
	use tokio::net::TcpListener;
	use tokio_rustls::TlsAcceptor;

	use super::testutil::NoVerify;
	use super::*;
	use crate::acl::AccessControl;
	use crate::config::TimeoutConfig;
	use crate::proxy::handler::{ProxyState, ReloadableState, TestProxyStateParams};
	use crate::proxy::router::Router;
	use crate::tunnel::revocation::RevocationSet;

	fn make_test_state() -> Arc<ProxyState> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let client_config: Arc<rustls::ClientConfig> = Arc::new(
			rustls::ClientConfig::builder()
				.dangerous()
				.with_custom_certificate_verifier(Arc::new(NoVerify))
				.with_no_client_auth(),
		);
		let reloadable: ReloadableState = ReloadableState {
			router: Router::new(&[]),
			backend_pools: HashMap::new(),
			acl: AccessControl::new(vec![], vec![]),
		};
		return ProxyState::for_test(TestProxyStateParams::new(
			reloadable,
			RevocationSet::default(),
			client_config,
			TimeoutConfig::default(),
		));
	}

	#[tokio::test]
	async fn test_pool_acquire_no_idle_fails_without_backend() {
		let state = make_test_state();
		let backend: BackendConfig =
			BackendConfig::new("test", "127.0.0.1:1".parse().unwrap(), 1.0, TransportKind::Tcp).unwrap();
		let connect_timeout: Duration = Duration::from_secs(state.timeouts.connect_secs.get());
		let handshake_timeout: Duration = Duration::from_secs(state.timeouts.handshake_secs.get());
		let result: Result<HttpSender> = state
			.conn_pool
			.acquire(
				&backend,
				&state.tls_connector,
				&state.client_tls_config,
				connect_timeout,
				handshake_timeout,
			)
			.await;
		assert!(result.is_err());
	}

	#[test]
	fn test_pool_tcp_h2_map_starts_empty() {
		let pool = ConnPool::new();
		assert!(pool.tcp_h2.is_empty());
	}

	#[test]
	fn test_pool_default_constants() {
		let pool = ConnPool::new();
		assert_eq!(pool.h2_conns_per_backend, 4);
		assert_eq!(pool.max_idle_quic_per_host, 16);
	}

	#[test]
	fn test_pool_with_custom_config() {
		let pool = ConnPool::new().with_pool_config(8, 32, 1024 * 1024, 2 * 1024 * 1024);
		assert_eq!(pool.h2_conns_per_backend, 8);
		assert_eq!(pool.max_idle_quic_per_host, 32);
		assert_eq!(pool.h2_stream_window, 1024 * 1024);
		assert_eq!(pool.h2_conn_window, 2 * 1024 * 1024);
	}

	#[tokio::test]
	async fn test_pool_acquire_quic_no_idle_fails_without_backend() {
		let state = make_test_state();
		let backend = BackendConfig::new("test", "127.0.0.1:1".parse().unwrap(), 1.0, TransportKind::Quic).unwrap();
		let connect_timeout: Duration = Duration::from_secs(state.timeouts.connect_secs.get());
		let handshake_timeout: Duration = Duration::from_secs(state.timeouts.handshake_secs.get());
		let result: Result<HttpSender> = state
			.conn_pool
			.acquire(
				&backend,
				&state.tls_connector,
				&state.client_tls_config,
				connect_timeout,
				handshake_timeout,
			)
			.await;
		assert!(result.is_err());
	}

	#[test]
	fn test_drain_clears_tcp_pool() {
		let pool = ConnPool::new();
		pool.tcp_h2.insert("127.0.0.1:8080".parse().unwrap(), HashMap::new());
		assert!(!pool.tcp_h2.is_empty());
		pool.drain();
		assert!(pool.tcp_h2.is_empty());
		assert!(pool.quic_idle.is_empty());
	}

	#[test]
	fn test_drain_on_empty_pool() {
		let pool = ConnPool::new();
		pool.drain();
		assert!(pool.tcp_h2.is_empty());
		assert!(pool.quic_idle.is_empty());
	}

	#[test]
	fn test_drain_backends_removes_only_specified_addrs() {
		let pool = ConnPool::new();
		let addr_a: SocketAddr = "127.0.0.1:8080".parse().unwrap();
		let addr_b: SocketAddr = "127.0.0.1:9090".parse().unwrap();
		let addr_c: SocketAddr = "127.0.0.1:7070".parse().unwrap();
		pool.tcp_h2.insert(addr_a, HashMap::new());
		pool.tcp_h2.insert(addr_b, HashMap::new());
		pool.tcp_h2.insert(addr_c, HashMap::new());

		pool.drain_backends(&[addr_a, addr_c]);

		assert!(!pool.tcp_h2.contains_key(&addr_a));
		assert!(pool.tcp_h2.contains_key(&addr_b));
		assert!(!pool.tcp_h2.contains_key(&addr_c));
	}

	#[test]
	fn test_drain_backends_noop_for_unknown_addrs() {
		let pool = ConnPool::new();
		let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
		pool.tcp_h2.insert(addr, HashMap::new());

		let unknown: SocketAddr = "10.0.0.1:443".parse().unwrap();
		pool.drain_backends(&[unknown]);

		assert!(pool.tcp_h2.contains_key(&addr));
	}

	#[test]
	fn test_drain_backends_empty_slice_is_noop() {
		let pool = ConnPool::new();
		let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
		pool.tcp_h2.insert(addr, HashMap::new());

		pool.drain_backends(&[]);

		assert!(pool.tcp_h2.contains_key(&addr));
	}

	#[test]
	fn test_conn_permit_acquire_succeeds() {
		let pool = ConnPool::new();
		let backend = BackendConfig::new("test", "127.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp)
			.unwrap()
			.with_max_connections(2)
			.unwrap();

		let _p1 = pool.try_acquire_conn_permit(&backend).unwrap();
		let _p2 = pool.try_acquire_conn_permit(&backend).unwrap();
	}

	#[test]
	fn test_conn_permit_exhausted() {
		let pool = ConnPool::new();
		let backend = BackendConfig::new("test", "127.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp)
			.unwrap()
			.with_max_connections(1)
			.unwrap();

		let _p1 = pool.try_acquire_conn_permit(&backend).unwrap();
		let result = pool.try_acquire_conn_permit(&backend);
		assert!(result.is_err());
	}

	#[test]
	fn test_conn_permit_released_on_drop() {
		let pool = ConnPool::new();
		let backend = BackendConfig::new("test", "127.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp)
			.unwrap()
			.with_max_connections(1)
			.unwrap();

		{
			let _p1 = pool.try_acquire_conn_permit(&backend).unwrap();
		}
		let _p2 = pool.try_acquire_conn_permit(&backend).unwrap();
	}

	#[test]
	fn test_connection_pressure_zero_when_idle() {
		let pool = ConnPool::new();
		let pressure: f64 = pool.connection_pressure("test", 256);
		assert_eq!(pressure, 0.0);
	}

	#[test]
	fn test_connection_pressure_increases_with_permits() {
		let pool = ConnPool::new();
		let backend = BackendConfig::new("test", "127.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp)
			.unwrap()
			.with_max_connections(4)
			.unwrap();

		let _p1 = pool.try_acquire_conn_permit(&backend).unwrap();
		let pressure: f64 = pool.connection_pressure("test", 4);
		assert!((pressure - 0.25).abs() < f64::EPSILON);

		let _p2 = pool.try_acquire_conn_permit(&backend).unwrap();
		let pressure: f64 = pool.connection_pressure("test", 4);
		assert!((pressure - 0.5).abs() < f64::EPSILON);
	}

	#[test]
	fn test_connection_pressure_full() {
		let pool = ConnPool::new();
		let backend = BackendConfig::new("test", "127.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp)
			.unwrap()
			.with_max_connections(1)
			.unwrap();

		let _p1 = pool.try_acquire_conn_permit(&backend).unwrap();
		let pressure: f64 = pool.connection_pressure("test", 1);
		assert!((pressure - 1.0).abs() < f64::EPSILON);
	}

	#[test]
	fn test_independent_backend_permits() {
		let pool = ConnPool::new();
		let backend_a = BackendConfig::new("a", "127.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp)
			.unwrap()
			.with_max_connections(1)
			.unwrap();
		let backend_b = BackendConfig::new("b", "127.0.0.2:8080".parse().unwrap(), 1.0, TransportKind::Tcp)
			.unwrap()
			.with_max_connections(1)
			.unwrap();

		let _pa = pool.try_acquire_conn_permit(&backend_a).unwrap();
		let _pb = pool.try_acquire_conn_permit(&backend_b).unwrap();

		assert!(pool.try_acquire_conn_permit(&backend_a).is_err());
		assert!(pool.try_acquire_conn_permit(&backend_b).is_err());
	}

	#[test]
	fn test_connection_pressure_zero_max_is_full() {
		// A backend advertising zero capacity is treated as fully saturated, not a divide-by-zero.
		let pool = ConnPool::new();
		assert!((pool.connection_pressure("any", 0) - 1.0).abs() < f64::EPSILON);
	}

	// ── Real TLS h2 backend, mirroring the forward path connect_tcp_h2 dials ──

	fn backend_tls_config() -> Arc<rustls::ServerConfig> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let key = rcgen::KeyPair::generate().unwrap();
		let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
		let cert = params.self_signed(&key).unwrap();
		let cert_der: CertificateDer<'static> = cert.der().clone();
		let key_der: PrivatePkcs8KeyDer<'static> = PrivatePkcs8KeyDer::from(key.serialize_der());
		let config = rustls::ServerConfig::builder()
			.with_no_client_auth()
			.with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
			.unwrap();
		return Arc::new(config);
	}

	// Spawn an h2-over-TLS server that answers 200 with body "ok" and counts requests served.
	async fn spawn_h2_backend() -> (SocketAddr, Arc<AtomicUsize>) {
		let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr: SocketAddr = listener.local_addr().unwrap();
		let hits: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
		let acceptor: TlsAcceptor = TlsAcceptor::from(backend_tls_config());

		let hits_srv: Arc<AtomicUsize> = hits.clone();
		tokio::spawn(async move {
			loop {
				let (tcp, _) = match listener.accept().await {
					Ok(pair) => pair,
					Err(_) => return,
				};
				let acceptor: TlsAcceptor = acceptor.clone();
				let hits_conn: Arc<AtomicUsize> = hits_srv.clone();
				tokio::spawn(async move {
					let tls = match acceptor.accept(tcp).await {
						Ok(s) => s,
						Err(_) => return,
					};
					let service = service_fn(move |_req| {
						let hits_req: Arc<AtomicUsize> = hits_conn.clone();
						async move {
							hits_req.fetch_add(1, Ordering::SeqCst);
							let resp: Response<Full<Bytes>> = Response::builder()
								.status(StatusCode::OK)
								.body(Full::new(Bytes::from("ok")))
								.unwrap();
							return Ok::<_, Infallible>(resp);
						}
					});
					let _ = server_http2::Builder::new(TokioExecutor::new())
						.serve_connection(TokioIo::new(tls), service)
						.await;
				});
			}
		});
		return (addr, hits);
	}

	fn tcp_backend(addr: SocketAddr) -> BackendConfig {
		return BackendConfig::new("h2be", addr, 1.0, TransportKind::Tcp).unwrap();
	}

	#[tokio::test]
	async fn test_acquire_tcp_connects_pools_and_sends() {
		let (addr, hits) = spawn_h2_backend().await;
		let state = make_test_state();
		let backend = tcp_backend(addr);
		let ct: Duration = Duration::from_secs(5);

		// First acquire dials a fresh H2 connection and pools it.
		let mut sender = state
			.conn_pool
			.acquire(&backend, &state.tls_connector, &state.client_tls_config, ct, ct)
			.await
			.expect("acquire should connect to the live backend");
		assert!(
			matches!(sender, HttpSender::H2(_)),
			"TCP backend must yield an H2 sender"
		);
		assert_eq!(state.conn_pool.pooled_h2_conns(&addr), 1, "connection must be pooled");

		// The sender actually round-trips a request to the backend.
		let req: Request<Body> = Request::builder().uri("/").body(Body::empty()).unwrap();
		let resp = sender
			.send_request(req)
			.await
			.expect("request should reach the backend");
		assert_eq!(resp.status(), StatusCode::OK);
		assert_eq!(hits.load(Ordering::SeqCst), 1);
	}

	#[tokio::test]
	async fn test_acquire_tcp_reuses_pooled_connection() {
		let (addr, _hits) = spawn_h2_backend().await;
		let state = make_test_state();
		let backend = tcp_backend(addr);
		let ct: Duration = Duration::from_secs(5);

		let _first = state
			.conn_pool
			.acquire(&backend, &state.tls_connector, &state.client_tls_config, ct, ct)
			.await
			.unwrap();
		// Second acquire should reuse the pooled H2 connection rather than pooling a second one.
		let _second = state
			.conn_pool
			.acquire(&backend, &state.tls_connector, &state.client_tls_config, ct, ct)
			.await
			.unwrap();
		assert_eq!(
			state.conn_pool.pooled_h2_conns(&addr),
			1,
			"reuse must not pool a duplicate connection",
		);
	}

	#[tokio::test]
	async fn test_warm_up_prewarms_tcp_connections() {
		let (addr, _hits) = spawn_h2_backend().await;
		let state = make_test_state();
		let backend = tcp_backend(addr);
		let ct: Duration = Duration::from_secs(5);

		state
			.conn_pool
			.warm_up(
				std::slice::from_ref(&backend),
				&state.tls_connector,
				&state.client_tls_config,
				ct,
				ct,
			)
			.await;

		// warm_up dials up to h2_conns_per_backend connections ahead of the first request.
		let pooled: usize = state.conn_pool.pooled_h2_conns(&addr);
		assert_eq!(
			pooled,
			usize::try_from(state.conn_pool.h2_conns_per_backend).unwrap(),
			"warm_up should fill the pool"
		);
	}

	#[tokio::test]
	async fn test_acquire_tcp_isolates_pool_by_host() {
		// Two backends share a socket address but present different TLS server names. Each must get
		// its own pooled connection; the second must not ride the first's TLS session. On the old
		// address-only key the second acquire would reuse the first and this count would be 1.
		let (addr, _hits) = spawn_h2_backend().await;
		let state = make_test_state();
		let ct: Duration = Duration::from_secs(5);
		let backend_a: BackendConfig = tcp_backend(addr).with_host("alpha.test".to_owned());
		let backend_b: BackendConfig = tcp_backend(addr).with_host("beta.test".to_owned());

		let _a = state
			.conn_pool
			.acquire(&backend_a, &state.tls_connector, &state.client_tls_config, ct, ct)
			.await
			.expect("host alpha should connect");
		let _b = state
			.conn_pool
			.acquire(&backend_b, &state.tls_connector, &state.client_tls_config, ct, ct)
			.await
			.expect("host beta should connect");

		assert_eq!(
			state.conn_pool.pooled_h2_conns(&addr),
			2,
			"each hostname must own a separate pooled connection, not share one across hostnames",
		);
	}
}
