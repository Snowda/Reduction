use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use dashmap::mapref::one::{Ref as MapRef, RefMut as MapRefMut};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use parking_lot::{Mutex, MutexGuard};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{Connecting, Connection, Endpoint};
use tokio::time::timeout;
use tracing::debug;

use super::{ConnPool, HttpSender, QUIC_BIND_ADDR};
use crate::config::BackendConfig;
use crate::error::{ReductionError, Result};
use crate::transport::quic::{self, QuicStream};

impl ConnPool {
	fn take_quic(&self, addr: &SocketAddr, host: &str) -> Option<Connection> {
		let entry: MapRef<'_, SocketAddr, Mutex<HashMap<String, VecDeque<Connection>>>> = self.quic_idle.get(addr)?;
		// Blocking lock (parking_lot, sync): the map is only ever held for a push/pop, so
		// contention resolves in nanoseconds — far cheaper than the fresh QUIC+TLS handshake a
		// try_lock miss would force. No guard is held across an await.
		let mut hosts: MutexGuard<'_, HashMap<String, VecDeque<Connection>>> = entry.lock();
		let queue: &mut VecDeque<Connection> = hosts.get_mut(host)?;
		while let Some(conn) = queue.pop_front() {
			if conn.close_reason().is_none() {
				return Some(conn);
			}
		}
		return None;
	}

	fn put_quic(&self, addr: SocketAddr, host: &str, conn: Connection) {
		if conn.close_reason().is_some() {
			return;
		}
		let entry: MapRefMut<'_, SocketAddr, Mutex<HashMap<String, VecDeque<Connection>>>> =
			self.quic_idle.entry(addr).or_insert_with(|| Mutex::new(HashMap::new()));
		// Blocking lock so a returning connection is pooled rather than dropped on contention.
		let mut hosts: MutexGuard<'_, HashMap<String, VecDeque<Connection>>> = entry.lock();
		let queue: &mut VecDeque<Connection> = hosts.entry(host.to_owned()).or_default();
		if queue.len() < usize::try_from(self.max_idle_quic_per_host).unwrap_or(usize::MAX) {
			queue.push_back(conn);
		}
	}

	pub async fn acquire_quic(
		&self,
		backend: &BackendConfig,
		client_tls_config: &Arc<rustls::ClientConfig>,
		connect_timeout: Duration,
		handshake_timeout: Duration,
	) -> Result<HttpSender> {
		let conn: Connection = if let Some(conn) = self.take_quic(&backend.address, &backend.host) {
			debug!(backend = %backend.id, "reusing pooled QUIC connection");
			conn
		} else {
			self.connect_quic(backend, client_tls_config, connect_timeout).await?
		};

		let (mut send, recv) = timeout(handshake_timeout, conn.open_bi())
			.await
			.map_err(|_| ReductionError::Forward("QUIC stream open: timed out".to_owned()))?
			.map_err(|e| ReductionError::Forward(format!("QUIC stream open: {e}")))?;

		tokio::io::AsyncWriteExt::write_all(&mut send, &[quic::STREAM_TYPE_HTTP])
			.await
			.map_err(|e| ReductionError::Forward(format!("write stream type: {e}")))?;

		// Return the connection to the pool immediately — QUIC multiplexes streams
		self.put_quic(backend.address, &backend.host, conn);

		let stream: QuicStream = QuicStream::new(send, recv);
		let io: TokioIo<QuicStream> = TokioIo::new(stream);

		let (sender, conn_driver): (http1::SendRequest<Body>, _) = timeout(handshake_timeout, http1::handshake(io))
			.await
			.map_err(|_| ReductionError::Forward("http handshake: timed out".to_owned()))?
			.map_err(|e| ReductionError::Forward(format!("http handshake: {e}")))?;

		tokio::spawn(async move {
			if let Err(e) = conn_driver.await {
				debug!(error = %e, "QUIC stream HTTP driver ended");
			}
		});

		return Ok(HttpSender::H1(sender));
	}

	async fn get_or_init_quic_endpoint(&self, client_tls_config: &Arc<rustls::ClientConfig>) -> Result<&Endpoint> {
		return self
			.quic_endpoint
			.get_or_try_init(|| async {
				let quic_crypto: QuicClientConfig = QuicClientConfig::try_from(client_tls_config.clone())
					.map_err(|e| ReductionError::Forward(format!("QUIC client crypto: {e}")))?;

				let mut client_config: quinn::ClientConfig = quinn::ClientConfig::new(Arc::new(quic_crypto));
				client_config.transport_config(Arc::new(quinn::TransportConfig::default()));

				let mut endpoint: Endpoint = Endpoint::client(QUIC_BIND_ADDR)
					.map_err(|e| ReductionError::Forward(format!("QUIC endpoint: {e}")))?;
				endpoint.set_default_client_config(client_config);

				debug!("shared QUIC client endpoint initialized");
				return Ok(endpoint);
			})
			.await;
	}

	async fn connect_quic(
		&self,
		backend: &BackendConfig,
		client_tls_config: &Arc<rustls::ClientConfig>,
		connect_timeout: Duration,
	) -> Result<Connection> {
		let endpoint: &Endpoint = self.get_or_init_quic_endpoint(client_tls_config).await?;

		let connecting: Connecting = endpoint
			.connect(backend.address, &backend.host)
			.map_err(|e| ReductionError::Forward(format!("QUIC connect: {e}")))?;

		let connection: Connection = timeout(connect_timeout, connecting)
			.await
			.map_err(|_| ReductionError::Forward("QUIC handshake: timed out".to_owned()))?
			.map_err(|e| ReductionError::Forward(format!("QUIC handshake: {e}")))?;

		debug!(backend = %backend.id, "QUIC connection established");
		return Ok(connection);
	}

	pub async fn acquire_raw_stream(
		&self,
		backend: &BackendConfig,
		client_tls_config: &Arc<rustls::ClientConfig>,
		connect_timeout: Duration,
	) -> Result<QuicStream> {
		if let Some(registry) = &self.tunnel_registry
			&& registry.is_tunnel_backend(&backend.id)
		{
			let stream: QuicStream = registry.acquire_stream(&backend.id).await?;
			return Ok(stream);
		}

		let conn: Connection = if let Some(conn) = self.take_quic(&backend.address, &backend.host) {
			conn
		} else {
			self.connect_quic(backend, client_tls_config, connect_timeout).await?
		};

		let (mut send, recv) = conn
			.open_bi()
			.await
			.map_err(|e| ReductionError::Forward(format!("raw stream open: {e}")))?;

		tokio::io::AsyncWriteExt::write_all(&mut send, &[quic::STREAM_TYPE_RAW])
			.await
			.map_err(|e| ReductionError::Forward(format!("write raw stream type: {e}")))?;

		self.put_quic(backend.address, &backend.host, conn);

		return Ok(QuicStream::new(send, recv));
	}
}

#[cfg(test)]
mod tests {
	use quinn::crypto::rustls::{QuicClientConfig as QuinnQuicClientConfig, QuicServerConfig};
	use quinn::{ClientConfig as QuinnClientConfig, ServerConfig as QuinnServerConfig};
	use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

	use super::super::testutil::NoVerify;
	use super::super::{H2_CONN_WINDOW, H2_STREAM_WINDOW};
	use super::*;

	// A connected QUIC server/client pair over loopback, for exercising the idle pool directly.
	async fn quic_conn_pair() -> (Connection, Connection, Endpoint, Endpoint) {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let key = rcgen::KeyPair::generate().unwrap();
		let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
		params.subject_alt_names = vec![rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]))];
		let cert = params.self_signed(&key).unwrap();
		let cert_der: CertificateDer<'static> = cert.der().clone();
		let key_der: PrivatePkcs8KeyDer<'static> = PrivatePkcs8KeyDer::from(key.serialize_der());
		let server_tls = rustls::ServerConfig::builder()
			.with_no_client_auth()
			.with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
			.unwrap();

		let quic_crypto = QuicServerConfig::try_from(Arc::new(server_tls)).unwrap();
		let server_ep = Endpoint::server(
			QuinnServerConfig::with_crypto(Arc::new(quic_crypto)),
			"127.0.0.1:0".parse().unwrap(),
		)
		.unwrap();
		let addr: SocketAddr = server_ep.local_addr().unwrap();

		let accept_ep = server_ep.clone();
		let accept = tokio::spawn(async move { accept_ep.accept().await.unwrap().await.unwrap() });

		let client_tls = rustls::ClientConfig::builder()
			.dangerous()
			.with_custom_certificate_verifier(Arc::new(NoVerify))
			.with_no_client_auth();
		let client_crypto = QuinnQuicClientConfig::try_from(Arc::new(client_tls)).unwrap();
		let mut client_ep = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
		client_ep.set_default_client_config(QuinnClientConfig::new(Arc::new(client_crypto)));
		let client_conn = client_ep.connect(addr, "localhost").unwrap().await.unwrap();
		let server_conn = accept.await.unwrap();
		return (server_conn, client_conn, server_ep, client_ep);
	}

	#[test]
	fn test_take_quic_nonexistent_addr() {
		let pool = ConnPool::new();
		let addr: SocketAddr = "10.0.0.1:9090".parse().unwrap();
		assert!(pool.take_quic(&addr, "10.0.0.1").is_none());
	}

	#[test]
	fn test_pool_quic_idle_map_starts_empty() {
		let pool = ConnPool::new();
		assert!(pool.quic_idle.is_empty());
	}

	#[tokio::test]
	async fn test_put_and_take_quic_round_trips_live_connection() {
		let (server_conn, _client, _sep, _cep) = quic_conn_pair().await;
		let addr: SocketAddr = "203.0.113.7:443".parse().unwrap();
		let pool = ConnPool::new();

		pool.put_quic(addr, "localhost", server_conn);
		assert!(
			pool.take_quic(&addr, "localhost").is_some(),
			"a live pooled QUIC connection must be retrievable"
		);
		// Queue is now drained.
		assert!(pool.take_quic(&addr, "localhost").is_none());
	}

	#[tokio::test]
	async fn test_put_quic_drops_closed_connection() {
		let (server_conn, _client, _sep, _cep) = quic_conn_pair().await;
		let addr: SocketAddr = "203.0.113.8:443".parse().unwrap();
		server_conn.close(0u32.into(), b"bye");
		let pool = ConnPool::new();

		pool.put_quic(addr, "localhost", server_conn);
		// A closed connection is never stored, so nothing is there to take.
		assert!(
			pool.take_quic(&addr, "localhost").is_none(),
			"closed connections must not be pooled"
		);
	}

	#[tokio::test]
	async fn test_take_quic_skips_closed_and_returns_none() {
		let (server_conn, _client, _sep, _cep) = quic_conn_pair().await;
		let addr: SocketAddr = "203.0.113.9:443".parse().unwrap();
		let pool = ConnPool::new();

		// Pool a live connection, then close it out-of-band; take must skip it and report empty.
		pool.put_quic(addr, "localhost", server_conn.clone());
		server_conn.close(0u32.into(), b"bye");
		assert!(
			pool.take_quic(&addr, "localhost").is_none(),
			"take_quic must skip a closed pooled connection"
		);
	}

	#[tokio::test]
	async fn test_put_quic_respects_idle_cap() {
		let (c1, _cl1, _s1, _e1) = quic_conn_pair().await;
		let (c2, _cl2, _s2, _e2) = quic_conn_pair().await;
		let addr: SocketAddr = "203.0.113.10:443".parse().unwrap();
		let pool = ConnPool::new().with_pool_config(4, 1, H2_STREAM_WINDOW, H2_CONN_WINDOW); // cap idle QUIC at 1

		pool.put_quic(addr, "localhost", c1);
		pool.put_quic(addr, "localhost", c2); // beyond the cap → dropped
		assert!(pool.take_quic(&addr, "localhost").is_some());
		assert!(
			pool.take_quic(&addr, "localhost").is_none(),
			"idle cap of 1 must reject the second connection"
		);
	}

	#[tokio::test]
	async fn test_drain_closes_pooled_quic_connections() {
		let (server_conn, _client, _sep, _cep) = quic_conn_pair().await;
		let addr: SocketAddr = "203.0.113.11:443".parse().unwrap();
		let pool = ConnPool::new();
		pool.put_quic(addr, "localhost", server_conn);
		assert!(!pool.quic_idle.is_empty());

		pool.drain();
		assert!(pool.quic_idle.is_empty(), "drain must clear the QUIC idle pool");
	}

	// ── Hostname isolation: pool identity is (address, verified TLS server name), not address alone ──

	#[tokio::test]
	async fn test_quic_pool_isolates_by_host() {
		// A QUIC connection pooled under one TLS server name must not be handed to a request
		// targeting a different server name at the same socket address. On address-only keying this
		// take would succeed with the wrong connection.
		let (server_conn, _client, _sep, _cep) = quic_conn_pair().await;
		let addr: SocketAddr = "203.0.113.20:443".parse().unwrap();
		let pool = ConnPool::new();

		pool.put_quic(addr, "host-a.internal", server_conn);
		assert!(
			pool.take_quic(&addr, "host-b.internal").is_none(),
			"a connection verified for host-a must not be reused for host-b at the same address",
		);
		assert!(
			pool.take_quic(&addr, "host-a.internal").is_some(),
			"the matching host must still retrieve its pooled connection",
		);
	}
}
