use super::{
	ArrayString, ArrayVec, Arc, CONTROL_WRITE_TIMEOUT, CancellationToken, ControlLoopContext, Duration, Instant, KeyValue,
	OwnedSemaphorePermit, PeerIdentity, ProxyMetrics, QuicStream, REJECT_REASON_ALLOWLIST, REJECT_REASON_BACKEND_CAP,
	REJECT_REASON_CN_MISMATCH, REJECT_REASON_GLOBAL_CAP, REJECT_REASON_KEY, REJECT_REASON_REVOKED, REJECT_REASON_VERSION,
	HealthState, ReductionError, Result, RevocationSet, SessionId, SocketAddr, TunnelConfig, TunnelFrame,
	TunnelRegistry, TunnelSession, bounded_control_write, debug, exceeds_session_cap, info, mpsc, protocol,
	reject_and_close, run_control_loop, timeout, warn, watch,
};

pub struct TunnelConn {
	pub incoming: quinn::Incoming,
	pub remote_addr: SocketAddr,
	pub registry: Arc<TunnelRegistry>,
	pub config: TunnelConfig,
	pub shutdown: CancellationToken,
	pub metrics: ProxyMetrics,
	pub revocation_rx: watch::Receiver<RevocationSet>,
	pub pending_registration: Option<OwnedSemaphorePermit>,
	// F4: where a control peer's Health frames are applied. None = health transport off (Phase 1).
	pub health_tx: Option<watch::Sender<HealthState>>,
}

// A tunnel connection past the QUIC/mTLS handshake, protocol-version negotiation, and Register frame —
// but before any admission gate has run.
struct Established {
	connection: quinn::Connection,
	control_stream: QuicStream,
	identity: PeerIdentity,
	remote_addr: SocketAddr,
	backend_id: ArrayString<256>,
	pool: ArrayString<32>,
	capabilities: ArrayVec<ArrayString<8>, 4>,
}

// A registration committed to the registry and acked to the client: the control-plane handles the
// session loop drives until the tunnel ends.
struct Committed {
	control_stream: QuicStream,
	control_rx: mpsc::Receiver<TunnelFrame>,
	connection: quinn::Connection,
	backend_id: ArrayString<256>,
	session_id: SessionId,
	// F4: this peer registered advertising CONTROL_CAPABILITY, so its Health frames are honored.
	is_control_peer: bool,
}

// The per-connection registration pipeline: establish → admit → commit → serve. Each stage owns its own
// reject paths (kept visible in full for auditability) so this driver reads as the linear sequence of
// admission phases without carrying their branch density itself.
pub async fn handle_tunnel_connection(conn: TunnelConn) -> Result<()> {
	let TunnelConn {
		incoming,
		remote_addr,
		registry,
		config,
		shutdown,
		metrics,
		revocation_rx,
		mut pending_registration,
		health_tx,
	} = conn;

	let established =
		establish_registration(incoming, remote_addr, &config, &metrics, &mut pending_registration).await?;
	let established =
		admit_registration(established, &registry, &config, &metrics, &revocation_rx, &mut pending_registration).await?;
	let Committed {
		mut control_stream,
		mut control_rx,
		connection,
		backend_id,
		session_id,
		is_control_peer,
	} = commit_registration(established, &registry, &config, &metrics, &revocation_rx, &mut pending_registration).await?;

	let heartbeat_timeout: Duration = Duration::from_secs(config.heartbeat_timeout_secs);
	run_control_loop(
		&mut control_stream,
		&mut control_rx,
		ControlLoopContext {
			connection: &connection,
			registry: &registry,
			shutdown: &shutdown,
			metrics: &metrics,
			backend_id: &backend_id,
			session_id,
			heartbeat_timeout,
			is_control_peer,
			health_tx,
		},
	)
	.await;

	registry.deregister(&backend_id, &session_id);
	metrics.tunnel_sessions_active.add(-1, &[]);
	info!(%backend_id, %session_id, "tunnel session ended");

	return Ok(());
}

// Accept the QUIC/mTLS handshake and the client's control stream, extracting the handshake-proven identity.
// mTLS is mandatory, so a connection with no parseable identity is rejected outright (before any control stream exists).
async fn accept_registration_stream(
	incoming: quinn::Incoming,
	remote_addr: SocketAddr,
	register_timeout: Duration,
) -> Result<(quinn::Connection, QuicStream, PeerIdentity)> {
	let connection: quinn::Connection = timeout(register_timeout, incoming)
		.await
		.map_err(|_| ReductionError::Tunnel("tunnel handshake timed out".to_owned()))?
		.map_err(|e| ReductionError::Tunnel(format!("handshake failed: {e}")))?;

	let identity: PeerIdentity = match PeerIdentity::from_quic_connection(&connection) {
		Ok(id) => id,
		Err(e) => {
			warn!(%remote_addr, error = %e, "tunnel registration rejected: no parseable peer identity");
			return Err(ReductionError::Tunnel(format!("peer identity: {e}")));
		}
	};

	debug!(%remote_addr, cert_cn = identity.common_name.as_str(), "tunnel QUIC connection established");

	let (send, recv) = timeout(register_timeout, connection.accept_bi())
		.await
		.map_err(|_| ReductionError::Tunnel("control stream timed out".to_owned()))?
		.map_err(|e| ReductionError::Tunnel(format!("accept control stream: {e}")))?;

	return Ok((connection, QuicStream::new(send, recv), identity));
}

// Negotiate the protocol version over the accepted control stream and read the client's Register frame.
// A version mismatch gets a reasoned Shutdown instead of an opaque later decode error; the peer version travels in the error detail.
async fn establish_registration(
	incoming: quinn::Incoming,
	remote_addr: SocketAddr,
	config: &TunnelConfig,
	metrics: &ProxyMetrics,
	pending: &mut Option<OwnedSemaphorePermit>,
) -> Result<Established> {
	let register_timeout: Duration = Duration::from_secs(config.registration_timeout_secs);
	let (connection, mut control_stream, identity) =
		accept_registration_stream(incoming, remote_addr, register_timeout).await?;

	let peer_version: u8 = timeout(register_timeout, protocol::read_preamble(&mut control_stream))
		.await
		.map_err(|_| ReductionError::Tunnel("preamble timed out".to_owned()))??;
	if peer_version != protocol::PROTOCOL_VERSION {
		return Err(reject_registration(
			Rejection {
				control_stream,
				connection: &connection,
				identity: &identity,
				remote_addr,
			},
			metrics,
			pending,
			REJECT_REASON_VERSION,
			"unsupported protocol version",
			ReductionError::Tunnel(format!("unsupported protocol version {peer_version}")),
		)
		.await);
	}
	// Answer with our preamble so the client can verify the server the same way.
	timeout(CONTROL_WRITE_TIMEOUT, protocol::write_preamble(&mut control_stream))
		.await
		.map_err(|_| ReductionError::Tunnel("write preamble stalled".to_owned()))??;

	let frame: TunnelFrame = timeout(register_timeout, protocol::read_frame(&mut control_stream))
		.await
		.map_err(|_| ReductionError::Tunnel("registration timed out".to_owned()))?
		.map_err(|e| ReductionError::Tunnel(format!("read register frame: {e}")))?;

	let (backend_id, pool, capabilities) = match frame {
		TunnelFrame::Register {
			backend_id,
			pool,
			capabilities,
		} => (backend_id, pool, capabilities),
		other => {
			return Err(ReductionError::Tunnel(format!(
				"expected Register frame, got {:?}",
				other
			)));
		}
	};

	return Ok(Established {
		connection,
		control_stream,
		identity,
		remote_addr,
		backend_id,
		pool,
		capabilities,
	});
}

// The connection being rejected plus the identity/address for the audit log. Groups the four fields
// that always travel together into `reject_registration`, keeping its signature within arity limits.
struct Rejection<'a> {
	control_stream: QuicStream,
	connection: &'a quinn::Connection,
	identity: &'a PeerIdentity,
	remote_addr: SocketAddr,
}

// Emit the standard registration-rejection metric and audit log, release the pre-registration permit,
// and send the client a reasoned Shutdown before the connection drops. Returns the error to propagate,
// so a gate reads `return Err(reject_registration(…).await)`. The rejected identity and reason are
// always logged; `err` carries the gate-specific detail into both this log and the caller's failure log.
async fn reject_registration(
	rej: Rejection<'_>,
	metrics: &ProxyMetrics,
	pending: &mut Option<OwnedSemaphorePermit>,
	reason: &'static str,
	close_msg: &str,
	err: ReductionError,
) -> ReductionError {
	metrics
		.tunnel_registration_rejected
		.add(1, &[KeyValue::new(REJECT_REASON_KEY, reason)]);
	warn!(cert_cn = rej.identity.common_name.as_str(), remote_addr = %rej.remote_addr, reason, detail = %err,
		"tunnel registration rejected");
	drop(pending.take());
	reject_and_close(rej.control_stream, rej.connection, close_msg).await;
	return err;
}

// Run every registration admission gate against the cert-proven identity: backend_id must equal the cert CN,
// the identity must not be revoked, it must satisfy any static allowlist, and the session cap must have room.
// The shared reject path handles metric, audit log, permit release, and reasoned Shutdown; returns unchanged when all pass.
async fn admit_registration(
	established: Established,
	registry: &TunnelRegistry,
	config: &TunnelConfig,
	metrics: &ProxyMetrics,
	revocation_rx: &watch::Receiver<RevocationSet>,
	pending: &mut Option<OwnedSemaphorePermit>,
) -> Result<Established> {
	let remote_addr: SocketAddr = established.remote_addr;

	// Bind the claimed backend_id to the cert: the handshake proved *a* valid cert, this proves *this* cert is entitled to *this* backend_id.
	if established.backend_id.as_str() != established.identity.common_name.as_str() {
		return Err(reject_registration(
			Rejection {
				control_stream: established.control_stream,
				connection: &established.connection,
				identity: &established.identity,
				remote_addr,
			},
			metrics,
			pending,
			REJECT_REASON_CN_MISMATCH,
			"backend_id does not match certificate",
			ReductionError::Tunnel("backend_id does not match certificate CN".to_owned()),
		)
		.await);
	}

	// Fleet-scale denial: reject any cert whose key SPKI (or backend_id) is revoked even though the CA trusts it.
	// After the CN bind (so identity is proven), before the allowlist (so a revoked device is cut off regardless).
	if revocation_rx.borrow().is_revoked(&established.identity) {
		return Err(reject_registration(
			Rejection {
				control_stream: established.control_stream,
				connection: &established.connection,
				identity: &established.identity,
				remote_addr,
			},
			metrics,
			pending,
			REJECT_REASON_REVOKED,
			REJECT_REASON_REVOKED,
			ReductionError::Tunnel("identity revoked".to_owned()),
		)
		.await);
	}

	// Additional static kill-switch, applied on top of the now-cert-proven backend_id.
	if !config.allowed_backend_ids.is_empty() && !config.allowed_backend_ids.contains(&established.backend_id) {
		return Err(reject_registration(
			Rejection {
				control_stream: established.control_stream,
				connection: &established.connection,
				identity: &established.identity,
				remote_addr,
			},
			metrics,
			pending,
			REJECT_REASON_ALLOWLIST,
			"not in allowlist",
			ReductionError::Tunnel("backend not in allowlist".to_owned()),
		)
		.await);
	}

	// Global accept backpressure: cap total concurrent sessions across all backends. Enforced before
	// the ack so a device at capacity is turned away cleanly rather than registered then dropped. This
	// is a soft cap (checked, not locked, against the live total), which is the intended behavior for a
	// safety limit — the per-backend cap in the registry remains the hard per-identity bound.
	if exceeds_session_cap(registry.total_sessions(), config.max_total_sessions) {
		return Err(reject_registration(
			Rejection {
				control_stream: established.control_stream,
				connection: &established.connection,
				identity: &established.identity,
				remote_addr,
			},
			metrics,
			pending,
			REJECT_REASON_GLOBAL_CAP,
			"at capacity",
			ReductionError::Tunnel("global session cap reached".to_owned()),
		)
		.await);
	}

	return Ok(established);
}

// Commit the admitted registration: mint a session id, register it (the registry owns the per-backend cap),
// re-check revocation to close the check/register race, then ack. The admission permit releases only after a successful ack.
async fn commit_registration(
	established: Established,
	registry: &TunnelRegistry,
	config: &TunnelConfig,
	metrics: &ProxyMetrics,
	revocation_rx: &watch::Receiver<RevocationSet>,
	pending: &mut Option<OwnedSemaphorePermit>,
) -> Result<Committed> {
	let Established {
		connection,
		mut control_stream,
		identity,
		remote_addr,
		backend_id,
		pool,
		capabilities,
	} = established;

	let session_id: SessionId = SessionId::generate()?;
	let is_control_peer: bool = capabilities.iter().any(|c| c.as_str() == protocol::CONTROL_CAPABILITY);

	let (control_tx, control_rx) =
		mpsc::channel::<TunnelFrame>(usize::try_from(config.control_channel_capacity.get()).unwrap_or(usize::MAX));

	let session: TunnelSession = TunnelSession {
		session_id,
		backend_id,
		pool,
		remote_addr,
		connected_at: Instant::now(),
		last_heartbeat: Instant::now(),
		control_tx,
		connection: connection.clone(),
		identity,
		is_control_peer,
	};

	// Commit BEFORE acking: the per-backend cap is the registry's own admission check, and acking first would
	// tell the client "registered" for a session that can still be refused. Register-then-ack gives it a reasoned Shutdown instead.
	if let Err(e) = registry.register(session) {
		return Err(reject_registration(
			Rejection {
				control_stream,
				connection: &connection,
				identity: &identity,
				remote_addr,
			},
			metrics,
			pending,
			REJECT_REASON_BACKEND_CAP,
			"at capacity",
			e,
		)
		.await);
	}

	// Close the check/register race: an update landing between the pre-register check and register() is swept
	// against a registry not yet holding this session, so neither catches it. Re-checking after register()
	// leaves no gap — an update is now either visible here or sweeps an already-registered session.
	if revocation_rx.borrow().is_revoked(&identity) {
		registry.deregister(&backend_id, &session_id);
		return Err(reject_registration(
			Rejection {
				control_stream,
				connection: &connection,
				identity: &identity,
				remote_addr,
			},
			metrics,
			pending,
			REJECT_REASON_REVOKED,
			REJECT_REASON_REVOKED,
			ReductionError::Tunnel("identity revoked".to_owned()),
		)
		.await);
	}

	// Ack only once the session is committed (and re-checked): from the client's view, RegisterAck
	// now means "registered", unconditionally. A failed or stalled ack write rolls the registration back.
	if !bounded_control_write(&mut control_stream, &TunnelFrame::RegisterAck { session_id }).await {
		registry.deregister(&backend_id, &session_id);
		return Err(ReductionError::Tunnel(
			"register ack write failed or stalled".to_owned(),
		));
	}

	info!(%backend_id, session_id = %session_id, %remote_addr, ?capabilities, "tunnel backend registered");

	// The connection is now represented by the registry's per-backend limit; release the separate
	// handshake/control-stream guard so it protects only unaudited pre-registration work.
	drop(pending.take());
	metrics.tunnel_sessions_active.add(1, &[]);

	// Clone detection: backend_id is cert-bound, so a second concurrent session means a second holder
	// of the same private key (or a reconnect race). Surface it — the fleet layer decides on quarantine.
	let session_count: usize = registry.session_count(identity.common_name.as_str());
	if session_count > 1 {
		metrics.tunnel_duplicate_sessions.add(1, &[]);
		warn!(
			backend_id = identity.common_name.as_str(),
			sessions = session_count,
			%remote_addr,
			"duplicate concurrent tunnel session for backend — possible cloned identity"
		);
	}

	return Ok(Committed {
		control_stream,
		control_rx,
		connection,
		backend_id,
		session_id,
		is_control_peer,
	});
}


#[cfg(test)]
mod tests {
	use std::num::NonZeroU32;

	use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
	use quinn::{Endpoint, ServerConfig};
	use tokio::io::AsyncWriteExt;
	use tokio::sync::Semaphore;

	use super::super::testutil::{
		REGISTER_TEST_TIMEOUT_SECS, assert_rejected, connect_and_register, dial_and_register, poll_session_count,
		read_next, revoke_spki, spawn_server_and_connect, spawn_server_and_register,
	};
	use super::super::run_tunnel_listener;
	use super::*;
	use crate::test_support::{generate_ca, generate_signed_cert, write_pem};
	use crate::tls::certs::{build_client_config, build_server_config};

	#[tokio::test]
	async fn test_register_matching_cn_is_acked_and_registered() {
		let mut client = connect_and_register("device-7", "device-7", vec![]).await;
		let frame = read_next(&mut client).await;
		assert!(
			matches!(frame, Some(TunnelFrame::RegisterAck { .. })),
			"expected RegisterAck, got {frame:?}"
		);
		assert!(
			poll_session_count(&client.registry, "device-7", 1).await,
			"matching registration did not create a registry entry",
		);
	}

	#[tokio::test]
	async fn test_register_mismatched_cn_is_rejected() {
		// Cert CN device-7 tries to register as device-99 (impersonation) → rejected, no entry.
		let mut client = connect_and_register("device-7", "device-99", vec![]).await;
		let frame = read_next(&mut client).await;
		assert_rejected(&frame, "certificate");
		assert_eq!(
			client.registry.session_count("device-99"),
			0,
			"impersonated backend must not be registered"
		);
		assert_eq!(client.registry.session_count("device-7"), 0);
	}

	#[tokio::test]
	async fn test_register_allowlist_still_enforced_on_top() {
		// CN matches backend_id (binding passes) but backend_id is not in the allowlist → rejected.
		let allowed: Vec<ArrayString<256>> = vec![ArrayString::from("other-device").unwrap()];
		let mut client = connect_and_register("device-7", "device-7", allowed).await;
		let frame = read_next(&mut client).await;
		assert_rejected(&frame, "allowlist");
		assert_eq!(client.registry.session_count("device-7"), 0);
	}

	// Register-then-ack contract: at the per-backend cap the SECOND registration's first frame must be a
	// reasoned Shutdown, never a RegisterAck then an abrupt drop (the old ack-before-commit acked a refused session).
	#[allow(clippy::too_many_lines)]
	#[tokio::test]
	async fn test_per_backend_cap_rejects_with_shutdown_and_no_ack() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let client_leaf = generate_signed_cert(&ca, "device-7", vec![]);
		let server_leaf = generate_signed_cert(
			&ca,
			"reduction-server",
			vec![rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]))],
		);

		let ca_file = write_pem(&ca.cert.pem());
		let server_cert_file = write_pem(&server_leaf.cert.pem());
		let server_key_file = write_pem(&server_leaf.signing_key.serialize_pem());
		let client_cert_file = write_pem(&client_leaf.cert.pem());
		let client_key_file = write_pem(&client_leaf.signing_key.serialize_pem());

		let (server_tls, _r1) =
			build_server_config(server_cert_file.path(), server_key_file.path(), ca_file.path()).unwrap();
		let quic_crypto = QuicServerConfig::try_from(Arc::new(server_tls)).unwrap();
		let quinn_server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
		let endpoint = Endpoint::server(quinn_server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
		let addr: SocketAddr = endpoint.local_addr().unwrap();

		// Cap of ONE session for this backend; the second registration must hit the registry limit.
		let registry: Arc<TunnelRegistry> = Arc::new(TunnelRegistry::new(1));
		let (_revocation_tx, revocation_rx) = watch::channel(RevocationSet::default());

		let server_registry = Arc::clone(&registry);
		tokio::spawn(async move {
			for _ in 0..2 {
				if let Some(incoming) = endpoint.accept().await {
					let remote = incoming.remote_address();
					let reg = Arc::clone(&server_registry);
					let rx = revocation_rx.clone();
					tokio::spawn(async move {
						let _ = handle_tunnel_connection(TunnelConn {
							incoming,
							remote_addr: remote,
							registry: reg,
							config: TunnelConfig::default(),
							shutdown: CancellationToken::new(),
							metrics: ProxyMetrics::new(),
							revocation_rx: rx,
							pending_registration: None,
							health_tx: None,
						})
						.await;
					});
				}
			}
			// Hold the endpoint so established connections stay alive for the test body.
			std::future::pending::<()>().await;
		});

		let connect = |cert_path: std::path::PathBuf, key_path: std::path::PathBuf, ca_path: std::path::PathBuf| async move {
			let (client_tls, _r, _v) = build_client_config(&cert_path, &key_path, &ca_path).unwrap();
			let quic_client_crypto = QuicClientConfig::try_from(Arc::new(client_tls)).unwrap();
			let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
			client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_crypto)));
			let connection = client_endpoint.connect(addr, "127.0.0.1").unwrap().await.unwrap();
			let (send, recv) = connection.open_bi().await.unwrap();
			let mut control = QuicStream::new(send, recv);
			protocol::write_preamble(&mut control).await.unwrap();
			let register = TunnelFrame::Register {
				backend_id: ArrayString::from("device-7").unwrap(),
				pool: ArrayString::from("default").unwrap(),
				capabilities: ArrayVec::new(),
			};
			protocol::write_frame(&mut control, &register).await.unwrap();
			let server_version: u8 = protocol::read_preamble(&mut control).await.unwrap();
			assert_eq!(server_version, protocol::PROTOCOL_VERSION);
			return (control, connection, client_endpoint);
		};

		// First registration fills the cap and is acked.
		let (mut control1, _conn1, _ep1) = connect(
			client_cert_file.path().to_path_buf(),
			client_key_file.path().to_path_buf(),
			ca_file.path().to_path_buf(),
		)
		.await;
		let first = timeout(
			Duration::from_secs(REGISTER_TEST_TIMEOUT_SECS),
			protocol::read_frame(&mut control1),
		)
		.await
		.ok()
		.and_then(|r| r.ok());
		assert!(
			matches!(first, Some(TunnelFrame::RegisterAck { .. })),
			"first registration must be acked, got {first:?}"
		);
		assert!(
			poll_session_count(&registry, "device-7", 1).await,
			"first session must be registered"
		);

		// Second registration (same identity) hits the cap: first frame is a reasoned Shutdown.
		let (mut control2, _conn2, _ep2) = connect(
			client_cert_file.path().to_path_buf(),
			client_key_file.path().to_path_buf(),
			ca_file.path().to_path_buf(),
		)
		.await;
		let second = timeout(
			Duration::from_secs(REGISTER_TEST_TIMEOUT_SECS),
			protocol::read_frame(&mut control2),
		)
		.await
		.ok()
		.and_then(|r| r.ok());
		assert_rejected(&second, "capacity");
		assert_eq!(
			registry.session_count("device-7"),
			1,
			"the capped registration must not add a session"
		);
	}

	// #7 guard: a peer that stops reading its control stream must bound the write, not park the loop in
	// poll_flush forever. duplex(1) can't absorb the length prefix, so under the paused clock the timeout elapses and the helper reports failure.

	// v1 dialect) instead of a later opaque decode error — and no session forms.
	#[tokio::test]
	async fn test_unsupported_protocol_version_rejected_with_shutdown() {
		let ca = generate_ca();
		let client_leaf = generate_signed_cert(&ca, "device-7", vec![]);
		let mut client =
			spawn_server_and_connect(&ca, &client_leaf, TunnelConfig::default(), RevocationSet::default()).await;

		// Hand-rolled preamble claiming a future version.
		let mut preamble: Vec<u8> = protocol::PROTOCOL_MAGIC.to_vec();
		preamble.push(99);
		client.control.write_all(&preamble).await.unwrap();
		client.control.flush().await.unwrap();

		let frame = read_next(&mut client).await;
		assert_rejected(&frame, "version");
		assert_eq!(
			client.registry.total_sessions(),
			0,
			"a version-mismatched client must not register"
		);
	}

	// #12: a pre-preamble (legacy) client leads with a length-prefixed frame whose prefix can't equal the
	// magic, so the server refuses cleanly (no ack, no session) rather than failing later with framing garbage.
	#[tokio::test]
	async fn test_legacy_client_without_preamble_is_refused() {
		let ca = generate_ca();
		let client_leaf = generate_signed_cert(&ca, "device-7", vec![]);
		let mut client =
			spawn_server_and_connect(&ca, &client_leaf, TunnelConfig::default(), RevocationSet::default()).await;

		let register = TunnelFrame::Register {
			backend_id: ArrayString::from("device-7").unwrap(),
			pool: ArrayString::from("default").unwrap(),
			capabilities: ArrayVec::new(),
		};
		protocol::write_frame(&mut client.control, &register).await.unwrap();

		let frame = read_next(&mut client).await;
		assert!(
			frame.is_none(),
			"a legacy client must not receive any frame, got {frame:?}"
		);
		assert_eq!(client.registry.total_sessions(), 0, "a legacy client must not register");
	}

	// #10: a rejected registration must release its admission permit BEFORE the reject drain; held through the
	// 2s drain, ~64 rejectable connects/sec would pin the whole 128-permit budget and starve legitimate registrations.
	#[tokio::test]
	async fn test_rejection_releases_admission_permit_before_drain() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let client_leaf = generate_signed_cert(&ca, "device-7", vec![]);
		let server_leaf = generate_signed_cert(
			&ca,
			"reduction-server",
			vec![rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]))],
		);

		let ca_file = write_pem(&ca.cert.pem());
		let server_cert_file = write_pem(&server_leaf.cert.pem());
		let server_key_file = write_pem(&server_leaf.signing_key.serialize_pem());
		let client_cert_file = write_pem(&client_leaf.cert.pem());
		let client_key_file = write_pem(&client_leaf.signing_key.serialize_pem());

		let (server_tls, _r1) =
			build_server_config(server_cert_file.path(), server_key_file.path(), ca_file.path()).unwrap();
		let (client_tls, _r2, _v2) =
			build_client_config(client_cert_file.path(), client_key_file.path(), ca_file.path()).unwrap();

		let quic_crypto = QuicServerConfig::try_from(Arc::new(server_tls)).unwrap();
		let quinn_server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
		let endpoint = Endpoint::server(quinn_server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
		let addr: SocketAddr = endpoint.local_addr().unwrap();

		let admission: Arc<Semaphore> = Arc::new(Semaphore::new(1));
		let permit: OwnedSemaphorePermit = Arc::clone(&admission).try_acquire_owned().unwrap();
		let registry: Arc<TunnelRegistry> = Arc::new(TunnelRegistry::new(8));
		let (_revocation_tx, revocation_rx) = watch::channel(RevocationSet::default());

		let server_registry = Arc::clone(&registry);
		tokio::spawn(async move {
			if let Some(incoming) = endpoint.accept().await {
				let remote = incoming.remote_address();
				let _ = handle_tunnel_connection(TunnelConn {
					incoming,
					remote_addr: remote,
					registry: server_registry,
					config: TunnelConfig::default(),
					shutdown: CancellationToken::new(),
					metrics: ProxyMetrics::new(),
					revocation_rx,
					pending_registration: Some(permit),
					health_tx: None,
				})
				.await;
			}
			// Hold the endpoint so the rejected connection stays open through the drain.
			std::future::pending::<()>().await;
		});

		let quic_client_crypto = QuicClientConfig::try_from(Arc::new(client_tls)).unwrap();
		let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
		client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_crypto)));
		let connection = client_endpoint.connect(addr, "127.0.0.1").unwrap().await.unwrap();
		let (send, recv) = connection.open_bi().await.unwrap();
		let mut control = QuicStream::new(send, recv);

		// CN device-7 registers as device-99 → CN-mismatch rejection. The client then neither reads
		// the Shutdown nor closes, so the server's reject drain waits its full 2s.
		protocol::write_preamble(&mut control).await.unwrap();
		protocol::write_frame(
			&mut control,
			&TunnelFrame::Register {
				backend_id: ArrayString::from("device-99").unwrap(),
				pool: ArrayString::from("default").unwrap(),
				capabilities: ArrayVec::new(),
			},
		)
		.await
		.unwrap();

		// The permit must return well before REJECT_DRAIN_TIMEOUT (2s); a wall-clock deadline, not an iteration
		// count, so sleep-loop drift past the drain window can't let the old held-through-drain ordering pass.
		const PERMIT_POLL_BUDGET: Duration = Duration::from_millis(1200);
		let poll_start: Instant = Instant::now();
		let mut freed: bool = false;
		while poll_start.elapsed() < PERMIT_POLL_BUDGET {
			if admission.available_permits() == 1 {
				freed = true;
				break;
			}
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
		assert!(
			freed,
			"the admission permit must be released before the reject drain completes"
		);
		assert_eq!(registry.total_sessions(), 0);
	}

	// Build a revocation set containing exactly one SPKI: this leaf's key hash.

	#[tokio::test]
	async fn test_same_key_registers_before_revocation_rejected_after() {
		// Functional diff: the identical CA + client key + backend_id register successfully with an
		// empty set, and are rejected once — and only once — that key's SPKI is on the set. The set is
		// therefore proven to be what denies it (nothing else changed between the two attempts).
		let ca = generate_ca();
		let client_leaf = generate_signed_cert(&ca, "device-7", vec![]);

		// BEFORE: empty revocation set → registers.
		let mut before =
			spawn_server_and_register(&ca, &client_leaf, "device-7", vec![], RevocationSet::default()).await;
		assert!(
			matches!(read_next(&mut before).await, Some(TunnelFrame::RegisterAck { .. })),
			"with an empty revocation set the registration must be acked",
		);
		assert!(
			poll_session_count(&before.registry, "device-7", 1).await,
			"session should be registered before revocation"
		);

		// AFTER: same key, same backend_id, only the set differs → rejected, no entry.
		let mut after =
			spawn_server_and_register(&ca, &client_leaf, "device-7", vec![], revoke_spki(&client_leaf)).await;
		assert_rejected(&read_next(&mut after).await, REJECT_REASON_REVOKED);
		assert_eq!(
			after.registry.session_count("device-7"),
			0,
			"revoked key must not be registered"
		);
	}

	#[tokio::test]
	async fn test_backend_id_revocation_blocks_different_key_same_cn() {
		// A backend_id entry revokes the NAME: a freshly-minted key (never in any SPKI list) presenting
		// the same CN is still cut off. This is the decommission case — the device_id is gone for good.
		let ca = generate_ca();
		let fresh_key = generate_signed_cert(&ca, "edge-1", vec![]);
		let revocation =
			RevocationSet::parse("[[revoked]]\nbackend_id = \"edge-1\"\nreason = \"decommissioned\"\n").unwrap();

		let mut client = spawn_server_and_register(&ca, &fresh_key, "edge-1", vec![], revocation).await;
		assert_rejected(&read_next(&mut client).await, REJECT_REASON_REVOKED);
		assert_eq!(client.registry.session_count("edge-1"), 0);
	}


	#[tokio::test]
	async fn test_global_session_cap_rejects_beyond_limit() {
		// Functional diff: with a global cap of 1, the FIRST device registers and the SECOND — a
		// distinct, CA-trusted, allowlist-clean device — is turned away solely because the cap is full.
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let server_leaf = generate_signed_cert(
			&ca,
			"reduction-server",
			vec![rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]))],
		);
		let ca_file = write_pem(&ca.cert.pem());
		let server_cert_file = write_pem(&server_leaf.cert.pem());
		let server_key_file = write_pem(&server_leaf.signing_key.serialize_pem());
		let (server_tls, _r1) =
			build_server_config(server_cert_file.path(), server_key_file.path(), ca_file.path()).unwrap();

		let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
		let addr: SocketAddr = probe.local_addr().unwrap();
		drop(probe);

		let registry: Arc<TunnelRegistry> = Arc::new(TunnelRegistry::new(8));
		let shutdown = CancellationToken::new();
		let config = TunnelConfig {
			max_total_sessions: Some(NonZeroU32::new(1).unwrap()),
			..Default::default()
		};
		let (_vtx, revocation_rx) = watch::channel(RevocationSet::default());

		let listener_registry = Arc::clone(&registry);
		let listener_shutdown = shutdown.clone();
		tokio::spawn(async move {
			let _ = run_tunnel_listener(
				addr,
				Arc::new(server_tls),
				listener_registry,
				listener_shutdown,
				config,
				ProxyMetrics::new(),
				revocation_rx,
			)
			.await;
		});
		assert!(poll_session_count(&registry, "device-1", 0).await);

		// First device fills the single slot.
		let d1 = generate_signed_cert(&ca, "device-1", vec![]);
		let (mut c1, _conn1, _ep1) = dial_and_register(addr, &ca, &d1, "device-1").await;
		let ack = timeout(
			Duration::from_secs(REGISTER_TEST_TIMEOUT_SECS),
			protocol::read_frame(&mut c1),
		)
		.await
		.ok()
		.and_then(|r| r.ok());
		assert!(
			matches!(ack, Some(TunnelFrame::RegisterAck { .. })),
			"first device must register, got {ack:?}"
		);
		assert!(
			poll_session_count(&registry, "device-1", 1).await,
			"first device not registered"
		);

		// Second, distinct device is rejected purely by the cap.
		let d2 = generate_signed_cert(&ca, "device-2", vec![]);
		let (mut c2, _conn2, _ep2) = dial_and_register(addr, &ca, &d2, "device-2").await;
		let resp = timeout(
			Duration::from_secs(REGISTER_TEST_TIMEOUT_SECS),
			protocol::read_frame(&mut c2),
		)
		.await
		.ok()
		.and_then(|r| r.ok());
		assert_rejected(&resp, "at capacity");
		assert_eq!(
			registry.session_count("device-2"),
			0,
			"capped device must not be registered"
		);

		shutdown.cancel();
	}

	// One connect attempt from a fresh client endpoint (new ephemeral port, same loopback IP).
	// Returns true if the connection establishes within `within`; false if it is dropped/ignored
	// (the accept limiter sends nothing back, so an ignored connect never resolves and times out).
}
