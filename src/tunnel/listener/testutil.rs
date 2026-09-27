use super::*;
use quinn::crypto::rustls::QuicClientConfig;

use crate::test_support::{generate_ca, generate_signed_cert, write_pem};
use crate::tls::certs::{build_client_config, build_server_config};

pub const REGISTER_TEST_TIMEOUT_SECS: u64 = 10;

// A connected tunnel client whose registration has been sent. Holding the connection + endpoints
// keeps the session alive so the caller controls its lifetime (and the registry stays stable).
pub struct TestClient {
	pub control: QuicStream,
	pub _connection: quinn::Connection,
	pub _client_endpoint: Endpoint,
	pub registry: Arc<TunnelRegistry>,
}

pub async fn read_next(client: &mut TestClient) -> Option<TunnelFrame> {
	return timeout(
		Duration::from_secs(REGISTER_TEST_TIMEOUT_SECS),
		protocol::read_frame(&mut client.control),
	)
	.await
	.ok()
	.and_then(|r| r.ok());
}

pub async fn poll_session_count(registry: &Arc<TunnelRegistry>, backend_id: &str, want: usize) -> bool {
	for _ in 0..100 {
		if registry.session_count(backend_id) == want {
			return true;
		}
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	return false;
}

// Drive one real QUIC+mTLS registration through handle_tunnel_connection: the client presents a cert with
// CN `client_cn` and Registers for `backend_id`; the returned TestClient holds the live connection.
pub async fn connect_and_register(
	client_cn: &str,
	backend_id: &str,
	allowed_backend_ids: Vec<ArrayString<256>>,
) -> TestClient {
	let ca = generate_ca();
	let client_leaf = generate_signed_cert(&ca, client_cn, vec![]);
	return spawn_server_and_register(
		&ca,
		&client_leaf,
		backend_id,
		allowed_backend_ids,
		RevocationSet::default(),
	)
	.await;
}

// Lower-level harness: run one registration with a caller-supplied CA and client leaf against a server
// seeded with a specific revocation set, so a test can drive the *same* key through two registrations that
// differ only in the set — the diff proving the set is what denies it.
pub async fn spawn_server_and_register(
	ca: &rcgen::CertifiedKey<rcgen::KeyPair>,
	client_leaf: &rcgen::CertifiedKey<rcgen::KeyPair>,
	backend_id: &str,
	allowed_backend_ids: Vec<ArrayString<256>>,
	revocation: RevocationSet,
) -> TestClient {
	let config: TunnelConfig = TunnelConfig {
		allowed_backend_ids,
		..Default::default()
	};
	return spawn_server_and_register_with_config(ca, client_leaf, backend_id, config, revocation).await;
}

// Same harness with a caller-supplied TunnelConfig, for tests that tune the heartbeat contract.
pub async fn spawn_server_and_register_with_config(
	ca: &rcgen::CertifiedKey<rcgen::KeyPair>,
	client_leaf: &rcgen::CertifiedKey<rcgen::KeyPair>,
	backend_id: &str,
	config: TunnelConfig,
	revocation: RevocationSet,
) -> TestClient {
	let mut client: TestClient = spawn_server_and_connect(ca, client_leaf, config, revocation).await;

	protocol::write_preamble(&mut client.control).await.unwrap();
	let register = TunnelFrame::Register {
		backend_id: ArrayString::from(backend_id).unwrap(),
		pool: ArrayString::from("default").unwrap(),
		capabilities: ArrayVec::new(),
	};
	protocol::write_frame(&mut client.control, &register).await.unwrap();
	let server_version: u8 = protocol::read_preamble(&mut client.control).await.unwrap();
	assert_eq!(server_version, protocol::PROTOCOL_VERSION);

	return client;
}

// Connect-only harness: everything up to an open control stream, with no preamble or Register
// sent — for tests that drive the negotiation bytes themselves.
pub async fn spawn_server_and_connect(
	ca: &rcgen::CertifiedKey<rcgen::KeyPair>,
	client_leaf: &rcgen::CertifiedKey<rcgen::KeyPair>,
	config: TunnelConfig,
	revocation: RevocationSet,
) -> TestClient {
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

	let server_leaf = generate_signed_cert(
		ca,
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

	let registry: Arc<TunnelRegistry> = Arc::new(TunnelRegistry::new(8));
	let (_revocation_tx, revocation_rx) = watch::channel(revocation);

	// Accept exactly one connection and hand it to the real registration path. Holding `endpoint`
	// in the task keeps it (and, for the accepted-and-blocking success case, the server) alive.
	let server_registry = Arc::clone(&registry);
	tokio::spawn(async move {
		if let Some(incoming) = endpoint.accept().await {
			let remote = incoming.remote_address();
			let _ = handle_tunnel_connection(TunnelConn {
				incoming,
				remote_addr: remote,
				registry: server_registry,
				config,
				shutdown: CancellationToken::new(),
				metrics: ProxyMetrics::new(),
				revocation_rx,
				pending_registration: None,
				health_tx: None,
			})
			.await;
		}
	});

	let quic_client_crypto = QuicClientConfig::try_from(Arc::new(client_tls)).unwrap();
	let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
	client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_crypto)));
	let connection = client_endpoint.connect(addr, "127.0.0.1").unwrap().await.unwrap();

	let (send, recv) = connection.open_bi().await.unwrap();
	let control_stream = QuicStream::new(send, recv);

	return TestClient {
		control: control_stream,
		_connection: connection,
		_client_endpoint: client_endpoint,
		registry,
	};
}

// F4 harness: spawn a server whose control loop applies Health frames to a returned health receiver,
// and register a client advertising `capabilities` for `backend_id`. Returns the live client plus the
// `health_rx` the proxy path would read. Mirrors `spawn_server_and_connect` but wires `health_tx`.
pub async fn spawn_health_peer(
	ca: &rcgen::CertifiedKey<rcgen::KeyPair>,
	client_leaf: &rcgen::CertifiedKey<rcgen::KeyPair>,
	backend_id: &str,
	capabilities: ArrayVec<ArrayString<8>, 4>,
) -> (TestClient, watch::Receiver<HealthState>) {
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

	let server_leaf = generate_signed_cert(ca, "reduction-server", vec![rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]))]);
	let ca_file = write_pem(&ca.cert.pem());
	let server_cert_file = write_pem(&server_leaf.cert.pem());
	let server_key_file = write_pem(&server_leaf.signing_key.serialize_pem());
	let client_cert_file = write_pem(&client_leaf.cert.pem());
	let client_key_file = write_pem(&client_leaf.signing_key.serialize_pem());

	let (server_tls, _r1) = build_server_config(server_cert_file.path(), server_key_file.path(), ca_file.path()).unwrap();
	let (client_tls, _r2, _v2) = build_client_config(client_cert_file.path(), client_key_file.path(), ca_file.path()).unwrap();

	let quic_crypto = QuicServerConfig::try_from(Arc::new(server_tls)).unwrap();
	let quinn_server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
	let endpoint = Endpoint::server(quinn_server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
	let addr: SocketAddr = endpoint.local_addr().unwrap();

	let registry: Arc<TunnelRegistry> = Arc::new(TunnelRegistry::new(8));
	let (_revocation_tx, revocation_rx) = watch::channel(RevocationSet::default());
	let (health_tx, health_rx) = watch::channel(HealthState::new());

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
				pending_registration: None,
				health_tx: Some(health_tx),
			})
			.await;
		}
	});

	let quic_client_crypto = QuicClientConfig::try_from(Arc::new(client_tls)).unwrap();
	let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
	client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_crypto)));
	let connection = client_endpoint.connect(addr, "127.0.0.1").unwrap().await.unwrap();
	let (send, recv) = connection.open_bi().await.unwrap();
	let mut control_stream = QuicStream::new(send, recv);

	protocol::write_preamble(&mut control_stream).await.unwrap();
	let register = TunnelFrame::Register {
		backend_id: ArrayString::from(backend_id).unwrap(),
		pool: ArrayString::from(backend_id).unwrap(),
		capabilities,
	};
	protocol::write_frame(&mut control_stream, &register).await.unwrap();
	let _server_version: u8 = protocol::read_preamble(&mut control_stream).await.unwrap();

	let client = TestClient { control: control_stream, _connection: connection, _client_endpoint: client_endpoint, registry };
	return (client, health_rx);
}

// A rejected registration reliably delivers a Shutdown carrying the reason before the connection
// closes (reject_and_close drains the stream), and never creates a registry entry.
pub fn assert_rejected(frame: &Option<TunnelFrame>, reason_needle: &str) {
	match frame {
		Some(TunnelFrame::Shutdown { reason }) => {
			assert!(reason.as_str().contains(reason_needle), "unexpected reason: {reason}");
		}
		other => panic!("expected Shutdown with reason containing '{reason_needle}', got {other:?}"),
	}
}


pub fn revoke_spki(client_leaf: &rcgen::CertifiedKey<rcgen::KeyPair>) -> RevocationSet {
	let identity: PeerIdentity = PeerIdentity::from_leaf_der(client_leaf.cert.der()).unwrap();
	let toml: String = format!(
		"[[revoked]]\nspki = \"{}\"\nreason = \"clone detected\"\n",
		identity.spki_hex(),
	);
	return RevocationSet::parse(&toml).unwrap();
}


pub async fn dial_and_register(
	addr: SocketAddr,
	ca: &rcgen::CertifiedKey<rcgen::KeyPair>,
	client_leaf: &rcgen::CertifiedKey<rcgen::KeyPair>,
	backend_id: &str,
) -> (QuicStream, quinn::Connection, Endpoint) {
	let ca_file = write_pem(&ca.cert.pem());
	let client_cert_file = write_pem(&client_leaf.cert.pem());
	let client_key_file = write_pem(&client_leaf.signing_key.serialize_pem());
	let (client_tls, _r, _v) =
		build_client_config(client_cert_file.path(), client_key_file.path(), ca_file.path()).unwrap();

	let quic_client_crypto = QuicClientConfig::try_from(Arc::new(client_tls)).unwrap();
	let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
	client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_crypto)));

	let mut connection = None;
	for _ in 0..50 {
		match client_endpoint.connect(addr, "127.0.0.1").unwrap().await {
			Ok(conn) => {
				connection = Some(conn);
				break;
			}
			Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
		}
	}
	let connection = connection.expect("could not connect to tunnel listener");

	let (send, recv) = connection.open_bi().await.unwrap();
	let mut control = QuicStream::new(send, recv);
	protocol::write_preamble(&mut control).await.unwrap();
	protocol::write_frame(
		&mut control,
		&TunnelFrame::Register {
			backend_id: ArrayString::from(backend_id).unwrap(),
			pool: ArrayString::from("default").unwrap(),
			capabilities: ArrayVec::new(),
		},
	)
	.await
	.unwrap();
	let server_version: u8 = protocol::read_preamble(&mut control).await.unwrap();
	assert_eq!(server_version, protocol::PROTOCOL_VERSION);
	return (control, connection, client_endpoint);
}


pub async fn connect_once(
	addr: SocketAddr,
	ca: &rcgen::CertifiedKey<rcgen::KeyPair>,
	client_leaf: &rcgen::CertifiedKey<rcgen::KeyPair>,
	within: Duration,
) -> bool {
	let ca_file = write_pem(&ca.cert.pem());
	let client_cert_file = write_pem(&client_leaf.cert.pem());
	let client_key_file = write_pem(&client_leaf.signing_key.serialize_pem());
	let (client_tls, _r, _v) =
		build_client_config(client_cert_file.path(), client_key_file.path(), ca_file.path()).unwrap();
	let quic_client_crypto = QuicClientConfig::try_from(Arc::new(client_tls)).unwrap();
	let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
	client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_crypto)));

	// On timeout the Connecting future is dropped, aborting the attempt; the endpoint is dropped
	// at scope end. An ignored connect never resolves, so it reads as "did not establish".
	return matches!(
		timeout(within, client_endpoint.connect(addr, "127.0.0.1").unwrap()).await,
		Ok(Ok(_conn))
	);
}

