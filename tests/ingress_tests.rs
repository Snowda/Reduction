// End-to-end ingress tests: drive the real UDP ingress listener against a live QUIC backend that
// implements the envelope decode, and verify from the backend's own collected datagrams that the
// accounting closes (received == relayed + Σ dropped == N), every payload is byte-identical, every
// peer equals the real sender's ip:port, and a different input set yields different output. Also
// asserts the diff-against-disabled property: with no ingress spawned, the port is unbound and the
// backend sees nothing.
#![cfg(feature = "integration_tests")]
// Integration-test crate: unwrap/expect/panic are the idiomatic way to fail a test loudly. The
// project's deny-level restriction lints auto-exempt inline #[cfg(test)] modules but not test crates.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::str_to_string)]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arrayvec::ArrayString;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig as QuinnServerConfig};
use reduction::circuit::CircuitBreakers;
use reduction::config::{
	BackendConfig, CircuitBreakerConfig, IngressConfig, IngressProtocol, ReductionConfig, RetryConfig, TransportKind,
};
use reduction::health::HealthState;
use reduction::ingress::protocol::{self, Datagram, Envelope};
use reduction::ingress::tcp::{self, TcpIngressParams};
use reduction::ingress::udp::{self, UdpIngressParams};
use reduction::proxy::ConnPool;
use reduction::transport::quic::STREAM_TYPE_RAW;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

fn install_provider() {
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

// Accept any server certificate: the test's trust is the loopback boundary, not PKI. Mirrors the
// connection-pool tests' verifier.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
	fn verify_server_cert(
		&self,
		_: &CertificateDer<'_>,
		_: &[CertificateDer<'_>],
		_: &ServerName<'_>,
		_: &[u8],
		_: UnixTime,
	) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
		return Ok(rustls::client::danger::ServerCertVerified::assertion());
	}

	fn verify_tls12_signature(
		&self,
		_: &[u8],
		_: &CertificateDer<'_>,
		_: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
	}

	fn verify_tls13_signature(
		&self,
		_: &[u8],
		_: &CertificateDer<'_>,
		_: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		return vec![
			rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
			rustls::SignatureScheme::RSA_PSS_SHA256,
		];
	}
}

fn client_config() -> Arc<rustls::ClientConfig> {
	install_provider();
	return Arc::new(
		rustls::ClientConfig::builder()
			.dangerous()
			.with_custom_certificate_verifier(Arc::new(NoVerify))
			.with_no_client_auth(),
	);
}

// A QUIC backend that speaks the ingress envelope: accept a raw bi stream, consume the STREAM_TYPE_RAW
// byte + preamble, then decode every frame, collecting each Batch's datagrams. Returns its address and
// the shared collection.
async fn spawn_quic_envelope_backend() -> (SocketAddr, Arc<Mutex<Vec<Datagram>>>) {
	install_provider();
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
	let endpoint = Endpoint::server(
		QuinnServerConfig::with_crypto(Arc::new(quic_crypto)),
		"127.0.0.1:0".parse().unwrap(),
	)
	.unwrap();
	let addr: SocketAddr = endpoint.local_addr().unwrap();

	let collected: Arc<Mutex<Vec<Datagram>>> = Arc::new(Mutex::new(Vec::new()));
	let collected_srv: Arc<Mutex<Vec<Datagram>>> = Arc::clone(&collected);

	tokio::spawn(async move {
		while let Some(incoming) = endpoint.accept().await {
			let Ok(connection) = incoming.await else {
				continue;
			};
			let collected_conn: Arc<Mutex<Vec<Datagram>>> = Arc::clone(&collected_srv);
			tokio::spawn(async move {
				while let Ok((_send, mut recv)) = connection.accept_bi().await {
					let collected_stream: Arc<Mutex<Vec<Datagram>>> = Arc::clone(&collected_conn);
					tokio::spawn(async move {
						let mut stream_type: [u8; 1] = [0u8; 1];
						if recv.read_exact(&mut stream_type).await.is_err() || stream_type[0] != STREAM_TYPE_RAW {
							return;
						}
						if protocol::read_preamble(&mut recv).await.is_err() {
							return;
						}
						loop {
							match protocol::read_frame(&mut recv).await {
								Ok(Envelope::Batch { datagrams }) => {
									collected_stream.lock().unwrap().extend(datagrams);
								}
								Ok(_) => {}
								Err(_) => return,
							}
						}
					});
				}
			});
		}
	});

	return (addr, collected);
}

// A minimal valid ReductionConfig for the ingress worker's config-watch initial value; the test never
// triggers a reload, so its contents only need to parse.
fn base_config() -> ReductionConfig {
	let toml_str: &str = r#"
[listen]
address = "127.0.0.1:8443"
transport = "quic"

[tls.server.manual]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"

[[backends]]
id = "ingest"
address = "127.0.0.1:9000"
weight = 1.0
transport = "quic"

[[routes]]
path_prefix = "/"
backend_id = "ingest"
"#;
	return toml::from_str(toml_str).unwrap();
}

async fn free_udp_port() -> SocketAddr {
	let probe: UdpSocket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let addr: SocketAddr = probe.local_addr().unwrap();
	drop(probe);
	return addr;
}

fn ingress_params(
	listen: SocketAddr,
	backend: BackendConfig,
	client: Arc<rustls::ClientConfig>,
	shutdown: CancellationToken,
) -> UdpIngressParams {
	let (_health_tx, health_rx): (watch::Sender<HealthState>, watch::Receiver<HealthState>) =
		watch::channel(HealthState::new());
	// Leak the config sender by holding it in the params' closure is unnecessary; drop it — the worker's
	// reload arm disables itself and serves on the initial config, which is all these tests need.
	let (_config_tx, config_rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) =
		watch::channel(base_config());
	let config: IngressConfig = IngressConfig {
		id: ArrayString::from("site-udp").unwrap(),
		protocol: IngressProtocol::Udp,
		listen,
		// One worker keeps delivery order deterministic across platforms (SO_REUSEPORT fan-out is Linux).
		workers: 1,
		recv_buffer_bytes: 8 * 1024 * 1024,
		max_datagram_bytes: 8192,
		backend_ids: vec![ArrayString::from("ingest").unwrap()],
		batch_max_datagrams: 512,
		batch_max_bytes: 61440,
		linger_ms: 10,
		queue_depth_per_backend: 4096,
		max_connections: None,
		idle_timeout_secs: None,
	};
	return UdpIngressParams {
		config,
		backends: vec![backend],
		acl: reduction::acl::AccessControl::new(vec![], vec![]),
		// One loopback IP carries every test peer (distinguished by port), so all share one rate-limit
		// bucket — keep the quota high enough that the burst is never throttled.
		requests_per_second: 1_000_000,
		conn_pool: Arc::new(ConnPool::new()),
		client_tls_config: client,
		health_rx,
		config_rx,
		circuit: Arc::new(CircuitBreakers::new(&CircuitBreakerConfig::default())),
		retry: RetryConfig::default(),
		connect_timeout: Duration::from_secs(5),
		max_backends: 64,
		shutdown,
	};
}

#[tokio::test]
async fn ingress_accounting_closes_and_preserves_peers_and_payloads() {
	let (backend_addr, collected) = spawn_quic_envelope_backend().await;
	let backend: BackendConfig = BackendConfig::new("ingest", backend_addr, 1.0, TransportKind::Quic).unwrap();
	let listen: SocketAddr = free_udp_port().await;
	let shutdown: CancellationToken = CancellationToken::new();

	let counters = udp::spawn_udp_ingress(&ingress_params(listen, backend, client_config(), shutdown.clone()))
		.expect("ingress must bind");

	// Three peers (distinct source ports on loopback), ten distinct payloads each.
	const PEERS: usize = 3;
	const PER_PEER: usize = 10;
	const TOTAL: usize = PEERS * PER_PEER;
	let total: u64 = u64::try_from(TOTAL).unwrap();
	let mut expected: HashSet<(SocketAddr, Vec<u8>)> = HashSet::new();
	let mut clients: Vec<UdpSocket> = Vec::new();
	for peer_index in 0..PEERS {
		let client: UdpSocket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let peer_addr: SocketAddr = client.local_addr().unwrap();
		for msg_index in 0..PER_PEER {
			let payload: Vec<u8> = format!("peer{peer_index}-msg{msg_index}").into_bytes();
			client.send_to(&payload, listen).await.unwrap();
			expected.insert((peer_addr, payload));
		}
		clients.push(client);
	}

	// Wait until the backend has collected every datagram (or time out).
	let mut waited_ms: u64 = 0;
	loop {
		if collected.lock().unwrap().len() >= TOTAL {
			break;
		}
		assert!(
			waited_ms < 5000,
			"backend did not receive all {TOTAL} datagrams in time"
		);
		tokio::time::sleep(Duration::from_millis(50)).await;
		waited_ms += 50;
	}

	// Accounting closes: received == relayed + Σ dropped == N, with zero drops on the clean path.
	assert_eq!(counters.received(), total, "every sent datagram must be received");
	assert_eq!(
		counters.relayed(),
		total,
		"every datagram must be relayed on the clean path"
	);
	assert_eq!(
		counters.total_dropped(),
		0,
		"no datagram may be dropped on the clean path"
	);
	assert_eq!(
		counters.received(),
		counters.relayed() + counters.total_dropped(),
		"the accounting invariant must hold",
	);

	// Every payload byte-identical and every peer equal to the real sender's ip:port.
	let received: Vec<Datagram> = collected.lock().unwrap().clone();
	assert_eq!(received.len(), TOTAL);
	let got: HashSet<(SocketAddr, Vec<u8>)> = received
		.iter()
		.map(|d| (d.peer.socket_addr(), d.payload.clone()))
		.collect();
	assert_eq!(
		got, expected,
		"the backend must see exactly the datagrams sent, with real peer addresses"
	);

	shutdown.cancel();
}

// Linux-only: with SO_REUSEPORT, N workers bind the same port and the kernel flow-hashes datagrams
// across them. Shared counters must sum to the full total and the backend must collect every datagram,
// proving the multi-worker path accounts correctly (not just that it binds).
#[cfg(target_os = "linux")]
#[tokio::test]
async fn ingress_reuseport_multi_worker_accounts_all_datagrams() {
	let (backend_addr, collected) = spawn_quic_envelope_backend().await;
	let backend: BackendConfig = BackendConfig::new("ingest", backend_addr, 1.0, TransportKind::Quic).unwrap();
	let listen: SocketAddr = free_udp_port().await;
	let shutdown: CancellationToken = CancellationToken::new();
	let mut params: UdpIngressParams = ingress_params(listen, backend, client_config(), shutdown.clone());
	params.config.workers = 4;

	let counters = udp::spawn_udp_ingress(&params).expect("four SO_REUSEPORT workers must bind the same port");

	const PEERS: usize = 8;
	const PER_PEER: usize = 25;
	const TOTAL: usize = PEERS * PER_PEER;
	let total: u64 = u64::try_from(TOTAL).unwrap();
	let mut clients: Vec<UdpSocket> = Vec::new();
	for peer_index in 0..PEERS {
		let client: UdpSocket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		for msg_index in 0..PER_PEER {
			let payload: Vec<u8> = format!("w-peer{peer_index}-msg{msg_index}").into_bytes();
			client.send_to(&payload, listen).await.unwrap();
		}
		clients.push(client);
	}

	let mut waited_ms: u64 = 0;
	loop {
		if collected.lock().unwrap().len() >= TOTAL {
			break;
		}
		assert!(
			waited_ms < 5000,
			"multi-worker backend did not receive all {TOTAL} datagrams in time"
		);
		tokio::time::sleep(Duration::from_millis(50)).await;
		waited_ms += 50;
	}

	assert_eq!(
		counters.received(),
		total,
		"shared counters must sum every worker's receives"
	);
	assert_eq!(
		counters.relayed(),
		total,
		"every datagram must be relayed across workers"
	);
	assert_eq!(counters.total_dropped(), 0, "no drops on the clean multi-worker path");
	assert_eq!(collected.lock().unwrap().len(), TOTAL);
	shutdown.cancel();
}

#[tokio::test]
async fn ingress_disabled_leaves_port_unbound_and_backend_empty() {
	// Diff against disabled: with no ingress spawned, the port is unbound; datagrams sent there reach
	// nothing, so the backend collects zero frames. Mode off must not silently swallow data.
	let (_backend_addr, collected) = spawn_quic_envelope_backend().await;
	let listen: SocketAddr = free_udp_port().await;

	let client: UdpSocket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	for i in 0..20u8 {
		// UDP send to an unbound port is fire-and-forget; it must simply go nowhere.
		let _ = client.send_to(&[i], listen).await;
	}
	tokio::time::sleep(Duration::from_millis(300)).await;
	assert!(
		collected.lock().unwrap().is_empty(),
		"with no ingress bound, the backend must receive nothing",
	);
}

// A QUIC backend for the TCP path: consume STREAM_TYPE_RAW + preamble + Hello + Open{peer} (recording
// the peer), then echo every subsequent raw byte back. Returns its address and the observed peer slot.
async fn spawn_quic_tcp_echo_backend() -> (SocketAddr, Arc<Mutex<Option<SocketAddr>>>) {
	install_provider();
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
	let endpoint = Endpoint::server(
		QuinnServerConfig::with_crypto(Arc::new(quic_crypto)),
		"127.0.0.1:0".parse().unwrap(),
	)
	.unwrap();
	let addr: SocketAddr = endpoint.local_addr().unwrap();

	let observed_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
	let observed_srv: Arc<Mutex<Option<SocketAddr>>> = Arc::clone(&observed_peer);

	tokio::spawn(async move {
		while let Some(incoming) = endpoint.accept().await {
			let Ok(connection) = incoming.await else {
				continue;
			};
			let observed_conn: Arc<Mutex<Option<SocketAddr>>> = Arc::clone(&observed_srv);
			tokio::spawn(async move {
				while let Ok((mut send, mut recv)) = connection.accept_bi().await {
					let observed_stream: Arc<Mutex<Option<SocketAddr>>> = Arc::clone(&observed_conn);
					tokio::spawn(async move {
						let mut stream_type: [u8; 1] = [0u8; 1];
						if recv.read_exact(&mut stream_type).await.is_err() || stream_type[0] != STREAM_TYPE_RAW {
							return;
						}
						if protocol::read_preamble(&mut recv).await.is_err() {
							return;
						}
						// Hello, then Open{peer}.
						match protocol::read_frame(&mut recv).await {
							Ok(Envelope::Hello { .. }) => {}
							_ => return,
						}
						match protocol::read_frame(&mut recv).await {
							Ok(Envelope::Open { peer }) => {
								*observed_stream.lock().unwrap() = Some(peer.socket_addr());
							}
							_ => return,
						}
						// Echo the raw byte stream that follows the Open frame.
						let mut buf: [u8; 4096] = [0u8; 4096];
						loop {
							// quinn's inherent RecvStream::read yields Ok(Some(n)) / Ok(None) at EOF.
							match recv.read(&mut buf).await {
								Ok(Some(n)) => {
									if send.write_all(&buf[..n]).await.is_err() {
										return;
									}
									let _ = send.flush().await;
								}
								Ok(None) | Err(_) => return,
							}
						}
					});
				}
			});
		}
	});

	return (addr, observed_peer);
}

async fn free_tcp_port() -> SocketAddr {
	let probe: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr: SocketAddr = probe.local_addr().unwrap();
	drop(probe);
	return addr;
}

fn tcp_ingress_config(listen: SocketAddr) -> reduction::config::IngressConfig {
	return reduction::config::IngressConfig {
		id: ArrayString::from("site-tcp").unwrap(),
		protocol: IngressProtocol::Tcp,
		listen,
		workers: 1,
		recv_buffer_bytes: 8 * 1024 * 1024,
		max_datagram_bytes: 8192,
		backend_ids: vec![ArrayString::from("ingest").unwrap()],
		batch_max_datagrams: 512,
		batch_max_bytes: 61440,
		linger_ms: 10,
		queue_depth_per_backend: 4096,
		max_connections: Some(100),
		idle_timeout_secs: Some(60),
	};
}

#[tokio::test]
async fn tcp_ingress_relays_bytes_and_preserves_peer() {
	let (backend_addr, observed_peer) = spawn_quic_tcp_echo_backend().await;
	let backend: BackendConfig = BackendConfig::new("ingest", backend_addr, 1.0, TransportKind::Quic).unwrap();
	let listen: SocketAddr = free_tcp_port().await;
	let shutdown: CancellationToken = CancellationToken::new();
	let (_health_tx, health_rx): (watch::Sender<HealthState>, watch::Receiver<HealthState>) =
		watch::channel(HealthState::new());

	let params: TcpIngressParams = TcpIngressParams {
		config: tcp_ingress_config(listen),
		backends: vec![backend],
		acl: reduction::acl::AccessControl::new(vec![], vec![]),
		requests_per_second: 1_000_000,
		conn_pool: Arc::new(ConnPool::new()),
		client_tls_config: client_config(),
		health_rx,
		circuit: Arc::new(CircuitBreakers::new(&CircuitBreakerConfig::default())),
		connect_timeout: Duration::from_secs(5),
		max_backends: 64,
		shutdown: shutdown.clone(),
	};
	let counters = tcp::spawn_tcp_ingress(params).await.expect("tcp ingress must bind");

	// Connect, send a payload, and read the echo back through the relay.
	let mut client: TcpStream = TcpStream::connect(listen).await.unwrap();
	let sender_addr: SocketAddr = client.local_addr().unwrap();
	client.write_all(b"ping-through-tcp-ingress").await.unwrap();
	let mut echoed: [u8; 24] = [0u8; 24];
	tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echoed))
		.await
		.expect("echo must return within the timeout")
		.expect("the relay must echo the payload back");
	assert_eq!(
		&echoed, b"ping-through-tcp-ingress",
		"the byte stream must relay unframed and intact"
	);

	assert_eq!(counters.accepted(), 1, "the connection must be counted as accepted");
	assert_eq!(counters.total_dropped(), 0, "no drop on the clean TCP path");
	assert_eq!(
		observed_peer.lock().unwrap().as_ref(),
		Some(&sender_addr),
		"the Open frame must carry the real TCP client's ip:port",
	);

	shutdown.cancel();
}

#[tokio::test]
async fn tcp_ingress_disabled_leaves_port_unbound() {
	// Diff against disabled: with no TCP ingress bound, connecting to the port fails.
	let listen: SocketAddr = free_tcp_port().await;
	let result = tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(listen)).await;
	// Either the connect returns an error (refused) or times out — in no case does it succeed.
	let connected: bool = matches!(result, Ok(Ok(_)));
	assert!(
		!connected,
		"with no TCP ingress bound, the port must not accept connections"
	);
}
