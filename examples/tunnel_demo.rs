mod support;

use std::future::pending;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arrayvec::ArrayString;
use core_utils::clock::current_unix_millis;
use http::header::CONTENT_TYPE;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use quinn::crypto::rustls::QuicClientConfig;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use reduction::acl::AccessControl;
use reduction::balancer::BackendPool;
use reduction::body::Body;
use reduction::circuit::CircuitBreakers;
use reduction::config::{
	BackendConfig, CircuitBreakerConfig, ClientAuthPolicy, DeviceIdSource, MAX_BACKEND_ID_LEN,
	ProxyConfig,
	RetryConfig, RouteConfig, Stickiness, TimeoutConfig, TransportKind, TunnelConfig,
};
use reduction::fast_hash::FastMap;
use reduction::health::HealthState;
use reduction::metrics::ProxyMetrics;
use reduction::proxy::server::serve;
use reduction::proxy::{ConnPool, HttpAuthz, ProxyState, ReloadableState, Router};
use reduction::ratelimit::RateLimit;
use reduction::label_intern::LabelInterner;
use reduction::snapshot_map::SnapshotMap;
use reduction::tls;
use reduction::transport::quic::QuicStream;
use reduction::tunnel::protocol::{self, SessionId, TunnelFrame};
use reduction::tunnel::registry::TunnelRegistry;
use reduction::tunnel::revocation::RevocationSet;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::support::Context;

// This demo also shows the tunnel listener's own info logs next to the demo text.
const LIBRARY_LOG_LEVEL: &str = "info";
const PROXY_PORT: u16 = 18443;
const TUNNEL_PORT: NonZeroU16 = NonZeroU16::MIN.saturating_add(18444 - 1);
const BACKEND_ID: &str = "tunnel-backend";
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const MAX_TUNNEL_SESSIONS: u32 = 8;
const DEFAULT_QUEUE_DEPTH: u32 = 1000;
const STARTUP_SETTLE: Duration = Duration::from_millis(500);
const SHUTDOWN_SETTLE: Duration = Duration::from_millis(200);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

const TOPOLOGY_NOTES: [&str; 4] = [
	"",
	"  The backend INITIATED the QUIC connection to the proxy.",
	"  The proxy opens new streams on that connection to forward requests.",
	"  No inbound ports needed on the backend side.",
];

#[tokio::main]
async fn main() -> Result<(), String> {
	rustls::crypto::aws_lc_rs::default_provider()
		.install_default()
		.map_err(|_| "install rustls crypto provider: a provider is already installed".to_owned())?;

	tracing_subscriber::registry()
		.with(support::output_layer(LIBRARY_LOG_LEVEL))
		.init();

	info!("Reduction - NAT Traversal Tunnel Demo");
	info!("======================================");

	let dir = tempfile::tempdir().context("create temp dir")?;
	let dir_path = dir.path();

	// -- Phase 1: TLS certificates --
	info!("-- Phase 1: TLS Certificate Generation --");
	generate_certs(dir_path)?;

	// -- Phase 2: Start proxy with tunnel listener --
	info!("-- Phase 2: Start Proxy with Tunnel Listener --");
	let shutdown: CancellationToken = CancellationToken::new();
	let tunnel_registry: &'static TunnelRegistry = Box::leak(Box::new(TunnelRegistry::new(MAX_TUNNEL_SESSIONS)));
	start_proxy(dir_path, tunnel_registry, &shutdown).await?;
	tokio::time::sleep(STARTUP_SETTLE).await;
	info!("  Proxy (:{PROXY_PORT}) and tunnel listener (:{TUNNEL_PORT}) started");

	// -- Phase 3: Backend connects via reverse tunnel --
	let backend_shutdown = CancellationToken::new();
	show_registration(dir_path, tunnel_registry, backend_shutdown.clone()).await?;

	// -- Phase 4: Client sends requests through tunnel --
	show_client_requests(dir_path).await?;

	// -- Phase 5: Show tunnel topology --
	show_topology();

	// -- Cleanup --
	backend_shutdown.cancel();
	shutdown.cancel();
	tokio::time::sleep(SHUTDOWN_SETTLE).await;

	info!("-- Demo Complete --");
	return Ok(());
}

const REGISTRATION_INTRO: [&str; 4] = [
	"-- Phase 3: Backend Registers via Reverse Tunnel --",
	"  Backend behind NAT dials the proxy's tunnel listener.",
	"  (In production, the backend is behind a firewall and cannot",
	"   accept inbound connections — it initiates the connection.)",
];

fn show_lines<S: AsRef<str>>(lines: &[S]) {
	lines.iter().for_each(|line| info!("{}", line.as_ref()));
}

async fn show_registration(
	dir: &Path,
	tunnel_registry: &TunnelRegistry,
	backend_shutdown: CancellationToken,
) -> Result<(), String> {
	show_lines(&REGISTRATION_INTRO);

	let session_id = start_tunnel_backend(dir, backend_shutdown).await?;
	tokio::time::sleep(STARTUP_SETTLE).await;

	let sessions = tunnel_registry.session_count(BACKEND_ID);
	show_lines(&[
		format!("  Session ID: {session_id}"),
		format!("  Active tunnel sessions for '{BACKEND_ID}': {sessions}"),
		"  Backend is now reachable through the proxy!".to_owned(),
	]);
	return Ok(());
}

async fn show_client_requests(dir: &Path) -> Result<(), String> {
	info!("-- Phase 4: Client Requests Routed Through Tunnel --");
	let client_connector = build_client_connector(dir)?;
	let proxy_addr: SocketAddr = SocketAddr::new(LOOPBACK, PROXY_PORT);

	let requests: [(&str, &str, &str); 3] = [
		("POST", "/api/echo", "hello through tunnel"),
		("GET", "/api/status", ""),
		("POST", "/api/data", r#"{"sensor":"temp-01","value":23.5}"#),
	];
	for (method, path, body) in requests {
		let resp = send_request(&client_connector, proxy_addr, method, path, body).await?;
		info!("  {method:<4} {path} -> {resp}");
	}
	return Ok(());
}

fn show_topology() {
	show_lines(&[
		"-- Phase 5: Tunnel Topology --".to_owned(),
		"  ┌──────────┐      mTLS/TCP      ┌───────────┐    Tunnel QUIC     ┌──────────────┐".to_owned(),
		"  │  Client   │ ───────────────►  │ Reduction │ ◄─────────────────  │  Backend     │".to_owned(),
		"  │           │  POST /api        │   Proxy   │   (reverse tunnel)  │  (behind NAT)│".to_owned(),
		format!("  │           │                   │  :{PROXY_PORT}   │   :{TUNNEL_PORT}             │              │"),
		"  └──────────┘                    └───────────┘                     └──────────────┘".to_owned(),
	]);
	show_lines(&TOPOLOGY_NOTES);
}

// ---------------------------------------------------------------------------
// Certificate generation (same pattern as demo.rs)
// ---------------------------------------------------------------------------

fn generate_certs(dir: &Path) -> Result<(), String> {
	let (ca_cert, ca_key) = generate_ca()?;
	let (server_cert, server_key) = generate_signed_cert(
		&ca_cert,
		&ca_key,
		"Reduction Server",
		vec![SanType::IpAddress(LOOPBACK)],
	)?;
	// The client cert's CN must equal BACKEND_ID: the tunnel listener binds a registration's
	// backend_id to the certificate CN (identity binding), so the reverse tunnel authenticates as
	// this backend.
	let (client_cert, client_key) = generate_signed_cert(&ca_cert, &ca_key, BACKEND_ID, vec![])?;

	let files: [(&str, String); 5] = [
		("ca.crt", ca_cert.pem()),
		("server.crt", server_cert.pem()),
		("server.key", server_key.serialize_pem()),
		("client.crt", client_cert.pem()),
		("client.key", client_key.serialize_pem()),
	];
	files
		.iter()
		.try_for_each(|(name, pem)| write_file(&dir.join(name), pem))?;

	[
		"CA certificate",
		"Server certificate (SAN: 127.0.0.1)",
		"Client certificate (mTLS)",
	]
	.iter()
	.for_each(|made| info!("  [ok] {made}"));
	return Ok(());
}

fn write_file(path: &Path, contents: &str) -> Result<(), String> {
	return fs::write(path, contents).context(&format!("write {}", path.display()));
}

fn generate_ca() -> Result<(rcgen::Certificate, KeyPair), String> {
	let mut params = CertificateParams::new(vec![]).context("CA params")?;
	params.distinguished_name.push(DnType::CommonName, "Reduction Demo CA");
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let key = KeyPair::generate().context("CA key")?;
	let cert = params.self_signed(&key).context("self-sign CA")?;
	return Ok((cert, key));
}

fn generate_signed_cert(
	ca_cert: &rcgen::Certificate,
	ca_key: &KeyPair,
	cn: &str,
	sans: Vec<SanType>,
) -> Result<(rcgen::Certificate, KeyPair), String> {
	let mut params = CertificateParams::new(vec![]).context(&format!("{cn} params"))?;
	params.distinguished_name.push(DnType::CommonName, cn);
	params.subject_alt_names = sans;
	let key = KeyPair::generate().context(&format!("{cn} key"))?;
	let issuer = rcgen::Issuer::from_ca_cert_der(ca_cert.der(), ca_key).context("CA issuer")?;
	let cert = params.signed_by(&key, &issuer).context(&format!("sign {cn}"))?;
	return Ok((cert, key));
}

// ---------------------------------------------------------------------------
// Proxy setup with tunnel support
// ---------------------------------------------------------------------------

fn array_id<const N: usize>(id: &str) -> Result<ArrayString<N>, String> {
	return ArrayString::from(id).context(&format!("id {id}"));
}

fn build_backend_pools(
	backends: &[BackendConfig],
	routes: &[(&str, &str)],
) -> Result<FastMap<ArrayString<MAX_BACKEND_ID_LEN>, BackendPool>, String> {
	let mut pools: FastMap<ArrayString<MAX_BACKEND_ID_LEN>, BackendPool> = FastMap::default();
	for (_, backend_id) in routes {
		let bs: Vec<BackendConfig> = backends
			.iter()
			.filter(|b| b.pool.as_str() == *backend_id)
			.cloned()
			.collect();
		if !bs.is_empty() && !pools.contains_key(*backend_id) {
			let pool: BackendPool = BackendPool::new(bs).context(&format!("pool {backend_id}"))?;
			pools.insert(array_id(backend_id)?, pool);
		}
	}
	return Ok(pools);
}

fn build_reloadable() -> Result<ReloadableState, String> {
	// The tunnel backend has no static address — it connects to us.
	// We still need a BackendConfig for route matching; address is a placeholder.
	let placeholder: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
	let backends: Vec<BackendConfig> =
		vec![BackendConfig::new(BACKEND_ID, placeholder, 1.0, TransportKind::Tcp).context("tunnel backend config")?];
	let routes: Vec<(&str, &str)> = vec![("/api", BACKEND_ID)];

	let route_configs: Vec<RouteConfig> = routes
		.iter()
		.map(|(prefix, id)| {
			return Ok(RouteConfig {
				path_prefix: array_id(prefix)?,
				backend_id: Some(array_id(id)?),
				timeout_secs: None,
				is_wakeable: false,
				stickiness: Stickiness::Identity,
				allows_spill_on_exhaustion: false,
				split: Vec::new(),
			});
		})
		.collect::<Result<Vec<RouteConfig>, String>>()?;

	return Ok(ReloadableState {
		router: Router::new(&route_configs),
		backend_pools: build_backend_pools(&backends, &routes)?,
		acl: AccessControl::new(vec![], vec![]),
	});
}

async fn start_proxy(
	dir: &Path,
	tunnel_registry: &'static TunnelRegistry,
	shutdown: &CancellationToken,
) -> Result<(), String> {
	let (server_tls_config, _) =
		tls::build_server_config(&dir.join("server.crt"), &dir.join("server.key"), &dir.join("ca.crt"))
			.context("proxy server TLS config")?;
	let server_tls: Arc<rustls::ServerConfig> = Arc::new(server_tls_config);

	let (client_tls_config, _, _) =
		tls::build_client_config(&dir.join("client.crt"), &dir.join("client.key"), &dir.join("ca.crt"))
			.context("proxy client TLS config")?;
	let client_tls: Arc<rustls::ClientConfig> = Arc::new(client_tls_config);
	let tls_connector: TlsConnector = TlsConnector::from(Arc::clone(&client_tls));

	let (_, reloadable_rx) = watch::channel(build_reloadable()?);
	let (_, health_rx) = watch::channel(HealthState::new());
	let (_, revocation_rx) = watch::channel(RevocationSet::default());

	let conn_pool: ConnPool = ConnPool::new().with_tunnel_registry(tunnel_registry);

	let proxy_state: &'static ProxyState = Box::leak(Box::new(ProxyState {
		reloadable: reloadable_rx,
		revocation: revocation_rx.clone(),
		tls_connector,
		client_tls_config: client_tls,
		health_rx,
		conn_pool,
		rate_limiter: RateLimit::new(None),
		queues: SnapshotMap::new(),
		labels: LabelInterner::new(),
		default_queue_depth: DEFAULT_QUEUE_DEPTH,
		metrics: ProxyMetrics::new(),
		circuit_breakers: CircuitBreakers::new(&CircuitBreakerConfig::default()),
		shutdown: shutdown.clone(),
		timeouts: TimeoutConfig::default(),
		proxy_config: ProxyConfig::default(),
		retry_config: RetryConfig::default(),
		client_auth: ClientAuthPolicy::Required,
		device_id_source: DeviceIdSource::UidOrCn,
		http_authz: HttpAuthz::default(),
	}));

	// Start TCP proxy listener
	let proxy_addr: SocketAddr = SocketAddr::new(LOOPBACK, PROXY_PORT);
	let proxy_listener = reduction::transport::tcp::TcpListener::bind(proxy_addr, Arc::clone(&server_tls), None)
		.await
		.context(&format!("bind proxy {proxy_addr}"))?;

	tokio::spawn(async move {
		if let Err(e) = serve(proxy_listener, proxy_state, None, pending::<()>()).await {
			error!("proxy server stopped: {e}");
		}
	});

	// Start tunnel listener (QUIC, for backend registration)
	let tunnel_addr: SocketAddr = SocketAddr::new(LOOPBACK, TUNNEL_PORT.get());
	let tunnel_config: TunnelConfig = TunnelConfig {
		is_enabled: true,
		listen_address: Some(LOOPBACK),
		listen_port: TUNNEL_PORT,
		..TunnelConfig::default()
	};

	let listener_shutdown: CancellationToken = shutdown.clone();
	tokio::spawn(async move {
		if let Err(e) = reduction::tunnel::listener::run_tunnel_listener(
			tunnel_addr,
			server_tls,
			tunnel_registry,
			listener_shutdown,
			tunnel_config,
			ProxyMetrics::new(),
			revocation_rx,
		)
		.await
		{
			error!("tunnel listener error: {e}");
		}
	});
	return Ok(());
}

// ---------------------------------------------------------------------------
// Simulated backend behind NAT (connects TO the proxy via reverse tunnel)
// ---------------------------------------------------------------------------

async fn connect_tunnel(dir: &Path) -> Result<quinn::Connection, String> {
	let (client_tls_config, _, _) =
		tls::build_client_config(&dir.join("client.crt"), &dir.join("client.key"), &dir.join("ca.crt"))
			.context("backend client TLS config")?;
	let client_tls: Arc<rustls::ClientConfig> = Arc::new(client_tls_config);

	let quic_crypto: QuicClientConfig = QuicClientConfig::try_from(client_tls).context("QUIC client crypto config")?;
	let mut quic_client_config: quinn::ClientConfig = quinn::ClientConfig::new(Arc::new(quic_crypto));
	quic_client_config.transport_config(Arc::new(quinn::TransportConfig::default()));

	let any_local: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
	let mut endpoint: quinn::Endpoint = quinn::Endpoint::client(any_local).context("QUIC client endpoint")?;
	endpoint.set_default_client_config(quic_client_config);

	// Connect to the proxy's tunnel listener
	let tunnel_addr: SocketAddr = SocketAddr::new(LOOPBACK, TUNNEL_PORT.get());
	let connection: quinn::Connection = endpoint
		.connect(tunnel_addr, "127.0.0.1")
		.context("QUIC connect config")?
		.await
		.context("QUIC handshake")?;

	info!("  [ok] QUIC connection established to proxy tunnel listener");
	return Ok(connection);
}

// Register over the control channel (the first bidi stream). The result holds the session ID from the proxy.
async fn register(connection: &quinn::Connection) -> Result<(QuicStream, SessionId), String> {
	let (send, recv) = connection.open_bi().await.context("open control stream")?;
	let mut control_stream: QuicStream = QuicStream::new(send, recv);

	// Version preamble, then the Register frame
	protocol::write_preamble(&mut control_stream)
		.await
		.context("send protocol preamble")?;
	let register: TunnelFrame = TunnelFrame::Register {
		backend_id: array_id(BACKEND_ID)?,
		pool: array_id(BACKEND_ID)?,
		capabilities: ["http"]
			.iter()
			.map(|s| ArrayString::from(s).context("capability"))
			.collect::<Result<_, String>>()?,
	};
	protocol::write_frame(&mut control_stream, &register)
		.await
		.context("send Register")?;
	info!("  [ok] Sent Register frame (backend_id: {BACKEND_ID})");

	// The server answers with its own preamble before any frame
	let server_version: u8 = protocol::read_preamble(&mut control_stream)
		.await
		.context("read server preamble")?;
	if server_version != protocol::PROTOCOL_VERSION {
		return Err(format!(
			"server speaks protocol version {server_version}, this demo speaks {}",
			protocol::PROTOCOL_VERSION
		));
	}

	// Read RegisterAck
	let ack: TunnelFrame = protocol::read_frame(&mut control_stream)
		.await
		.context("read RegisterAck")?;
	return match ack {
		TunnelFrame::RegisterAck { session_id } => {
			info!("  [ok] Received RegisterAck (session: {})", session_id);
			Ok((control_stream, session_id))
		}
		other => Err(format!("expected RegisterAck, got {other:?}")),
	};
}

// Send heartbeats on the control channel until shutdown, then say goodbye.
fn spawn_heartbeat(mut control_stream: QuicStream, shutdown: CancellationToken) -> Result<(), String> {
	let goodbye: TunnelFrame = TunnelFrame::Shutdown {
		reason: ArrayString::from("demo ending").context("shutdown reason")?,
	};
	tokio::spawn(async move {
		let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
		loop {
			tokio::select! {
				_ = interval.tick() => {
					let frame: TunnelFrame = TunnelFrame::Heartbeat { timestamp_ms: current_unix_millis() };
					if protocol::write_frame(&mut control_stream, &frame).await.is_err() {
						break;
					}
					// Read HeartbeatAck (ignore errors — proxy may have shut down)
					let _ = protocol::read_frame(&mut control_stream).await;
				}
				_ = shutdown.cancelled() => {
					let _ = protocol::write_frame(&mut control_stream, &goodbye).await;
					break;
				}
			}
		}
	});
	return Ok(());
}

// Serve HTTP/1.1 on each stream the proxy opens on the tunnel connection.
fn spawn_stream_acceptor(conn: quinn::Connection, shutdown: CancellationToken) {
	tokio::spawn(async move {
		loop {
			tokio::select! {
				result = conn.accept_bi() => {
					let Ok((send, recv)) = result else { break };
					let io: TokioIo<QuicStream> = TokioIo::new(QuicStream::new(send, recv));
					tokio::spawn(async move {
						let service = service_fn(backend_handler);
						if let Err(e) = server_http1::Builder::new().serve_connection(io, service).await {
							warn!("backend HTTP error: {e}");
						}
					});
				}
				_ = shutdown.cancelled() => break,
			}
		}
	});
}

async fn start_tunnel_backend(dir: &Path, shutdown: CancellationToken) -> Result<SessionId, String> {
	let connection: quinn::Connection = connect_tunnel(dir).await?;
	let (control_stream, session_id) = register(&connection).await?;
	spawn_heartbeat(control_stream, shutdown.clone())?;
	spawn_stream_acceptor(connection, shutdown);
	return Ok(session_id);
}

async fn backend_handler(req: Request<Incoming>) -> Result<Response<Body>, hyper::Error> {
	let path: String = req.uri().path().to_owned();
	let method: String = req.method().to_string();
	let body_bytes = req
		.into_body()
		.collect()
		.await
		.map(|b| b.to_bytes())
		.unwrap_or_default();
	let body_str: String = String::from_utf8_lossy(&body_bytes).into_owned();

	let response_body: String = if body_str.is_empty() {
		format!(r#"{{"path":"{path}","method":"{method}","backend":"{BACKEND_ID}","transport":"reverse-tunnel"}}"#,)
	} else {
		format!(
			r#"{{"path":"{path}","method":"{method}","backend":"{BACKEND_ID}","transport":"reverse-tunnel","received":"{body_str}"}}"#,
		)
	};

	// Response::new defaults to 200 OK; building it directly cannot fail, unlike Response::builder().
	let mut response: Response<Body> = Response::new(Body::from(response_body));
	response
		.headers_mut()
		.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
	return Ok(response);
}

// ---------------------------------------------------------------------------
// mTLS client (same pattern as demo.rs)
// ---------------------------------------------------------------------------

fn build_client_connector(dir: &Path) -> Result<TlsConnector, String> {
	let (client_config, _, _): (rustls::ClientConfig, _, _) =
		tls::build_client_config(&dir.join("client.crt"), &dir.join("client.key"), &dir.join("ca.crt"))
			.context("demo client TLS config")?;
	return Ok(TlsConnector::from(Arc::new(client_config)));
}

async fn send_request(
	connector: &TlsConnector,
	addr: SocketAddr,
	method: &str,
	path: &str,
	body: &str,
) -> Result<String, String> {
	let tcp: TcpStream = TcpStream::connect(addr).await.context(&format!("connect {addr}"))?;
	let server_name: ServerName<'static> = ServerName::IpAddress(addr.ip().into());
	let tls = connector
		.connect(server_name, tcp)
		.await
		.context("client TLS handshake")?;
	let io = TokioIo::new(tls);

	let (mut sender, conn) = http1::handshake(io).await.context("HTTP/1 handshake")?;
	tokio::spawn(conn);

	let req: Request<Body> = Request::builder()
		.method(method)
		.uri(path)
		.header("host", format!("127.0.0.1:{}", addr.port()))
		.body(Body::from(body.to_owned()))
		.context(&format!("build {method} {path}"))?;

	let response = sender
		.send_request(req)
		.await
		.context(&format!("send {method} {path}"))?;
	let status: StatusCode = response.status();
	let bytes = response
		.into_body()
		.collect()
		.await
		.context("read response body")?
		.to_bytes();
	let body_str: String = String::from_utf8_lossy(&bytes).into_owned();

	return Ok(format!("{status} {body_str}"));
}
