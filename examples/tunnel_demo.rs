// Example/demo code, outside the production lint gate (which lints only --lib --bins). Demos use
// unwrap/expect/panic, `&str` .to_string(), and lossy casts freely to stay readable; relax those
// restriction lints here rather than clutter the demo with error plumbing.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::str_to_string)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arrayvec::ArrayString;
use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::{Request, Response, StatusCode};
use axum::routing::any;
use http_body_util::BodyExt;
use hyper::client::conn::http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use dashmap::DashMap;
use quinn::crypto::rustls::QuicClientConfig;
use reduction::balancer::BackendPool;
use reduction::circuit::CircuitBreakers;
use reduction::config::{
    BackendConfig, CircuitBreakerConfig, TimeoutConfig, TransportKind,
    TunnelConfig,
};
use reduction::health::HealthState;
use reduction::metrics::ProxyMetrics;
use reduction::acl::AccessControl;
use reduction::cache::ResponseCache;
use reduction::config::CacheConfig;
use reduction::proxy::{ConnPool, ProxyState, ReloadableState, Router, proxy_handler};
use reduction::ratelimit::RateLimit;
use reduction::tls;
use reduction::transport::quic::QuicStream;
use reduction::tunnel::protocol::{self, SessionId, TunnelFrame};
use reduction::tunnel::registry::TunnelRegistry;

const PROXY_PORT: u16 = 18443;
const TUNNEL_PORT: u16 = 18444;
const BACKEND_ID: &str = "tunnel-backend";

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("Reduction - NAT Traversal Tunnel Demo");
    println!("======================================\n");

    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path();

    // -- Phase 1: TLS certificates --
    println!("-- Phase 1: TLS Certificate Generation --\n");
    generate_certs(dir_path);
    println!();

    // -- Phase 2: Start proxy with tunnel listener --
    println!("-- Phase 2: Start Proxy with Tunnel Listener --\n");
    let shutdown = CancellationToken::new();
    let tunnel_registry = Arc::new(TunnelRegistry::new(8));
    start_proxy(dir_path, Arc::clone(&tunnel_registry), shutdown.clone()).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("  Proxy (:{PROXY_PORT}) and tunnel listener (:{TUNNEL_PORT}) started\n");

    // -- Phase 3: Backend connects via reverse tunnel --
    println!("-- Phase 3: Backend Registers via Reverse Tunnel --\n");
    println!("  Backend behind NAT dials the proxy's tunnel listener.");
    println!("  (In production, the backend is behind a firewall and cannot");
    println!("   accept inbound connections — it initiates the connection.)\n");

    let backend_shutdown = CancellationToken::new();
    let session_id = start_tunnel_backend(
        dir_path,
        backend_shutdown.clone(),
    ).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let sessions = tunnel_registry.session_count(BACKEND_ID);
    println!("  Session ID: {session_id}");
    println!("  Active tunnel sessions for '{BACKEND_ID}': {sessions}");
    println!("  Backend is now reachable through the proxy!\n");

    // -- Phase 4: Client sends requests through tunnel --
    println!("-- Phase 4: Client Requests Routed Through Tunnel --\n");
    let client_connector = build_client_connector(dir_path);
    let proxy_addr: SocketAddr = ([127, 0, 0, 1], PROXY_PORT).into();

    let resp = send_request(
        &client_connector, proxy_addr, "POST", "/api/echo",
        "hello through tunnel",
    ).await;
    println!("  POST /api/echo -> {resp}");

    let resp = send_request(
        &client_connector, proxy_addr, "GET", "/api/status", "",
    ).await;
    println!("  GET  /api/status -> {resp}");

    let resp = send_request(
        &client_connector, proxy_addr, "POST", "/api/data",
        r#"{"sensor":"temp-01","value":23.5}"#,
    ).await;
    println!("  POST /api/data -> {resp}");

    // -- Phase 5: Show tunnel topology --
    println!("\n-- Phase 5: Tunnel Topology --\n");
    println!("  ┌──────────┐      mTLS/TCP      ┌───────────┐    Tunnel QUIC     ┌──────────────┐");
    println!("  │  Client   │ ───────────────►  │ Reduction │ ◄─────────────────  │  Backend     │");
    println!("  │           │  POST /api        │   Proxy   │   (reverse tunnel)  │  (behind NAT)│");
    println!("  │           │                   │  :{PROXY_PORT}   │   :{TUNNEL_PORT}             │              │");
    println!("  └──────────┘                    └───────────┘                     └──────────────┘");
    println!();
    println!("  The backend INITIATED the QUIC connection to the proxy.");
    println!("  The proxy opens new streams on that connection to forward requests.");
    println!("  No inbound ports needed on the backend side.\n");

    // -- Cleanup --
    backend_shutdown.cancel();
    shutdown.cancel();
    tokio::time::sleep(Duration::from_millis(200)).await;

    println!("-- Demo Complete --");
}

// ---------------------------------------------------------------------------
// Certificate generation (same pattern as demo.rs)
// ---------------------------------------------------------------------------

fn generate_certs(dir: &Path) {
    let (ca_cert, ca_key) = generate_ca();
    let (server_cert, server_key) = generate_signed_cert(
        &ca_cert, &ca_key, "Reduction Server",
        vec![SanType::IpAddress(IpAddr::from([127, 0, 0, 1]))],
    );
    let (client_cert, client_key) = generate_signed_cert(
        &ca_cert, &ca_key, "Reduction Client", vec![],
    );

    std::fs::write(dir.join("ca.crt"), ca_cert.pem()).unwrap();
    std::fs::write(dir.join("server.crt"), server_cert.pem()).unwrap();
    std::fs::write(dir.join("server.key"), server_key.serialize_pem()).unwrap();
    std::fs::write(dir.join("client.crt"), client_cert.pem()).unwrap();
    std::fs::write(dir.join("client.key"), client_key.serialize_pem()).unwrap();

    println!("  [ok] CA certificate");
    println!("  [ok] Server certificate (SAN: 127.0.0.1)");
    println!("  [ok] Client certificate (mTLS)");
}

fn generate_ca() -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.distinguished_name.push(DnType::CommonName, "Reduction Demo CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert, key)
}

fn generate_signed_cert(
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
    cn: &str,
    sans: Vec<SanType>,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.subject_alt_names = sans;
    let key = KeyPair::generate().unwrap();
    let issuer = rcgen::Issuer::from_ca_cert_der(ca_cert.der(), ca_key).unwrap();
    let cert = params.signed_by(&key, &issuer).unwrap();
    (cert, key)
}

// ---------------------------------------------------------------------------
// Proxy setup with tunnel support
// ---------------------------------------------------------------------------

fn build_backend_pools(backends: &[BackendConfig], routes: &[(&str, &str)]) -> HashMap<ArrayString<256>, BackendPool> {
    let mut pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();
    for (_, backend_id) in routes {
        let bs: Vec<BackendConfig> = backends.iter()
            .filter(|b| b.pool.as_str() == *backend_id)
            .cloned()
            .collect();
        if !bs.is_empty() && !pools.contains_key(*backend_id) {
            let pool: BackendPool = BackendPool::new(bs, 0.0).expect("too many backends");
            pools.insert(ArrayString::from(backend_id).unwrap(), pool);
        }
    }
    return pools;
}

async fn start_proxy(
    dir: &Path,
    tunnel_registry: Arc<TunnelRegistry>,
    shutdown: CancellationToken,
) {
    let (server_tls_config, _) = tls::build_server_config(
        &dir.join("server.crt"),
        &dir.join("server.key"),
        &dir.join("ca.crt"),
    ).unwrap();
    let server_tls: Arc<rustls::ServerConfig> = Arc::new(server_tls_config);

    let (client_tls_config, _) = tls::build_client_config(
        &dir.join("client.crt"),
        &dir.join("client.key"),
        &dir.join("ca.crt"),
    ).unwrap();
    let client_tls: Arc<rustls::ClientConfig> = Arc::new(client_tls_config);
    let tls_connector: TlsConnector = TlsConnector::from(client_tls.clone());

    // The tunnel backend has no static address — it connects to us.
    // We still need a BackendConfig for route matching; address is a placeholder.
    let backends: Vec<BackendConfig> = vec![
        BackendConfig::new(
            BACKEND_ID,
            "0.0.0.0:0".parse().unwrap(),
            1.0,
            TransportKind::Tcp,
        ).unwrap(),
    ];
    let routes: Vec<(&str, &str)> = vec![("/api", BACKEND_ID)];

    let route_configs: Vec<reduction::config::RouteConfig> = routes.iter()
        .map(|(prefix, id)| reduction::config::RouteConfig {
            path_prefix: ArrayString::from(prefix).unwrap(),
            backend_id: ArrayString::from(id).unwrap(),
            timeout_secs: None,
        })
        .collect();

    let initial_state: ReloadableState = ReloadableState {
        router: Router::new(&route_configs),
        backend_pools: build_backend_pools(&backends, &routes),
    };

    let (_, reloadable_rx) = watch::channel(initial_state);
    let (_, health_rx) = watch::channel(HealthState::new());

    let conn_pool: ConnPool = ConnPool::new()
        .with_tunnel_registry(Arc::clone(&tunnel_registry));

    let proxy_state: Arc<ProxyState> = Arc::new(ProxyState {
        reloadable: reloadable_rx,
        tls_connector,
        client_tls_config: client_tls,
        health_rx,
        conn_pool,
        acl: AccessControl::new(vec![], vec![]),
        rate_limiter: RateLimit::new(u32::MAX).unwrap(),
        queues: DashMap::new(),
        default_queue_depth: 1000,
        metrics: ProxyMetrics::new(),
        circuit_breakers: CircuitBreakers::new(&CircuitBreakerConfig::default()),
        shutdown: shutdown.clone(),
        timeouts: TimeoutConfig::default(),
        proxy_config: reduction::config::ProxyConfig::default(),
        compression_config: reduction::config::CompressionConfig::default(),
        retry_config: reduction::config::RetryConfig::default(),
        cache_config: CacheConfig::default(),
        response_cache: ResponseCache::new(&CacheConfig::default()),
    });

    let app = axum::Router::new()
        .fallback(any(proxy_handler))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .with_state(proxy_state)
        .into_make_service_with_connect_info::<reduction::transport::ConnectAddr>();

    // Start TCP proxy listener
    let proxy_listener = reduction::transport::tcp::TcpListener::bind(
        ([127, 0, 0, 1], PROXY_PORT).into(),
        Arc::clone(&server_tls),
    ).await.unwrap();

    tokio::spawn(async move {
        axum::serve(proxy_listener, app).await.unwrap();
    });

    // Start tunnel listener (QUIC, for backend registration)
    let tunnel_tls: Arc<rustls::ServerConfig> = server_tls;
    let tunnel_config: TunnelConfig = TunnelConfig {
        enabled: true,
        listen_address: Some(([127, 0, 0, 1], TUNNEL_PORT).into()),
        ..TunnelConfig::default()
    };
    let tunnel_metrics: ProxyMetrics = ProxyMetrics::new();
    let tunnel_shutdown: CancellationToken = shutdown.clone();

    tokio::spawn(async move {
        if let Err(e) = reduction::tunnel::listener::run_tunnel_listener(
            ([127, 0, 0, 1], TUNNEL_PORT).into(),
            tunnel_tls,
            tunnel_registry,
            tunnel_shutdown,
            tunnel_config,
            tunnel_metrics,
        ).await {
            eprintln!("tunnel listener error: {e}");
        }
    });
}

// ---------------------------------------------------------------------------
// Simulated backend behind NAT (connects TO the proxy via reverse tunnel)
// ---------------------------------------------------------------------------

async fn start_tunnel_backend(
    dir: &Path,
    shutdown: CancellationToken,
) -> SessionId {
    let (client_tls_config, _) = tls::build_client_config(
        &dir.join("client.crt"),
        &dir.join("client.key"),
        &dir.join("ca.crt"),
    ).unwrap();
    let client_tls: Arc<rustls::ClientConfig> = Arc::new(client_tls_config);

    let quic_crypto: QuicClientConfig = QuicClientConfig::try_from(client_tls)
        .expect("QUIC client crypto config failed");
    let mut quic_client_config: quinn::ClientConfig =
        quinn::ClientConfig::new(Arc::new(quic_crypto));
    quic_client_config.transport_config(Arc::new(quinn::TransportConfig::default()));

    let mut endpoint: quinn::Endpoint =
        quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .expect("QUIC client endpoint failed");
    endpoint.set_default_client_config(quic_client_config);

    // Connect to the proxy's tunnel listener
    let tunnel_addr: SocketAddr = ([127, 0, 0, 1], TUNNEL_PORT).into();
    let connection: quinn::Connection = endpoint
        .connect(tunnel_addr, "127.0.0.1")
        .expect("QUIC connect config failed")
        .await
        .expect("QUIC handshake failed");

    println!("  [ok] QUIC connection established to proxy tunnel listener");

    // Open control channel (first bidi stream)
    let (send, recv) = connection.open_bi().await
        .expect("failed to open control stream");
    let mut control_stream: QuicStream = QuicStream::new(send, recv);

    // Send Register frame
    let register: TunnelFrame = TunnelFrame::Register {
        backend_id: ArrayString::from(BACKEND_ID).unwrap(),
        pool: ArrayString::from(BACKEND_ID).unwrap(),
        capabilities: ["http"].iter().map(|s| ArrayString::from(s).unwrap()).collect(),
    };
    protocol::write_frame(&mut control_stream, &register).await
        .expect("failed to send Register");
    println!("  [ok] Sent Register frame (backend_id: {BACKEND_ID})");

    // Read RegisterAck
    let ack: TunnelFrame = protocol::read_frame(&mut control_stream).await
        .expect("failed to read RegisterAck");
    let session_id: SessionId = match ack {
        TunnelFrame::RegisterAck { session_id } => {
            println!("  [ok] Received RegisterAck (session: {})", session_id);
            session_id
        }
        other => panic!("expected RegisterAck, got {:?}", other),
    };

    // Spawn heartbeat sender on the control channel
    let heartbeat_shutdown: CancellationToken = shutdown.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let ts: u64 = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let frame: TunnelFrame = TunnelFrame::Heartbeat { timestamp_ms: ts };
                    if protocol::write_frame(&mut control_stream, &frame).await.is_err() {
                        break;
                    }
                    // Read HeartbeatAck (ignore errors — proxy may have shut down)
                    let _ = protocol::read_frame(&mut control_stream).await;
                }
                _ = heartbeat_shutdown.cancelled() => {
                    let _ = protocol::write_frame(&mut control_stream, &TunnelFrame::Shutdown {
                        reason: ArrayString::from("demo ending").unwrap(),
                    }).await;
                    break;
                }
            }
        }
    });

    // Spawn stream acceptor — serves HTTP/1.1 on streams opened by the proxy
    let conn: quinn::Connection = connection.clone();
    let accept_shutdown: CancellationToken = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = conn.accept_bi() => {
                    match result {
                        Ok((send, recv)) => {
                            let stream: QuicStream = QuicStream::new(send, recv);
                            let io: TokioIo<QuicStream> = TokioIo::new(stream);
                            tokio::spawn(async move {
                                let service = service_fn(backend_handler);
                                if let Err(e) = server_http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await
                                {
                                    eprintln!("backend HTTP error: {e}");
                                }
                            });
                        }
                        Err(_) => break,
                    }
                }
                _ = accept_shutdown.cancelled() => break,
            }
        }
    });

    return session_id;
}

async fn backend_handler(
    req: Request<hyper::body::Incoming>,
) -> std::result::Result<Response<Body>, hyper::Error> {
    let path: String = req.uri().path().to_string();
    let method: String = req.method().to_string();
    let body_bytes = req.into_body().collect().await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let body_str: String = String::from_utf8_lossy(&body_bytes).into_owned();

    let response_body: String = if body_str.is_empty() {
        format!(
            r#"{{"path":"{path}","method":"{method}","backend":"{BACKEND_ID}","transport":"reverse-tunnel"}}"#,
        )
    } else {
        format!(
            r#"{{"path":"{path}","method":"{method}","backend":"{BACKEND_ID}","transport":"reverse-tunnel","received":"{body_str}"}}"#,
        )
    };

    return Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(response_body))
        .unwrap());
}

// ---------------------------------------------------------------------------
// mTLS client (same pattern as demo.rs)
// ---------------------------------------------------------------------------

fn build_client_connector(dir: &Path) -> TlsConnector {
    let (client_config, _): (rustls::ClientConfig, _) = tls::build_client_config(
        &dir.join("client.crt"),
        &dir.join("client.key"),
        &dir.join("ca.crt"),
    ).unwrap();
    return TlsConnector::from(Arc::new(client_config));
}

async fn send_request(
    connector: &TlsConnector,
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: &str,
) -> String {
    let tcp: TcpStream = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("127.0.0.1").unwrap().to_owned();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let io = TokioIo::new(tls);

    let (mut sender, conn) = http1::handshake(io).await.unwrap();
    tokio::spawn(conn);

    let req: Request<Body> = Request::builder()
        .method(method)
        .uri(path)
        .header("host", format!("127.0.0.1:{}", addr.port()))
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = sender.send_request(req).await.unwrap();
    let status: StatusCode = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str: String = String::from_utf8_lossy(&bytes).into_owned();

    return format!("{status} {body_str}");
}
