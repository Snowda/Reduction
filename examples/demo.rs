use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::{Request, Response, StatusCode};
use axum::routing::any;
use http_body_util::BodyExt;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tokio_rustls::server::TlsStream;

use dashmap::DashMap;
use reduction::balancer::BackendPool;
use reduction::config::{self, BackendConfig, ReductionConfig, TransportKind};
use reduction::health::{BackendHealth, HealthBroadcast, HealthState};
use reduction::metrics::ProxyMetrics;
use reduction::proxy::{ConnPool, ProxyState, ReloadableState, Router, proxy_handler};
use reduction::ratelimit::RateLimit;
use reduction::tls;

const PROXY_PORT: u16 = 18443;
const BACKEND_PORT: u16 = 19443;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    println!("Reduction - M2M Reverse Proxy Demo");
    println!("===================================\n");

    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path();

    // -- Phase 1: TLS certificates --
    println!("-- Phase 1: TLS Certificate Generation --\n");
    generate_certs(dir_path);
    let config_path = dir_path.join("config.toml");
    write_config(dir_path, &config_path, &[("/api", "backend-a")]);
    println!("  Written to {}\n", dir_path.display());

    // -- Phase 2: Data plane --
    println!("-- Phase 2: Data Plane --\n");
    let handles = start_services(dir_path, &config_path).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("  Backend (:{BACKEND_PORT}) and proxy (:{PROXY_PORT}) started\n");

    let client_connector = build_client_connector(dir_path);
    let proxy_addr: SocketAddr = ([127, 0, 0, 1], PROXY_PORT).into();

    let resp = send_request(
        &client_connector, proxy_addr, "POST", "/api/echo",
        "hello from M2M client",
    ).await;
    println!("  POST /api/echo -> {resp}");

    let resp = send_request(
        &client_connector, proxy_addr, "POST", "/api/data",
        r#"{"sensor":"temp-01","value":23.5}"#,
    ).await;
    println!("  POST /api/data -> {resp}");

    // -- Phase 3: Management plane - health --
    println!("\n-- Phase 3: Management Plane - Health State --\n");
    demonstrate_health(&handles.health_tx);

    // -- Phase 4: Management plane - config reload --
    println!("\n-- Phase 4: Management Plane - Config Reload --\n");
    demonstrate_config_reload(dir_path, &config_path, &client_connector, proxy_addr).await;

    println!("\n-- Demo Complete --");
}

// ---------------------------------------------------------------------------
// Certificate generation
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
    println!("  [ok] Client certificate");
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
    let cert = params.signed_by(&key, ca_cert, ca_key).unwrap();
    (cert, key)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

fn path_str(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn write_config(dir: &Path, config_path: &Path, routes: &[(&str, &str)]) {
    let mut toml = format!(
r#"[listen]
address = "127.0.0.1:{PROXY_PORT}"
transport = "tcp"

[tls.server]
cert_path = "{server_crt}"
key_path = "{server_key}"
ca_cert_path = "{ca_crt}"

[tls.client]
cert_path = "{client_crt}"
key_path = "{client_key}"
ca_cert_path = "{ca_crt}"

[[backends]]
id = "backend-a"
address = "127.0.0.1:{BACKEND_PORT}"
weight = 1.0
transport = "tcp"
"#,
        server_crt = path_str(&dir.join("server.crt")),
        server_key = path_str(&dir.join("server.key")),
        client_crt = path_str(&dir.join("client.crt")),
        client_key = path_str(&dir.join("client.key")),
        ca_crt = path_str(&dir.join("ca.crt")),
    );

    for (prefix, backend_id) in routes {
        toml.push_str(&format!(
            "\n[[routes]]\npath_prefix = \"{prefix}\"\nbackend_id = \"{backend_id}\"\n"
        ));
    }

    std::fs::write(config_path, toml).unwrap();
}

// ---------------------------------------------------------------------------
// Backend server (simulates an upstream M2M service)
// ---------------------------------------------------------------------------

struct DemoTlsListener {
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl axum::serve::Listener for DemoTlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = self.listener.accept().await.unwrap();
            match self.acceptor.accept(stream).await {
                Ok(tls) => return (tls, addr),
                Err(_) => continue,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        return self.listener.local_addr();
    }
}

async fn backend_handler(req: Request<Body>) -> Response<Body> {
    let path: String = req.uri().path().to_string();
    let method: String = req.method().to_string();
    let body_bytes = req.into_body().collect().await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let body_str: String = String::from_utf8_lossy(&body_bytes).into_owned();

    let response_body: String = if body_str.is_empty() {
        format!(r#"{{"path":"{path}","method":"{method}","backend":"backend-a"}}"#)
    } else {
        format!(r#"{{"path":"{path}","method":"{method}","backend":"backend-a","received":"{body_str}"}}"#)
    };

    return Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(response_body))
        .unwrap();
}

// ---------------------------------------------------------------------------
// Service startup (assembles proxy from library components)
// ---------------------------------------------------------------------------

struct DemoHandles {
    health_tx: watch::Sender<HealthState>,
    _watcher: config::watcher::ConfigWatcher,
}

fn build_backend_pools(config: &ReductionConfig) -> HashMap<String, BackendPool> {
    let mut pools: HashMap<String, BackendPool> = HashMap::new();
    for route in &config.routes {
        let backends: Vec<BackendConfig> = config.backends.iter()
            .filter(|b| b.pool == route.backend_id)
            .cloned()
            .collect();
        if !backends.is_empty() && !pools.contains_key(&route.backend_id) {
            let pool: BackendPool = BackendPool::new(
                backends,
                config.balancer.jitter_factor,
            ).expect("too many backends");
            pools.insert(route.backend_id.clone(), pool);
        }
    }
    return pools;
}

async fn start_services(dir: &Path, config_path: &Path) -> DemoHandles {
    let config: ReductionConfig = config::load_config(config_path).unwrap();

    // -- Backend --
    let backend_tls: Arc<rustls::ServerConfig> = Arc::new(tls::build_server_config(
        &dir.join("server.crt"),
        &dir.join("server.key"),
        &dir.join("ca.crt"),
    ).unwrap());

    let backend_addr: SocketAddr = ([127, 0, 0, 1], BACKEND_PORT).into();
    let backend_listener = tokio::net::TcpListener::bind(backend_addr).await.unwrap();
    let demo_listener = DemoTlsListener {
        listener: backend_listener,
        acceptor: tokio_rustls::TlsAcceptor::from(backend_tls),
    };

    let backend_app = axum::Router::new().fallback(any(backend_handler));
    tokio::spawn(async move {
        axum::serve(demo_listener, backend_app).await.unwrap();
    });

    // -- Proxy --
    let server_tls: Arc<rustls::ServerConfig> = Arc::new(tls::build_server_config(
        &config.tls.server.cert_path,
        &config.tls.server.key_path,
        &config.tls.server.ca_cert_path,
    ).unwrap());

    let client_tls: Arc<rustls::ClientConfig> = Arc::new(tls::build_client_config(
        &config.tls.client.cert_path,
        &config.tls.client.key_path,
        &config.tls.client.ca_cert_path,
    ).unwrap());

    let tls_connector: TlsConnector = TlsConnector::from(client_tls.clone());

    let initial_state: ReloadableState = ReloadableState {
        router: Router::new(&config.routes),
        backend_pools: build_backend_pools(&config),
    };

    let (reloadable_tx, reloadable_rx) = watch::channel(initial_state);
    let (health_tx, health_rx) = watch::channel(HealthState::new());

    let proxy_state: Arc<ProxyState> = Arc::new(ProxyState {
        reloadable: reloadable_rx,
        tls_connector,
        client_tls_config: client_tls,
        health_rx,
        conn_pool: ConnPool::new(),
        rate_limiter: RateLimit::new(u32::MAX).unwrap(),
        queues: DashMap::new(),
        default_queue_depth: config.balancer.queue_depth,
        metrics: ProxyMetrics::new(),
    });

    // Config watcher + reload task
    let (config_tx, config_rx) = watch::channel(config.clone());
    let watcher = config::watcher::ConfigWatcher::new(
        config_path.to_path_buf(), config_tx,
    ).unwrap();

    tokio::spawn({
        let mut config_rx = config_rx;
        async move {
            while config_rx.changed().await.is_ok() {
                let cfg: ReductionConfig = config_rx.borrow_and_update().clone();
                let new_state: ReloadableState = ReloadableState {
                    router: Router::new(&cfg.routes),
                    backend_pools: build_backend_pools(&cfg),
                };
                if reloadable_tx.send(new_state).is_err() {
                    return;
                }
            }
        }
    });

    let app = axum::Router::new()
        .fallback(any(proxy_handler))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .with_state(proxy_state)
        .into_make_service_with_connect_info::<reduction::transport::ConnectAddr>();


    let proxy_listener = reduction::transport::tcp::TcpListener::bind(
        config.listen.address, server_tls,
    ).await.unwrap();

    tokio::spawn(async move {
        axum::serve(proxy_listener, app).await.unwrap();
    });

    return DemoHandles { health_tx, _watcher: watcher };
}

// ---------------------------------------------------------------------------
// mTLS client
// ---------------------------------------------------------------------------

fn build_client_connector(dir: &Path) -> TlsConnector {
    let client_config: rustls::ClientConfig = tls::build_client_config(
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

// ---------------------------------------------------------------------------
// Phase 3: Health state demonstration
// ---------------------------------------------------------------------------

fn demonstrate_health(health_tx: &watch::Sender<HealthState>) {
    // Show bitcode wire format used for M2M health broadcasts
    let broadcast: HealthBroadcast = HealthBroadcast {
        entries: vec![
            BackendHealth { backend_id: "node-1".into(), load: 0.2, latency_ms: 30, available: true },
            BackendHealth { backend_id: "node-2".into(), load: 0.8, latency_ms: 200, available: true },
        ],
    };
    let wire: Vec<u8> = bitcode::encode(&broadcast);
    println!("  Wire format: 2 health entries -> {} bytes (bitcode)", wire.len());

    // Decode round-trip
    let decoded: HealthBroadcast = bitcode::decode(&wire).unwrap();
    println!("  Decode check: {} entries recovered\n", decoded.entries.len());

    // Demonstrate health-weighted backend selection
    let backends: Vec<BackendConfig> = vec![
        BackendConfig::new("node-1".into(), "10.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp),
        BackendConfig::new("node-2".into(), "10.0.0.2:8080".parse().unwrap(), 1.0, TransportKind::Tcp),
    ];
    let pool: BackendPool = BackendPool::new(backends, 0.0).unwrap();
    let client_ip: IpAddr = "192.168.1.1".parse().unwrap();

    // Equal health (unknown backends default to weight 1.0)
    let health: HealthState = HealthState::new();
    let selected = pool.select(client_ip, &health).unwrap();
    println!("  Equal health    -> selected: {}", selected.id);

    // node-1 under heavy load
    let mut health: HealthState = HealthState::new();
    health.update(HealthBroadcast {
        entries: vec![
            BackendHealth { backend_id: "node-1".into(), load: 0.95, latency_ms: 800, available: true },
            BackendHealth { backend_id: "node-2".into(), load: 0.1, latency_ms: 20, available: true },
        ],
    });
    let selected = pool.select(client_ip, &health).unwrap();
    println!("  node-1 loaded   -> selected: {}", selected.id);

    // node-1 unavailable
    let mut health: HealthState = HealthState::new();
    health.update(HealthBroadcast {
        entries: vec![
            BackendHealth { backend_id: "node-1".into(), load: 0.0, latency_ms: 0, available: false },
            BackendHealth { backend_id: "node-2".into(), load: 0.3, latency_ms: 50, available: true },
        ],
    });
    let selected = pool.select(client_ip, &health).unwrap();
    println!("  node-1 down     -> selected: {}", selected.id);

    // Push live health update to the running proxy
    health_tx.send_modify(|state| {
        state.update(HealthBroadcast {
            entries: vec![BackendHealth {
                backend_id: "backend-a".into(),
                load: 0.2,
                latency_ms: 30,
                available: true,
            }],
        });
    });
    println!("\n  Pushed live health update to running proxy (backend-a: load=0.2, latency=30ms)");
}

// ---------------------------------------------------------------------------
// Phase 4: Config hot-reload demonstration
// ---------------------------------------------------------------------------

async fn demonstrate_config_reload(
    dir: &Path,
    config_path: &Path,
    connector: &TlsConnector,
    proxy_addr: SocketAddr,
) {
    // Add a new route via config file modification
    write_config(dir, config_path, &[("/api/v2", "backend-a"), ("/api", "backend-a")]);
    println!("  Config updated: added /api/v2 route");

    // Wait for the file watcher to detect the change and rebuild state
    tokio::time::sleep(Duration::from_secs(2)).await;

    let resp = send_request(connector, proxy_addr, "GET", "/api/v2/status", "").await;
    println!("  GET /api/v2/status -> {resp}");
}
