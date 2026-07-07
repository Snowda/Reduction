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
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arrayvec::ArrayString;
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
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use tracing::info_span;

use dashmap::DashMap;
use reduction::balancer::BackendPool;
use reduction::circuit::CircuitBreakers;
use reduction::compression;
use reduction::config::{self, BackendConfig, CircuitBreakerConfig, ReductionConfig, TimeoutConfig};
use reduction::health::HealthState;
use reduction::metrics::ProxyMetrics;
use reduction::acl::AccessControl;
use reduction::cache::ResponseCache;
use reduction::config::CacheConfig;
use reduction::proxy::{ConnPool, ProxyState, ReloadableState, Router, proxy_handler};
use reduction::ratelimit::RateLimit;
use reduction::tls;

const PROXY_PORT: u16 = 18443;
const BACKEND_PORT: u16 = 19443;

struct LatencyHistogram {
    samples: Vec<f64>,
}

impl LatencyHistogram {
    fn new(capacity: usize) -> Self {
        return Self {
            samples: Vec::with_capacity(capacity),
        };
    }

    fn record(&mut self, ms: f64) {
        self.samples.push(ms);
    }

    fn percentile(&mut self, p: f64) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let idx: usize = ((p / 100.0) * (self.samples.len() - 1) as f64).round() as usize;
        return self.samples[idx];
    }

    fn mean(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        return self.samples.iter().sum::<f64>() / self.samples.len() as f64;
    }
}

// Reusable HTTP/1.1 keep-alive client over mTLS.
struct KeepAliveClient {
    connector: TlsConnector,
    addr: SocketAddr,
    sender: Option<http1::SendRequest<Body>>,
}

impl KeepAliveClient {
    fn new(connector: TlsConnector, addr: SocketAddr) -> Self {
        return Self { connector, addr, sender: None };
    }

    async fn ensure_connected(&mut self) -> bool {
        if let Some(ref mut sender) = self.sender {
            match timeout(Duration::from_millis(50), sender.ready()).await {
                Ok(Ok(_)) => return true,
                _ => self.sender = None,
            }
        }

        let tcp: TcpStream = match TcpStream::connect(self.addr).await {
            Ok(s) => s,
            Err(_) => return false,
        };
        let server_name = ServerName::try_from("127.0.0.1").unwrap().to_owned();
        let tls = match self.connector.connect(server_name, tcp).await {
            Ok(s) => s,
            Err(_) => return false,
        };
        let io = TokioIo::new(tls);

        let (sender, conn) = match http1::handshake(io).await {
            Ok(r) => r,
            Err(_) => return false,
        };
        tokio::spawn(conn);
        self.sender = Some(sender);
        return true;
    }

    async fn send(&mut self, req: Request<Body>) -> bool {
        if !self.ensure_connected().await {
            return false;
        }

        let sender: &mut http1::SendRequest<Body> = self.sender.as_mut().unwrap();
        let response = match sender.send_request(req).await {
            Ok(r) => r,
            Err(_) => {
                self.sender = None;
                return false;
            }
        };

        let status: StatusCode = response.status();
        let _ = response.into_body().collect().await;
        return status == StatusCode::OK;
    }

    async fn send_plain(&mut self, body: &str) -> bool {
        let req: Request<Body> = Request::builder()
            .method("POST")
            .uri("/api/echo")
            .header("host", format!("127.0.0.1:{}", self.addr.port()))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        return self.send(req).await;
    }

    async fn send_zstd(&mut self, body: &str) -> bool {
        let compressed_body: Vec<u8> = match compression::compress(body.as_bytes()) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let req: Request<Body> = Request::builder()
            .method("POST")
            .uri("/api/echo")
            .header("host", format!("127.0.0.1:{}", self.addr.port()))
            .header("content-type", "application/json")
            .header("content-encoding", "zstd")
            .header("accept-encoding", "zstd")
            .body(Body::from(compressed_body))
            .unwrap();
        return self.send(req).await;
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let concurrency: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
    let total_requests: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let flags: Vec<&str> = args.iter().skip(3).map(|s| s.as_str()).collect();
    let enable_trace: bool = flags.contains(&"--trace");
    let enable_zstd: bool = flags.contains(&"--zstd");

    // Tracing setup: chrome trace file or minimal subscriber
    let _guard: Option<tracing_chrome::FlushGuard> = if enable_trace {
        let (chrome_layer, guard) = tracing_chrome::ChromeLayerBuilder::new()
            .file("trace.json".to_string())
            .include_args(true)
            .build();
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        tracing_subscriber::registry()
            .with(chrome_layer)
            .with(tracing_subscriber::EnvFilter::new("info"))
            .init();
        println!("  Tracing enabled -> trace.json (open in https://ui.perfetto.dev)");
        Some(guard)
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .init();
        None
    };

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    println!("Reduction - Profile Load Test");
    println!("==============================");
    println!("  Concurrency: {concurrency}");
    println!("  Total requests: {total_requests}");
    println!("  Zstd:        {}", if enable_zstd { "on (request + response compression)" } else { "off" });
    println!();

    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path();

    generate_certs(dir_path);
    let config_path = dir_path.join("config.toml");
    write_config(dir_path, &config_path);

    let _handles = start_services(dir_path, &config_path).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("  Backend (:{BACKEND_PORT}) and proxy (:{PROXY_PORT}) started\n");

    // Warm up with a keep-alive client
    let proxy_addr: SocketAddr = ([127, 0, 0, 1], PROXY_PORT).into();
    let mut warmup_client: KeepAliveClient =
        KeepAliveClient::new(build_client_connector(dir_path), proxy_addr);
    let _ = warmup_client.send_plain("warmup").await;
    println!("  Warmup complete\n");

    // Run load test
    let completed: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let errors: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let requests_per_worker: usize = total_requests / concurrency;

    let overall_start: Instant = Instant::now();

    let mut handles: Vec<tokio::task::JoinHandle<Vec<f64>>> = Vec::with_capacity(concurrency);
    for worker_id in 0..concurrency {
        let connector: TlsConnector = build_client_connector(dir_path);
        let completed: Arc<AtomicU64> = Arc::clone(&completed);
        let errors: Arc<AtomicU64> = Arc::clone(&errors);

        handles.push(tokio::spawn(async move {
            let mut latencies: Vec<f64> = Vec::with_capacity(requests_per_worker);
            let mut client: KeepAliveClient = KeepAliveClient::new(connector, proxy_addr);

            for i in 0..requests_per_worker {
                let body: String = format!(
                    r#"{{"worker":{worker_id},"seq":{i},"data":"payload-for-load-test"}}"#,
                );
                let start: Instant = Instant::now();
                let result = if enable_zstd {
                    client.send_zstd(&body)
                        .instrument(info_span!("request", worker = worker_id, seq = i, zstd = true))
                        .await
                } else {
                    client.send_plain(&body)
                        .instrument(info_span!("request", worker = worker_id, seq = i))
                        .await
                };
                let elapsed_ms: f64 = start.elapsed().as_secs_f64() * 1000.0;

                if result {
                    completed.fetch_add(1, Ordering::Relaxed);
                    latencies.push(elapsed_ms);
                } else {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }

            return latencies;
        }));
    }

    let mut histogram: LatencyHistogram = LatencyHistogram::new(total_requests);
    for handle in handles {
        let latencies: Vec<f64> = handle.await.unwrap();
        for lat in latencies {
            histogram.record(lat);
        }
    }

    let total_time: f64 = overall_start.elapsed().as_secs_f64();
    let completed_count: u64 = completed.load(Ordering::Relaxed);
    let error_count: u64 = errors.load(Ordering::Relaxed);
    let rps: f64 = completed_count as f64 / total_time;

    println!("-- Results --\n");
    println!("  Duration:  {total_time:.2}s");
    println!("  Completed: {completed_count}");
    println!("  Errors:    {error_count}");
    println!("  RPS:       {rps:.0}");
    println!();
    println!("  Latency (ms):");
    println!("    mean: {:.2}", histogram.mean());
    println!("    p50:  {:.2}", histogram.percentile(50.0));
    println!("    p95:  {:.2}", histogram.percentile(95.0));
    println!("    p99:  {:.2}", histogram.percentile(99.0));
    println!("    p999: {:.2}", histogram.percentile(99.9));
    println!("    max:  {:.2}", histogram.percentile(100.0));

    if enable_trace {
        println!("\n  Trace written to trace.json");
        println!("  Open in: https://ui.perfetto.dev");
    }

    println!("\n-- Load Test Complete --");
}

// ---------------------------------------------------------------------------
// Certificate generation (same as demo.rs)
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
// Configuration
// ---------------------------------------------------------------------------

fn path_str(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn write_config(dir: &Path, config_path: &Path) {
    let toml: String = format!(
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

[[routes]]
path_prefix = "/api"
backend_id = "backend-a"
"#,
        server_crt = path_str(&dir.join("server.crt")),
        server_key = path_str(&dir.join("server.key")),
        client_crt = path_str(&dir.join("client.crt")),
        client_key = path_str(&dir.join("client.key")),
        ca_crt = path_str(&dir.join("ca.crt")),
    );

    std::fs::write(config_path, toml).unwrap();
}

// ---------------------------------------------------------------------------
// Backend server
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

    let response_body: String = format!(
        r#"{{"path":"{path}","method":"{method}","echo":"{body_str}"}}"#,
    );

    return Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(response_body))
        .unwrap();
}

// ---------------------------------------------------------------------------
// Service startup
// ---------------------------------------------------------------------------

struct ServiceHandles {
    _health_tx: watch::Sender<HealthState>,
    _watcher: config::watcher::ConfigWatcher,
}

fn build_backend_pools(config: &ReductionConfig) -> HashMap<ArrayString<256>, BackendPool> {
    let mut pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();
    for route in &config.routes {
        let backends: Vec<BackendConfig> = config.backends.iter()
            .filter(|b| b.pool.as_str() == route.backend_id.as_str())
            .cloned()
            .collect();
        if !backends.is_empty() && !pools.contains_key(route.backend_id.as_str()) {
            let pool: BackendPool = BackendPool::new(
                backends,
                config.balancer.jitter_factor,
            ).expect("too many backends");
            pools.insert(route.backend_id, pool);
        }
    }
    return pools;
}

async fn start_services(dir: &Path, config_path: &Path) -> ServiceHandles {
    let config: ReductionConfig = config::load_config(config_path).unwrap();

    // -- Backend --
    let (backend_tls_config, _) = tls::build_server_config(
        &dir.join("server.crt"),
        &dir.join("server.key"),
        &dir.join("ca.crt"),
    ).unwrap();
    let backend_tls: Arc<rustls::ServerConfig> = Arc::new(backend_tls_config);

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
    let (server_tls_config, _) = tls::build_server_config(
        &config.tls.server.as_manual().unwrap().cert_path,
        &config.tls.server.as_manual().unwrap().key_path,
        &config.tls.server.as_manual().unwrap().ca_cert_path,
    ).unwrap();
    let server_tls: Arc<rustls::ServerConfig> = Arc::new(server_tls_config);

    let (client_tls_config, _) = tls::build_client_config(
        &config.tls.client.cert_path,
        &config.tls.client.key_path,
        &config.tls.client.ca_cert_path,
    ).unwrap();
    let client_tls: Arc<rustls::ClientConfig> = Arc::new(client_tls_config);

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
        acl: AccessControl::new(vec![], vec![]),
        rate_limiter: RateLimit::new(u32::MAX).unwrap(),
        queues: DashMap::new(),
        default_queue_depth: config.balancer.queue_depth,
        metrics: ProxyMetrics::new(),
        circuit_breakers: CircuitBreakers::new(&CircuitBreakerConfig::default()),
        shutdown: CancellationToken::new(),
        timeouts: TimeoutConfig::default(),
        proxy_config: reduction::config::ProxyConfig::default(),
        compression_config: reduction::config::CompressionConfig::default(),
        retry_config: reduction::config::RetryConfig::default(),
        cache_config: CacheConfig::default(),
        response_cache: ResponseCache::new(&CacheConfig::default()),
    });

    let (config_tx, config_rx) = watch::channel(config.clone());
    let watcher = config::watcher::ConfigWatcher::new(
        config_path, config_tx,
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

    return ServiceHandles { _health_tx: health_tx, _watcher: watcher };
}

// ---------------------------------------------------------------------------
// mTLS client
// ---------------------------------------------------------------------------

fn build_client_connector(dir: &Path) -> TlsConnector {
    let (client_config, _): (rustls::ClientConfig, _) = tls::build_client_config(
        &dir.join("client.crt"),
        &dir.join("client.key"),
        &dir.join("ca.crt"),
    ).unwrap();
    return TlsConnector::from(Arc::new(client_config));
}
