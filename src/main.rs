use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::any;
use dashmap::DashMap;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use reduction::balancer::BackendPool;
use reduction::config::{self, ReductionConfig, TransportKind};
use reduction::error::{ReductionError, Result};
use reduction::health::HealthState;
use reduction::metrics::{self, ProxyMetrics};
use reduction::proxy::{ConnPool, ProxyState, ReloadableState, Router, proxy_handler};
use reduction::ratelimit::RateLimit;
use reduction::tls;
use reduction::transport;

fn init_tracing() {
    let filter: EnvFilter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
}

fn build_backend_pools(config: &ReductionConfig) -> Result<HashMap<String, BackendPool>> {
    let mut pools: HashMap<String, BackendPool> = HashMap::new();

    for route in &config.routes {
        let backends: Vec<config::BackendConfig> = config
            .backends
            .iter()
            .filter(|b| b.pool == route.backend_id)
            .cloned()
            .collect();

        if !backends.is_empty() && !pools.contains_key(&route.backend_id) {
            let pool: BackendPool = BackendPool::new(
                backends,
                config.balancer.jitter_factor,
            )?;
            pools.insert(route.backend_id.clone(), pool);
        }
    }

    return Ok(pools);
}

fn spawn_config_reload_task(
    mut config_rx: watch::Receiver<ReductionConfig>,
    reloadable_tx: watch::Sender<ReloadableState>,
) {
    tokio::spawn(async move {
        while config_rx.changed().await.is_ok() {
            let config: ReductionConfig = config_rx.borrow_and_update().clone();
            let backend_pools: HashMap<String, BackendPool> = match build_backend_pools(&config) {
                Ok(pools) => pools,
                Err(e) => {
                    error!(error = %e, "failed to rebuild backend pools, keeping current config");
                    continue;
                }
            };
            let new_state: ReloadableState = ReloadableState {
                router: Router::new(&config.routes),
                backend_pools,
            };
            if reloadable_tx.send(new_state).is_err() {
                info!("all proxy state receivers dropped, stopping config reload");
                return;
            }
            info!("proxy state rebuilt from updated config");
        }
    });
}

async fn run(config_path: PathBuf) -> Result<()> {
    let config: ReductionConfig = config::load_config(&config_path)?;

    metrics::init_metrics(&config.metrics)?;
    let proxy_metrics: ProxyMetrics = ProxyMetrics::new();

    let (config_tx, config_rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) =
        watch::channel(config.clone());

    let _config_watcher: config::watcher::ConfigWatcher =
        config::watcher::ConfigWatcher::new(config_path, config_tx)?;

    let server_tls_config: Arc<rustls::ServerConfig> = Arc::new(tls::build_server_config(
        &config.tls.server.cert_path,
        &config.tls.server.key_path,
        &config.tls.server.ca_cert_path,
    )?);

    let client_tls_config: Arc<rustls::ClientConfig> = Arc::new(tls::build_client_config(
        &config.tls.client.cert_path,
        &config.tls.client.key_path,
        &config.tls.client.ca_cert_path,
    )?);

    let tls_connector: TlsConnector = TlsConnector::from(client_tls_config.clone());

    let initial_reloadable: ReloadableState = ReloadableState {
        router: Router::new(&config.routes),
        backend_pools: build_backend_pools(&config)?,
    };

    let (reloadable_tx, reloadable_rx): (watch::Sender<ReloadableState>, watch::Receiver<ReloadableState>) =
        watch::channel(initial_reloadable);

    let (_health_tx, health_rx): (watch::Sender<HealthState>, watch::Receiver<HealthState>) =
        watch::channel(HealthState::new());

    let rate_limiter: RateLimit = RateLimit::new(config.ratelimit.requests_per_second)
        .expect("invalid rate limit config");
    info!(rps = config.ratelimit.requests_per_second, "rate limiting enabled");

    let proxy_state: Arc<ProxyState> = Arc::new(ProxyState {
        reloadable: reloadable_rx,
        tls_connector,
        client_tls_config,
        health_rx,
        conn_pool: ConnPool::new(),
        rate_limiter,
        queues: DashMap::new(),
        default_queue_depth: config.balancer.queue_depth,
        metrics: proxy_metrics,
    });

    spawn_config_reload_task(config_rx, reloadable_tx);

    let app = axum::Router::new()
        .fallback(any(proxy_handler))
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024))
        .with_state(proxy_state)
        .into_make_service_with_connect_info::<transport::ConnectAddr>();

    info!("reduction proxy starting on {}", config.listen.address);

    match config.listen.transport {
        TransportKind::Tcp => {
            let listener: transport::tcp::TcpListener =
                transport::tcp::TcpListener::bind(config.listen.address, server_tls_config)
                    .await?;
            return axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
                .map_err(ReductionError::from);
        }
        TransportKind::Quic => {
            let quic_config: quinn::ServerConfig =
                transport::quic::build_quic_server_config(server_tls_config)?;
            let listener: transport::quic::QuicListener =
                transport::quic::QuicListener::bind(config.listen.address, quic_config)?;
            return axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
                .map_err(ReductionError::from);
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = signal::ctrl_c();

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received ctrl-c, starting graceful shutdown"),
        _ = terminate => info!("received SIGTERM, starting graceful shutdown"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        return Err(ReductionError::Config(
            "usage: reduction <config.toml>".to_string(),
        ));
    }

    let config_path: PathBuf = PathBuf::from(&args[1]);

    return run(config_path).await;
}
