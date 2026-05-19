mod balancer;
mod compression;
mod config;
mod error;
mod health;
mod metrics;
mod proxy;
mod ratelimit;
mod tls;
mod transport;

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::any;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tracing::info;
use tracing_subscriber::EnvFilter;

use balancer::{BackendPool, RequestQueue};
use config::{ReductionConfig, TransportKind};
use error::{ReductionError, Result};
use health::HealthState;
use proxy::{ProxyState, ReloadableState, Router, init_request_queue, proxy_handler};

fn init_tracing() {
    let filter: EnvFilter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
}

fn build_backend_pools(config: &ReductionConfig) -> HashMap<String, BackendPool> {
    let mut pools: HashMap<String, BackendPool> = HashMap::new();

    for route in &config.routes {
        let backends: Vec<config::BackendConfig> = config
            .backends
            .iter()
            .filter(|b| b.id == route.backend_id)
            .cloned()
            .collect();

        if !backends.is_empty() && !pools.contains_key(&route.backend_id) {
            let pool: BackendPool = BackendPool::new(backends, config.balancer.jitter_factor);
            pools.insert(route.backend_id.clone(), pool);
        }
    }

    return pools;
}

fn spawn_config_reload_task(
    mut config_rx: watch::Receiver<ReductionConfig>,
    reloadable_tx: watch::Sender<ReloadableState>,
) {
    tokio::spawn(async move {
        while config_rx.changed().await.is_ok() {
            let config = config_rx.borrow_and_update().clone();
            let new_state: ReloadableState = ReloadableState {
                router: Router::new(&config.routes),
                backend_pools: build_backend_pools(&config),
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
    let (config_tx, config_rx) = watch::channel(config.clone());

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

    let tls_connector: TlsConnector = TlsConnector::from(client_tls_config);

    let initial_reloadable: ReloadableState = ReloadableState {
        router: Router::new(&config.routes),
        backend_pools: build_backend_pools(&config),
    };

    let (reloadable_tx, reloadable_rx) = watch::channel(initial_reloadable);

    init_request_queue(RequestQueue::new(config.balancer.queue_depth))?;
    let (_health_tx, health_rx) = watch::channel(HealthState::new());

    let proxy_state: ProxyState = ProxyState {
        reloadable: reloadable_rx,
        tls_connector,
        health_rx,
    };

    spawn_config_reload_task(config_rx, reloadable_tx);

    let app: axum::Router = axum::Router::new()
        .fallback(any(proxy_handler))
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024))
        .with_state(proxy_state);

    info!("reduction proxy starting on {}", config.listen.address);

    match config.listen.transport {
        TransportKind::Tcp => {
            let listener: transport::tcp::TcpListener =
                transport::tcp::TcpListener::bind(config.listen.address, server_tls_config)
                    .await?;
            return axum::serve(listener, app)
                .await
                .map_err(ReductionError::from);
        }
        TransportKind::Quic => {
            let quic_config: quinn::ServerConfig =
                transport::quic::build_quic_server_config(server_tls_config)?;
            let listener: transport::quic::QuicListener =
                transport::quic::QuicListener::bind(config.listen.address, quic_config)?;
            return axum::serve(listener, app)
                .await
                .map_err(ReductionError::from);
        }
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
