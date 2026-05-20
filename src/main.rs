use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::any;
use dashmap::DashMap;
use tokio::sync::watch;
use tokio::time::sleep;
use tokio_rustls::TlsConnector;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use reduction::acl::AccessControl;
use reduction::balancer::BackendPool;
use reduction::circuit::CircuitBreakers;
use reduction::config::{self, ReductionConfig, TransportKind};
use reduction::error::{ReductionError, Result};
use reduction::health::HealthState;
use reduction::metrics::{self, ProxyMetrics};
use reduction::proxy::{ConnPool, ProxyState, ReloadableState, Router, proxy_handler};
use reduction::ratelimit::RateLimit;
use reduction::tls;
use reduction::transport;

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
            let pool: BackendPool = BackendPool::with_max(
                backends,
                config.balancer.jitter_factor,
                config.balancer.max_backends,
            )?;
            pools.insert(route.backend_id.clone(), pool);
        }
    }

    return Ok(pools);
}

fn spawn_config_reload_task(
    mut config_rx: watch::Receiver<ReductionConfig>,
    reloadable_tx: watch::Sender<ReloadableState>,
    proxy_state: Arc<ProxyState>,
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

            let new_addrs: HashSet<SocketAddr> = new_state.backend_pools.values()
                .flat_map(|p| p.backends.iter().map(|b| b.address))
                .collect();

            let old_state: ReloadableState = reloadable_tx.borrow().clone();
            let removed_addrs: Vec<SocketAddr> = old_state.backend_pools.values()
                .flat_map(|p| p.backends.iter().map(|b| b.address))
                .filter(|addr| !new_addrs.contains(addr))
                .collect();

            if reloadable_tx.send(new_state).is_err() {
                info!("all proxy state receivers dropped, stopping config reload");
                return;
            }
            info!("proxy state rebuilt from updated config");

            if !removed_addrs.is_empty() {
                let drain_timeout: u64 = config.balancer.drain_timeout_secs;
                let pool = Arc::clone(&proxy_state);
                let reloadable_rx = reloadable_tx.subscribe();
                info!(
                    backends = ?removed_addrs,
                    timeout_secs = drain_timeout,
                    "draining removed backends"
                );
                tokio::spawn(async move {
                    sleep(Duration::from_secs(drain_timeout)).await;
                    let current: ReloadableState = reloadable_rx.borrow().clone();
                    let still_active: HashSet<SocketAddr> = current.backend_pools.values()
                        .flat_map(|p| p.backends.iter().map(|b| b.address))
                        .collect();
                    let to_evict: Vec<SocketAddr> = removed_addrs.into_iter()
                        .filter(|addr| !still_active.contains(addr))
                        .collect();
                    if !to_evict.is_empty() {
                        pool.conn_pool.drain_backends(&to_evict);
                        info!(backends = ?to_evict, "drain complete, idle connections evicted");
                    }
                });
            }

            proxy_state.conn_pool.warm_up(
                &config.backends,
                &proxy_state.tls_connector,
                &proxy_state.client_tls_config,
                Duration::from_secs(config.timeouts.connect_secs),
                Duration::from_secs(config.timeouts.handshake_secs),
            ).await;
            info!(count = config.backends.len(), "connection pool pre-warmed after config reload");
        }
    });
}

async fn run(config_path: PathBuf, config: ReductionConfig) -> Result<()> {
    metrics::init_metrics(&config.metrics)?;
    let proxy_metrics: ProxyMetrics = ProxyMetrics::new();

    let (config_tx, config_rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) =
        watch::channel(config.clone());

    let _config_watcher: config::watcher::ConfigWatcher =
        config::watcher::ConfigWatcher::new(config_path, config_tx)?;

    let (server_tls_config, server_cert_resolver) = tls::build_server_config(
        &config.tls.server.cert_path,
        &config.tls.server.key_path,
        &config.tls.server.ca_cert_path,
    )?;
    let server_tls_config: Arc<rustls::ServerConfig> = Arc::new(server_tls_config);

    let (client_tls_config, client_cert_resolver) = tls::build_client_config(
        &config.tls.client.cert_path,
        &config.tls.client.key_path,
        &config.tls.client.ca_cert_path,
    )?;
    let client_tls_config: Arc<rustls::ClientConfig> = Arc::new(client_tls_config);

    let _cert_watcher: tls::CertWatcher =
        tls::CertWatcher::new(server_cert_resolver, client_cert_resolver)?;

    let tls_connector: TlsConnector = TlsConnector::from(client_tls_config.clone());

    let initial_reloadable: ReloadableState = ReloadableState {
        router: Router::new(&config.routes),
        backend_pools: build_backend_pools(&config)?,
    };

    let (reloadable_tx, reloadable_rx): (watch::Sender<ReloadableState>, watch::Receiver<ReloadableState>) =
        watch::channel(initial_reloadable);

    let (_health_tx, health_rx): (watch::Sender<HealthState>, watch::Receiver<HealthState>) =
        watch::channel(HealthState::with_config(
            config.balancer.max_backends,
            Duration::from_secs(config.health.staleness_ttl_secs),
        ));

    let acl: AccessControl = AccessControl::new(
        config.access.allow.clone(),
        config.access.deny.clone(),
    );
    info!(
        allow = config.access.allow.len(),
        deny = config.access.deny.len(),
        "access control configured",
    );

    let rate_limiter: RateLimit = RateLimit::new(config.ratelimit.requests_per_second)
        .expect("invalid rate limit config");
    info!(rps = config.ratelimit.requests_per_second, "rate limiting enabled");

    let shutdown_token: CancellationToken = CancellationToken::new();

    let circuit_breakers: CircuitBreakers = CircuitBreakers::new(&config.circuit_breaker);
    info!(
        failure_threshold = config.circuit_breaker.failure_threshold,
        recovery_timeout_secs = config.circuit_breaker.recovery_timeout_secs,
        half_open_max = config.circuit_breaker.half_open_max_requests,
        "circuit breaker configured"
    );

    let conn_pool: ConnPool = ConnPool::new().with_pool_config(
        config.proxy.h2_connections_per_backend,
        config.proxy.max_idle_quic_per_host,
    );

    let proxy_state: Arc<ProxyState> = Arc::new(ProxyState {
        reloadable: reloadable_rx,
        tls_connector,
        client_tls_config,
        health_rx,
        conn_pool,
        acl,
        rate_limiter,
        queues: DashMap::new(),
        default_queue_depth: config.balancer.queue_depth,
        metrics: proxy_metrics,
        circuit_breakers,
        shutdown: shutdown_token.clone(),
        timeouts: config.timeouts.clone(),
        proxy_config: config.proxy.clone(),
        compression_config: config.compression.clone(),
        retry_config: config.retry.clone(),
    });

    spawn_config_reload_task(config_rx, reloadable_tx, Arc::clone(&proxy_state));

    proxy_state.conn_pool.warm_up(
        &config.backends,
        &proxy_state.tls_connector,
        &proxy_state.client_tls_config,
        Duration::from_secs(config.timeouts.connect_secs),
        Duration::from_secs(config.timeouts.handshake_secs),
    ).await;
    info!(count = config.backends.len(), "connection pool pre-warmed on startup");

    let drain_state: Arc<ProxyState> = Arc::clone(&proxy_state);
    let drain_timeout: Duration = Duration::from_secs(config.balancer.drain_timeout_secs);

    let app = axum::Router::new()
        .fallback(any(proxy_handler))
        .layer(axum::extract::DefaultBodyLimit::max(config.proxy.max_response_body_bytes))
        .with_state(proxy_state)
        .into_make_service_with_connect_info::<transport::ConnectAddr>();

    info!("reduction proxy starting on {}", config.listen.address);

    match config.listen.transport {
        TransportKind::Tcp => {
            let listener: transport::tcp::TcpListener =
                transport::tcp::TcpListener::bind(config.listen.address, server_tls_config)
                    .await?;
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal(shutdown_token))
                .await
                .map_err(ReductionError::from)?;
        }
        TransportKind::Quic => {
            let quic_config: quinn::ServerConfig =
                transport::quic::build_quic_server_config(server_tls_config)?;
            let listener: transport::quic::QuicListener =
                transport::quic::QuicListener::bind_with_token(
                    config.listen.address,
                    quic_config,
                    shutdown_token.clone(),
                )?;
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal(shutdown_token))
                .await
                .map_err(ReductionError::from)?;
        }
    }

    drain_connections(drain_state, drain_timeout).await;
    return Ok(());
}

async fn shutdown_signal(token: CancellationToken) {
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

    token.cancel();
}

async fn drain_connections(
    state: Arc<ProxyState>,
    drain_timeout: Duration,
) {
    info!(timeout_secs = drain_timeout.as_secs(), "draining in-flight connections");

    let poll_interval: Duration = Duration::from_millis(250);
    let deadline: tokio::time::Instant = tokio::time::Instant::now() + drain_timeout;

    loop {
        let active: i64 = state.metrics.active_connection_count();
        if active <= 0 {
            info!("all connections drained");
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            warn!(active, "drain timeout reached, forcing shutdown with in-flight connections");
            break;
        }
        sleep(poll_interval).await;
    }

    state.conn_pool.drain();
    info!("connection pool closed");
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| ReductionError::Config("failed to install crypto provider".to_string()))?;

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        return Err(ReductionError::Config(
            "usage: reduction <config.toml>".to_string(),
        ));
    }

    let config_path: PathBuf = PathBuf::from(&args[1]);
    let config: ReductionConfig = config::load_config(&config_path)?;

    let tracer_provider = reduction::tracing_init::init_tracing(&config.tracing)?;

    let result = run(config_path, config).await;

    reduction::tracing_init::shutdown_tracing(tracer_provider);

    return result;
}
