use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use arrayvec::ArrayString;
use dashmap::DashMap;
use reduction::acl::AccessControl;
use reduction::cache::ResponseCache;
use reduction::circuit::CircuitBreakers;
use reduction::config::ReductionConfig;
use reduction::error::Result;
use reduction::health::HealthState;
use reduction::metrics::ProxyMetrics;
use reduction::proxy::{ConnPool, ProxyState, ReloadableState, Router};
use reduction::ratelimit::RateLimit;
use reduction::tunnel::registry::TunnelRegistry;
use reduction::tunnel::revocation::RevocationSet;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config_reload::build_backend_pools;

// Load-balancing subsystems built from config: the reloadable routing/pool/ACL state (published over a
// watch channel), the health state receiver, the rate limiter, and the circuit breakers. Grouped so the
// per-subsystem startup logging lives here rather than inflating the top-level wiring.
pub struct Balancing {
	pub reloadable_tx: watch::Sender<ReloadableState>,
	pub reloadable_rx: watch::Receiver<ReloadableState>,
	pub configured_backend_ids: HashSet<ArrayString<256>>,
	pub health_rx: watch::Receiver<HealthState>,
	// F4: the publish end of the health channel, handed to the tunnel listener so a control-plane peer
	// can update it. Kept alive there; when the health transport is off it is simply dropped.
	pub health_tx: watch::Sender<HealthState>,
	pub rate_limiter: RateLimit,
	pub circuit_breakers: CircuitBreakers,
}

pub fn build_balancing(config: &ReductionConfig) -> Result<Balancing> {
	let acl: AccessControl = AccessControl::new(config.access.allow.clone(), config.access.deny.clone());
	info!(
		allow = config.access.allow.len(),
		deny = config.access.deny.len(),
		"access control configured",
	);

	let initial_reloadable: ReloadableState = ReloadableState {
		router: Router::new(&config.routes),
		backend_pools: build_backend_pools(config)?,
		acl,
	};
	// The set of raw-reachable backend ids (pool keys), captured before initial_reloadable is moved into
	// the watch channel. Used to reject a raw_relay_authz entry that names a non-existent backend.
	let configured_backend_ids: HashSet<ArrayString<256>> = initial_reloadable.backend_pools.keys().copied().collect();

	let (reloadable_tx, reloadable_rx): (watch::Sender<ReloadableState>, watch::Receiver<ReloadableState>) =
		watch::channel(initial_reloadable);

	// The publish end goes to the tunnel listener (F4): a control-plane peer's Health frames update the
	// state the proxy path reads. With the health transport off the listener drops it, and the receiver
	// keeps returning the initial state exactly as before.
	let (health_tx, health_rx): (watch::Sender<HealthState>, watch::Receiver<HealthState>) =
		watch::channel(HealthState::with_config(
			config.balancer.max_backends,
			Duration::from_secs(config.health.staleness_ttl_secs),
			config.health.latency_threshold_ms,
		));

	let rate_limiter: RateLimit = RateLimit::new(config.ratelimit.requests_per_second)?;
	info!(rps = config.ratelimit.requests_per_second, "rate limiting enabled");

	let circuit_breakers: CircuitBreakers = CircuitBreakers::new(&config.circuit_breaker);
	info!(
		failure_threshold = config.circuit_breaker.failure_threshold.get(),
		recovery_timeout_secs = config.circuit_breaker.recovery_timeout_secs,
		half_open_max = config.circuit_breaker.half_open_max_requests.get(),
		"circuit breaker configured"
	);

	return Ok(Balancing {
		reloadable_tx,
		reloadable_rx,
		configured_backend_ids,
		health_rx,
		health_tx,
		rate_limiter,
		circuit_breakers,
	});
}

// The pre-built subsystems that become fields of the shared ProxyState. Bundled so `build_proxy_state`
// takes one value instead of a wall of positional arguments.
pub struct ProxyStateInputs {
	pub proxy_metrics: ProxyMetrics,
	pub tls_connector: TlsConnector,
	pub client_tls_config: Arc<rustls::ClientConfig>,
	pub reloadable_rx: watch::Receiver<ReloadableState>,
	pub health_rx: watch::Receiver<HealthState>,
	pub rate_limiter: RateLimit,
	pub circuit_breakers: CircuitBreakers,
}

// Assemble the shared ProxyState: the connection pool (tunnel-aware when tunneling is enabled), then the
// Arc<ProxyState> every request handler reads. The response cache is logged here when enabled.
pub fn build_proxy_state(
	config: &ReductionConfig,
	tunnel_registry: &Arc<TunnelRegistry>,
	revocation_rx: &watch::Receiver<RevocationSet>,
	shutdown_token: &CancellationToken,
	inputs: ProxyStateInputs,
) -> Arc<ProxyState> {
	let mut conn_pool: ConnPool = ConnPool::new().with_pool_config(
		config.proxy.h2_connections_per_backend.get(),
		config.proxy.max_idle_quic_per_host,
		config.proxy.h2_stream_window,
		config.proxy.h2_conn_window,
	);
	if config.tunnel.enabled {
		conn_pool = conn_pool.with_tunnel_registry(Arc::clone(tunnel_registry));
	}

	let proxy_state: Arc<ProxyState> = Arc::new(ProxyState {
		reloadable: inputs.reloadable_rx,
		revocation: revocation_rx.clone(),
		tls_connector: inputs.tls_connector,
		client_tls_config: inputs.client_tls_config,
		health_rx: inputs.health_rx,
		conn_pool,
		rate_limiter: inputs.rate_limiter,
		queues: DashMap::new(),
		labels: DashMap::new(),
		default_queue_depth: config.balancer.queue_depth,
		metrics: inputs.proxy_metrics,
		circuit_breakers: inputs.circuit_breakers,
		shutdown: shutdown_token.clone(),
		timeouts: config.timeouts.clone(),
		proxy_config: config.proxy.clone(),
		compression_config: config.compression.clone(),
		retry_config: config.retry.clone(),
		cache_config: config.cache.clone(),
		response_cache: ResponseCache::new(&config.cache),
		client_auth: config.listen.client_auth,
	});

	if config.cache.enabled {
		info!(
			max_entries = config.cache.max_entries.get(),
			max_entry_bytes = config.cache.max_entry_bytes.get(),
			default_ttl_secs = config.cache.default_ttl_secs.get(),
			"response cache enabled"
		);
	}

	return proxy_state;
}
