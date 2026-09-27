use super::{
	AccessControl, Arc, ArrayString, BackendPool, CacheConfig, CancellationToken, CircuitBreakers, ClientAuthPolicy,
	CompressionConfig, ConnPool, DashMap, HashMap, HealthState, KeyValue, ProxyConfig, ProxyMetrics, RateLimit,
	RequestQueue, ResponseCache, RetryConfig, RevocationSet, Router, TimeoutConfig, TlsConnector, watch,
};
#[cfg(any(test, feature = "integration_tests"))]
use super::CircuitBreakerConfig;
#[cfg(any(test, feature = "integration_tests"))]
use crate::tunnel::registry::TunnelRegistry;

#[derive(Clone)]
pub struct ReloadableState {
	pub router: Router,
	pub backend_pools: HashMap<ArrayString<256>, BackendPool>,
	// IP allow/deny lists, hot-swapped with the rest of the reloadable config so an [access] edit
	// takes effect at the next admission check without a restart. Read via reloadable.borrow().
	pub acl: AccessControl,
}

pub struct ProxyState {
	pub reloadable: watch::Receiver<ReloadableState>,
	// Revocation denylist, hot-swapped by the same watch pattern as the rest of hot config. Read
	// per-request to 403 a revoked device before it can reach a backend or the cache.
	pub revocation: watch::Receiver<RevocationSet>,
	pub tls_connector: TlsConnector,
	pub client_tls_config: Arc<rustls::ClientConfig>,
	pub health_rx: watch::Receiver<HealthState>,
	pub conn_pool: ConnPool,
	pub rate_limiter: RateLimit,
	pub queues: DashMap<ArrayString<256>, Arc<RequestQueue>>,
	// One interned ("backend", <id>) metric label per backend id (Arc<str>), so per-request label clones are
	// refcount bumps, not allocations. Lazily populated on the request path; bounded by configured backends.
	pub labels: DashMap<ArrayString<256>, KeyValue>,
	pub default_queue_depth: u32,
	pub metrics: ProxyMetrics,
	pub circuit_breakers: CircuitBreakers,
	pub shutdown: CancellationToken,
	pub timeouts: TimeoutConfig,
	pub proxy_config: ProxyConfig,
	pub compression_config: CompressionConfig,
	pub retry_config: RetryConfig,
	pub cache_config: CacheConfig,
	pub response_cache: ResponseCache,
	// Inbound client-auth policy of the public listener. Read on the admission path so a nameless peer
	// is admitted only when the policy is not Required (public-browser mode). Copy, so per-request reads
	// are trivial. Set once at startup from `[listen] client_auth`; not hot-reloaded (a listener rebind).
	pub client_auth: ClientAuthPolicy,
}

// Queue depth every test ProxyState builder used; named so the constructor below has no bare literal.
#[cfg(any(test, feature = "integration_tests"))]
const DEFAULT_TEST_QUEUE_DEPTH: u32 = 1000;

// The subset of ProxyState that tests vary; everything else takes a fixed default in `for_test`. `new` fills
// the common four inputs with production-default circuit-breaker/retry/cache; override via struct-update syntax.
#[cfg(any(test, feature = "integration_tests"))]
pub struct TestProxyStateParams {
	pub reloadable: ReloadableState,
	pub revocation: RevocationSet,
	pub client_tls_config: Arc<rustls::ClientConfig>,
	pub timeouts: TimeoutConfig,
	pub circuit_breaker_config: CircuitBreakerConfig,
	pub retry_config: RetryConfig,
	pub cache_config: CacheConfig,
	pub proxy_config: ProxyConfig,
	pub tunnel_registry: Option<Arc<TunnelRegistry>>,
	pub client_auth: ClientAuthPolicy,
	pub compression_config: CompressionConfig,
}

#[cfg(any(test, feature = "integration_tests"))]
impl TestProxyStateParams {
	// The common case: the four inputs that always vary, with default circuit-breaker/retry/cache.
	#[must_use]
	pub fn new(
		reloadable: ReloadableState,
		revocation: RevocationSet,
		client_tls_config: Arc<rustls::ClientConfig>,
		timeouts: TimeoutConfig,
	) -> Self {
		return Self {
			reloadable,
			revocation,
			client_tls_config,
			timeouts,
			circuit_breaker_config: CircuitBreakerConfig::default(),
			retry_config: RetryConfig::default(),
			cache_config: CacheConfig::default(),
			proxy_config: ProxyConfig::default(),
			tunnel_registry: None,
			client_auth: ClientAuthPolicy::Required,
			compression_config: CompressionConfig::default(),
		};
	}
}

#[cfg(any(test, feature = "integration_tests"))]
impl ProxyState {
	// Build a ProxyState for tests: caller supplies what varies, the rest are production defaults (TLS connector
	// and cache derive from the supplied configs). The one u32::MAX rate-limit unwrap is infallible.
	#[cfg_attr(not(test), allow(clippy::unwrap_used))]
	#[must_use]
	pub fn for_test(params: TestProxyStateParams) -> Arc<Self> {
		let (_reloadable_tx, reloadable) = watch::channel(params.reloadable);
		let (_health_tx, health_rx) = watch::channel(HealthState::new());
		let (_revocation_tx, revocation) = watch::channel(params.revocation);
		let tls_connector: TlsConnector = TlsConnector::from(params.client_tls_config.clone());
		let response_cache: ResponseCache = ResponseCache::new(&params.cache_config);
		return Arc::new(Self {
			reloadable,
			revocation,
			tls_connector,
			client_tls_config: params.client_tls_config,
			health_rx,
			conn_pool: match params.tunnel_registry {
				Some(registry) => ConnPool::new().with_tunnel_registry(registry),
				None => ConnPool::new(),
			},
			rate_limiter: RateLimit::new(u32::MAX).unwrap(),
			queues: DashMap::new(),
			labels: DashMap::new(),
			default_queue_depth: DEFAULT_TEST_QUEUE_DEPTH,
			metrics: ProxyMetrics::new(),
			circuit_breakers: CircuitBreakers::new(&params.circuit_breaker_config),
			shutdown: CancellationToken::new(),
			timeouts: params.timeouts,
			proxy_config: params.proxy_config,
			compression_config: params.compression_config,
			retry_config: params.retry_config,
			cache_config: params.cache_config,
			response_cache,
			client_auth: params.client_auth,
		});
	}
}

#[cfg(test)]
mod tests {
	use std::net::IpAddr;

	use super::*;

	#[test]
	fn test_reloadable_state_is_clone() {
		let state = ReloadableState {
			router: Router::new(&[]),
			backend_pools: HashMap::new(),
			acl: AccessControl::new(vec![], vec![]),
		};
		let cloned = state.clone();
		// The clone is the behavior under test; assert it reproduced the source state's shape.
		assert_eq!(cloned.backend_pools.len(), state.backend_pools.len());
	}

	// ACL hot-swap seam: publishing a new ReloadableState over the watch channel changes the admission
	// decision with no restart (the old fixed-field design could not have, so this asserts the feature works).
	#[test]
	fn test_acl_hot_swaps_over_reloadable_channel() {
		let denied: IpAddr = "10.0.0.1".parse().unwrap();
		let deny_all: ReloadableState = ReloadableState {
			router: Router::new(&[]),
			backend_pools: HashMap::new(),
			acl: AccessControl::new(vec![], vec!["10.0.0.0/8".parse().unwrap()]),
		};
		let (tx, rx): (watch::Sender<ReloadableState>, watch::Receiver<ReloadableState>) = watch::channel(deny_all);

		// Initial snapshot denies the peer.
		assert!(rx.borrow().acl.check(denied).is_err());

		// Swap in a permissive ACL; the same reader now admits the peer.
		tx.send(ReloadableState {
			router: Router::new(&[]),
			backend_pools: HashMap::new(),
			acl: AccessControl::new(vec![], vec![]),
		})
		.unwrap();
		assert!(rx.borrow().acl.check(denied).is_ok());
	}

	#[test]
	fn test_proxy_config_defaults() {
		let cfg: ProxyConfig = ProxyConfig::default();
		assert_eq!(cfg.max_response_body_bytes, 10 * 1024 * 1024);
		assert_eq!(cfg.max_request_body_bytes, 10 * 1024 * 1024);
		assert_eq!(cfg.h2_connections_per_backend.get(), 4);
		assert_eq!(cfg.max_idle_quic_per_host, 16);
		assert_eq!(cfg.h2_stream_window, 2 * 1024 * 1024);
		assert_eq!(cfg.h2_conn_window, 4 * 1024 * 1024);
		assert_eq!(cfg.inline_compress_threshold, 8192);
		assert_eq!(cfg.quic_channel_capacity.get(), 256);
	}

	#[test]
	fn test_compression_config_defaults() {
		let cfg: CompressionConfig = CompressionConfig::default();
		assert_eq!(cfg.level, 3);
		assert_eq!(cfg.min_bytes, 256);
	}

	#[test]
	fn test_timeout_config_defaults() {
		let cfg: TimeoutConfig = TimeoutConfig::default();
		assert_eq!(cfg.connect_secs.get(), 5);
		assert_eq!(cfg.handshake_secs.get(), 5);
		assert_eq!(cfg.request_secs.get(), 30);
	}
}
