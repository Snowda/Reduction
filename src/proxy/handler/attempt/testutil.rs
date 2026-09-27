use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::time::Instant;

use arrayvec::{ArrayString, ArrayVec};
use axum::body::Body;
use axum::http::request::Parts;
use axum::http::{Request, Response, StatusCode};
use opentelemetry::KeyValue;

use crate::acl::AccessControl;
use crate::balancer::BackendPool;
use crate::config::{BackendConfig, CacheConfig, CircuitBreakerConfig, ProxyConfig, RetryConfig, TimeoutConfig, TransportKind};
use crate::proxy::handler::{ConnPermitGuard, ProxyState, ReloadableState, TestProxyStateParams, backend_label};
use crate::proxy::router::Router;
use crate::tunnel::revocation::RevocationSet;

use super::{RequestCtx, RetryState, Selected};

// An arbitrary loopback address for backends and clients; nothing ever connects to it because these
// tests stop short of the network forward, so the port need not be reachable.
const TEST_ADDR: &str = "127.0.0.1:9";
// Fast, jitter-free retry so the backoff sleeps in the retry paths cost ~1ms, not the production 200ms.
const FAST_BASE_DELAY_MS: u64 = 1;

pub fn install_crypto() {
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

// A ClientConfig with an empty trust store — never used for a handshake here, only stored in ProxyState.
pub fn client_config() -> Arc<rustls::ClientConfig> {
	return Arc::new(
		rustls::ClientConfig::builder()
			.with_root_certificates(rustls::RootCertStore::empty())
			.with_no_client_auth(),
	);
}

pub fn fast_retry() -> RetryConfig {
	return RetryConfig {
		max_retries: 2,
		base_delay_ms: FAST_BASE_DELAY_MS,
		max_delay_ms: FAST_BASE_DELAY_MS,
		jitter_ms: 0,
	};
}

// A circuit breaker that opens on the first failure and stays open (long recovery), so `check` is
// forced to Open synchronously by a single record_failure.
pub fn cb_opens_immediately() -> CircuitBreakerConfig {
	return CircuitBreakerConfig {
		failure_threshold: NonZeroU32::new(1).unwrap(),
		recovery_timeout_secs: 60,
		half_open_max_requests: NonZeroU32::new(1).unwrap(),
	};
}

// Opens on the first failure but with a zero recovery window, so the very next `check` transitions to
// half-open without any real elapsed time.
pub fn cb_half_opens_immediately() -> CircuitBreakerConfig {
	return CircuitBreakerConfig {
		failure_threshold: NonZeroU32::new(1).unwrap(),
		recovery_timeout_secs: 0,
		half_open_max_requests: NonZeroU32::new(1).unwrap(),
	};
}

pub fn cache_off() -> CacheConfig {
	return CacheConfig {
		enabled: false,
		..CacheConfig::default()
	};
}

pub fn cache_on() -> CacheConfig {
	return CacheConfig {
		enabled: true,
		max_entries: NonZeroUsize::new(100).unwrap(),
		max_entry_bytes: NonZeroUsize::new(1024 * 1024).unwrap(),
		default_ttl_secs: NonZeroU64::new(300).unwrap(),
	};
}

pub fn make_state(cb: CircuitBreakerConfig, retry: RetryConfig, cache: CacheConfig) -> Arc<ProxyState> {
	install_crypto();
	let reloadable: ReloadableState = ReloadableState {
		router: Router::new(&[]),
		backend_pools: HashMap::new(),
		acl: AccessControl::new(vec![], vec![]),
	};
	return ProxyState::for_test(TestProxyStateParams {
		circuit_breaker_config: cb,
		retry_config: retry,
		cache_config: cache,
		..TestProxyStateParams::new(reloadable, RevocationSet::default(), client_config(), TimeoutConfig::default())
	});
}

// Like make_state but with a 1s F1 wake deadline, so the park's timeout->503 path resolves quickly.
pub fn make_state_short_wake() -> Arc<ProxyState> {
	install_crypto();
	let reloadable: ReloadableState = ReloadableState {
		router: Router::new(&[]),
		backend_pools: HashMap::new(),
		acl: AccessControl::new(vec![], vec![]),
	};
	let proxy_config: ProxyConfig = ProxyConfig {
		wake_timeout_secs: NonZeroU64::new(1).unwrap(),
		..ProxyConfig::default()
	};
	return ProxyState::for_test(TestProxyStateParams {
		circuit_breaker_config: cb_opens_immediately(),
		retry_config: fast_retry(),
		cache_config: cache_off(),
		proxy_config,
		..TestProxyStateParams::new(reloadable, RevocationSet::default(), client_config(), TimeoutConfig::default())
	});
}

pub fn make_backend(id: &str) -> BackendConfig {
	return BackendConfig::new(id, TEST_ADDR.parse().unwrap(), 1.0, TransportKind::Tcp).unwrap();
}

pub fn make_backend_capped(id: &str, max_connections: u32) -> BackendConfig {
	return make_backend(id).with_max_connections(max_connections).unwrap();
}

// Owns the borrowed-by-RequestCtx locals so a test can hand out a fresh ctx without lifetime juggling.
pub struct Fixture {
	pub state: Arc<ProxyState>,
	pub pool: BackendPool,
	pub cache_identity: String,
}

impl Fixture {
	pub fn new(state: Arc<ProxyState>, backends: Vec<BackendConfig>) -> Self {
		return Self {
			state,
			pool: BackendPool::new(backends).unwrap(),
			cache_identity: String::new(),
		};
	}

	pub fn ctx(&self, max_attempts: u32, is_cacheable_method: bool, request_has_cookie: bool, accepts_zstd: bool) -> RequestCtx<'_> {
		return RequestCtx {
			state: &self.state,
			pool: &self.pool,
			client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
			client_identity: None,
			backend_id: ArrayString::from("svc").unwrap(),
			cache_identity: &self.cache_identity,
			start: Instant::now(),
			max_attempts,
			is_cacheable_method,
			request_has_cookie,
			accepts_zstd,
		};
	}
}

pub fn empty_retry() -> RetryState {
	return RetryState {
		failed_backends: ArrayVec::new(),
		last_response: None,
		last_error_msg: None,
	};
}

// Build a Selected with a real connection permit, mirroring select_and_gate's own construction, so
// handle_response can be driven without a live network selection.
pub fn make_selected(state: &Arc<ProxyState>, backend: BackendConfig) -> Selected {
	let sel_label: KeyValue = backend_label(&state.labels, &backend.id);
	let permit = state.conn_pool.try_acquire_conn_permit(&backend).unwrap();
	let conn: ConnPermitGuard = ConnPermitGuard {
		counter: state.metrics.backend_active_connections.clone(),
		backend_kv: sel_label.clone(),
		_permit: permit,
	};
	return Selected { backend, sel_label, conn, half_open: None };
}

pub fn parts_for(method: &str, uri: &str) -> Parts {
	let req: Request<Body> = Request::builder().method(method).uri(uri).body(Body::empty()).unwrap();
	return req.into_parts().0;
}

pub fn response_with(status: StatusCode, cache_control: Option<&str>, body: &str) -> Response<Body> {
	let mut builder = Response::builder().status(status);
	if let Some(cc) = cache_control {
		builder = builder.header("cache-control", cc);
	}
	return builder.body(Body::from(body.to_owned())).unwrap();
}
