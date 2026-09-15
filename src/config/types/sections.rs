// The individual `[section]` config blocks of ReductionConfig (balancer, timeouts, rate limit, access,
// metrics, tracing, proxy, compression, health, circuit breaker, retry, tunnel, cache), plus the const
// NonZero constructors their defaults use. Split out of `types.rs` so that file stays focused on the
// top-level ReductionConfig and its cross-field validation. Re-exported via `pub use sections::*`.

use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use arrayvec::ArrayString;
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};

// Const NonZero constructors. `MIN.saturating_add(value - 1)` builds the value without the
// banned unwrap()/expect()/panic that `NonZeroX::new(value).unwrap()` would require: MIN is 1,
// so saturating_add(value - 1) yields `value`. Inputs are compile-time literals >= 1; passing 0
// underflows `value - 1` into a const-eval error, which correctly rejects a zero default.
const fn nonzero_u32(value: u32) -> NonZeroU32 {
	return NonZeroU32::MIN.saturating_add(value - 1);
}

const fn nonzero_u64(value: u64) -> NonZeroU64 {
	return NonZeroU64::MIN.saturating_add(value - 1);
}

const fn nonzero_usize(value: usize) -> NonZeroUsize {
	return NonZeroUsize::MIN.saturating_add(value - 1);
}

// ── Balancer defaults ──

pub const DEFAULT_QUEUE_DEPTH: u32 = 1000;
pub const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_MAX_BACKENDS: u32 = 64;
pub const HARD_MAX_BACKENDS: u32 = 256;

const fn default_queue_depth() -> u32 {
	return DEFAULT_QUEUE_DEPTH;
}
const fn default_drain_timeout_secs() -> u64 {
	return DEFAULT_DRAIN_TIMEOUT_SECS;
}
const fn default_max_backends() -> u32 {
	return DEFAULT_MAX_BACKENDS;
}

#[derive(Debug, Clone, Serialize)]
pub struct BalancerConfig {
	pub queue_depth: u32,
	pub drain_timeout_secs: u64,
	pub max_backends: u32,
}

impl<'de> Deserialize<'de> for BalancerConfig {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire {
			#[serde(default = "default_queue_depth")]
			queue_depth: u32,
			#[serde(default = "default_drain_timeout_secs")]
			drain_timeout_secs: u64,
			#[serde(default = "default_max_backends")]
			max_backends: u32,
		}
		let wire: Wire = Wire::deserialize(deserializer)?;
		validate_max_backends(wire.max_backends).map_err(serde::de::Error::custom)?;
		return Ok(Self {
			queue_depth: wire.queue_depth,
			drain_timeout_secs: wire.drain_timeout_secs,
			max_backends: wire.max_backends,
		});
	}
}

impl Default for BalancerConfig {
	fn default() -> Self {
		return Self {
			queue_depth: DEFAULT_QUEUE_DEPTH,
			drain_timeout_secs: DEFAULT_DRAIN_TIMEOUT_SECS,
			max_backends: DEFAULT_MAX_BACKENDS,
		};
	}
}

fn validate_max_backends(max_backends: u32) -> std::result::Result<(), String> {
	if max_backends == 0 {
		return Err("max_backends must be at least 1".into());
	}
	if max_backends > HARD_MAX_BACKENDS {
		return Err(format!(
			"max_backends {max_backends} exceeds hard limit {HARD_MAX_BACKENDS}"
		));
	}
	return Ok(());
}


// ── Timeout defaults ──

pub const DEFAULT_CONNECT_TIMEOUT_SECS: NonZeroU64 = nonzero_u64(5);
pub const DEFAULT_HANDSHAKE_TIMEOUT_SECS: NonZeroU64 = nonzero_u64(5);
pub const DEFAULT_REQUEST_TIMEOUT_SECS: NonZeroU64 = nonzero_u64(30);
// Max gap between response-body frames from a backend before the transfer is aborted. The request
// timeout only bounds time-to-headers; without this a backend could send headers and then stall the
// body forever while holding a connection permit, a queue slot, and the active-connection gauge.
pub const DEFAULT_RESPONSE_IDLE_TIMEOUT_SECS: NonZeroU64 = nonzero_u64(60);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TimeoutConfig {
	pub connect_secs: NonZeroU64,
	pub handshake_secs: NonZeroU64,
	pub request_secs: NonZeroU64,
	// Idle timeout applied to the streaming response body (see DEFAULT_RESPONSE_IDLE_TIMEOUT_SECS).
	pub response_idle_secs: NonZeroU64,
}

impl Default for TimeoutConfig {
	fn default() -> Self {
		return Self {
			connect_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
			handshake_secs: DEFAULT_HANDSHAKE_TIMEOUT_SECS,
			request_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
			response_idle_secs: DEFAULT_RESPONSE_IDLE_TIMEOUT_SECS,
		};
	}
}

// ── Rate limit defaults ──

pub const DEFAULT_REQUESTS_PER_SECOND: u32 = u32::MAX;
// How often the keyed rate-limiter GC sweep runs. governor's per-IP DashMap store never removes
// entries on its own, so a sweep drops the fully-replenished ones — bounding the map to the active
// source-IP set instead of every IP ever seen.
pub const DEFAULT_RETAIN_INTERVAL_SECS: NonZeroU64 = nonzero_u64(300);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RateLimitConfig {
	pub requests_per_second: u32,
	pub retain_interval_secs: NonZeroU64,
}

impl Default for RateLimitConfig {
	fn default() -> Self {
		return Self {
			requests_per_second: DEFAULT_REQUESTS_PER_SECOND,
			retain_interval_secs: DEFAULT_RETAIN_INTERVAL_SECS,
		};
	}
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AccessControlConfig {
	#[serde(default)]
	pub allow: Vec<IpNet>,
	#[serde(default)]
	pub deny: Vec<IpNet>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
	pub otlp_endpoint: Option<String>,
}

// ── Tracing defaults ──

pub const DEFAULT_TRACE_SAMPLE_RATIO: f64 = 1.0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TracingConfig {
	pub otlp_endpoint: Option<String>,
	pub sample_ratio: f64,
}

impl Default for TracingConfig {
	fn default() -> Self {
		return Self {
			otlp_endpoint: None,
			sample_ratio: DEFAULT_TRACE_SAMPLE_RATIO,
		};
	}
}

// ── Proxy defaults ──

pub const DEFAULT_MAX_RESPONSE_BODY_BYTES: u32 = 10 * 1024 * 1024;
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: u32 = 10 * 1024 * 1024;
pub const DEFAULT_H2_CONNECTIONS_PER_BACKEND: NonZeroU32 = nonzero_u32(4);
pub const DEFAULT_MAX_IDLE_QUIC_PER_HOST: u32 = 16;
pub const DEFAULT_H2_STREAM_WINDOW: u32 = 2 * 1024 * 1024;
pub const DEFAULT_H2_CONN_WINDOW: u32 = 4 * 1024 * 1024;
pub const DEFAULT_INLINE_COMPRESS_THRESHOLD: u32 = 8192;
pub const DEFAULT_QUIC_CHANNEL_CAPACITY: NonZeroU32 = nonzero_u32(256);
// F1: how long a request to a cold `wakeable` backend is parked awaiting a session before a 503.
pub const DEFAULT_WAKE_TIMEOUT_SECS: NonZeroU64 = nonzero_u64(30);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProxyConfig {
	pub max_response_body_bytes: u32,
	// Cap on any request body the proxy holds in memory: the retry buffer and zstd request
	// decompression (both compressed input and decompressed output). Bodies with a declared
	// Content-Length above this stream through without retry support instead of being buffered.
	pub max_request_body_bytes: u32,
	pub h2_connections_per_backend: NonZeroU32,
	pub max_idle_quic_per_host: u32,
	pub h2_stream_window: u32,
	pub h2_conn_window: u32,
	pub inline_compress_threshold: u32,
	pub quic_channel_capacity: NonZeroU32,
	// F1: park deadline for a request to a cold `wakeable` backend — released early when a session
	// registers, else a 503 + Retry-After at this timeout. Must be < `[timeouts] request_secs`.
	pub wake_timeout_secs: NonZeroU64,
}

impl Default for ProxyConfig {
	fn default() -> Self {
		return Self {
			max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
			max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
			h2_connections_per_backend: DEFAULT_H2_CONNECTIONS_PER_BACKEND,
			max_idle_quic_per_host: DEFAULT_MAX_IDLE_QUIC_PER_HOST,
			h2_stream_window: DEFAULT_H2_STREAM_WINDOW,
			h2_conn_window: DEFAULT_H2_CONN_WINDOW,
			inline_compress_threshold: DEFAULT_INLINE_COMPRESS_THRESHOLD,
			quic_channel_capacity: DEFAULT_QUIC_CHANNEL_CAPACITY,
			wake_timeout_secs: DEFAULT_WAKE_TIMEOUT_SECS,
		};
	}
}

// ── Compression defaults ──

pub const DEFAULT_COMPRESSION_LEVEL: i32 = 3;
pub const DEFAULT_MIN_COMPRESS_BYTES: u32 = 256;
// zstd response transform is on by default: bandwidth saving on constrained links is a core product
// goal for the M2M path. A public deployment that must not re-encode bodies (e.g. the first blog
// cutover) sets `enabled = false`. Default `true` so existing M2M configs are unchanged.
pub const DEFAULT_COMPRESSION_ENABLED: bool = true;

const fn default_compression_enabled() -> bool {
	return DEFAULT_COMPRESSION_ENABLED;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CompressionConfig {
	// When false, the proxy never applies the zstd response transform, even if the client sends
	// `Accept-Encoding: zstd`. A body the backend already encoded is passed through regardless.
	#[serde(default = "default_compression_enabled")]
	pub enabled: bool,
	pub level: i32,
	pub min_bytes: u32,
}

impl Default for CompressionConfig {
	fn default() -> Self {
		return Self {
			enabled: DEFAULT_COMPRESSION_ENABLED,
			level: DEFAULT_COMPRESSION_LEVEL,
			min_bytes: DEFAULT_MIN_COMPRESS_BYTES,
		};
	}
}

// ── Health defaults ──

pub const DEFAULT_STALENESS_TTL_SECS: u64 = 300;
pub const DEFAULT_LATENCY_THRESHOLD_MS: u32 = 500;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HealthConfig {
	pub staleness_ttl_secs: u64,
	pub latency_threshold_ms: u32,
}

impl Default for HealthConfig {
	fn default() -> Self {
		return Self {
			staleness_ttl_secs: DEFAULT_STALENESS_TTL_SECS,
			latency_threshold_ms: DEFAULT_LATENCY_THRESHOLD_MS,
		};
	}
}

// ── Circuit breaker defaults ──

pub const DEFAULT_FAILURE_THRESHOLD: NonZeroU32 = nonzero_u32(5);
pub const DEFAULT_RECOVERY_TIMEOUT_SECS: u64 = 60;
pub const DEFAULT_HALF_OPEN_MAX_REQUESTS: NonZeroU32 = nonzero_u32(2);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CircuitBreakerConfig {
	pub failure_threshold: NonZeroU32,
	pub recovery_timeout_secs: u64,
	pub half_open_max_requests: NonZeroU32,
}

impl Default for CircuitBreakerConfig {
	fn default() -> Self {
		return Self {
			failure_threshold: DEFAULT_FAILURE_THRESHOLD,
			recovery_timeout_secs: DEFAULT_RECOVERY_TIMEOUT_SECS,
			half_open_max_requests: DEFAULT_HALF_OPEN_MAX_REQUESTS,
		};
	}
}

// ── Retry defaults ──

pub const DEFAULT_MAX_RETRIES: u32 = 2;
pub const DEFAULT_RETRY_BASE_DELAY_MS: u64 = 200;
pub const DEFAULT_RETRY_MAX_DELAY_MS: u64 = 2000;
pub const DEFAULT_RETRY_JITTER_MS: u64 = 100;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RetryConfig {
	pub max_retries: u32,
	pub base_delay_ms: u64,
	pub max_delay_ms: u64,
	pub jitter_ms: u64,
}

impl Default for RetryConfig {
	fn default() -> Self {
		return Self {
			max_retries: DEFAULT_MAX_RETRIES,
			base_delay_ms: DEFAULT_RETRY_BASE_DELAY_MS,
			max_delay_ms: DEFAULT_RETRY_MAX_DELAY_MS,
			jitter_ms: DEFAULT_RETRY_JITTER_MS,
		};
	}
}

// ── Tunnel defaults ──

pub const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 45;
pub const DEFAULT_MAX_SESSIONS_PER_BACKEND: NonZeroU32 = nonzero_u32(8);
pub const DEFAULT_REGISTRATION_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_CONTROL_CHANNEL_CAPACITY: NonZeroU32 = nonzero_u32(16);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TunnelConfig {
	pub enabled: bool,
	pub listen_address: Option<SocketAddr>,
	pub heartbeat_timeout_secs: u64,
	pub allowed_backend_ids: Vec<ArrayString<256>>,
	pub max_sessions_per_backend: NonZeroU32,
	pub registration_timeout_secs: u64,
	pub control_channel_capacity: NonZeroU32,
	// Path to the revocation denylist (revoked.toml), written by the fleet layer and hot-watched.
	// None disables revocation (empty set). See docs/configuration.md.
	pub revocation_path: Option<PathBuf>,
	// Global cap on concurrent tunnel sessions across ALL backends (accept backpressure). None =
	// unlimited. Enforced at registration, on top of the per-backend `max_sessions_per_backend` cap.
	pub max_total_sessions: Option<NonZeroU32>,
	// Per-source-IP accept rate limit for incoming tunnel connections (connections/sec). None =
	// unlimited. Enforced at accept() BEFORE the QUIC handshake, so a connection flood from one
	// source is dropped cheaply rather than each connection paying a full handshake + registration.
	pub max_accepts_per_second_per_ip: Option<NonZeroU32>,
	// F4: honor `Health` frames from a control-plane peer (registered with CONTROL_CAPABILITY),
	// applying them to the balancer's HealthState. Off by default — the Phase 2 flag for the health
	// transport; when false the listener ignores health frames exactly as before.
	pub control_plane_health: bool,
}

impl Default for TunnelConfig {
	fn default() -> Self {
		return Self {
			enabled: false,
			listen_address: None,
			heartbeat_timeout_secs: DEFAULT_HEARTBEAT_TIMEOUT_SECS,
			allowed_backend_ids: Vec::new(),
			max_sessions_per_backend: DEFAULT_MAX_SESSIONS_PER_BACKEND,
			registration_timeout_secs: DEFAULT_REGISTRATION_TIMEOUT_SECS,
			control_channel_capacity: DEFAULT_CONTROL_CHANNEL_CAPACITY,
			revocation_path: None,
			max_total_sessions: None,
			max_accepts_per_second_per_ip: None,
			control_plane_health: false,
		};
	}
}

// ── Cache defaults ──

pub const DEFAULT_CACHE_MAX_ENTRIES: NonZeroUsize = nonzero_usize(1000);
pub const DEFAULT_CACHE_MAX_ENTRY_BYTES: NonZeroUsize = nonzero_usize(1024 * 1024);
pub const DEFAULT_CACHE_DEFAULT_TTL_SECS: NonZeroU64 = nonzero_u64(60);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CacheConfig {
	pub enabled: bool,
	pub max_entries: NonZeroUsize,
	pub max_entry_bytes: NonZeroUsize,
	pub default_ttl_secs: NonZeroU64,
}

impl Default for CacheConfig {
	fn default() -> Self {
		return Self {
			enabled: false,
			max_entries: DEFAULT_CACHE_MAX_ENTRIES,
			max_entry_bytes: DEFAULT_CACHE_MAX_ENTRY_BYTES,
			default_ttl_secs: DEFAULT_CACHE_DEFAULT_TTL_SECS,
		};
	}
}

#[cfg(test)]
mod tests {
	use std::path::Path;

	use super::*;

	// ── nonzero const helpers ──

	#[test]
	fn nonzero_helpers_produce_exact_values() {
		assert_eq!(nonzero_u32(1).get(), 1);
		assert_eq!(nonzero_u32(4).get(), 4);
		assert_eq!(nonzero_u64(60).get(), 60);
		assert_eq!(nonzero_usize(1000).get(), 1000);
	}

	// ── validators ──

	#[test]
	fn validate_max_backends_rejects_zero_and_above_hard_limit() {
		let zero_err: String = validate_max_backends(0).unwrap_err();
		assert!(zero_err.contains("at least 1"), "got: {zero_err}");
		let over_err: String = validate_max_backends(HARD_MAX_BACKENDS + 1).unwrap_err();
		assert!(over_err.contains("hard limit"), "got: {over_err}");
		assert!(validate_max_backends(HARD_MAX_BACKENDS).is_ok());
		assert!(validate_max_backends(1).is_ok());
	}

	// ── BalancerConfig ──

	#[test]
	fn balancer_empty_toml_matches_default() {
		let parsed: BalancerConfig = toml::from_str("").unwrap();
		let default: BalancerConfig = BalancerConfig::default();
		assert_eq!(parsed.queue_depth, default.queue_depth);
		assert_eq!(parsed.drain_timeout_secs, default.drain_timeout_secs);
		assert_eq!(parsed.max_backends, default.max_backends);
		assert_eq!(default.queue_depth, DEFAULT_QUEUE_DEPTH);
		assert_eq!(default.drain_timeout_secs, DEFAULT_DRAIN_TIMEOUT_SECS);
		assert_eq!(default.max_backends, DEFAULT_MAX_BACKENDS);
	}

	#[test]
	fn balancer_rejects_zero_max_backends() {
		let result: std::result::Result<BalancerConfig, _> = toml::from_str("max_backends = 0");
		assert!(result.is_err());
		let err: String = result.unwrap_err().to_string();
		assert!(err.contains("at least 1"), "got: {err}");
	}

	#[test]
	fn balancer_rejects_max_backends_above_hard_limit() {
		let toml_str: String = format!("max_backends = {}", HARD_MAX_BACKENDS + 1);
		let result: std::result::Result<BalancerConfig, _> = toml::from_str(&toml_str);
		assert!(result.is_err());
		let err: String = result.unwrap_err().to_string();
		assert!(err.contains("hard limit"), "got: {err}");
	}

	#[test]
	fn balancer_accepts_hard_limit_max_backends() {
		let toml_str: String = format!("max_backends = {HARD_MAX_BACKENDS}");
		let parsed: BalancerConfig = toml::from_str(&toml_str).unwrap();
		assert_eq!(parsed.max_backends, HARD_MAX_BACKENDS);
	}


	// ── Section defaults: empty TOML must equal Default and the named constants ──

	#[test]
	fn timeout_config_empty_toml_matches_default() {
		let parsed: TimeoutConfig = toml::from_str("").unwrap();
		let default: TimeoutConfig = TimeoutConfig::default();
		assert_eq!(parsed.connect_secs, default.connect_secs);
		assert_eq!(parsed.handshake_secs, default.handshake_secs);
		assert_eq!(parsed.request_secs, default.request_secs);
		assert_eq!(parsed.response_idle_secs, default.response_idle_secs);
		assert_eq!(default.connect_secs, DEFAULT_CONNECT_TIMEOUT_SECS);
		assert_eq!(default.handshake_secs, DEFAULT_HANDSHAKE_TIMEOUT_SECS);
		assert_eq!(default.request_secs, DEFAULT_REQUEST_TIMEOUT_SECS);
		assert_eq!(default.response_idle_secs, DEFAULT_RESPONSE_IDLE_TIMEOUT_SECS);
	}

	#[test]
	fn rate_limit_config_empty_toml_matches_default() {
		let parsed: RateLimitConfig = toml::from_str("").unwrap();
		let default: RateLimitConfig = RateLimitConfig::default();
		assert_eq!(parsed.requests_per_second, default.requests_per_second);
		assert_eq!(default.requests_per_second, DEFAULT_REQUESTS_PER_SECOND);
		assert_eq!(parsed.retain_interval_secs, default.retain_interval_secs);
		assert_eq!(default.retain_interval_secs, DEFAULT_RETAIN_INTERVAL_SECS);
	}

	#[test]
	fn rate_limit_config_parses_explicit_retain_interval() {
		let parsed: RateLimitConfig = toml::from_str("retain_interval_secs = 60").unwrap();
		assert_eq!(parsed.retain_interval_secs.get(), 60);
	}

	#[test]
	fn access_control_config_empty_toml_matches_default() {
		let parsed: AccessControlConfig = toml::from_str("").unwrap();
		assert!(parsed.allow.is_empty());
		assert!(parsed.deny.is_empty());
	}

	#[test]
	fn metrics_config_empty_toml_matches_default() {
		let parsed: MetricsConfig = toml::from_str("").unwrap();
		assert!(parsed.otlp_endpoint.is_none());
	}

	#[test]
	fn tracing_config_empty_toml_matches_default() {
		let parsed: TracingConfig = toml::from_str("").unwrap();
		let default: TracingConfig = TracingConfig::default();
		assert!(parsed.otlp_endpoint.is_none());
		assert!(default.otlp_endpoint.is_none());
		assert_eq!(parsed.sample_ratio, default.sample_ratio);
		assert_eq!(default.sample_ratio, DEFAULT_TRACE_SAMPLE_RATIO);
	}

	#[test]
	fn proxy_config_empty_toml_matches_default() {
		let parsed: ProxyConfig = toml::from_str("").unwrap();
		let default: ProxyConfig = ProxyConfig::default();
		assert_eq!(parsed.max_response_body_bytes, default.max_response_body_bytes);
		assert_eq!(parsed.max_request_body_bytes, default.max_request_body_bytes);
		assert_eq!(parsed.h2_connections_per_backend, default.h2_connections_per_backend);
		assert_eq!(parsed.max_idle_quic_per_host, default.max_idle_quic_per_host);
		assert_eq!(parsed.h2_stream_window, default.h2_stream_window);
		assert_eq!(parsed.h2_conn_window, default.h2_conn_window);
		assert_eq!(parsed.inline_compress_threshold, default.inline_compress_threshold);
		assert_eq!(parsed.quic_channel_capacity, default.quic_channel_capacity);
		assert_eq!(default.max_response_body_bytes, DEFAULT_MAX_RESPONSE_BODY_BYTES);
		assert_eq!(default.max_request_body_bytes, DEFAULT_MAX_REQUEST_BODY_BYTES);
		assert_eq!(default.h2_connections_per_backend, DEFAULT_H2_CONNECTIONS_PER_BACKEND);
		assert_eq!(default.max_idle_quic_per_host, DEFAULT_MAX_IDLE_QUIC_PER_HOST);
		assert_eq!(default.h2_stream_window, DEFAULT_H2_STREAM_WINDOW);
		assert_eq!(default.h2_conn_window, DEFAULT_H2_CONN_WINDOW);
		assert_eq!(default.inline_compress_threshold, DEFAULT_INLINE_COMPRESS_THRESHOLD);
		assert_eq!(default.quic_channel_capacity, DEFAULT_QUIC_CHANNEL_CAPACITY);
	}

	#[test]
	fn compression_config_empty_toml_matches_default() {
		let parsed: CompressionConfig = toml::from_str("").unwrap();
		let default: CompressionConfig = CompressionConfig::default();
		assert_eq!(parsed.enabled, default.enabled);
		assert_eq!(parsed.level, default.level);
		assert_eq!(parsed.min_bytes, default.min_bytes);
		assert_eq!(default.enabled, DEFAULT_COMPRESSION_ENABLED);
		assert!(default.enabled, "zstd transform is on by default (M2M bandwidth saving)");
		assert_eq!(default.level, DEFAULT_COMPRESSION_LEVEL);
		assert_eq!(default.min_bytes, DEFAULT_MIN_COMPRESS_BYTES);
	}

	#[test]
	fn compression_config_parses_disabled() {
		let parsed: CompressionConfig = toml::from_str("enabled = false").unwrap();
		assert!(!parsed.enabled, "the zstd transform must be switchable off for a public cutover");
	}

	#[test]
	fn health_config_empty_toml_matches_default() {
		let parsed: HealthConfig = toml::from_str("").unwrap();
		let default: HealthConfig = HealthConfig::default();
		assert_eq!(parsed.staleness_ttl_secs, default.staleness_ttl_secs);
		assert_eq!(parsed.latency_threshold_ms, default.latency_threshold_ms);
		assert_eq!(default.staleness_ttl_secs, DEFAULT_STALENESS_TTL_SECS);
		assert_eq!(default.latency_threshold_ms, DEFAULT_LATENCY_THRESHOLD_MS);
	}

	#[test]
	fn circuit_breaker_config_empty_toml_matches_default() {
		let parsed: CircuitBreakerConfig = toml::from_str("").unwrap();
		let default: CircuitBreakerConfig = CircuitBreakerConfig::default();
		assert_eq!(parsed.failure_threshold, default.failure_threshold);
		assert_eq!(parsed.recovery_timeout_secs, default.recovery_timeout_secs);
		assert_eq!(parsed.half_open_max_requests, default.half_open_max_requests);
		assert_eq!(default.failure_threshold, DEFAULT_FAILURE_THRESHOLD);
		assert_eq!(default.recovery_timeout_secs, DEFAULT_RECOVERY_TIMEOUT_SECS);
		assert_eq!(default.half_open_max_requests, DEFAULT_HALF_OPEN_MAX_REQUESTS);
	}

	#[test]
	fn retry_config_empty_toml_matches_default() {
		let parsed: RetryConfig = toml::from_str("").unwrap();
		let default: RetryConfig = RetryConfig::default();
		assert_eq!(parsed.max_retries, default.max_retries);
		assert_eq!(parsed.base_delay_ms, default.base_delay_ms);
		assert_eq!(parsed.max_delay_ms, default.max_delay_ms);
		assert_eq!(parsed.jitter_ms, default.jitter_ms);
		assert_eq!(default.max_retries, DEFAULT_MAX_RETRIES);
		assert_eq!(default.base_delay_ms, DEFAULT_RETRY_BASE_DELAY_MS);
		assert_eq!(default.max_delay_ms, DEFAULT_RETRY_MAX_DELAY_MS);
		assert_eq!(default.jitter_ms, DEFAULT_RETRY_JITTER_MS);
	}

	#[test]
	fn tunnel_config_empty_toml_matches_default() {
		let parsed: TunnelConfig = toml::from_str("").unwrap();
		let default: TunnelConfig = TunnelConfig::default();
		assert!(!parsed.enabled);
		assert!(parsed.listen_address.is_none());
		assert!(parsed.allowed_backend_ids.is_empty());
		assert!(parsed.revocation_path.is_none());
		assert!(parsed.max_total_sessions.is_none());
		assert_eq!(parsed.heartbeat_timeout_secs, default.heartbeat_timeout_secs);
		assert_eq!(parsed.max_sessions_per_backend, default.max_sessions_per_backend);
		assert_eq!(parsed.registration_timeout_secs, default.registration_timeout_secs);
		assert_eq!(parsed.control_channel_capacity, default.control_channel_capacity);
		assert_eq!(default.heartbeat_timeout_secs, DEFAULT_HEARTBEAT_TIMEOUT_SECS);
		assert_eq!(default.max_sessions_per_backend, DEFAULT_MAX_SESSIONS_PER_BACKEND);
		assert_eq!(default.registration_timeout_secs, DEFAULT_REGISTRATION_TIMEOUT_SECS);
		assert_eq!(default.control_channel_capacity, DEFAULT_CONTROL_CHANNEL_CAPACITY);
	}

	#[test]
	fn tunnel_config_parses_revocation_path() {
		let parsed: TunnelConfig = toml::from_str("revocation_path = \"/etc/reduction/revoked.toml\"").unwrap();
		assert_eq!(
			parsed.revocation_path.as_deref(),
			Some(Path::new("/etc/reduction/revoked.toml")),
		);
	}

	#[test]
	fn tunnel_config_parses_max_total_sessions() {
		let parsed: TunnelConfig = toml::from_str("max_total_sessions = 512").unwrap();
		assert_eq!(parsed.max_total_sessions, NonZeroU32::new(512));
		// Zero is rejected by NonZeroU32, guarding against a cap that would deny everything.
		assert!(toml::from_str::<TunnelConfig>("max_total_sessions = 0").is_err());
	}

	#[test]
	fn tunnel_config_parses_max_accepts_per_second_per_ip() {
		let parsed: TunnelConfig = toml::from_str("max_accepts_per_second_per_ip = 20").unwrap();
		assert_eq!(parsed.max_accepts_per_second_per_ip, NonZeroU32::new(20));
		// Unset defaults to unlimited (feature off).
		let default: TunnelConfig = toml::from_str("").unwrap();
		assert!(default.max_accepts_per_second_per_ip.is_none());
		// Zero is rejected, guarding against a rate that would drop every connection.
		assert!(toml::from_str::<TunnelConfig>("max_accepts_per_second_per_ip = 0").is_err());
	}

	#[test]
	fn cache_config_empty_toml_matches_default() {
		let parsed: CacheConfig = toml::from_str("").unwrap();
		let default: CacheConfig = CacheConfig::default();
		assert!(!parsed.enabled);
		assert_eq!(parsed.max_entries, default.max_entries);
		assert_eq!(parsed.max_entry_bytes, default.max_entry_bytes);
		assert_eq!(parsed.default_ttl_secs, default.default_ttl_secs);
		assert_eq!(default.max_entries, DEFAULT_CACHE_MAX_ENTRIES);
		assert_eq!(default.max_entry_bytes, DEFAULT_CACHE_MAX_ENTRY_BYTES);
		assert_eq!(default.default_ttl_secs, DEFAULT_CACHE_DEFAULT_TTL_SECS);
	}
}
