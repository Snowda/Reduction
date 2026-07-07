use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};

use arrayvec::ArrayString;
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{ReductionError, Result};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReductionConfig {
    pub listen: ListenConfig,
    pub tls: TlsConfig,
    pub backends: Vec<BackendConfig>,
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub balancer: BalancerConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub compression: CompressionConfig,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub access: AccessControlConfig,
    #[serde(default)]
    pub ratelimit: RateLimitConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    #[serde(default)]
    pub timeouts: TimeoutConfig,
    #[serde(default)]
    pub retry: RetryConfig,
    #[serde(default)]
    pub tracing: TracingConfig,
    #[serde(default)]
    pub tunnel: TunnelConfig,
    #[serde(default)]
    pub cache: CacheConfig,
}

// ── Balancer defaults ──

pub const DEFAULT_QUEUE_DEPTH: u32 = 1000;
pub const DEFAULT_JITTER_FACTOR: f64 = 0.05;
pub const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_MAX_BACKENDS: u32 = 64;
pub const HARD_MAX_BACKENDS: u32 = 256;

fn default_queue_depth() -> u32 { return DEFAULT_QUEUE_DEPTH; }
fn default_jitter_factor() -> f64 { return DEFAULT_JITTER_FACTOR; }
fn default_drain_timeout_secs() -> u64 { return DEFAULT_DRAIN_TIMEOUT_SECS; }
fn default_max_backends() -> u32 { return DEFAULT_MAX_BACKENDS; }

#[derive(Debug, Clone, Serialize)]
pub struct BalancerConfig {
    pub queue_depth: u32,
    pub jitter_factor: f64,
    pub drain_timeout_secs: u64,
    pub max_backends: u32,
}

impl<'de> Deserialize<'de> for BalancerConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default = "default_queue_depth")]
            queue_depth: u32,
            #[serde(default = "default_jitter_factor")]
            jitter_factor: f64,
            #[serde(default = "default_drain_timeout_secs")]
            drain_timeout_secs: u64,
            #[serde(default = "default_max_backends")]
            max_backends: u32,
        }
        let wire: Wire = Wire::deserialize(deserializer)?;
        validate_jitter_factor(wire.jitter_factor).map_err(serde::de::Error::custom)?;
        validate_max_backends(wire.max_backends).map_err(serde::de::Error::custom)?;
        return Ok(BalancerConfig {
            queue_depth: wire.queue_depth,
            jitter_factor: wire.jitter_factor,
            drain_timeout_secs: wire.drain_timeout_secs,
            max_backends: wire.max_backends,
        });
    }
}

impl Default for BalancerConfig {
    fn default() -> Self {
        return Self {
            queue_depth: DEFAULT_QUEUE_DEPTH,
            jitter_factor: DEFAULT_JITTER_FACTOR,
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
        return Err(format!("max_backends {max_backends} exceeds hard limit {HARD_MAX_BACKENDS}"));
    }
    return Ok(());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub path_prefix: ArrayString<64>,
    pub backend_id: ArrayString<256>,
    pub timeout_secs: Option<u64>,
}

// ── Timeout defaults ──

pub const DEFAULT_CONNECT_TIMEOUT_SECS: NonZeroU64 = nonzero_u64(5);
pub const DEFAULT_HANDSHAKE_TIMEOUT_SECS: NonZeroU64 = nonzero_u64(5);
pub const DEFAULT_REQUEST_TIMEOUT_SECS: NonZeroU64 = nonzero_u64(30);

fn default_connect_timeout_secs() -> NonZeroU64 { return DEFAULT_CONNECT_TIMEOUT_SECS; }
fn default_handshake_timeout_secs() -> NonZeroU64 { return DEFAULT_HANDSHAKE_TIMEOUT_SECS; }
fn default_request_timeout_secs() -> NonZeroU64 { return DEFAULT_REQUEST_TIMEOUT_SECS; }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_secs: NonZeroU64,
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_secs: NonZeroU64,
    #[serde(default = "default_request_timeout_secs")]
    pub request_secs: NonZeroU64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        return Self {
            connect_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
            handshake_secs: DEFAULT_HANDSHAKE_TIMEOUT_SECS,
            request_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
        };
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    pub address: SocketAddr,
    pub transport: TransportKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Tcp,
    Quic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub server: ServerTlsConfig,
    pub client: TlsIdentity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerTlsConfig {
    Manual(TlsIdentity),
    #[cfg(feature = "acme")]
    Acme(AcmeTlsConfig),
}

impl ServerTlsConfig {
    pub fn ca_cert_path(&self) -> &Path {
        return match self {
            ServerTlsConfig::Manual(identity) => &identity.ca_cert_path,
            #[cfg(feature = "acme")]
            ServerTlsConfig::Acme(acme) => &acme.ca_cert_path,
        };
    }

    pub fn as_manual(&self) -> Option<&TlsIdentity> {
        return match self {
            ServerTlsConfig::Manual(identity) => Some(identity),
            #[cfg(feature = "acme")]
            ServerTlsConfig::Acme(_) => None,
        };
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsIdentity {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_cert_path: PathBuf,
}

// ── ACME defaults ──

#[cfg(feature = "acme")]
pub const DEFAULT_ACME_CACHE_DIR: &str = "./acme_cache";

#[cfg(feature = "acme")]
fn default_acme_cache_dir() -> PathBuf { return PathBuf::from(DEFAULT_ACME_CACHE_DIR); }

#[cfg(feature = "acme")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeTlsConfig {
    pub domains: Vec<ArrayString<256>>,
    pub acme_email: ArrayString<256>,
    pub ca_cert_path: PathBuf,
    #[serde(default = "default_acme_cache_dir")]
    pub cache_dir: PathBuf,
    #[serde(default)]
    pub staging: bool,
}

// ── Backend defaults ──

pub const DEFAULT_MAX_CONNECTIONS: u32 = 256;

fn default_max_connections() -> u32 { return DEFAULT_MAX_CONNECTIONS; }

#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub id: ArrayString<256>,
    pub pool: ArrayString<32>,
    pub address: SocketAddr,
    pub host: String,
    pub weight: f64,
    pub transport: TransportKind,
    pub max_connections: u32,
}

fn validate_max_connections(max_connections: u32) -> std::result::Result<(), String> {
    if max_connections == 0 {
        return Err("max_connections must be at least 1".to_owned());
    }
    return Ok(());
}

fn validate_weight(weight: f64) -> std::result::Result<(), String> {
    if weight.is_nan() || weight.is_infinite() {
        return Err(format!("weight must be finite, got {weight}"));
    }
    if weight < 0.0 {
        return Err(format!("weight must be non-negative, got {weight}"));
    }
    return Ok(());
}

fn validate_jitter_factor(jitter_factor: f64) -> std::result::Result<(), String> {
    if jitter_factor.is_nan() || jitter_factor.is_infinite() {
        return Err(format!("jitter_factor must be finite, got {jitter_factor}"));
    }
    if jitter_factor < 0.0 {
        return Err(format!("jitter_factor must be non-negative, got {jitter_factor}"));
    }
    if jitter_factor >= 1.0 {
        return Err(format!("jitter_factor must be less than 1.0, got {jitter_factor}"));
    }
    return Ok(());
}

impl BackendConfig {
    pub fn new(id: &str, address: SocketAddr, weight: f64, transport: TransportKind) -> Result<Self> {
        validate_weight(weight).map_err(ReductionError::Config)?;
        let id: ArrayString<256> = ArrayString::from(id)
            .map_err(|_| ReductionError::Config("backend id exceeds 256 characters".to_owned()))?;
        let host: String = address.ip().to_string();
        let pool: ArrayString<32> = ArrayString::from(id.as_str())
            .map_err(|_| ReductionError::Config("backend id exceeds 32 characters for default pool name".to_owned()))?;
        let max_connections: u32 = DEFAULT_MAX_CONNECTIONS;
        return Ok(Self { id, pool, address, host, weight, transport, max_connections });
    }

    pub fn with_pool(mut self, pool: &str) -> Result<Self> {
        self.pool = ArrayString::from(pool)
            .map_err(|_| ReductionError::Config("pool name exceeds 32 characters".to_owned()))?;
        return Ok(self);
    }

    pub fn with_host(mut self, host: String) -> Self {
        self.host = host;
        return self;
    }

    pub fn with_max_connections(mut self, max_connections: u32) -> Result<Self> {
        validate_max_connections(max_connections).map_err(ReductionError::Config)?;
        self.max_connections = max_connections;
        return Ok(self);
    }
}

impl Serialize for BackendConfig {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            id: &'a str,
            pool: &'a str,
            host: &'a str,
            address: String,
            weight: f64,
            transport: &'a TransportKind,
            max_connections: u32,
        }
        let wire: Wire<'_> = Wire {
            id: &self.id,
            pool: &self.pool,
            host: &self.host,
            address: self.address.to_string(),
            weight: self.weight,
            transport: &self.transport,
            max_connections: self.max_connections,
        };
        return wire.serialize(serializer);
    }
}

impl<'de> Deserialize<'de> for BackendConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            id: String,
            pool: Option<String>,
            host: Option<String>,
            address: String,
            weight: f64,
            transport: TransportKind,
            #[serde(default = "default_max_connections")]
            max_connections: u32,
        }
        let wire: Wire = Wire::deserialize(deserializer)?;
        let address: SocketAddr = wire.address.parse()
            .map_err(|e| serde::de::Error::custom(format!("invalid backend address '{}': {e}", wire.address)))?;
        validate_weight(wire.weight).map_err(serde::de::Error::custom)?;
        validate_max_connections(wire.max_connections).map_err(serde::de::Error::custom)?;
        let id: ArrayString<256> = ArrayString::from(&wire.id)
            .map_err(|_| serde::de::Error::custom(format!("backend id '{}' exceeds 256 characters", wire.id)))?;
        let pool: ArrayString<32> = match wire.pool {
            Some(p) => ArrayString::from(&p)
                .map_err(|_| serde::de::Error::custom(format!("pool name '{}' exceeds 32 characters", p)))?,
            None => ArrayString::from(id.as_str())
                .map_err(|_| serde::de::Error::custom(format!("backend id '{}' exceeds 32 characters for default pool name", wire.id)))?,
        };
        let host: String = wire.host.unwrap_or_else(|| address.ip().to_string());
        return Ok(BackendConfig {
            id,
            pool,
            address,
            host,
            weight: wire.weight,
            transport: wire.transport,
            max_connections: wire.max_connections,
        });
    }
}

// ── Rate limit defaults ──

pub const DEFAULT_REQUESTS_PER_SECOND: u32 = u32::MAX;

fn default_requests_per_second() -> u32 { return DEFAULT_REQUESTS_PER_SECOND; }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        return Self {
            requests_per_second: DEFAULT_REQUESTS_PER_SECOND,
        };
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessControlConfig {
    #[serde(default)]
    pub allow: Vec<IpNet>,
    #[serde(default)]
    pub deny: Vec<IpNet>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsConfig {
    pub otlp_endpoint: Option<String>,
}

// ── Tracing defaults ──

pub const DEFAULT_TRACE_SAMPLE_RATIO: f64 = 1.0;

fn default_trace_sample_ratio() -> f64 { return DEFAULT_TRACE_SAMPLE_RATIO; }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    pub otlp_endpoint: Option<String>,
    #[serde(default = "default_trace_sample_ratio")]
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
pub const DEFAULT_H2_CONNECTIONS_PER_BACKEND: NonZeroU32 = nonzero_u32(4);
pub const DEFAULT_MAX_IDLE_QUIC_PER_HOST: u32 = 16;
pub const DEFAULT_H2_STREAM_WINDOW: u32 = 2 * 1024 * 1024;
pub const DEFAULT_H2_CONN_WINDOW: u32 = 4 * 1024 * 1024;
pub const DEFAULT_INLINE_COMPRESS_THRESHOLD: u32 = 8192;
pub const DEFAULT_QUIC_CHANNEL_CAPACITY: NonZeroU32 = nonzero_u32(256);

fn default_max_response_body_bytes() -> u32 { return DEFAULT_MAX_RESPONSE_BODY_BYTES; }
fn default_h2_connections_per_backend() -> NonZeroU32 { return DEFAULT_H2_CONNECTIONS_PER_BACKEND; }
fn default_max_idle_quic_per_host() -> u32 { return DEFAULT_MAX_IDLE_QUIC_PER_HOST; }
fn default_h2_stream_window() -> u32 { return DEFAULT_H2_STREAM_WINDOW; }
fn default_h2_conn_window() -> u32 { return DEFAULT_H2_CONN_WINDOW; }
fn default_inline_compress_threshold() -> u32 { return DEFAULT_INLINE_COMPRESS_THRESHOLD; }
fn default_quic_channel_capacity() -> NonZeroU32 { return DEFAULT_QUIC_CHANNEL_CAPACITY; }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_max_response_body_bytes")]
    pub max_response_body_bytes: u32,
    #[serde(default = "default_h2_connections_per_backend")]
    pub h2_connections_per_backend: NonZeroU32,
    #[serde(default = "default_max_idle_quic_per_host")]
    pub max_idle_quic_per_host: u32,
    #[serde(default = "default_h2_stream_window")]
    pub h2_stream_window: u32,
    #[serde(default = "default_h2_conn_window")]
    pub h2_conn_window: u32,
    #[serde(default = "default_inline_compress_threshold")]
    pub inline_compress_threshold: u32,
    #[serde(default = "default_quic_channel_capacity")]
    pub quic_channel_capacity: NonZeroU32,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        return Self {
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
            h2_connections_per_backend: DEFAULT_H2_CONNECTIONS_PER_BACKEND,
            max_idle_quic_per_host: DEFAULT_MAX_IDLE_QUIC_PER_HOST,
            h2_stream_window: DEFAULT_H2_STREAM_WINDOW,
            h2_conn_window: DEFAULT_H2_CONN_WINDOW,
            inline_compress_threshold: DEFAULT_INLINE_COMPRESS_THRESHOLD,
            quic_channel_capacity: DEFAULT_QUIC_CHANNEL_CAPACITY,
        };
    }
}

// ── Compression defaults ──

pub const DEFAULT_COMPRESSION_LEVEL: i32 = 3;
pub const DEFAULT_MIN_COMPRESS_BYTES: u32 = 256;

fn default_compression_level() -> i32 { return DEFAULT_COMPRESSION_LEVEL; }
fn default_min_compress_bytes() -> u32 { return DEFAULT_MIN_COMPRESS_BYTES; }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    #[serde(default = "default_compression_level")]
    pub level: i32,
    #[serde(default = "default_min_compress_bytes")]
    pub min_bytes: u32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        return Self {
            level: DEFAULT_COMPRESSION_LEVEL,
            min_bytes: DEFAULT_MIN_COMPRESS_BYTES,
        };
    }
}

// ── Health defaults ──

pub const DEFAULT_STALENESS_TTL_SECS: u64 = 300;
pub const DEFAULT_LATENCY_THRESHOLD_MS: u32 = 500;

fn default_staleness_ttl_secs() -> u64 { return DEFAULT_STALENESS_TTL_SECS; }
fn default_latency_threshold_ms() -> u32 { return DEFAULT_LATENCY_THRESHOLD_MS; }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    #[serde(default = "default_staleness_ttl_secs")]
    pub staleness_ttl_secs: u64,
    #[serde(default = "default_latency_threshold_ms")]
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

fn default_failure_threshold() -> NonZeroU32 { return DEFAULT_FAILURE_THRESHOLD; }
fn default_recovery_timeout_secs() -> u64 { return DEFAULT_RECOVERY_TIMEOUT_SECS; }
fn default_half_open_max_requests() -> NonZeroU32 { return DEFAULT_HALF_OPEN_MAX_REQUESTS; }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: NonZeroU32,
    #[serde(default = "default_recovery_timeout_secs")]
    pub recovery_timeout_secs: u64,
    #[serde(default = "default_half_open_max_requests")]
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

fn default_max_retries() -> u32 { return DEFAULT_MAX_RETRIES; }
fn default_retry_base_delay_ms() -> u64 { return DEFAULT_RETRY_BASE_DELAY_MS; }
fn default_retry_max_delay_ms() -> u64 { return DEFAULT_RETRY_MAX_DELAY_MS; }
fn default_retry_jitter_ms() -> u64 { return DEFAULT_RETRY_JITTER_MS; }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_retry_base_delay_ms")]
    pub base_delay_ms: u64,
    #[serde(default = "default_retry_max_delay_ms")]
    pub max_delay_ms: u64,
    #[serde(default = "default_retry_jitter_ms")]
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

pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 15;
pub const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 45;
pub const DEFAULT_MAX_SESSIONS_PER_BACKEND: NonZeroU32 = nonzero_u32(8);
pub const DEFAULT_REGISTRATION_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_CONTROL_CHANNEL_CAPACITY: NonZeroU32 = nonzero_u32(16);

fn default_heartbeat_interval_secs() -> u64 { return DEFAULT_HEARTBEAT_INTERVAL_SECS; }
fn default_heartbeat_timeout_secs() -> u64 { return DEFAULT_HEARTBEAT_TIMEOUT_SECS; }
fn default_max_sessions_per_backend() -> NonZeroU32 { return DEFAULT_MAX_SESSIONS_PER_BACKEND; }
fn default_registration_timeout_secs() -> u64 { return DEFAULT_REGISTRATION_TIMEOUT_SECS; }
fn default_control_channel_capacity() -> NonZeroU32 { return DEFAULT_CONTROL_CHANNEL_CAPACITY; }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    #[serde(default)]
    pub enabled: bool,
    pub listen_address: Option<SocketAddr>,
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "default_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
    #[serde(default)]
    pub allowed_backend_ids: Vec<ArrayString<256>>,
    #[serde(default = "default_max_sessions_per_backend")]
    pub max_sessions_per_backend: NonZeroU32,
    #[serde(default = "default_registration_timeout_secs")]
    pub registration_timeout_secs: u64,
    #[serde(default = "default_control_channel_capacity")]
    pub control_channel_capacity: NonZeroU32,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        return Self {
            enabled: false,
            listen_address: None,
            heartbeat_interval_secs: DEFAULT_HEARTBEAT_INTERVAL_SECS,
            heartbeat_timeout_secs: DEFAULT_HEARTBEAT_TIMEOUT_SECS,
            allowed_backend_ids: Vec::new(),
            max_sessions_per_backend: DEFAULT_MAX_SESSIONS_PER_BACKEND,
            registration_timeout_secs: DEFAULT_REGISTRATION_TIMEOUT_SECS,
            control_channel_capacity: DEFAULT_CONTROL_CHANNEL_CAPACITY,
        };
    }
}

// ── Cache defaults ──

pub const DEFAULT_CACHE_MAX_ENTRIES: NonZeroUsize = nonzero_usize(1000);
pub const DEFAULT_CACHE_MAX_ENTRY_BYTES: NonZeroUsize = nonzero_usize(1024 * 1024);
pub const DEFAULT_CACHE_DEFAULT_TTL_SECS: NonZeroU64 = nonzero_u64(60);

fn default_cache_max_entries() -> NonZeroUsize { return DEFAULT_CACHE_MAX_ENTRIES; }
fn default_cache_max_entry_bytes() -> NonZeroUsize { return DEFAULT_CACHE_MAX_ENTRY_BYTES; }
fn default_cache_default_ttl_secs() -> NonZeroU64 { return DEFAULT_CACHE_DEFAULT_TTL_SECS; }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: NonZeroUsize,
    #[serde(default = "default_cache_max_entry_bytes")]
    pub max_entry_bytes: NonZeroUsize,
    #[serde(default = "default_cache_default_ttl_secs")]
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
