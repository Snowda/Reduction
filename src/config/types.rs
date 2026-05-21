use std::net::SocketAddr;
use std::path::PathBuf;

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

#[derive(Debug, Clone, Serialize)]
pub struct BalancerConfig {
    pub queue_depth: usize,
    pub jitter_factor: f64,
    pub drain_timeout_secs: u64,
    pub max_backends: usize,
}

impl<'de> Deserialize<'de> for BalancerConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default = "default_queue_depth")]
            queue_depth: usize,
            #[serde(default = "default_jitter_factor")]
            jitter_factor: f64,
            #[serde(default = "default_drain_timeout_secs")]
            drain_timeout_secs: u64,
            #[serde(default = "default_max_backends")]
            max_backends: usize,
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
            queue_depth: default_queue_depth(),
            jitter_factor: default_jitter_factor(),
            drain_timeout_secs: default_drain_timeout_secs(),
            max_backends: default_max_backends(),
        };
    }
}

fn default_queue_depth() -> usize {
    return 1000;
}

fn default_jitter_factor() -> f64 {
    return 0.05;
}

fn default_drain_timeout_secs() -> u64 {
    return 30;
}

fn default_max_backends() -> usize {
    return 64;
}

fn validate_max_backends(max_backends: usize) -> std::result::Result<(), String> {
    if max_backends == 0 {
        return Err("max_backends must be at least 1".to_string());
    }
    if max_backends > HARD_MAX_BACKENDS {
        return Err(format!("max_backends {max_backends} exceeds hard limit {HARD_MAX_BACKENDS}"));
    }
    return Ok(());
}

pub const HARD_MAX_BACKENDS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub path_prefix: String,
    pub backend_id: String,
    pub timeout_secs: Option<u64>,
}

fn default_connect_timeout_secs() -> u64 {
    return 5;
}

fn default_handshake_timeout_secs() -> u64 {
    return 5;
}

fn default_request_timeout_secs() -> u64 {
    return 30;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_secs: u64,
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_secs: u64,
    #[serde(default = "default_request_timeout_secs")]
    pub request_secs: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        return Self {
            connect_secs: default_connect_timeout_secs(),
            handshake_secs: default_handshake_timeout_secs(),
            request_secs: default_request_timeout_secs(),
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
    pub server: TlsIdentity,
    pub client: TlsIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsIdentity {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_cert_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub id: String,
    pub pool: String,
    pub address: SocketAddr,
    pub host: String,
    pub weight: f64,
    pub transport: TransportKind,
    pub max_connections: u32,
}

fn default_max_connections() -> u32 {
    return 256;
}

fn validate_max_connections(max_connections: u32) -> std::result::Result<(), String> {
    if max_connections == 0 {
        return Err("max_connections must be at least 1".to_string());
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
    pub fn new(id: String, address: SocketAddr, weight: f64, transport: TransportKind) -> Self {
        validate_weight(weight).expect("invalid backend weight");
        let host: String = address.ip().to_string();
        let pool: String = id.clone();
        let max_connections: u32 = default_max_connections();
        return Self { id, pool, address, host, weight, transport, max_connections };
    }

    pub fn with_pool(mut self, pool: String) -> Self {
        self.pool = pool;
        return self;
    }

    pub fn with_host(mut self, host: String) -> Self {
        self.host = host;
        return self;
    }

    pub fn with_max_connections(mut self, max_connections: u32) -> Self {
        validate_max_connections(max_connections).expect("invalid max_connections");
        self.max_connections = max_connections;
        return self;
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
        let pool: String = wire.pool.unwrap_or_else(|| wire.id.clone());
        let host: String = wire.host.unwrap_or_else(|| address.ip().to_string());
        return Ok(BackendConfig {
            id: wire.id,
            pool,
            address,
            host,
            weight: wire.weight,
            transport: wire.transport,
            max_connections: wire.max_connections,
        });
    }
}

fn default_requests_per_second() -> u32 {
    return u32::MAX;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        return Self {
            requests_per_second: default_requests_per_second(),
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

fn default_trace_sample_ratio() -> f64 {
    return 1.0;
}

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
            sample_ratio: default_trace_sample_ratio(),
        };
    }
}

fn default_max_response_body_bytes() -> usize {
    return 10 * 1024 * 1024;
}

fn default_h2_connections_per_backend() -> usize {
    return 4;
}

fn default_max_idle_quic_per_host() -> usize {
    return 16;
}

fn default_h2_stream_window() -> u32 {
    return 2 * 1024 * 1024;
}

fn default_h2_conn_window() -> u32 {
    return 4 * 1024 * 1024;
}

fn default_inline_compress_threshold() -> usize {
    return 8192;
}

fn default_quic_channel_capacity() -> usize {
    return 256;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_max_response_body_bytes")]
    pub max_response_body_bytes: usize,
    #[serde(default = "default_h2_connections_per_backend")]
    pub h2_connections_per_backend: usize,
    #[serde(default = "default_max_idle_quic_per_host")]
    pub max_idle_quic_per_host: usize,
    #[serde(default = "default_h2_stream_window")]
    pub h2_stream_window: u32,
    #[serde(default = "default_h2_conn_window")]
    pub h2_conn_window: u32,
    #[serde(default = "default_inline_compress_threshold")]
    pub inline_compress_threshold: usize,
    #[serde(default = "default_quic_channel_capacity")]
    pub quic_channel_capacity: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        return Self {
            max_response_body_bytes: default_max_response_body_bytes(),
            h2_connections_per_backend: default_h2_connections_per_backend(),
            max_idle_quic_per_host: default_max_idle_quic_per_host(),
            h2_stream_window: default_h2_stream_window(),
            h2_conn_window: default_h2_conn_window(),
            inline_compress_threshold: default_inline_compress_threshold(),
            quic_channel_capacity: default_quic_channel_capacity(),
        };
    }
}

fn default_compression_level() -> i32 {
    return 3;
}

fn default_min_compress_bytes() -> usize {
    return 256;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    #[serde(default = "default_compression_level")]
    pub level: i32,
    #[serde(default = "default_min_compress_bytes")]
    pub min_bytes: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        return Self {
            level: default_compression_level(),
            min_bytes: default_min_compress_bytes(),
        };
    }
}

fn default_staleness_ttl_secs() -> u64 {
    return 300;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    #[serde(default = "default_staleness_ttl_secs")]
    pub staleness_ttl_secs: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        return Self {
            staleness_ttl_secs: default_staleness_ttl_secs(),
        };
    }
}

fn default_failure_threshold() -> u32 {
    return 5;
}

fn default_recovery_timeout_secs() -> u64 {
    return 60;
}

fn default_half_open_max_requests() -> u32 {
    return 2;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_recovery_timeout_secs")]
    pub recovery_timeout_secs: u64,
    #[serde(default = "default_half_open_max_requests")]
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        return Self {
            failure_threshold: default_failure_threshold(),
            recovery_timeout_secs: default_recovery_timeout_secs(),
            half_open_max_requests: default_half_open_max_requests(),
        };
    }
}

fn default_max_retries() -> u32 {
    return 2;
}

fn default_retry_base_delay_ms() -> u64 {
    return 200;
}

fn default_retry_max_delay_ms() -> u64 {
    return 2000;
}

fn default_retry_jitter_ms() -> u64 {
    return 100;
}

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
            max_retries: default_max_retries(),
            base_delay_ms: default_retry_base_delay_ms(),
            max_delay_ms: default_retry_max_delay_ms(),
            jitter_ms: default_retry_jitter_ms(),
        };
    }
}

fn default_heartbeat_interval_secs() -> u64 {
    return 15;
}

fn default_heartbeat_timeout_secs() -> u64 {
    return 45;
}

fn default_max_sessions_per_backend() -> usize {
    return 8;
}

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
    pub allowed_backend_ids: Vec<String>,
    #[serde(default = "default_max_sessions_per_backend")]
    pub max_sessions_per_backend: usize,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        return Self {
            enabled: false,
            listen_address: None,
            heartbeat_interval_secs: default_heartbeat_interval_secs(),
            heartbeat_timeout_secs: default_heartbeat_timeout_secs(),
            allowed_backend_ids: Vec::new(),
            max_sessions_per_backend: default_max_sessions_per_backend(),
        };
    }
}

fn default_cache_max_entries() -> usize {
    return 1000;
}

fn default_cache_max_entry_bytes() -> usize {
    return 1024 * 1024;
}

fn default_cache_default_ttl_secs() -> u64 {
    return 60;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_cache_max_entry_bytes")]
    pub max_entry_bytes: usize,
    #[serde(default = "default_cache_default_ttl_secs")]
    pub default_ttl_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        return Self {
            enabled: false,
            max_entries: default_cache_max_entries(),
            max_entry_bytes: default_cache_max_entry_bytes(),
            default_ttl_secs: default_cache_default_ttl_secs(),
        };
    }
}
