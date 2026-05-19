use std::net::SocketAddr;
use std::path::PathBuf;

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
    pub ratelimit: RateLimitConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct BalancerConfig {
    pub queue_depth: usize,
    pub jitter_factor: f64,
}

impl<'de> Deserialize<'de> for BalancerConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default = "default_queue_depth")]
            queue_depth: usize,
            #[serde(default = "default_jitter_factor")]
            jitter_factor: f64,
        }
        let wire: Wire = Wire::deserialize(deserializer)?;
        validate_jitter_factor(wire.jitter_factor).map_err(serde::de::Error::custom)?;
        return Ok(BalancerConfig {
            queue_depth: wire.queue_depth,
            jitter_factor: wire.jitter_factor,
        });
    }
}

impl Default for BalancerConfig {
    fn default() -> Self {
        return Self {
            queue_depth: default_queue_depth(),
            jitter_factor: default_jitter_factor(),
        };
    }
}

fn default_queue_depth() -> usize {
    return 1000;
}

fn default_jitter_factor() -> f64 {
    return 0.05;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub path_prefix: String,
    pub backend_id: String,
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
        return Self { id, pool, address, host, weight, transport };
    }

    pub fn with_pool(mut self, pool: String) -> Self {
        self.pool = pool;
        return self;
    }

    pub fn with_host(mut self, host: String) -> Self {
        self.host = host;
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
        }
        let wire: Wire<'_> = Wire {
            id: &self.id,
            pool: &self.pool,
            host: &self.host,
            address: self.address.to_string(),
            weight: self.weight,
            transport: &self.transport,
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
        }
        let wire: Wire = Wire::deserialize(deserializer)?;
        let address: SocketAddr = wire.address.parse()
            .map_err(|e| serde::de::Error::custom(format!("invalid backend address '{}': {e}", wire.address)))?;
        validate_weight(wire.weight).map_err(serde::de::Error::custom)?;
        let pool: String = wire.pool.unwrap_or_else(|| wire.id.clone());
        let host: String = wire.host.unwrap_or_else(|| address.ip().to_string());
        return Ok(BackendConfig {
            id: wire.id,
            pool,
            address,
            host,
            weight: wire.weight,
            transport: wire.transport,
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
pub struct MetricsConfig {
    pub otlp_endpoint: Option<String>,
}
