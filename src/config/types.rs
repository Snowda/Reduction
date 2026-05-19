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
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerConfig {
    #[serde(default = "default_queue_depth")]
    pub queue_depth: usize,
    #[serde(default = "default_jitter_factor")]
    pub jitter_factor: f64,
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
    pub address: SocketAddr,
    pub host: String,
    pub weight: f64,
    pub transport: TransportKind,
}

impl BackendConfig {
    pub fn new(id: String, address: SocketAddr, weight: f64, transport: TransportKind) -> Self {
        let host: String = address.ip().to_string();
        return Self { id, address, host, weight, transport };
    }
}

impl Serialize for BackendConfig {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            id: &'a str,
            address: String,
            weight: f64,
            transport: &'a TransportKind,
        }
        let wire = Wire {
            id: &self.id,
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
            address: String,
            weight: f64,
            transport: TransportKind,
        }
        let wire = Wire::deserialize(deserializer)?;
        let address: SocketAddr = wire.address.parse()
            .map_err(|e| serde::de::Error::custom(format!("invalid backend address '{}': {e}", wire.address)))?;
        let host: String = address.ip().to_string();
        return Ok(BackendConfig {
            id: wire.id,
            address,
            host,
            weight: wire.weight,
            transport: wire.transport,
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsConfig {
    pub otlp_endpoint: Option<String>,
}
