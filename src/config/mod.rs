pub mod types;
pub mod watcher;

use std::path::Path;

use tracing::info;

use crate::error::Result;
use crate::fs_util::load_or_recover;

pub use types::*;

pub fn load_config(path: &Path) -> Result<ReductionConfig> {
    let config: ReductionConfig = load_or_recover(path, |s| toml::from_str(s))?;

    info!(path = %path.display(), "loaded configuration");

    return Ok(config);
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use arrayvec::ArrayString;

    use super::*;

    fn minimal_toml() -> &'static str {
        return r#"
[listen]
address = "127.0.0.1:8443"
transport = "tcp"

[tls.server]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"

[[backends]]
id = "api"
address = "10.0.0.1:8080"
weight = 1.0
transport = "tcp"

[[routes]]
path_prefix = "/api"
backend_id = "api"
"#;
    }

    #[test]
    fn test_parse_minimal_config() {
        let config: ReductionConfig = toml::from_str(minimal_toml()).unwrap();
        assert_eq!(config.listen.transport, TransportKind::Tcp);
        assert_eq!(config.backends.len(), 1);
        assert_eq!(config.backends[0].id.as_str(), "api");
        assert_eq!(config.backends[0].weight, 1.0);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].path_prefix.as_str(), "/api");
    }

    #[test]
    fn test_parse_multiple_backends() {
        let toml_str: &str = r#"
[listen]
address = "0.0.0.0:8443"
transport = "quic"

[tls.server]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"

[[backends]]
id = "api-primary"
address = "10.0.0.1:8080"
weight = 3.0
transport = "quic"

[[backends]]
id = "api-secondary"
address = "10.0.0.2:8080"
weight = 1.0
transport = "quic"

[[routes]]
path_prefix = "/api/v1"
backend_id = "api-primary"

[[routes]]
path_prefix = "/api/v2"
backend_id = "api-secondary"
"#;

        let config: ReductionConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.listen.transport, TransportKind::Quic);
        assert_eq!(config.backends.len(), 2);
        assert_eq!(config.backends[0].weight, 3.0);
        assert_eq!(config.backends[1].weight, 1.0);
        assert_eq!(config.routes.len(), 2);
    }

    #[test]
    fn test_parse_invalid_config_missing_field() {
        let toml_str: &str = r#"
[listen]
address = "127.0.0.1:8443"
"#;

        let result: std::result::Result<ReductionConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_round_trip() {
        let original: ReductionConfig = ReductionConfig {
            listen: ListenConfig {
                address: "127.0.0.1:8443".parse().unwrap(),
                transport: TransportKind::Quic,
            },
            tls: TlsConfig {
                server: ServerTlsConfig::Manual(TlsIdentity {
                    cert_path: "certs/server.crt".into(),
                    key_path: "certs/server.key".into(),
                    ca_cert_path: "certs/ca.crt".into(),
                }),
                client: TlsIdentity {
                    cert_path: "certs/client.crt".into(),
                    key_path: "certs/client.key".into(),
                    ca_cert_path: "certs/ca.crt".into(),
                },
            },
            backends: vec![
                BackendConfig::new(
                    "api",
                    "10.0.0.1:8080".parse().unwrap(),
                    2.5,
                    TransportKind::Quic,
                ),
            ],
            routes: vec![
                RouteConfig {
                    path_prefix: ArrayString::from("/api").unwrap(),
                    backend_id: ArrayString::from("api").unwrap(),
                    timeout_secs: None,
                },
            ],
            balancer: BalancerConfig::default(),
            proxy: ProxyConfig::default(),
            compression: CompressionConfig::default(),
            health: HealthConfig::default(),
            access: AccessControlConfig::default(),
            ratelimit: RateLimitConfig::default(),
            metrics: MetricsConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            timeouts: TimeoutConfig::default(),
            retry: RetryConfig::default(),
            tracing: TracingConfig::default(),
            tunnel: TunnelConfig::default(),
            cache: CacheConfig::default(),
        };

        let serialized: String = toml::to_string(&original).unwrap();
        let deserialized: ReductionConfig = toml::from_str(&serialized).unwrap();

        assert_eq!(deserialized.listen.address, original.listen.address);
        assert_eq!(deserialized.listen.transport, original.listen.transport);
        assert_eq!(deserialized.backends.len(), 1);
        assert_eq!(deserialized.backends[0].id.as_str(), "api");
        assert_eq!(deserialized.backends[0].pool.as_str(), "api");
        assert_eq!(deserialized.backends[0].weight, 2.5);
        assert_eq!(deserialized.routes.len(), 1);
        assert_eq!(deserialized.routes[0].path_prefix.as_str(), "/api");
    }

    #[test]
    fn test_load_config_from_file() {
        let dir: tempfile::TempDir = tempfile::tempdir().unwrap();
        let config_path: std::path::PathBuf = dir.path().join("test_config.toml");

        let mut file: std::fs::File = std::fs::File::create(&config_path).unwrap();
        file.write_all(minimal_toml().as_bytes()).unwrap();

        let config: ReductionConfig = load_config(&config_path).unwrap();
        assert_eq!(config.backends[0].id.as_str(), "api");
    }

    #[test]
    fn test_load_config_missing_file() {
        let result: Result<ReductionConfig> = load_config(std::path::Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_transport_kind_values() {
        assert_eq!(TransportKind::Tcp, TransportKind::Tcp);
        assert_eq!(TransportKind::Quic, TransportKind::Quic);
        assert_ne!(TransportKind::Tcp, TransportKind::Quic);
    }

    #[test]
    fn test_reject_negative_weight() {
        let toml_str: &str = r#"
[listen]
address = "127.0.0.1:8443"
transport = "tcp"

[tls.server]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"

[[backends]]
id = "api"
address = "10.0.0.1:8080"
weight = -1.0
transport = "tcp"

[[routes]]
path_prefix = "/api"
backend_id = "api"
"#;
        let result: std::result::Result<ReductionConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
        let err: String = result.unwrap_err().to_string();
        assert!(err.contains("non-negative"), "expected non-negative error, got: {err}");
    }

    #[test]
    fn test_reject_nan_weight() {
        let toml_str: &str = r#"
[listen]
address = "127.0.0.1:8443"
transport = "tcp"

[tls.server]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"

[[backends]]
id = "api"
address = "10.0.0.1:8080"
weight = nan
transport = "tcp"

[[routes]]
path_prefix = "/api"
backend_id = "api"
"#;
        let result: std::result::Result<ReductionConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_inf_weight() {
        let toml_str: &str = r#"
[listen]
address = "127.0.0.1:8443"
transport = "tcp"

[tls.server]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"

[[backends]]
id = "api"
address = "10.0.0.1:8080"
weight = inf
transport = "tcp"

[[routes]]
path_prefix = "/api"
backend_id = "api"
"#;
        let result: std::result::Result<ReductionConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_negative_jitter_factor() {
        let toml_str: &str = r#"
[listen]
address = "127.0.0.1:8443"
transport = "tcp"

[tls.server]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"

[balancer]
jitter_factor = -0.1

[[backends]]
id = "api"
address = "10.0.0.1:8080"
weight = 1.0
transport = "tcp"

[[routes]]
path_prefix = "/api"
backend_id = "api"
"#;
        let result: std::result::Result<ReductionConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
        let err: String = result.unwrap_err().to_string();
        assert!(err.contains("non-negative"), "expected non-negative error, got: {err}");
    }

    #[test]
    fn test_reject_jitter_factor_gte_one() {
        let toml_str: &str = r#"
[listen]
address = "127.0.0.1:8443"
transport = "tcp"

[tls.server]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"

[balancer]
jitter_factor = 1.0

[[backends]]
id = "api"
address = "10.0.0.1:8080"
weight = 1.0
transport = "tcp"

[[routes]]
path_prefix = "/api"
backend_id = "api"
"#;
        let result: std::result::Result<ReductionConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
        let err: String = result.unwrap_err().to_string();
        assert!(err.contains("less than 1.0"), "expected <1.0 error, got: {err}");
    }

    #[test]
    fn test_accept_zero_weight() {
        let toml_str: &str = r#"
[listen]
address = "127.0.0.1:8443"
transport = "tcp"

[tls.server]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"

[[backends]]
id = "api"
address = "10.0.0.1:8080"
weight = 0.0
transport = "tcp"

[[routes]]
path_prefix = "/api"
backend_id = "api"
"#;
        let config: ReductionConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.backends[0].weight, 0.0);
    }

    #[test]
    fn test_pool_defaults_to_id() {
        let config: ReductionConfig = toml::from_str(minimal_toml()).unwrap();
        assert_eq!(config.backends[0].id.as_str(), "api");
        assert_eq!(config.backends[0].pool.as_str(), "api");
    }

    #[test]
    fn test_pool_explicit_grouping() {
        let toml_str: &str = r#"
[listen]
address = "127.0.0.1:8443"
transport = "tcp"

[tls.server]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"

[[backends]]
id = "api-primary"
pool = "api"
address = "10.0.0.1:8080"
weight = 3.0
transport = "tcp"

[[backends]]
id = "api-secondary"
pool = "api"
address = "10.0.0.2:8080"
weight = 1.0
transport = "tcp"

[[routes]]
path_prefix = "/api"
backend_id = "api"
"#;
        let config: ReductionConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.backends.len(), 2);
        assert_eq!(config.backends[0].id.as_str(), "api-primary");
        assert_eq!(config.backends[0].pool.as_str(), "api");
        assert_eq!(config.backends[1].id.as_str(), "api-secondary");
        assert_eq!(config.backends[1].pool.as_str(), "api");
    }

    #[test]
    fn test_accept_valid_jitter_factor() {
        let toml_str: &str = r#"
[listen]
address = "127.0.0.1:8443"
transport = "tcp"

[tls.server]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"

[balancer]
jitter_factor = 0.99

[[backends]]
id = "api"
address = "10.0.0.1:8080"
weight = 1.0
transport = "tcp"

[[routes]]
path_prefix = "/api"
backend_id = "api"
"#;
        let config: ReductionConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.balancer.jitter_factor, 0.99);
    }

    #[test]
    fn test_drain_timeout_default() {
        let config: BalancerConfig = BalancerConfig::default();
        assert_eq!(config.drain_timeout_secs, 30);
    }

    #[test]
    fn test_max_connections_defaults_to_256() {
        let backend: BackendConfig = BackendConfig::new(
            "test".into(),
            "10.0.0.1:8080".parse().unwrap(),
            1.0,
            TransportKind::Tcp,
        );
        assert_eq!(backend.max_connections, 256);
    }

    #[test]
    fn test_max_connections_with_builder() {
        let backend: BackendConfig = BackendConfig::new(
            "test".into(),
            "10.0.0.1:8080".parse().unwrap(),
            1.0,
            TransportKind::Tcp,
        ).with_max_connections(50);
        assert_eq!(backend.max_connections, 50);
    }

    #[test]
    #[should_panic(expected = "invalid max_connections")]
    fn test_max_connections_zero_panics() {
        BackendConfig::new(
            "test".into(),
            "10.0.0.1:8080".parse().unwrap(),
            1.0,
            TransportKind::Tcp,
        ).with_max_connections(0);
    }

    #[test]
    fn test_max_connections_from_toml() {
        let toml_str: &str = r#"
[listen]
address = "0.0.0.0:8443"
transport = "tcp"

[tls]
server = { cert_path = "s.crt", key_path = "s.key", ca_cert_path = "ca.crt" }
client = { cert_path = "c.crt", key_path = "c.key", ca_cert_path = "ca.crt" }

[[backends]]
id = "api"
address = "10.0.0.1:8080"
weight = 1.0
transport = "tcp"
max_connections = 100

[[routes]]
path_prefix = "/"
backend_id = "api"
"#;
        let config: ReductionConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.backends[0].max_connections, 100);
    }

    #[test]
    fn test_max_connections_omitted_defaults() {
        let toml_str: &str = r#"
[listen]
address = "0.0.0.0:8443"
transport = "tcp"

[tls]
server = { cert_path = "s.crt", key_path = "s.key", ca_cert_path = "ca.crt" }
client = { cert_path = "c.crt", key_path = "c.key", ca_cert_path = "ca.crt" }

[[backends]]
id = "api"
address = "10.0.0.1:8080"
weight = 1.0
transport = "tcp"

[[routes]]
path_prefix = "/"
backend_id = "api"
"#;
        let config: ReductionConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.backends[0].max_connections, 256);
    }

    #[test]
    fn test_reject_zero_max_connections_from_toml() {
        let toml_str: &str = r#"
[listen]
address = "0.0.0.0:8443"
transport = "tcp"

[tls]
server = { cert_path = "s.crt", key_path = "s.key", ca_cert_path = "ca.crt" }
client = { cert_path = "c.crt", key_path = "c.key", ca_cert_path = "ca.crt" }

[[backends]]
id = "api"
address = "10.0.0.1:8080"
weight = 1.0
transport = "tcp"
max_connections = 0

[[routes]]
path_prefix = "/"
backend_id = "api"
"#;
        let result: std::result::Result<ReductionConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }
}
