pub mod types;
#[cfg(feature = "proxy")]
pub mod watcher;

use std::path::Path;

use tracing::info;
pub use types::*;

use crate::error::Result;
use crate::fs_util::load_or_recover;

pub fn load_config(path: &Path) -> Result<ReductionConfig> {
	let config: ReductionConfig = load_or_recover(path, |s| toml::from_str(s))?;
	config.validate()?;

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

[tls.server.manual]
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

	// Pins the shipped config.example.toml to the current schema: it must deserialize, and its
	// documented sections (including the commented-out tunnel/CRL fields once uncommented) must match.
	#[test]
	fn test_example_config_deserializes() {
		let example: &str = include_str!("../../config.example.toml");
		let config: ReductionConfig =
			toml::from_str(example).expect("config.example.toml must stay in sync with the config schema");
		// The tunnel section is present-but-empty (all fields commented) → all defaults.
		assert!(!config.tunnel.enabled);
		assert!(config.tunnel.revocation_path.is_none());
		assert!(config.tunnel.max_total_sessions.is_none());
		// Server TLS is manual with no CRL by default (crl_path commented out).
		assert!(config.tls.server.as_manual().is_some_and(|id| id.crl_path.is_none()));
	}

	#[test]
	fn test_parse_multiple_backends() {
		let toml_str: &str = r#"
[listen]
address = "0.0.0.0:8443"
transport = "quic"

[tls.server.manual]
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
	fn test_unknown_top_level_security_section_is_rejected() {
		let toml_str: String = format!("{}\n[acess]\nallow = [\"10.0.0.0/8\"]\n", minimal_toml(),);
		let result: std::result::Result<ReductionConfig, _> = toml::from_str(&toml_str);
		assert!(
			result.is_err(),
			"a misspelled access section must not silently default to allow-all"
		);
	}

	#[test]
	fn test_unknown_nested_security_field_is_rejected() {
		let toml_str: String = format!("{}\n[tunnel]\nmax_accepts_per_second_per_i = 20\n", minimal_toml(),);
		let result: std::result::Result<ReductionConfig, _> = toml::from_str(&toml_str);
		assert!(
			result.is_err(),
			"a misspelled tunnel limit must not silently remain disabled"
		);
	}

	#[test]
	fn test_unknown_backend_field_is_rejected() {
		let toml_str: String = minimal_toml().replace("weight = 1.0", "weight = 1.0\nmax_connection = 10");
		let result: std::result::Result<ReductionConfig, _> = toml::from_str(&toml_str);
		assert!(
			result.is_err(),
			"the custom backend deserializer must reject unknown fields too"
		);
	}

	#[test]
	fn test_config_round_trip() {
		let original: ReductionConfig = ReductionConfig {
			listen: ListenConfig {
				address: "127.0.0.1:8443".parse().unwrap(),
				transport: TransportKind::Quic,
				client_auth: ClientAuthPolicy::Required,
			},
			tls: TlsConfig {
				server: ServerTlsConfig::Manual(TlsIdentity {
					cert_path: "certs/server.crt".into(),
					key_path: "certs/server.key".into(),
					ca_cert_path: "certs/ca.crt".into(),
					crl_path: None,
				}),
				client: Some(TlsIdentity {
					cert_path: "certs/client.crt".into(),
					key_path: "certs/client.key".into(),
					ca_cert_path: "certs/ca.crt".into(),
					crl_path: None,
				}),
			},
			backends: vec![
				BackendConfig::new("api", "10.0.0.1:8080".parse().unwrap(), 2.5, TransportKind::Quic).unwrap(),
			],
			routes: vec![RouteConfig {
				path_prefix: ArrayString::from("/api").unwrap(),
				backend_id: ArrayString::from("api").unwrap(),
				timeout_secs: None,
			}],
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
			raw_relay_authz: Vec::new(),
			ingress: Vec::new(),
			http_redirect: HttpRedirectConfig::default(),
			health_endpoint: HealthEndpointConfig::default(),
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
	fn test_validate_accepts_default_heartbeat_contract() {
		let config: ReductionConfig = toml::from_str(minimal_toml()).unwrap();
		assert!(config.validate().is_ok());
	}

	// ── Topology invariants: parseable configs the runtime cannot honor must fail at load. ──

	#[test]
	fn test_validate_rejects_route_to_nonexistent_pool() {
		// A route naming a backend_id no backend's pool matches builds no pool → 502 at request time.
		let toml_str: String = minimal_toml().replace("backend_id = \"api\"", "backend_id = \"missing\"");
		let config: ReductionConfig = toml::from_str(&toml_str).unwrap();
		let err = config.validate().unwrap_err();
		assert!(
			format!("{err}").contains("no matching backend pool"),
			"error must name the failure: {err}"
		);
	}

	#[test]
	fn test_validate_rejects_duplicate_backend_id() {
		// A second backend with the same id conflates id-keyed health/circuit-breaker/balancer state.
		let toml_str: String = format!(
			"{}\n[[backends]]\nid = \"api\"\naddress = \"10.0.0.2:8080\"\nweight = 1.0\ntransport = \"tcp\"\n",
			minimal_toml(),
		);
		let config: ReductionConfig = toml::from_str(&toml_str).unwrap();
		let err = config.validate().unwrap_err();
		assert!(
			format!("{err}").contains("duplicate backend id"),
			"error must name the failure: {err}"
		);
	}

	#[test]
	fn test_validate_rejects_duplicate_route_prefix() {
		let toml_str: String = format!(
			"{}\n[[routes]]\npath_prefix = \"/api\"\nbackend_id = \"api\"\n",
			minimal_toml(),
		);
		let config: ReductionConfig = toml::from_str(&toml_str).unwrap();
		let err = config.validate().unwrap_err();
		assert!(
			format!("{err}").contains("duplicate route path_prefix"),
			"error must name the failure: {err}"
		);
	}

	#[test]
	fn test_validate_rejects_route_prefix_without_leading_slash() {
		let toml_str: String = minimal_toml().replace("path_prefix = \"/api\"", "path_prefix = \"api\"");
		let config: ReductionConfig = toml::from_str(&toml_str).unwrap();
		let err = config.validate().unwrap_err();
		assert!(
			format!("{err}").contains("must start with '/'"),
			"error must name the failure: {err}"
		);
	}

	#[test]
	fn test_validate_rejects_retry_base_delay_above_max() {
		let toml_str: String = format!(
			"{}\n[retry]\nbase_delay_ms = 5000\nmax_delay_ms = 2000\n",
			minimal_toml(),
		);
		let config: ReductionConfig = toml::from_str(&toml_str).unwrap();
		let err = config.validate().unwrap_err();
		assert!(
			format!("{err}").contains("must not exceed"),
			"error must name the failure: {err}"
		);
	}

	#[test]
	fn test_validate_accepts_two_backends_sharing_a_pool() {
		// Distinct ids sharing one pool is the intended multi-backend topology, not a duplicate.
		let toml_str: &str = r#"
[listen]
address = "127.0.0.1:8443"
transport = "tcp"

[tls.server.manual]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"

[[backends]]
id = "web-1"
pool = "web"
address = "10.0.0.1:8080"
weight = 1.0
transport = "tcp"

[[backends]]
id = "web-2"
pool = "web"
address = "10.0.0.2:8080"
weight = 1.0
transport = "tcp"

[[routes]]
path_prefix = "/"
backend_id = "web"
"#;
		let config: ReductionConfig = toml::from_str(toml_str).unwrap();
		assert!(
			config.validate().is_ok(),
			"two distinct backends in one pool is a valid topology"
		);
	}

	// A semantically invalid config must fail load_config WITHOUT being quarantined: it parsed
	// cleanly, so renaming it away (the corrupt-file treatment) would destroy an operator's file
	// over a fixable cross-field mistake.
	#[test]
	fn test_load_config_semantic_error_does_not_quarantine_file() {
		let dir: tempfile::TempDir = tempfile::tempdir().unwrap();
		let config_path: std::path::PathBuf = dir.path().join("config.toml");
		let toml_str: String = format!("{}\n[retry]\nbase_delay_ms = 100\nmax_delay_ms = 50\n", minimal_toml(),);
		std::fs::write(&config_path, &toml_str).unwrap();

		let result: Result<ReductionConfig> = load_config(&config_path);
		assert!(result.is_err(), "base_delay_ms > max_delay_ms must be rejected at load");
		assert!(config_path.exists(), "a parseable-but-invalid config must stay on disk");
	}

	// ── Ingress validation ──

	fn quic_backend_toml() -> &'static str {
		return "\n[[backends]]\nid = \"ingest-a\"\naddress = \"10.0.0.5:9000\"\nweight = 1.0\ntransport = \"quic\"\n";
	}

	#[test]
	fn test_validate_accepts_ingress_to_quic_backend() {
		let toml_str: String = format!(
			"{}{}\n[[ingress]]\nid = \"site-udp\"\nprotocol = \"udp\"\nlisten = \"10.20.0.1:5000\"\nbackend_ids = [\"ingest-a\"]\n",
			minimal_toml(),
			quic_backend_toml(),
		);
		let config: ReductionConfig = toml::from_str(&toml_str).unwrap();
		assert!(
			config.validate().is_ok(),
			"a private-listen ingress to a quic backend is valid"
		);
	}

	#[test]
	fn test_validate_rejects_ingress_to_non_quic_backend() {
		// "api" is a tcp backend in minimal_toml; ingress requires transport = quic.
		let toml_str: String = format!(
			"{}\n[[ingress]]\nid = \"site-udp\"\nprotocol = \"udp\"\nlisten = \"10.20.0.1:5000\"\nbackend_ids = [\"api\"]\n",
			minimal_toml(),
		);
		let config: ReductionConfig = toml::from_str(&toml_str).unwrap();
		let err = config.validate().unwrap_err();
		assert!(
			format!("{err}").contains("not a transport = quic backend"),
			"error must name the failure: {err}"
		);
	}

	#[test]
	fn test_validate_rejects_ingress_zero_cap() {
		let toml_str: String = format!(
			"{}{}\n[[ingress]]\nid = \"site-udp\"\nprotocol = \"udp\"\nlisten = \"10.20.0.1:5000\"\nbackend_ids = [\"ingest-a\"]\nbatch_max_datagrams = 0\n",
			minimal_toml(),
			quic_backend_toml(),
		);
		let config: ReductionConfig = toml::from_str(&toml_str).unwrap();
		let err = config.validate().unwrap_err();
		assert!(
			format!("{err}").contains("zero cap"),
			"error must name the failure: {err}"
		);
	}

	#[test]
	fn test_validate_rejects_ingress_batch_too_small_for_one_datagram() {
		let toml_str: String = format!(
			"{}{}\n[[ingress]]\nid = \"site-udp\"\nprotocol = \"udp\"\nlisten = \"10.20.0.1:5000\"\nbackend_ids = [\"ingest-a\"]\nmax_datagram_bytes = 8192\nbatch_max_bytes = 4096\n",
			minimal_toml(),
			quic_backend_toml(),
		);
		let config: ReductionConfig = toml::from_str(&toml_str).unwrap();
		let err = config.validate().unwrap_err();
		assert!(
			format!("{err}").contains("cannot fit one max_datagram_bytes payload"),
			"error must name the failure: {err}"
		);
	}

	#[test]
	fn test_validate_rejects_duplicate_ingress_listen() {
		let toml_str: String = format!(
			"{}{}\n[[ingress]]\nid = \"a\"\nprotocol = \"udp\"\nlisten = \"10.20.0.1:5000\"\nbackend_ids = [\"ingest-a\"]\n\n[[ingress]]\nid = \"b\"\nprotocol = \"udp\"\nlisten = \"10.20.0.1:5000\"\nbackend_ids = [\"ingest-a\"]\n",
			minimal_toml(),
			quic_backend_toml(),
		);
		let config: ReductionConfig = toml::from_str(&toml_str).unwrap();
		let err = config.validate().unwrap_err();
		assert!(
			format!("{err}").contains("duplicate ingress listen"),
			"error must name the failure: {err}"
		);
	}

	#[test]
	fn test_validate_rejects_non_private_ingress_without_allowlist() {
		let toml_str: String = format!(
			"{}{}\n[[ingress]]\nid = \"site-udp\"\nprotocol = \"udp\"\nlisten = \"8.8.8.8:5000\"\nbackend_ids = [\"ingest-a\"]\n",
			minimal_toml(),
			quic_backend_toml(),
		);
		let config: ReductionConfig = toml::from_str(&toml_str).unwrap();
		let err = config.validate().unwrap_err();
		assert!(
			format!("{err}").contains("without an [access] allow list"),
			"error must name the failure: {err}"
		);
	}

	#[test]
	fn test_validate_accepts_non_private_ingress_with_allowlist() {
		let toml_str: String = format!(
			"{}{}\n[access]\nallow = [\"203.0.113.0/24\"]\n\n[[ingress]]\nid = \"site-udp\"\nprotocol = \"udp\"\nlisten = \"8.8.8.8:5000\"\nbackend_ids = [\"ingest-a\"]\n",
			minimal_toml(),
			quic_backend_toml(),
		);
		let config: ReductionConfig = toml::from_str(&toml_str).unwrap();
		assert!(
			config.validate().is_ok(),
			"a routable ingress gated by an allowlist is valid"
		);
	}

	#[test]
	fn test_transport_kind_values() {
		assert_eq!(TransportKind::Tcp, TransportKind::Tcp);
		assert_eq!(TransportKind::Quic, TransportKind::Quic);
		assert_ne!(TransportKind::Tcp, TransportKind::Quic);
	}

	#[test]
	fn test_proxy_partial_section_fills_field_defaults() {
		// A [proxy] section that sets one field must leave the rest at their serde defaults.
		let toml_str: String = format!("{}\n[proxy]\nmax_idle_quic_per_host = 8\n", minimal_toml());
		let config: ReductionConfig = toml::from_str(&toml_str).unwrap();
		assert_eq!(config.proxy.max_idle_quic_per_host, 8);
		assert_eq!(config.proxy.max_request_body_bytes, DEFAULT_MAX_REQUEST_BODY_BYTES);
		assert_eq!(config.proxy.max_response_body_bytes, DEFAULT_MAX_RESPONSE_BODY_BYTES);
	}
}
