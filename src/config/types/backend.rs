use std::net::SocketAddr;

use arrayvec::ArrayString;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::TransportKind;
use crate::error::{ReductionError, Result};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
	pub path_prefix: ArrayString<64>,
	pub backend_id: ArrayString<256>,
	pub timeout_secs: Option<u64>,
}

// ── Backend defaults ──

pub const DEFAULT_MAX_CONNECTIONS: u32 = 256;

const fn default_max_connections() -> u32 {
	return DEFAULT_MAX_CONNECTIONS;
}

// Backend hop security, orthogonal to the wire transport. `Https` (the default) preserves the existing
// behavior — TLS (+ HTTP/2) to the backend, verified against tls.client's CA. `Http` proxies cleartext
// HTTP/1.1 with no TLS, for a plain-HTTP backend on a trusted private network (e.g. a static-site server
// on an isolated Compose network). Only meaningful for `transport = tcp`; QUIC always encrypts, so
// `Http` + `Quic` is a config error (rejected by ReductionConfig::validate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackendScheme {
	#[default]
	Https,
	Http,
}

impl BackendScheme {
	// True for cleartext HTTP/1.1 (no TLS handshake to the backend).
	#[must_use]
	#[inline]
	pub const fn is_plaintext(self) -> bool {
		return matches!(self, Self::Http);
	}
}

// serde skip: a default `Https` scheme is omitted so existing config output is byte-unchanged.
const fn is_https_scheme(scheme: &BackendScheme) -> bool {
	return matches!(scheme, BackendScheme::Https);
}

// PartialEq (not Eq — weight is f64) lets the reload task detect whether the routing-relevant config
// actually changed, so the response cache is flushed only on a real route/backend edit.
#[derive(Debug, Clone, PartialEq)]
pub struct BackendConfig {
	pub id: ArrayString<256>,
	pub pool: ArrayString<32>,
	pub address: SocketAddr,
	pub host: String,
	pub weight: f64,
	pub transport: TransportKind,
	// Backend hop security. Default Https (TLS + HTTP/2). Http = cleartext HTTP/1.1 (tcp only).
	pub scheme: BackendScheme,
	pub max_connections: u32,
	// Scale-to-zero (Option B): a control plane may start this backend on demand. A miss with no live
	// session is then a cold start to wait out, not a failure — findings F1/F2. Default false.
	pub wakeable: bool,
}

// serde skip: a false `wakeable` is omitted so existing config output is byte-unchanged.
const fn is_not_wakeable(wakeable: &bool) -> bool {
	return !*wakeable;
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

impl BackendConfig {
	pub fn new(id: &str, address: SocketAddr, weight: f64, transport: TransportKind) -> Result<Self> {
		validate_weight(weight).map_err(ReductionError::Config)?;
		let id: ArrayString<256> = ArrayString::from(id)
			.map_err(|_| ReductionError::Config("backend id exceeds 256 characters".to_owned()))?;
		let host: String = address.ip().to_string();
		let pool: ArrayString<32> = ArrayString::from(id.as_str())
			.map_err(|_| ReductionError::Config("backend id exceeds 32 characters for default pool name".to_owned()))?;
		let max_connections: u32 = DEFAULT_MAX_CONNECTIONS;
		return Ok(Self {
			id,
			pool,
			address,
			host,
			weight,
			transport,
			scheme: BackendScheme::Https,
			max_connections,
			wakeable: false,
		});
	}

	#[must_use]
	pub const fn with_wakeable(mut self, wakeable: bool) -> Self {
		self.wakeable = wakeable;
		return self;
	}

	#[must_use]
	pub const fn with_scheme(mut self, scheme: BackendScheme) -> Self {
		self.scheme = scheme;
		return self;
	}

	pub fn with_pool(mut self, pool: &str) -> Result<Self> {
		self.pool = ArrayString::from(pool)
			.map_err(|_| ReductionError::Config("pool name exceeds 32 characters".to_owned()))?;
		return Ok(self);
	}

	#[must_use]
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
			#[serde(skip_serializing_if = "is_https_scheme")]
			scheme: BackendScheme,
			max_connections: u32,
			#[serde(skip_serializing_if = "is_not_wakeable")]
			wakeable: bool,
		}
		let wire: Wire<'_> = Wire {
			id: &self.id,
			pool: &self.pool,
			host: &self.host,
			address: self.address.to_string(),
			weight: self.weight,
			transport: &self.transport,
			scheme: self.scheme,
			max_connections: self.max_connections,
			wakeable: self.wakeable,
		};
		return wire.serialize(serializer);
	}
}

impl<'de> Deserialize<'de> for BackendConfig {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire {
			id: String,
			pool: Option<String>,
			host: Option<String>,
			address: String,
			weight: f64,
			transport: TransportKind,
			#[serde(default)]
			scheme: BackendScheme,
			#[serde(default = "default_max_connections")]
			max_connections: u32,
			#[serde(default)]
			wakeable: bool,
		}
		let wire: Wire = Wire::deserialize(deserializer)?;
		let address: SocketAddr = wire
			.address
			.parse()
			.map_err(|e| serde::de::Error::custom(format!("invalid backend address '{}': {e}", wire.address)))?;
		validate_weight(wire.weight).map_err(serde::de::Error::custom)?;
		validate_max_connections(wire.max_connections).map_err(serde::de::Error::custom)?;
		let id: ArrayString<256> = ArrayString::from(&wire.id)
			.map_err(|_| serde::de::Error::custom(format!("backend id '{}' exceeds 256 characters", wire.id)))?;
		let pool: ArrayString<32> = match wire.pool {
			Some(p) => ArrayString::from(&p)
				.map_err(|_| serde::de::Error::custom(format!("pool name '{}' exceeds 32 characters", p)))?,
			None => ArrayString::from(id.as_str()).map_err(|_| {
				serde::de::Error::custom(format!(
					"backend id '{}' exceeds 32 characters for default pool name",
					wire.id
				))
			})?,
		};
		let host: String = wire.host.unwrap_or_else(|| address.ip().to_string());
		return Ok(Self {
			id,
			pool,
			address,
			host,
			weight: wire.weight,
			transport: wire.transport,
			scheme: wire.scheme,
			max_connections: wire.max_connections,
			wakeable: wire.wakeable,
		});
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const BACKEND_ID_MAX_CHARS: usize = 256;
	const POOL_NAME_MAX_CHARS: usize = 32;

	fn sample_backend() -> BackendConfig {
		// Valid inputs; unwrap acceptable in test setup.
		return BackendConfig::new("api", "10.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp).unwrap();
	}

	#[test]
	fn validate_weight_rejects_nan_inf_and_negative() {
		assert!(validate_weight(f64::NAN).is_err());
		assert!(validate_weight(f64::INFINITY).is_err());
		assert!(validate_weight(-1.0).is_err());
		assert!(validate_weight(0.0).is_ok());
	}

	#[test]
	fn validate_max_connections_rejects_zero() {
		assert!(validate_max_connections(0).is_err());
		assert!(validate_max_connections(1).is_ok());
	}

	#[test]
	fn backend_new_rejects_id_over_256_chars() {
		let long_id: String = "a".repeat(BACKEND_ID_MAX_CHARS + 1);
		let result: Result<BackendConfig> =
			BackendConfig::new(&long_id, "10.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp);
		assert!(result.is_err());
		let err: String = result.unwrap_err().to_string();
		assert!(err.contains("256"), "got: {err}");
	}

	#[test]
	fn backend_new_rejects_id_too_long_for_default_pool() {
		let long_id: String = "a".repeat(POOL_NAME_MAX_CHARS + 1);
		let result: Result<BackendConfig> =
			BackendConfig::new(&long_id, "10.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp);
		assert!(result.is_err());
		let err: String = result.unwrap_err().to_string();
		assert!(err.contains("default pool name"), "got: {err}");
	}

	#[test]
	fn backend_new_rejects_invalid_weight() {
		let result: Result<BackendConfig> =
			BackendConfig::new("api", "10.0.0.1:8080".parse().unwrap(), f64::NAN, TransportKind::Tcp);
		assert!(result.is_err());
	}

	#[test]
	fn backend_new_derives_host_from_address() {
		let backend: BackendConfig = sample_backend();
		assert_eq!(backend.host, "10.0.0.1");
		assert_eq!(backend.pool.as_str(), "api");
		assert_eq!(backend.max_connections, DEFAULT_MAX_CONNECTIONS);
	}

	#[test]
	fn backend_with_pool_sets_pool() {
		let backend: BackendConfig = sample_backend().with_pool("edge").unwrap();
		assert_eq!(backend.pool.as_str(), "edge");
	}

	#[test]
	fn backend_with_pool_rejects_name_over_32_chars() {
		let long_pool: String = "p".repeat(POOL_NAME_MAX_CHARS + 1);
		let result: Result<BackendConfig> = sample_backend().with_pool(&long_pool);
		assert!(result.is_err());
		let err: String = result.unwrap_err().to_string();
		assert!(err.contains("32"), "got: {err}");
	}

	#[test]
	fn backend_with_max_connections_rejects_zero() {
		let result: Result<BackendConfig> = sample_backend().with_max_connections(0);
		assert!(result.is_err());
		let err: String = result.unwrap_err().to_string();
		assert!(err.contains("at least 1"), "got: {err}");
	}

	#[test]
	fn backend_with_host_overrides_derived_host() {
		let backend: BackendConfig = sample_backend().with_host("api.internal".to_owned());
		assert_eq!(backend.host, "api.internal");
	}

	// ── BackendConfig serde ──

	#[test]
	fn backend_deserialize_rejects_invalid_address() {
		let toml_str: &str = "id = \"api\"\naddress = \"not-an-address\"\nweight = 1.0\ntransport = \"tcp\"";
		let result: std::result::Result<BackendConfig, _> = toml::from_str(toml_str);
		assert!(result.is_err());
		let err: String = result.unwrap_err().to_string();
		assert!(err.contains("invalid backend address"), "got: {err}");
	}

	#[test]
	fn backend_deserialize_rejects_id_over_256_chars() {
		let long_id: String = "a".repeat(BACKEND_ID_MAX_CHARS + 1);
		let toml_str: String =
			format!("id = \"{long_id}\"\naddress = \"10.0.0.1:8080\"\nweight = 1.0\ntransport = \"tcp\"");
		let result: std::result::Result<BackendConfig, _> = toml::from_str(&toml_str);
		assert!(result.is_err());
		let err: String = result.unwrap_err().to_string();
		assert!(err.contains("exceeds 256 characters"), "got: {err}");
	}

	#[test]
	fn backend_deserialize_rejects_pool_over_32_chars() {
		let long_pool: String = "p".repeat(POOL_NAME_MAX_CHARS + 1);
		let toml_str: String = format!(
			"id = \"api\"\npool = \"{long_pool}\"\naddress = \"10.0.0.1:8080\"\nweight = 1.0\ntransport = \"tcp\""
		);
		let result: std::result::Result<BackendConfig, _> = toml::from_str(&toml_str);
		assert!(result.is_err());
		let err: String = result.unwrap_err().to_string();
		assert!(err.contains("exceeds 32 characters"), "got: {err}");
	}

	#[test]
	fn backend_deserialize_rejects_long_id_without_explicit_pool() {
		let long_id: String = "a".repeat(POOL_NAME_MAX_CHARS + 1);
		let toml_str: String =
			format!("id = \"{long_id}\"\naddress = \"10.0.0.1:8080\"\nweight = 1.0\ntransport = \"tcp\"");
		let result: std::result::Result<BackendConfig, _> = toml::from_str(&toml_str);
		assert!(result.is_err());
		let err: String = result.unwrap_err().to_string();
		assert!(err.contains("default pool name"), "got: {err}");
	}

	#[test]
	fn backend_deserialize_accepts_long_id_with_explicit_pool() {
		let long_id: String = "a".repeat(POOL_NAME_MAX_CHARS + 1);
		let toml_str: String = format!(
			"id = \"{long_id}\"\npool = \"edge\"\naddress = \"10.0.0.1:8080\"\nweight = 1.0\ntransport = \"quic\""
		);
		let backend: BackendConfig = toml::from_str(&toml_str).unwrap();
		assert_eq!(backend.id.as_str(), long_id);
		assert_eq!(backend.pool.as_str(), "edge");
		assert_eq!(backend.transport, TransportKind::Quic);
	}

	#[test]
	fn backend_deserialize_rejects_negative_weight() {
		let toml_str: &str = "id = \"api\"\naddress = \"10.0.0.1:8080\"\nweight = -1.0\ntransport = \"tcp\"";
		let result: std::result::Result<BackendConfig, _> = toml::from_str(toml_str);
		assert!(result.is_err());
		let err: String = result.unwrap_err().to_string();
		assert!(err.contains("non-negative"), "got: {err}");
	}

	#[test]
	fn backend_deserialize_rejects_zero_max_connections() {
		let toml_str: &str =
			"id = \"api\"\naddress = \"10.0.0.1:8080\"\nweight = 1.0\ntransport = \"tcp\"\nmax_connections = 0";
		let result: std::result::Result<BackendConfig, _> = toml::from_str(toml_str);
		assert!(result.is_err());
		let err: String = result.unwrap_err().to_string();
		assert!(err.contains("at least 1"), "got: {err}");
	}

	#[test]
	fn backend_deserialize_defaults_pool_to_id_and_max_connections() {
		let toml_str: &str = "id = \"api\"\naddress = \"10.0.0.1:8080\"\nweight = 1.0\ntransport = \"tcp\"";
		let backend: BackendConfig = toml::from_str(toml_str).unwrap();
		assert_eq!(backend.pool.as_str(), "api");
		assert_eq!(backend.max_connections, DEFAULT_MAX_CONNECTIONS);
		assert_eq!(backend.host, "10.0.0.1");
	}

	#[test]
	fn backend_deserialize_uses_explicit_host() {
		let toml_str: &str =
			"id = \"api\"\nhost = \"api.internal\"\naddress = \"10.0.0.1:8080\"\nweight = 1.0\ntransport = \"tcp\"";
		let backend: BackendConfig = toml::from_str(toml_str).unwrap();
		assert_eq!(backend.host, "api.internal");
	}

	#[test]
	fn backend_serialize_round_trip_preserves_pool_and_host() {
		// Setup uses valid inputs; unwrap acceptable in tests.
		let original: BackendConfig = sample_backend()
			.with_pool("edge")
			.unwrap()
			.with_host("api.internal".to_owned())
			.with_max_connections(50)
			.unwrap();
		let serialized: String = toml::to_string(&original).unwrap();
		let restored: BackendConfig = toml::from_str(&serialized).unwrap();
		assert_eq!(restored.id.as_str(), original.id.as_str());
		assert_eq!(restored.pool.as_str(), "edge");
		assert_eq!(restored.host, "api.internal");
		assert_eq!(restored.address, original.address);
		assert_eq!(restored.weight, original.weight);
		assert_eq!(restored.transport, original.transport);
		assert_eq!(restored.max_connections, 50);
	}

	// ── BackendScheme ──

	#[test]
	fn backend_scheme_defaults_to_https() {
		// No `scheme` key must default to https (TLS + H2) — existing configs keep their behavior.
		let toml_str: &str = "id = \"api\"\naddress = \"10.0.0.1:8080\"\nweight = 1.0\ntransport = \"tcp\"";
		let backend: BackendConfig = toml::from_str(toml_str).unwrap();
		assert_eq!(backend.scheme, BackendScheme::Https);
		assert!(!backend.scheme.is_plaintext());
		assert_eq!(BackendScheme::default(), BackendScheme::Https);
	}

	#[test]
	fn backend_deserialize_parses_http_scheme() {
		let toml_str: &str =
			"id = \"blog\"\naddress = \"10.0.0.1:8080\"\nweight = 1.0\ntransport = \"tcp\"\nscheme = \"http\"";
		let backend: BackendConfig = toml::from_str(toml_str).unwrap();
		assert_eq!(backend.scheme, BackendScheme::Http);
		assert!(backend.scheme.is_plaintext());
	}

	#[test]
	fn backend_serialize_omits_default_https_scheme() {
		// The default scheme must not appear in serialized output, so existing round-trips are byte-stable.
		let backend: BackendConfig = sample_backend();
		let serialized: String = toml::to_string(&backend).unwrap();
		assert!(!serialized.contains("scheme"), "default https scheme must be omitted, got: {serialized}");
	}

	#[test]
	fn backend_serialize_round_trip_preserves_http_scheme() {
		let original: BackendConfig = sample_backend().with_scheme(BackendScheme::Http);
		let serialized: String = toml::to_string(&original).unwrap();
		assert!(serialized.contains("scheme = \"http\""), "http scheme must be serialized, got: {serialized}");
		let restored: BackendConfig = toml::from_str(&serialized).unwrap();
		assert_eq!(restored.scheme, BackendScheme::Http);
	}

	// ── RouteConfig ──

	#[test]
	fn route_config_round_trip_with_timeout() {
		let original: RouteConfig = RouteConfig {
			path_prefix: ArrayString::from("/api").unwrap(),
			backend_id: ArrayString::from("api").unwrap(),
			timeout_secs: Some(15),
		};
		let serialized: String = toml::to_string(&original).unwrap();
		let restored: RouteConfig = toml::from_str(&serialized).unwrap();
		assert_eq!(restored.path_prefix.as_str(), "/api");
		assert_eq!(restored.backend_id.as_str(), "api");
		assert_eq!(restored.timeout_secs, Some(15));
	}

	// The reload task gates its response-cache flush on `config.routes != prev_routes`, so an identical
	// route table must compare equal (cache stays warm) and a repointed route must compare unequal.
	#[test]
	fn route_config_eq_detects_repointed_backend() {
		let route = |backend: &str| RouteConfig {
			path_prefix: ArrayString::from("/api").unwrap(),
			backend_id: ArrayString::from(backend).unwrap(),
			timeout_secs: Some(15),
		};
		assert_eq!(route("api"), route("api"));
		assert_ne!(route("api"), route("api-v2"));
	}

	// Same gate for `config.backends`: a backend re-pointed to a different address must compare unequal
	// so the flush fires, while an unchanged backend list stays equal so the cache survives.
	#[test]
	fn backend_config_eq_detects_moved_address() {
		let moved: BackendConfig =
			BackendConfig::new("api", "10.0.0.2:8080".parse().unwrap(), 1.0, TransportKind::Tcp).unwrap();
		assert_eq!(sample_backend(), sample_backend());
		assert_ne!(sample_backend(), moved);
	}
}
