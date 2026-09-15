use std::collections::HashSet;
use std::net::SocketAddr;

use arrayvec::ArrayString;
use serde::{Deserialize, Serialize};

use crate::error::{ReductionError, Result};
use crate::ingress::protocol::MAX_ENVELOPE_FRAME;
use crate::tls::identity::MAX_COMMON_NAME_LEN;

// Backend/route, TLS, and listener-edge config types live in submodules; re-exported so
// `crate::config::X` stays stable.
mod backend;
mod ingress;
mod listener;
mod sections;
mod tls_config;

pub use listener::{
	ClientAuthPolicy, DEFAULT_HEALTH_ENDPOINT_LISTEN, DEFAULT_HTTP_REDIRECT_LISTEN, HealthEndpointConfig,
	HttpRedirectConfig, ListenConfig,
};
// The per-section config blocks (balancer/timeouts/rate limit/access/metrics/tracing/proxy/compression/
// health/circuit breaker/retry/tunnel/cache) and their default consts. Glob re-export keeps every
// `crate::config::X` and `crate::config::types::X` path stable.
pub use sections::*;

use ingress::is_private_listen_addr;
pub use ingress::{
	DEFAULT_BATCH_MAX_BYTES, DEFAULT_BATCH_MAX_DATAGRAMS, DEFAULT_INGRESS_WORKERS, DEFAULT_LINGER_MS,
	DEFAULT_MAX_DATAGRAM_BYTES, DEFAULT_QUEUE_DEPTH_PER_BACKEND, DEFAULT_RECV_BUFFER_BYTES, IngressConfig,
	IngressProtocol, MAX_UDP_DATAGRAM_BYTES,
};
pub use backend::{BackendConfig, BackendScheme, DEFAULT_MAX_CONNECTIONS, RouteConfig};
#[cfg(feature = "acme")]
pub use tls_config::{AcmeTlsConfig, BarrelStateConfig, DEFAULT_ACME_STATE_ENV};
pub use tls_config::{ServerTlsConfig, TlsConfig, TlsIdentity};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
	// Per-backend allowlist gating which authenticated devices may open a raw QUIC relay. A backend
	// without an entry is denied, so an empty list disables raw relays safely. See RawRelayAuthzEntry.
	#[serde(default)]
	pub raw_relay_authz: Vec<RawRelayAuthzEntry>,
	// Datagram/stream ingress listeners. Presence of any entry enables the ingress mode. Empty by
	// default so an ordinary reverse-proxy config is unaffected. See PLAN_INGRESS.md.
	#[serde(default)]
	pub ingress: Vec<IngressConfig>,
	// Optional cleartext port-80 listener that permanently redirects to the canonical HTTPS origin.
	// Disabled by default so an M2M deployment is unaffected. See HttpRedirectConfig.
	#[serde(default)]
	pub http_redirect: HttpRedirectConfig,
	// Optional non-public liveness/readiness endpoint. Disabled by default. See HealthEndpointConfig.
	#[serde(default)]
	pub health_endpoint: HealthEndpointConfig,
}

impl ReductionConfig {
	// Cross-field invariants that per-field serde validation cannot express. Called on initial load
	// and on every reload, so a contradictory config is rejected instead of shipping a contract the
	// runtime cannot honor (a reload failure keeps the previous config in force). Each check is a
	// separate method so a new invariant is one addition, not a branch in a growing function.
	pub fn validate(&self) -> Result<()> {
		self.validate_no_duplicate_backend_ids()?;
		self.validate_routes()?;
		self.validate_retry_backoff()?;
		self.validate_ingress()?;
		self.validate_backend_schemes()?;
		self.validate_http_redirect()?;
		self.validate_health_endpoint()?;
		self.validate_acme_barrel_state()?;
		return Ok(());
	}

	// Barrel ACME custody needs a non-empty persist_command: an empty command could never store renewed
	// state, so a renewal would succeed in memory yet be lost on restart. Reject it at load rather than
	// discovering it only when the first renewal tries (and fails) to persist.
	#[cfg(feature = "acme")]
	fn validate_acme_barrel_state(&self) -> Result<()> {
		if let ServerTlsConfig::Acme(acme) = &self.tls.server
			&& let Some(barrel) = &acme.barrel_state
			&& barrel.persist_command.is_empty()
		{
			return Err(ReductionError::Config(
				"tls.server.acme.barrel_state.persist_command must be non-empty: renewed ACME state could otherwise never be persisted".to_owned(),
			));
		}
		return Ok(());
	}

	// No ACME feature: nothing to validate for the Barrel state store.
	#[cfg(not(feature = "acme"))]
	#[allow(clippy::unused_self)]
	fn validate_acme_barrel_state(&self) -> Result<()> {
		return Ok(());
	}

	// The non-public health endpoint must not share a port with the public data plane or the redirect
	// listener — each needs its own socket. A bind collision would otherwise surface only as a runtime
	// bind error on whichever listener starts second.
	fn validate_health_endpoint(&self) -> Result<()> {
		if !self.health_endpoint.enabled {
			return Ok(());
		}
		let listen: SocketAddr = self.health_endpoint.listen;
		if listen == self.listen.address {
			return Err(ReductionError::Config(format!(
				"health_endpoint.listen '{listen}' collides with the main listen address: the health endpoint needs its own port",
			)));
		}
		if self.http_redirect.enabled && listen == self.http_redirect.listen {
			return Err(ReductionError::Config(format!(
				"health_endpoint.listen '{listen}' collides with http_redirect.listen: the health endpoint needs its own port",
			)));
		}
		return Ok(());
	}

	// The redirect listener needs a canonical target host to redirect to, and that host must be a bare
	// authority (no scheme, no path) since it is spliced into `https://{to_host}{path}`. An enabled
	// redirect with no/invalid `to_host` would emit `https:///path` — a broken Location — so reject it
	// at load. Also reject a redirect bound to the same address as the main listener (port collision).
	fn validate_http_redirect(&self) -> Result<()> {
		if !self.http_redirect.enabled {
			return Ok(());
		}
		let host: &str = self.http_redirect.to_host.trim();
		if host.is_empty() {
			return Err(ReductionError::Config(
				"http_redirect.enabled = true requires a non-empty to_host (the canonical HTTPS hostname to redirect to)".to_owned(),
			));
		}
		if host.contains("://") || host.contains('/') {
			return Err(ReductionError::Config(format!(
				"http_redirect.to_host '{host}' must be a bare host (optionally host:port), not a URL or path",
			)));
		}
		if self.http_redirect.listen == self.listen.address {
			return Err(ReductionError::Config(format!(
				"http_redirect.listen '{}' collides with the main listen address: the redirect listener needs its own port (typically 80)",
				self.http_redirect.listen,
			)));
		}
		return Ok(());
	}

	// A cleartext-HTTP backend scheme is only meaningful over TCP: QUIC mandates TLS 1.3, so `scheme =
	// "http"` on a QUIC backend is a contradiction the dial path could not honor. Reject it at load
	// rather than silently ignoring the field or attempting a nonsensical cleartext QUIC dial.
	fn validate_backend_schemes(&self) -> Result<()> {
		for backend in &self.backends {
			if backend.scheme.is_plaintext() && backend.transport != TransportKind::Tcp {
				return Err(ReductionError::Config(format!(
					"backend '{}' has scheme = \"http\" (cleartext) but transport = \"quic\": plain HTTP is only valid over TCP (QUIC always uses TLS)",
					backend.id,
				)));
			}
		}
		return Ok(());
	}

	// Ingress invariants the runtime cannot honor if violated: a backend_ids entry that is not a
	// transport = quic backend (ingress dials QUIC+mTLS raw streams), a zero cap (would drop or stall
	// everything), a batch byte budget that cannot fit one datagram or overruns the frame ceiling, a
	// duplicate listen address (two listeners fighting for one port), or a routable listen address
	// with no `[access]` allowlist (ingress relaxes the mTLS-only rule, so the allowlist is the gate).
	fn validate_ingress(&self) -> Result<()> {
		let quic_backend_ids: HashSet<&str> = self
			.backends
			.iter()
			.filter(|b| b.transport == TransportKind::Quic)
			.map(|b| b.id.as_str())
			.collect();
		let mut seen_listen: HashSet<SocketAddr> = HashSet::with_capacity(self.ingress.len());
		let has_allowlist: bool = !self.access.allow.is_empty();

		for ingress in &self.ingress {
			let id: &str = ingress.id.as_str();
			if ingress.backend_ids.is_empty() {
				return Err(ReductionError::Config(format!(
					"ingress '{id}' has no backend_ids: an ingress must fan out to at least one backend",
				)));
			}
			for backend_id in &ingress.backend_ids {
				if !quic_backend_ids.contains(backend_id.as_str()) {
					return Err(ReductionError::Config(format!(
						"ingress '{id}' references backend_id '{backend_id}' which is not a transport = quic backend: ingress dials backends over QUIC+mTLS raw streams",
					)));
				}
			}
			self.validate_ingress_caps(ingress)?;
			if !seen_listen.insert(ingress.listen) {
				return Err(ReductionError::Config(format!(
					"duplicate ingress listen address '{}': two listeners cannot bind the same port",
					ingress.listen,
				)));
			}
			if !is_private_listen_addr(ingress.listen.ip()) && !has_allowlist {
				return Err(ReductionError::Config(format!(
					"ingress '{id}' listens on non-private address '{}' without an [access] allow list: a routable ingress must be gated by a CIDR allowlist",
					ingress.listen,
				)));
			}
		}
		return Ok(());
	}

	// Non-zero caps and the batch/frame size relationship for one ingress entry, split out so
	// validate_ingress stays a readable sequence of topology checks.
	fn validate_ingress_caps(&self, ingress: &IngressConfig) -> Result<()> {
		let id: &str = ingress.id.as_str();
		if ingress.max_datagram_bytes == 0
			|| ingress.batch_max_datagrams == 0
			|| ingress.batch_max_bytes == 0
			|| ingress.queue_depth_per_backend == 0
			|| ingress.recv_buffer_bytes == 0
		{
			return Err(ReductionError::Config(format!(
				"ingress '{id}' has a zero cap: max_datagram_bytes, batch_max_datagrams, batch_max_bytes, queue_depth_per_backend, and recv_buffer_bytes must all be non-zero",
			)));
		}
		if ingress.max_datagram_bytes > MAX_UDP_DATAGRAM_BYTES {
			return Err(ReductionError::Config(format!(
				"ingress '{id}' max_datagram_bytes {} exceeds the largest possible UDP payload ({MAX_UDP_DATAGRAM_BYTES})",
				ingress.max_datagram_bytes,
			)));
		}
		if ingress.batch_max_bytes < ingress.max_datagram_bytes {
			return Err(ReductionError::Config(format!(
				"ingress '{id}' batch_max_bytes {} cannot fit one max_datagram_bytes payload ({}): a single datagram would never batch",
				ingress.batch_max_bytes, ingress.max_datagram_bytes,
			)));
		}
		let frame_ceiling: u32 = u32::try_from(MAX_ENVELOPE_FRAME).unwrap_or(u32::MAX);
		if ingress.batch_max_bytes > frame_ceiling {
			return Err(ReductionError::Config(format!(
				"ingress '{id}' batch_max_bytes {} exceeds the envelope frame ceiling ({frame_ceiling})",
				ingress.batch_max_bytes,
			)));
		}
		return Ok(());
	}

	// Health, circuit-breaker, and load-balancer state are all keyed by backend id; two backends
	// sharing an id silently conflate that state (and any per-id limit differences are lost), so a
	// duplicate is a topology error rather than a merge.
	fn validate_no_duplicate_backend_ids(&self) -> Result<()> {
		let mut seen: HashSet<&str> = HashSet::with_capacity(self.backends.len());
		for backend in &self.backends {
			if !seen.insert(backend.id.as_str()) {
				return Err(ReductionError::Config(format!(
					"duplicate backend id '{}': each backend id must be unique (health, circuit-breaker, and balancer state are keyed by id)",
					backend.id,
				)));
			}
		}
		return Ok(());
	}

	// Every route must name a routable, unambiguous target. A pool is built for a route only when a
	// backend's `pool` equals the route's backend_id, so a route naming no pool yields no pool and a
	// 502 at request time — the exact "starts fine, fails later" trap this rejects at load.
	fn validate_routes(&self) -> Result<()> {
		let pools: HashSet<&str> = self.backends.iter().map(|b| b.pool.as_str()).collect();
		let mut seen_prefixes: HashSet<&str> = HashSet::with_capacity(self.routes.len());
		for route in &self.routes {
			let prefix: &str = route.path_prefix.as_str();
			// Request paths always begin with '/', so a prefix that does not can never match.
			if !prefix.starts_with('/') {
				return Err(ReductionError::Config(format!(
					"route path_prefix '{prefix}' must start with '/': request paths always begin with '/', so this route can never match",
				)));
			}
			if !seen_prefixes.insert(prefix) {
				return Err(ReductionError::Config(format!(
					"duplicate route path_prefix '{prefix}': two routes with the same prefix make backend selection ambiguous",
				)));
			}
			if !pools.contains(route.backend_id.as_str()) {
				return Err(ReductionError::Config(format!(
					"route path_prefix '{prefix}' references backend_id '{}' with no matching backend pool: define a backend whose pool (defaulting to its id) is '{}'",
					route.backend_id, route.backend_id,
				)));
			}
		}
		return Ok(());
	}

	// Backoff is min(base * 2^attempt, max); a base above the cap collapses the exponential to a flat
	// `max` on the very first attempt, which is never the intent.
	fn validate_retry_backoff(&self) -> Result<()> {
		if self.retry.base_delay_ms > self.retry.max_delay_ms {
			return Err(ReductionError::Config(format!(
				"retry.base_delay_ms ({}) must not exceed retry.max_delay_ms ({}): the exponential backoff would be clamped to the cap on the first attempt",
				self.retry.base_delay_ms, self.retry.max_delay_ms,
			)));
		}
		return Ok(());
	}
}

// Per-backend allowlist entry gating which mTLS-authenticated devices may open a raw QUIC relay to a
// given backend_id (the routing-header value the client sends). A backend with no entry denies every
// device; a backend with an entry admits only the listed device CNs or key SPKIs. Consumed by
// proxy::RawRelayAuthz, which validates and indexes it at startup.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRelayAuthzEntry {
	pub backend_id: ArrayString<256>,
	// Device certificate common names (device IDs) permitted to raw-relay to this backend.
	#[serde(default)]
	pub allowed_cns: Vec<ArrayString<MAX_COMMON_NAME_LEN>>,
	// Device key SPKI SHA-256 hashes as hex (either case); validated to 64 hex chars at policy build.
	#[serde(default)]
	pub allowed_spkis: Vec<String>,
}

// `ListenConfig`, `TransportKind`'s siblings `ClientAuthPolicy`/`HttpRedirectConfig`/`HealthEndpointConfig`
// live in the `listener` submodule (re-exported above). `TransportKind` stays here because both `backend`
// and `listener` reference it via `super::TransportKind`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
	Tcp,
	Quic,
}

#[cfg(test)]
mod tests {
	use super::*;

	// ── backend scheme validation ──

	#[test]
	fn validate_rejects_http_scheme_on_quic_backend() {
		// minimal_toml()'s backend is transport = quic; forcing its scheme to cleartext http is a
		// contradiction (QUIC always uses TLS) and must be rejected by validate.
		let mut config: ReductionConfig = toml::from_str(minimal_toml()).unwrap();
		config.backends[0].scheme = BackendScheme::Http;
		let err: String = config.validate().unwrap_err().to_string();
		assert!(err.contains("cleartext") && err.contains("TCP"), "got: {err}");
	}

	#[test]
	fn validate_accepts_http_scheme_on_tcp_backend() {
		let mut config: ReductionConfig = toml::from_str(minimal_toml()).unwrap();
		config.backends[0].transport = TransportKind::Tcp;
		config.backends[0].scheme = BackendScheme::Http;
		assert!(config.validate().is_ok(), "cleartext http over tcp is a valid backend hop");
	}

	// ── http_redirect validation ──

	#[test]
	fn http_redirect_defaults_to_disabled() {
		let config: ReductionConfig = toml::from_str(minimal_toml()).unwrap();
		assert!(!config.http_redirect.enabled);
		assert!(config.validate().is_ok(), "a disabled redirect needs no to_host");
	}

	#[test]
	fn validate_rejects_enabled_redirect_without_to_host() {
		let mut config: ReductionConfig = toml::from_str(minimal_toml()).unwrap();
		config.http_redirect.enabled = true;
		config.http_redirect.listen = "0.0.0.0:80".parse().unwrap();
		let err: String = config.validate().unwrap_err().to_string();
		assert!(err.contains("to_host"), "got: {err}");
	}

	#[test]
	fn validate_rejects_to_host_that_is_a_url() {
		let mut config: ReductionConfig = toml::from_str(minimal_toml()).unwrap();
		config.http_redirect.enabled = true;
		config.http_redirect.listen = "0.0.0.0:80".parse().unwrap();
		config.http_redirect.to_host = "https://conorforde.com/".to_owned();
		let err: String = config.validate().unwrap_err().to_string();
		assert!(err.contains("bare host"), "got: {err}");
	}

	#[test]
	fn validate_rejects_redirect_listen_colliding_with_main_listener() {
		let mut config: ReductionConfig = toml::from_str(minimal_toml()).unwrap();
		config.http_redirect.enabled = true;
		config.http_redirect.to_host = "conorforde.com".to_owned();
		// minimal_toml() listens on 127.0.0.1:8443; collide the redirect with it.
		config.http_redirect.listen = config.listen.address;
		let err: String = config.validate().unwrap_err().to_string();
		assert!(err.contains("collides"), "got: {err}");
	}

	#[test]
	fn validate_accepts_well_formed_redirect() {
		let mut config: ReductionConfig = toml::from_str(minimal_toml()).unwrap();
		config.http_redirect.enabled = true;
		config.http_redirect.listen = "0.0.0.0:80".parse().unwrap();
		config.http_redirect.to_host = "conorforde.com".to_owned();
		assert!(config.validate().is_ok());
	}

	// ── health_endpoint validation ──

	#[test]
	fn health_endpoint_defaults_to_disabled() {
		let config: ReductionConfig = toml::from_str(minimal_toml()).unwrap();
		assert!(!config.health_endpoint.enabled);
		assert!(config.validate().is_ok());
	}

	#[test]
	fn validate_rejects_health_endpoint_colliding_with_main_listener() {
		let mut config: ReductionConfig = toml::from_str(minimal_toml()).unwrap();
		config.health_endpoint.enabled = true;
		config.health_endpoint.listen = config.listen.address;
		let err: String = config.validate().unwrap_err().to_string();
		assert!(err.contains("collides"), "got: {err}");
	}

	#[test]
	fn validate_accepts_health_endpoint_on_its_own_port() {
		let mut config: ReductionConfig = toml::from_str(minimal_toml()).unwrap();
		config.health_endpoint.enabled = true;
		config.health_endpoint.listen = "127.0.0.1:9090".parse().unwrap();
		assert!(config.validate().is_ok());
	}

	// ── RawRelayAuthzEntry ──

	#[test]
	fn raw_relay_authz_absent_defaults_to_empty() {
		let config: ReductionConfig = toml::from_str(&minimal_toml_for_raw_authz("")).unwrap();
		assert!(
			config.raw_relay_authz.is_empty(),
			"no [[raw_relay_authz]] parses as an empty, fail-closed policy set"
		);
	}

	#[test]
	fn raw_relay_authz_entry_parses_cns_and_spkis() {
		let entry: RawRelayAuthzEntry = toml::from_str(
			"backend_id = \"svc\"\nallowed_cns = [\"device-1\", \"device-2\"]\nallowed_spkis = [\"aabb\"]",
		)
		.unwrap();
		assert_eq!(entry.backend_id.as_str(), "svc");
		assert_eq!(entry.allowed_cns.len(), 2);
		assert_eq!(entry.allowed_cns[0].as_str(), "device-1");
		assert_eq!(entry.allowed_spkis, vec!["aabb".to_owned()]);
	}

	#[test]
	fn raw_relay_authz_entry_defaults_lists_to_empty() {
		let entry: RawRelayAuthzEntry = toml::from_str("backend_id = \"svc\"").unwrap();
		assert!(entry.allowed_cns.is_empty());
		assert!(entry.allowed_spkis.is_empty());
	}

	// A full config carrying one raw_relay_authz entry threads through to the parsed struct.
	#[test]
	fn raw_relay_authz_entry_round_trips_through_full_config() {
		let toml_str: String = format!(
			"{}\n[[raw_relay_authz]]\nbackend_id = \"svc\"\nallowed_cns = [\"device-9\"]\n",
			minimal_toml(),
		);
		let config: ReductionConfig = toml::from_str(&toml_str).unwrap();
		assert_eq!(config.raw_relay_authz.len(), 1);
		assert_eq!(config.raw_relay_authz[0].backend_id.as_str(), "svc");
		assert_eq!(config.raw_relay_authz[0].allowed_cns[0].as_str(), "device-9");
	}

	// A minimal valid ReductionConfig with `extra` TOML appended, so a section can be parsed in the
	// context of the whole config rather than in isolation.
	fn minimal_toml_for_raw_authz(extra: &str) -> String {
		return format!("{}\n{extra}", minimal_toml());
	}


	fn minimal_toml() -> &'static str {
		return r#"
[listen]
address = "127.0.0.1:8443"
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
id = "svc"
address = "10.0.0.1:8080"
weight = 1.0
transport = "quic"

[[routes]]
path_prefix = "/"
backend_id = "svc"
"#;
	}
}
