use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use super::TransportKind;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
	pub address: SocketAddr,
	pub transport: TransportKind,
	// Inbound client-certificate policy for the public listener. Defaults to `required` (mandatory
	// mTLS, the historical behavior). `disabled` accepts anonymous browsers and requests no client
	// cert; `optional` requests one but does not require it. Never inferred from ACME mode — an ACME
	// server can still be mandatory-mTLS, and a manual-cert server can still be public.
	#[serde(default)]
	pub client_auth: ClientAuthPolicy,
}

// ── HTTP→HTTPS redirect defaults ──

// Default cleartext bind for the port-80 redirect listener. Parsed in the Default impl (SocketAddr is
// not const-constructible from a string literal).
pub const DEFAULT_HTTP_REDIRECT_LISTEN: &str = "0.0.0.0:80";

// Minimal cleartext HTTP listener that answers every request with a permanent redirect (308) to the
// canonical HTTPS origin. It NEVER proxies content — it exists only so a browser typing `http://` lands
// on `https://`. Disabled by default; `to_host` is the canonical HTTPS hostname to redirect to (path and
// query are preserved). Kept separate from `[listen]` because it is a distinct cleartext socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HttpRedirectConfig {
	pub enabled: bool,
	pub listen: SocketAddr,
	// Canonical HTTPS hostname (bare host, optionally with :port) to redirect to. Required when enabled.
	pub to_host: String,
}

impl Default for HttpRedirectConfig {
	fn default() -> Self {
		return Self {
			enabled: false,
			// Infallible: the literal is a valid SocketAddr; fall back to an unspecified :80 if ever not.
			listen: DEFAULT_HTTP_REDIRECT_LISTEN
				.parse()
				.unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 80))),
			to_host: String::new(),
		};
	}
}

// ── health endpoint defaults ──

// Default bind for the non-public readiness/liveness endpoint. Loopback so it is not world-reachable
// by default; an orchestrator on the same host (or a sidecar) probes it. Parsed in the Default impl.
pub const DEFAULT_HEALTH_ENDPOINT_LISTEN: &str = "127.0.0.1:9090";

// A small cleartext HTTP endpoint, separate from the public data plane, exposing liveness (`/livez`) and
// readiness (`/readyz`) for an orchestrator/load balancer. Disabled by default; bind it to a private
// address (loopback or a management interface), never the public internet — it serves no proxy traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HealthEndpointConfig {
	pub enabled: bool,
	pub listen: SocketAddr,
}

impl Default for HealthEndpointConfig {
	fn default() -> Self {
		return Self {
			enabled: false,
			listen: DEFAULT_HEALTH_ENDPOINT_LISTEN
				.parse()
				.unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 9090))),
		};
	}
}

// Inbound mTLS client-certificate policy for the public listener. `Required` is the secure default
// (a browser with no client cert is rejected at the TLS handshake AND at the application admission
// gate); `Optional` requests a cert but admits anonymous peers; `Disabled` requests no cert at all
// (public-browser mode) so an anonymous browser can connect. Only `Required` refuses a nameless peer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuthPolicy {
	#[default]
	Required,
	Optional,
	Disabled,
}

impl ClientAuthPolicy {
	// Whether a connection presenting no mTLS identity is admitted past the pre-routing gate. True for
	// every policy except `Required`, which is the only one that refuses a nameless peer.
	#[must_use]
	#[inline]
	pub const fn allows_anonymous(self) -> bool {
		return !matches!(self, Self::Required);
	}

	// Whether the server should still build an inbound client-cert verifier. `Disabled` builds none
	// (no CertificateRequest is sent); `Required`/`Optional` both verify a presented cert against the CA.
	#[must_use]
	#[inline]
	pub const fn builds_verifier(self) -> bool {
		return !matches!(self, Self::Disabled);
	}

	// Whether a presented client cert is mandatory at the TLS handshake. Only `Required`; `Optional`
	// requests but tolerates absence (allow_unauthenticated), `Disabled` never requests one.
	#[must_use]
	#[inline]
	pub const fn is_mandatory(self) -> bool {
		return matches!(self, Self::Required);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn client_auth_policy_defaults_to_required() {
		// A [listen] block with no client_auth key must default to mandatory mTLS (the secure default),
		// so an existing config is byte-for-byte unchanged in behavior.
		let listen: ListenConfig = toml::from_str("address = \"127.0.0.1:8443\"\ntransport = \"tcp\"").unwrap();
		assert_eq!(listen.client_auth, ClientAuthPolicy::Required);
		assert_eq!(ClientAuthPolicy::default(), ClientAuthPolicy::Required);
	}

	#[test]
	fn client_auth_policy_parses_each_variant() {
		let disabled: ListenConfig =
			toml::from_str("address = \"127.0.0.1:8443\"\ntransport = \"tcp\"\nclient_auth = \"disabled\"").unwrap();
		assert_eq!(disabled.client_auth, ClientAuthPolicy::Disabled);
		let optional: ListenConfig =
			toml::from_str("address = \"127.0.0.1:8443\"\ntransport = \"tcp\"\nclient_auth = \"optional\"").unwrap();
		assert_eq!(optional.client_auth, ClientAuthPolicy::Optional);
		let required: ListenConfig =
			toml::from_str("address = \"127.0.0.1:8443\"\ntransport = \"tcp\"\nclient_auth = \"required\"").unwrap();
		assert_eq!(required.client_auth, ClientAuthPolicy::Required);
	}

	#[test]
	fn client_auth_policy_rejects_unknown_value() {
		let result: std::result::Result<ListenConfig, _> =
			toml::from_str("address = \"127.0.0.1:8443\"\ntransport = \"tcp\"\nclient_auth = \"maybe\"");
		assert!(result.is_err(), "an unknown client_auth value must be rejected, not silently defaulted");
	}

	#[test]
	fn client_auth_policy_predicates() {
		// Only Required refuses a nameless peer; only Disabled builds no verifier; only Required is mandatory.
		assert!(!ClientAuthPolicy::Required.allows_anonymous());
		assert!(ClientAuthPolicy::Optional.allows_anonymous());
		assert!(ClientAuthPolicy::Disabled.allows_anonymous());

		assert!(ClientAuthPolicy::Required.builds_verifier());
		assert!(ClientAuthPolicy::Optional.builds_verifier());
		assert!(!ClientAuthPolicy::Disabled.builds_verifier());

		assert!(ClientAuthPolicy::Required.is_mandatory());
		assert!(!ClientAuthPolicy::Optional.is_mandatory());
		assert!(!ClientAuthPolicy::Disabled.is_mandatory());
	}
}
