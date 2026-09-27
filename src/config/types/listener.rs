use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use super::TransportKind;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
	pub address: SocketAddr,
	pub transport: TransportKind,
	// Inbound client-cert policy for the public listener; defaults to `required` (mandatory mTLS).
	// Never inferred from ACME mode — an ACME server can still be mandatory-mTLS.
	#[serde(default)]
	pub client_auth: ClientAuthPolicy,
}

pub const DEFAULT_HTTP_REDIRECT_LISTEN: &str = "0.0.0.0:80";

// Cleartext port-80 listener that 308-redirects every request to the canonical HTTPS origin; never
// proxies content. Separate cleartext socket from `[listen]`; disabled by default.
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
			listen: DEFAULT_HTTP_REDIRECT_LISTEN
				.parse()
				.unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 80))),
			to_host: String::new(),
		};
	}
}

// Loopback default so the readiness/liveness endpoint is not world-reachable; parsed in the Default impl.
pub const DEFAULT_HEALTH_ENDPOINT_LISTEN: &str = "127.0.0.1:9090";

// Cleartext liveness (`/livez`) / readiness (`/readyz`) endpoint, separate from the public data plane.
// Disabled by default; bind it to a private address, never the public internet.
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

// Inbound mTLS client-cert policy for the public listener. `Required` (secure default) refuses a nameless
// peer; `Optional` requests but admits anonymous peers; `Disabled` requests no cert (public-browser mode).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuthPolicy {
	#[default]
	Required,
	Optional,
	Disabled,
}

impl ClientAuthPolicy {
	// Whether a connection presenting no mTLS identity is admitted past the pre-routing gate.
	#[must_use]
	#[inline]
	pub const fn allows_anonymous(self) -> bool {
		return !matches!(self, Self::Required);
	}

	// Whether the server builds an inbound client-cert verifier (`Disabled` builds none).
	#[must_use]
	#[inline]
	pub const fn builds_verifier(self) -> bool {
		return !matches!(self, Self::Disabled);
	}

	// Whether a presented client cert is mandatory at the TLS handshake (only `Required`).
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
		// No client_auth key must default to mandatory mTLS (secure default), unchanged behavior.
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
