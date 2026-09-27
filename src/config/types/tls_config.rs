use std::path::{Path, PathBuf};

#[cfg(feature = "acme")]
use arrayvec::ArrayString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
	pub server: ServerTlsConfig,
	// Backend-facing mTLS identity for dialing https/quic backends; optional, enforced by validate.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub client: Option<TlsIdentity>,
}

// Externally tagged so the TOML sub-table key is the variant (`[tls.server.manual]` / `[tls.server.acme]`)
// and `deny_unknown_fields` fires per variant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerTlsConfig {
	Manual(TlsIdentity),
	// Boxed: AcmeTlsConfig (~408 bytes) would otherwise bloat every ServerTlsConfig (clippy large_enum_variant).
	#[cfg(feature = "acme")]
	Acme(Box<AcmeTlsConfig>),
}

impl ServerTlsConfig {
	// Inbound client-cert CA (trust anchor for verifying peer certs). `None` under ACME with
	// `client_auth = "disabled"`, where no verifier is built; the manual identity always carries one.
	#[must_use]
	pub fn ca_cert_path(&self) -> Option<&Path> {
		return match self {
			Self::Manual(identity) => Some(&identity.ca_cert_path),
			#[cfg(feature = "acme")]
			Self::Acme(acme) => acme.ca_cert_path.as_deref(),
		};
	}

	#[must_use]
	pub const fn as_manual(&self) -> Option<&TlsIdentity> {
		return match self {
			Self::Manual(identity) => Some(identity),
			#[cfg(feature = "acme")]
			Self::Acme(_) => None,
		};
	}
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsIdentity {
	pub cert_path: PathBuf,
	pub key_path: PathBuf,
	pub ca_cert_path: PathBuf,
	// Optional CA-signed CRL enforced at the mTLS handshake (server side only, hot-watched). See docs/configuration.md.
	#[serde(default)]
	pub crl_path: Option<PathBuf>,
}

#[cfg(feature = "acme")]
pub const DEFAULT_ACME_CACHE_DIR: &str = "./acme_cache";

#[cfg(feature = "acme")]
fn default_acme_cache_dir() -> PathBuf {
	return PathBuf::from(DEFAULT_ACME_CACHE_DIR);
}

// Mirrors tls::secret_state::DEFAULT_ACME_STATE_ENV (that module is the runtime source of truth).
#[cfg(feature = "acme")]
pub const DEFAULT_ACME_STATE_ENV: &str = "REDUCTION_ACME_STATE";

#[cfg(feature = "acme")]
fn default_acme_state_env() -> String {
	return DEFAULT_ACME_STATE_ENV.to_owned();
}

// Barrel custody for the ACME secret state: injected at launch via `env_var`, renewed state persisted by
// running the hash-pinned `persist_command` with the blob on stdin (no file fallback). See docs/configuration.md.
#[cfg(feature = "acme")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BarrelStateConfig {
	#[serde(default = "default_acme_state_env")]
	pub env_var: String,
	// Command to persist renewed state (hash-pinned on the Barrel side; must be non-empty).
	pub persist_command: Vec<String>,
}

#[cfg(feature = "acme")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeTlsConfig {
	pub domains: Vec<ArrayString<256>>,
	pub acme_email: ArrayString<256>,
	// Inbound client-cert CA. Optional: omitted under `client_auth = "disabled"` (no verifier built),
	// required otherwise — enforced by ReductionConfig::validate.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub ca_cert_path: Option<PathBuf>,
	// File-store cache dir, used only when `barrel_state` is absent.
	#[serde(default = "default_acme_cache_dir")]
	pub cache_dir: PathBuf,
	#[serde(default)]
	pub staging: bool,
	// Override the ACME directory URL (private CA, step-ca, pebble); unset chooses Let's Encrypt by `staging`.
	#[serde(default)]
	pub directory_url: Option<String>,
	// Trust root (PEM) for the ACME server's own HTTPS endpoint; unset uses the system roots.
	#[serde(default)]
	pub directory_ca_cert: Option<PathBuf>,
	// Barrel custody for the secret state; when set, replaces the `cache_dir` file store.
	#[serde(default)]
	pub barrel_state: Option<BarrelStateConfig>,
}


#[cfg(test)]
mod tests {
	use super::*;

	fn manual_identity() -> TlsIdentity {
		return TlsIdentity {
			cert_path: PathBuf::from("certs/server.crt"),
			key_path: PathBuf::from("certs/server.key"),
			ca_cert_path: PathBuf::from("certs/ca.crt"),
			crl_path: None,
		};
	}

	#[test]
	fn server_tls_manual_exposes_identity() {
		let config: ServerTlsConfig = ServerTlsConfig::Manual(manual_identity());
		assert_eq!(config.ca_cert_path(), Some(Path::new("certs/ca.crt")));
		let identity: &TlsIdentity = config.as_manual().unwrap();
		assert_eq!(identity.cert_path, PathBuf::from("certs/server.crt"));
		assert_eq!(identity.key_path, PathBuf::from("certs/server.key"));
	}

	#[cfg(feature = "acme")]
	#[test]
	fn server_tls_acme_exposes_ca_cert_but_no_manual_identity() {
		let acme: AcmeTlsConfig = toml::from_str(
			"domains = [\"example.com\"]\nacme_email = \"ops@example.com\"\nca_cert_path = \"certs/ca.crt\"",
		)
		.unwrap();
		assert_eq!(acme.cache_dir, PathBuf::from(DEFAULT_ACME_CACHE_DIR));
		assert!(!acme.staging);
		assert!(acme.directory_url.is_none());
		assert!(acme.directory_ca_cert.is_none());
		assert_eq!(acme.ca_cert_path, Some(PathBuf::from("certs/ca.crt")));
		let config: ServerTlsConfig = ServerTlsConfig::Acme(Box::new(acme));
		assert_eq!(config.ca_cert_path(), Some(Path::new("certs/ca.crt")));
		assert!(config.as_manual().is_none());
	}

	#[cfg(feature = "acme")]
	#[test]
	fn server_tls_acme_without_ca_cert_path_has_no_inbound_ca() {
		let acme: AcmeTlsConfig =
			toml::from_str("domains = [\"example.com\"]\nacme_email = \"ops@example.com\"").unwrap();
		assert!(acme.ca_cert_path.is_none(), "omitted ca_cert_path must parse to None");
		let config: ServerTlsConfig = ServerTlsConfig::Acme(Box::new(acme));
		assert_eq!(config.ca_cert_path(), None);
	}

	#[cfg(feature = "acme")]
	#[test]
	fn acme_barrel_state_absent_defaults_to_none() {
		let acme: AcmeTlsConfig = toml::from_str(
			"domains = [\"example.com\"]\nacme_email = \"ops@example.com\"\nca_cert_path = \"certs/ca.crt\"",
		)
		.unwrap();
		assert!(acme.barrel_state.is_none(), "no [barrel_state] table means file-store custody");
	}

	#[cfg(feature = "acme")]
	#[test]
	fn acme_barrel_state_parses_env_and_persist_command() {
		let acme: AcmeTlsConfig = toml::from_str(
			"domains = [\"example.com\"]\nacme_email = \"ops@example.com\"\nca_cert_path = \"certs/ca.crt\"\n\
			 [barrel_state]\npersist_command = [\"barrel-agent\", \"run\", \"reduction-acme-store\"]\n",
		)
		.unwrap();
		let barrel = acme.barrel_state.expect("barrel_state must parse");
		assert_eq!(barrel.env_var, DEFAULT_ACME_STATE_ENV);
		assert_eq!(barrel.persist_command, vec!["barrel-agent", "run", "reduction-acme-store"]);
	}
}
