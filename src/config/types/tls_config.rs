use std::path::{Path, PathBuf};

#[cfg(feature = "acme")]
use arrayvec::ArrayString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
	pub server: ServerTlsConfig,
	pub client: TlsIdentity,
}

// Externally tagged (variant name is the TOML sub-table key, `[tls.server.manual]` / `[tls.server.acme]`),
// so `deny_unknown_fields` still fires per variant and a field typo names the field, not "did not match any variant".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerTlsConfig {
	Manual(TlsIdentity),
	// Boxed: AcmeTlsConfig (~408 bytes) would otherwise bloat every ServerTlsConfig (clippy large_enum_variant).
	#[cfg(feature = "acme")]
	Acme(Box<AcmeTlsConfig>),
}

impl ServerTlsConfig {
	#[must_use]
	pub fn ca_cert_path(&self) -> &Path {
		return match self {
			Self::Manual(identity) => &identity.ca_cert_path,
			#[cfg(feature = "acme")]
			Self::Acme(acme) => &acme.ca_cert_path,
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
	// Optional CA-signed CRL enforced at the mTLS handshake (server side only; ignored on the client
	// identity). Hot-watched — see docs/configuration.md. None = no handshake-level revocation.
	#[serde(default)]
	pub crl_path: Option<PathBuf>,
}

// ── ACME defaults ──

#[cfg(feature = "acme")]
pub const DEFAULT_ACME_CACHE_DIR: &str = "./acme_cache";

#[cfg(feature = "acme")]
fn default_acme_cache_dir() -> PathBuf {
	return PathBuf::from(DEFAULT_ACME_CACHE_DIR);
}

// Default environment variable the Barrel agent injects the opaque ACME state into at launch. Mirrors
// tls::secret_state::DEFAULT_ACME_STATE_ENV (kept in sync; that module is the runtime source of truth).
#[cfg(feature = "acme")]
pub const DEFAULT_ACME_STATE_ENV: &str = "REDUCTION_ACME_STATE";

#[cfg(feature = "acme")]
fn default_acme_state_env() -> String {
	return DEFAULT_ACME_STATE_ENV.to_owned();
}

// Barrel custody for the ACME secret state: the state is injected at launch via `env_var`, and renewed
// state is persisted by running the hash-pinned `persist_command` with the blob on its stdin. Presence
// of this table switches the ACME state store from the plaintext `cache_dir` file to Barrel custody
// (no plaintext ever touches a persistent filesystem, no file fallback). See docs/configuration.md.
#[cfg(feature = "acme")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BarrelStateConfig {
	#[serde(default = "default_acme_state_env")]
	pub env_var: String,
	// The exact command to run to persist renewed state (e.g. a `barrel-agent run <store-id>`
	// invocation). Hash-pinned on the Barrel side; must be non-empty.
	pub persist_command: Vec<String>,
}

#[cfg(feature = "acme")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeTlsConfig {
	pub domains: Vec<ArrayString<256>>,
	pub acme_email: ArrayString<256>,
	pub ca_cert_path: PathBuf,
	// File-store cache dir. Used only when `barrel_state` is absent; under Barrel custody the state
	// never touches this path.
	#[serde(default = "default_acme_cache_dir")]
	pub cache_dir: PathBuf,
	#[serde(default)]
	pub staging: bool,
	// Override the ACME directory URL (private ACME CA, step-ca, or a pebble test server). When
	// unset, the Let's Encrypt staging/production URL is chosen by `staging`.
	#[serde(default)]
	pub directory_url: Option<String>,
	// Trust root (PEM) for the ACME server's own HTTPS endpoint. Required when the directory is
	// served with a non-public CA (e.g. pebble's minica). When unset, the system roots are used.
	#[serde(default)]
	pub directory_ca_cert: Option<PathBuf>,
	// Barrel custody for the secret state. When set, the state store is Barrel (env-in, pinned-command-
	// out) instead of the `cache_dir` file. Validated to carry a non-empty persist_command.
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

	// ── ServerTlsConfig accessors ──

	#[test]
	fn server_tls_manual_exposes_identity() {
		let config: ServerTlsConfig = ServerTlsConfig::Manual(manual_identity());
		assert_eq!(config.ca_cert_path(), Path::new("certs/ca.crt"));
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
		let config: ServerTlsConfig = ServerTlsConfig::Acme(Box::new(acme));
		assert_eq!(config.ca_cert_path(), Path::new("certs/ca.crt"));
		assert!(config.as_manual().is_none());
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
		// env_var defaults when omitted.
		assert_eq!(barrel.env_var, DEFAULT_ACME_STATE_ENV);
		assert_eq!(barrel.persist_command, vec!["barrel-agent", "run", "reduction-acme-store"]);
	}

	// ── BackendConfig builders ──

}
