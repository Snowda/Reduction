#[cfg(feature = "acme")]
pub mod acme;
pub mod certs;
pub mod identity;
pub mod reload;
// ACME secret-state custody (opaque blob load/persist via a file or Barrel store). ACME-only.
#[cfg(feature = "acme")]
pub mod secret_state;

#[cfg(feature = "acme")]
pub use acme::{AcmeCertResolver, AcmeRenewalTask};
#[cfg(feature = "acme")]
pub use secret_state::{AcmeSecretState, DEFAULT_ACME_STATE_ENV, SecretStore};
#[cfg(feature = "acme")]
pub use certs::{build_acme_challenge_config, build_acme_server_config, build_acme_server_config_for_policy};
pub use certs::{
	build_client_config, build_client_config_with_resolver, build_server_config, build_server_config_for_policy,
	build_server_config_reloadable,
};
pub use identity::{PeerIdentity, SPKI_HEX_LEN};
#[cfg(feature = "proxy")]
pub use reload::{CertWatcher, TRUST_SIDE_CLIENT, TRUST_SIDE_SERVER, TrustWatcher};
pub use reload::{Reloadable, ReloadingCertResolver, ReloadingClientVerifier, ReloadingServerVerifier};
