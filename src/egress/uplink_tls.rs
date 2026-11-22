// Watches the cert, key and CA files of each uplink end, so a rotated file applies with no restart.
use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::ServerCertVerifier;

use crate::error::Result;
use crate::metrics::ProxyMetrics;
use crate::tls::{
	CertWatcher, ReloadingCertResolver, ReloadingClientVerifier, ReloadingServerVerifier, Stamp, TrustSide, TrustWatcher,
};

// The watchers of one end run while this value lives. A failed reload keeps the last good file in use.
pub struct TlsWatch {
	_cert: CertWatcher,
	_trust: TrustWatcher,
}

impl TlsWatch {
	pub fn listener(identity: Arc<ReloadingCertResolver>, trust: Arc<ReloadingClientVerifier>, ca_cert_path: &Path) -> Result<Self> {
		return Ok(Self {
			_cert: CertWatcher::new_server_only(identity)?,
			_trust: TrustWatcher::new(trust, &[ca_cert_path], TrustSide::EgressUplinkListener, ProxyMetrics::new())?,
		});
	}

	pub fn uplink(identity: Arc<ReloadingCertResolver>, trust: Arc<ReloadingServerVerifier>, ca_cert_path: &Path) -> Result<Self> {
		return Ok(Self {
			_cert: CertWatcher::new_client_only(identity)?,
			_trust: TrustWatcher::new(trust, &[ca_cert_path], TrustSide::EgressUplink, ProxyMetrics::new())?,
		});
	}
}

// The inner end's identity and trust, which its watchers reload in place.
pub struct UplinkTls {
	identity: Arc<ReloadingCertResolver>,
	trust: Arc<ReloadingServerVerifier>,
	_watch: TlsWatch,
}

impl UplinkTls {
	pub fn watch(identity: Arc<ReloadingCertResolver>, trust: Arc<ReloadingServerVerifier>, ca_cert_path: &Path) -> Result<Self> {
		let watch: TlsWatch = TlsWatch::uplink(Arc::clone(&identity), Arc::clone(&trust), ca_cert_path)?;
		return Ok(Self { identity, trust, _watch: watch });
	}

	#[must_use]
	pub fn stamp(&self) -> InnerStamp {
		return Stamp::new(self.identity.current(), self.trust.current());
	}
}

pub type InnerStamp = Stamp<dyn ServerCertVerifier>;

#[cfg(test)]
mod tests {
	use std::result::Result as StdResult;

	use server_utils::ctx::Ctx;

	use super::*;
	use crate::test_support::{Pki, pki};

	struct Parts {
		pki: Pki,
		identity: Arc<ReloadingCertResolver>,
		trust: Arc<ReloadingServerVerifier>,
	}

	fn parts() -> StdResult<Parts, String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let pki: Pki = pki("egress-inner")?;
		let identity: Arc<ReloadingCertResolver> =
			Arc::new(ReloadingCertResolver::new(pki.client.cert.path(), pki.client.key.path()).ctx("identity")?);
		let trust: Arc<ReloadingServerVerifier> = ReloadingServerVerifier::new(pki.ca_file.path()).ctx("trust")?;
		return Ok(Parts { pki, identity, trust });
	}

	// A reload of either side gives a new stamp. Without one, two stamps compare equal.
	#[test]
	fn a_stamp_changes_only_when_a_side_reloads() -> StdResult<(), String> {
		let parts: Parts = parts()?;
		let tls: UplinkTls = UplinkTls::watch(Arc::clone(&parts.identity), Arc::clone(&parts.trust), parts.pki.ca_file.path()).ctx("watch")?;
		let first: InnerStamp = tls.stamp();
		assert!(first == tls.stamp(), "no reload keeps the stamp");

		parts.identity.reload().ctx("reload identity")?;
		let after_identity: InnerStamp = tls.stamp();
		assert!(after_identity != first, "a reloaded identity is new material for the next handshake");

		parts.trust.reload().ctx("reload trust")?;
		assert!(tls.stamp() != after_identity, "a reloaded CA is new material for the next handshake");
		return Ok(());
	}

	#[test]
	fn a_listener_watch_starts_over_its_files() -> StdResult<(), String> {
		let parts: Parts = parts()?;
		let identity: Arc<ReloadingCertResolver> =
			Arc::new(ReloadingCertResolver::new(parts.pki.server.cert.path(), parts.pki.server.key.path()).ctx("identity")?);
		let trust: Arc<ReloadingClientVerifier> = ReloadingClientVerifier::new(parts.pki.ca_file.path(), None).ctx("trust")?;
		let _watch: TlsWatch = TlsWatch::listener(identity, trust, parts.pki.ca_file.path()).ctx("listener watch")?;
		return Ok(());
	}
}
