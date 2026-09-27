use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use tracing::info;

use super::Reloadable;
use crate::error::{ReductionError, Result};
use crate::tls::certs::load_ca_certs;

// Build a server-cert verifier from disk. An empty/missing/garbage bundle errors (load_ca_certs rejects
// empty), so a reload reading nothing keeps the previous roots — never an empty trust store.
fn load_server_trust(ca_cert_path: &Path) -> Result<Arc<dyn ServerCertVerifier>> {
	let roots: RootCertStore = load_ca_certs(ca_cert_path)?;
	let verifier: Arc<dyn ServerCertVerifier> = WebPkiServerVerifier::builder(Arc::new(roots))
		.build()
		.map_err(|e| ReductionError::Config(format!("failed to build server verifier: {e}")))?;
	return Ok(verifier);
}

// mTLS server-cert verifier whose trust anchors (the CA bundle at `tls.client.ca_cert_path`) are
// hot-swappable without rebuilding the ClientConfig. The `Arc<dyn ServerCertVerifier>` handed to
// rustls stays the same object across reloads; only its inner `WebPkiServerVerifier` is swapped behind
// an `RwLock`, so the shared TlsConnector and connection pool pick up new roots on the next backend
// handshake. This is the client-side twin of `ReloadingClientVerifier`; it is simpler because
// `ServerCertVerifier::root_hint_subjects` is not a required borrow-returning method, so no empty-hint
// workaround is needed. `dyn ServerCertVerifier` is rustls's own API shape — the documented
// dependency-interfacing exception to avoiding trait objects.
pub struct ReloadingServerVerifier {
	inner: RwLock<Arc<dyn ServerCertVerifier>>,
	ca_cert_path: PathBuf,
}

impl ReloadingServerVerifier {
	pub fn new(ca_cert_path: &Path) -> Result<Arc<Self>> {
		let verifier: Arc<dyn ServerCertVerifier> = load_server_trust(ca_cert_path)?;
		return Ok(Arc::new(Self {
			inner: RwLock::new(verifier),
			ca_cert_path: ca_cert_path.to_path_buf(),
		}));
	}

	// On any read/parse failure (incl. an empty bundle) the caller keeps the previous verifier —
	// last-known-good, so a corrupt or empty file never disables nor empties server-cert verification.
	pub fn reload(&self) -> Result<()> {
		let verifier: Arc<dyn ServerCertVerifier> = load_server_trust(&self.ca_cert_path)?;
		let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
		*guard = verifier;
		info!(ca = %self.ca_cert_path.display(), "backend trust anchors reloaded");
		return Ok(());
	}

	fn current(&self) -> Arc<dyn ServerCertVerifier> {
		let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
		return Arc::clone(&guard);
	}
}

impl Reloadable for ReloadingServerVerifier {
	fn reload(&self) -> Result<()> {
		return Self::reload(self);
	}
}

impl fmt::Debug for ReloadingServerVerifier {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		return f
			.debug_struct("ReloadingServerVerifier")
			.field("ca_cert_path", &self.ca_cert_path)
			.finish();
	}
}

impl ServerCertVerifier for ReloadingServerVerifier {
	fn verify_server_cert(
		&self,
		end_entity: &CertificateDer<'_>,
		intermediates: &[CertificateDer<'_>],
		server_name: &ServerName<'_>,
		ocsp_response: &[u8],
		now: UnixTime,
	) -> std::result::Result<ServerCertVerified, TlsError> {
		return self
			.current()
			.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now);
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> std::result::Result<HandshakeSignatureValid, TlsError> {
		return self.current().verify_tls12_signature(message, cert, dss);
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> std::result::Result<HandshakeSignatureValid, TlsError> {
		return self.current().verify_tls13_signature(message, cert, dss);
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		return self.current().supported_verify_schemes();
	}

	fn requires_raw_public_keys(&self) -> bool {
		return self.current().requires_raw_public_keys();
	}
}

#[cfg(test)]
mod tests {
	use super::super::testutil::server_verifier_accepts;
	use super::*;
	use crate::test_support::{generate_ca, generate_localhost_cert, write_pem};

	#[test]
	fn test_server_verifier_new_and_verify() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let leaf = generate_localhost_cert(&ca);
		let ca_file = write_pem(&ca.cert.pem());

		let verifier = ReloadingServerVerifier::new(ca_file.path()).unwrap();
		// Positive-for-the-right-reason: the leaf chains to the trusted CA and its SAN matches the name.
		assert!(
			server_verifier_accepts(&verifier, &leaf),
			"a CA-signed leaf with a matching name must verify"
		);
	}

	#[test]
	fn test_server_verifier_wrong_name_rejected() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let leaf = generate_localhost_cert(&ca);
		let ca_file = write_pem(&ca.cert.pem());

		let verifier = ReloadingServerVerifier::new(ca_file.path()).unwrap();
		// Chain is fine, but the requested name is not in the leaf's SANs — verification must fail, proving
		// the positive test above passes on the name and not merely the chain.
		let wrong: ServerName<'_> = ServerName::try_from("not-localhost.example").unwrap();
		let verified = verifier
			.verify_server_cert(leaf.cert.der(), &[], &wrong, &[], UnixTime::now())
			.is_ok();
		assert!(!verified, "a name mismatch must be rejected");
	}

	#[test]
	fn test_server_ca_reload_accepts_after_rotation() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca_old = generate_ca();
		let ca_new = generate_ca();
		// A server leaf signed by the NEW CA — not trusted while the bundle holds only the old root.
		let new_leaf = generate_localhost_cert(&ca_new);

		let ca_file = write_pem(&ca_old.cert.pem());
		let verifier = ReloadingServerVerifier::new(ca_file.path()).unwrap();
		// Functional diff, before: the new-CA server leaf is rejected (its issuer is not trusted).
		assert!(
			!server_verifier_accepts(&verifier, &new_leaf),
			"new-CA server leaf rejected before rotation"
		);

		// Rotate the backend trust bundle to the new CA and reload in place — no new verifier object.
		std::fs::write(ca_file.path(), ca_new.cert.pem()).unwrap();
		verifier.reload().unwrap();
		// After: the SAME leaf is now accepted. The reload is the only thing that changed acceptance.
		assert!(
			server_verifier_accepts(&verifier, &new_leaf),
			"new-CA server leaf accepted after rotation"
		);
	}

	#[test]
	fn test_server_ca_bundle_cross_sign_window() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca_old = generate_ca();
		let ca_new = generate_ca();
		let old_leaf = generate_localhost_cert(&ca_old);
		let new_leaf = generate_localhost_cert(&ca_new);

		// Bundle = old + new roots (multi-PEM). Servers under both CAs verify simultaneously.
		let ca_file = write_pem(&format!("{}{}", ca_old.cert.pem(), ca_new.cert.pem()));
		let verifier = ReloadingServerVerifier::new(ca_file.path()).unwrap();
		assert!(
			server_verifier_accepts(&verifier, &old_leaf),
			"old-CA server accepted during the window"
		);
		assert!(
			server_verifier_accepts(&verifier, &new_leaf),
			"new-CA server accepted during the window"
		);

		// Close the window: drop the old root from the bundle, reload.
		std::fs::write(ca_file.path(), ca_new.cert.pem()).unwrap();
		verifier.reload().unwrap();
		assert!(
			!server_verifier_accepts(&verifier, &old_leaf),
			"old-CA server rejected after the old root is removed"
		);
		assert!(
			server_verifier_accepts(&verifier, &new_leaf),
			"new-CA server still accepted"
		);
	}

	#[test]
	fn test_server_ca_reload_garbage_keeps_previous() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let leaf = generate_localhost_cert(&ca);
		let ca_file = write_pem(&ca.cert.pem());
		let verifier = ReloadingServerVerifier::new(ca_file.path()).unwrap();
		assert!(
			server_verifier_accepts(&verifier, &leaf),
			"server leaf accepted before the bad write"
		);

		// Garbage bundle → reload errors → previous roots stay in force (last-known-good).
		std::fs::write(ca_file.path(), "not a certificate").unwrap();
		assert!(
			verifier.reload().is_err(),
			"a garbage backend CA bundle must surface an error"
		);
		assert!(
			server_verifier_accepts(&verifier, &leaf),
			"garbage write must not empty the backend trust store"
		);

		// A valid rewrite afterwards recovers.
		std::fs::write(ca_file.path(), ca.cert.pem()).unwrap();
		verifier.reload().unwrap();
		assert!(
			server_verifier_accepts(&verifier, &leaf),
			"server verifier must recover after a valid rewrite"
		);
	}

	#[test]
	fn test_server_ca_reload_empty_keeps_previous() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let leaf = generate_localhost_cert(&ca);
		let ca_file = write_pem(&ca.cert.pem());
		let verifier = ReloadingServerVerifier::new(ca_file.path()).unwrap();
		assert!(
			server_verifier_accepts(&verifier, &leaf),
			"server leaf accepted before the empty write"
		);

		// An EMPTY bundle would make every backend unreachable — it must be refused and previous roots kept.
		std::fs::write(ca_file.path(), "").unwrap();
		assert!(
			verifier.reload().is_err(),
			"an empty backend CA bundle must surface an error"
		);
		assert!(
			server_verifier_accepts(&verifier, &leaf),
			"empty write must not empty the backend trust store"
		);
	}

	#[test]
	fn test_server_verifier_startup_empty_ca_errors() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		// At startup an empty/garbage bundle fails fast rather than trusting no backend at all.
		let empty_ca = write_pem("");
		assert!(
			ReloadingServerVerifier::new(empty_ca.path()).is_err(),
			"empty CA at boot must fail fast"
		);
	}

}
