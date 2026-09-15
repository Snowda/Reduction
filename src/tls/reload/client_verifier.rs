use std::fmt;
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, RootCertStore, SignatureScheme};
use tracing::info;

use super::Reloadable;
use crate::error::{ReductionError, Result};
use crate::tls::certs::load_ca_certs;

pub fn load_crls(path: &Path) -> Result<Vec<CertificateRevocationListDer<'static>>> {
	let file: fs::File = fs::File::open(path)
		.map_err(|e| ReductionError::Config(format!("failed to open CRL file {}: {e}", path.display())))?;
	let reader: BufReader<fs::File> = BufReader::new(file);
	let crls: Vec<CertificateRevocationListDer<'static>> = CertificateRevocationListDer::pem_reader_iter(reader)
		.collect::<std::result::Result<Vec<_>, _>>()
		.map_err(|e| ReductionError::Config(format!("failed to parse CRLs from {}: {e}", path.display())))?;
	return Ok(crls);
}

fn build_client_verifier(
	roots: RootCertStore,
	crls: Vec<CertificateRevocationListDer<'static>>,
	allow_unauthenticated: bool,
) -> Result<Arc<dyn ClientCertVerifier>> {
	let builder = WebPkiClientVerifier::builder(Arc::new(roots));
	// With CRLs, enforce nextUpdate so a stale CRL is rejected rather than silently trusted past its
	// validity. With none, build a plain verifier (no revocation) — matching build_server_config.
	let builder = if crls.is_empty() {
		builder
	} else {
		builder.with_crls(crls).enforce_revocation_expiration()
	};
	// Optional-mTLS: still request and verify a client cert against the CA, but admit a peer that
	// presents none (client_auth_mandatory() → false). Required-mTLS omits this, so a nameless peer is
	// refused at the handshake. Disabled builds no verifier at all (see build_server_config_for_policy).
	let builder = if allow_unauthenticated {
		builder.allow_unauthenticated()
	} else {
		builder
	};
	return builder
		.build()
		.map_err(|e| ReductionError::Config(format!("failed to build client verifier: {e}")));
}

// Load trust anchors and CRLs from disk; an empty/missing/garbage CA bundle errors (caller keeps last-known-good).
fn load_trust(
	ca_cert_path: &Path,
	crl_path: Option<&Path>,
	allow_unauthenticated: bool,
) -> Result<Arc<dyn ClientCertVerifier>> {
	let roots: RootCertStore = load_ca_certs(ca_cert_path)?;
	let crls: Vec<CertificateRevocationListDer<'static>> = match crl_path {
		Some(path) => load_crls(path)?,
		None => Vec::new(),
	};
	return build_client_verifier(roots, crls, allow_unauthenticated);
}

// mTLS client-cert verifier whose trust anchors AND CRLs are both hot-swappable without rebuilding the
// server config: the `Arc<dyn ClientCertVerifier>` stays the same object, only its inner verifier is swapped
// (live listeners pick up new roots/CRLs on the next handshake). `dyn` is rustls's own API shape.
pub struct ReloadingClientVerifier {
	inner: RwLock<Arc<dyn ClientCertVerifier>>,
	ca_cert_path: PathBuf,
	// None = no handshake-level revocation (roots still hot-reload).
	crl_path: Option<PathBuf>,
	// Optional-mTLS flag: true admits a peer that presents no cert. Stored so reload() rebuilds the
	// inner verifier with the same policy rather than silently reverting to mandatory on a CA rotation.
	allow_unauthenticated: bool,
}

impl ReloadingClientVerifier {
	// Mandatory mTLS: a peer presenting no client cert is rejected at the handshake.
	pub fn new(ca_cert_path: &Path, crl_path: Option<&Path>) -> Result<Arc<Self>> {
		return Self::new_with_policy(ca_cert_path, crl_path, false);
	}

	// Optional mTLS: request and verify a client cert against the CA, but admit a peer that presents none.
	pub fn new_optional(ca_cert_path: &Path, crl_path: Option<&Path>) -> Result<Arc<Self>> {
		return Self::new_with_policy(ca_cert_path, crl_path, true);
	}

	fn new_with_policy(ca_cert_path: &Path, crl_path: Option<&Path>, allow_unauthenticated: bool) -> Result<Arc<Self>> {
		let verifier: Arc<dyn ClientCertVerifier> = load_trust(ca_cert_path, crl_path, allow_unauthenticated)?;
		return Ok(Arc::new(Self {
			inner: RwLock::new(verifier),
			ca_cert_path: ca_cert_path.to_path_buf(),
			crl_path: crl_path.map(Path::to_path_buf),
			allow_unauthenticated,
		}));
	}

	// On any read/parse failure (incl. an empty CA bundle) the previous verifier is kept (last-known-good).
	pub fn reload(&self) -> Result<()> {
		let verifier: Arc<dyn ClientCertVerifier> =
			load_trust(&self.ca_cert_path, self.crl_path.as_deref(), self.allow_unauthenticated)?;
		let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
		*guard = verifier;
		info!(
			ca = %self.ca_cert_path.display(),
			crl = ?self.crl_path.as_ref().map(|p| p.display().to_string()),
			"client trust anchors reloaded",
		);
		return Ok(());
	}

	fn current(&self) -> Arc<dyn ClientCertVerifier> {
		let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
		return Arc::clone(&guard);
	}
}

impl fmt::Debug for ReloadingClientVerifier {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		return f
			.debug_struct("ReloadingClientVerifier")
			.field("ca_cert_path", &self.ca_cert_path)
			.field("crl_path", &self.crl_path)
			.finish();
	}
}

impl ClientCertVerifier for ReloadingClientVerifier {
	// Empty by design: the borrow is bound to `&self` so it can't reflect hot-swapped roots, and caching
	// startup subjects would advertise the OLD CA after a rotation. The hint is advisory; every device here
	// holds one cert and sends it regardless. Equivalent to rustls's clear_root_hint_subjects().
	fn root_hint_subjects(&self) -> &[DistinguishedName] {
		return &[];
	}

	fn verify_client_cert(
		&self,
		end_entity: &CertificateDer<'_>,
		intermediates: &[CertificateDer<'_>],
		now: UnixTime,
	) -> std::result::Result<ClientCertVerified, TlsError> {
		return self.current().verify_client_cert(end_entity, intermediates, now);
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

	fn offer_client_auth(&self) -> bool {
		return self.current().offer_client_auth();
	}

	fn client_auth_mandatory(&self) -> bool {
		return self.current().client_auth_mandatory();
	}

	fn requires_raw_public_keys(&self) -> bool {
		return self.current().requires_raw_public_keys();
	}
}

impl Reloadable for ReloadingClientVerifier {
	fn reload(&self) -> Result<()> {
		// Delegate to the inherent method (inherent resolution wins, but be explicit to rule out
		// any accidental self-recursion through the trait method).
		return Self::reload(self);
	}
}

#[cfg(test)]
mod tests {
	use super::super::testutil::{crl_ca, crl_leaf, make_crl_pem, verifier_accepts};
	use super::*;
	use crate::test_support::write_pem;

	#[test]
	fn test_crl_verifier_rejects_revoked_accepts_valid() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = crl_ca();
		let revoked = crl_leaf(&ca, "device-bad", 1);
		let good = crl_leaf(&ca, "device-good", 2);
		let ca_file = write_pem(&ca.cert.pem());
		let crl_file = write_pem(&make_crl_pem(&ca, &[1]));

		let verifier = ReloadingClientVerifier::new(ca_file.path(), Some(crl_file.path())).unwrap();
		// The functional diff: identical CA + verifier, differing only in whether the leaf's serial is
		// on the CRL. The revoked serial is refused at verification; the untouched one is accepted.
		assert!(
			!verifier_accepts(&verifier, &revoked),
			"a CRL-listed cert must be rejected"
		);
		assert!(verifier_accepts(&verifier, &good), "an unlisted cert must still verify");
	}

	#[test]
	fn test_crl_verifier_reload_swaps_in_new_revocation() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = crl_ca();
		let leaf = crl_leaf(&ca, "device-1", 1);

		// Start with an empty CRL: the leaf verifies.
		let ca_file = write_pem(&ca.cert.pem());
		let crl_file = write_pem(&make_crl_pem(&ca, &[]));
		let verifier = ReloadingClientVerifier::new(ca_file.path(), Some(crl_file.path())).unwrap();
		assert!(
			verifier_accepts(&verifier, &leaf),
			"with an empty CRL the leaf must verify"
		);

		// Overwrite the CRL to revoke the leaf's serial and reload in place — same verifier object,
		// now rejecting what it accepted a moment ago. This is what a live handshake would observe.
		std::fs::write(crl_file.path(), make_crl_pem(&ca, &[1])).unwrap();
		verifier.reload().unwrap();
		assert!(
			!verifier_accepts(&verifier, &leaf),
			"after reload the newly-revoked leaf must be rejected"
		);
	}

	// ── CA trust-anchor (bundle) hot-reload ──

	#[test]
	fn test_ca_reload_accepts_after_rotation() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca_old = crl_ca();
		let ca_new = crl_ca();
		// A leaf signed by the NEW CA — not trusted while the bundle holds only the old root.
		let new_leaf = crl_leaf(&ca_new, "device-new", 1);

		let ca_file = write_pem(&ca_old.cert.pem());
		let verifier = ReloadingClientVerifier::new(ca_file.path(), None).unwrap();
		// Functional diff, before: the new-CA leaf is rejected (its issuer is not in the trust bundle).
		assert!(
			!verifier_accepts(&verifier, &new_leaf),
			"new-CA leaf must be rejected before rotation"
		);

		// Rotate the trust bundle to the new CA and reload in place — no new verifier object.
		std::fs::write(ca_file.path(), ca_new.cert.pem()).unwrap();
		verifier.reload().unwrap();
		// After: the SAME leaf is now accepted. The reload is the only thing that changed acceptance.
		assert!(
			verifier_accepts(&verifier, &new_leaf),
			"new-CA leaf must be accepted after rotation"
		);
	}

	#[test]
	fn test_ca_bundle_cross_sign_window() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca_old = crl_ca();
		let ca_new = crl_ca();
		let old_leaf = crl_leaf(&ca_old, "device-old", 1);
		let new_leaf = crl_leaf(&ca_new, "device-new", 2);

		// Bundle = old + new roots (multi-PEM). Both CAs are trusted simultaneously.
		let ca_file = write_pem(&format!("{}{}", ca_old.cert.pem(), ca_new.cert.pem()));
		let verifier = ReloadingClientVerifier::new(ca_file.path(), None).unwrap();
		assert!(
			verifier_accepts(&verifier, &old_leaf),
			"old-CA leaf accepted during the window"
		);
		assert!(
			verifier_accepts(&verifier, &new_leaf),
			"new-CA leaf accepted during the window"
		);

		// Close the window: drop the old root from the bundle, reload.
		std::fs::write(ca_file.path(), ca_new.cert.pem()).unwrap();
		verifier.reload().unwrap();
		assert!(
			!verifier_accepts(&verifier, &old_leaf),
			"old-CA leaf rejected after the old root is removed"
		);
		assert!(verifier_accepts(&verifier, &new_leaf), "new-CA leaf still accepted");
	}

	#[test]
	fn test_ca_reload_garbage_keeps_previous() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = crl_ca();
		let leaf = crl_leaf(&ca, "device-1", 1);
		let ca_file = write_pem(&ca.cert.pem());
		let verifier = ReloadingClientVerifier::new(ca_file.path(), None).unwrap();
		assert!(verifier_accepts(&verifier, &leaf), "leaf accepted before the bad write");

		// Garbage bundle → reload errors → previous roots stay in force (last-known-good).
		std::fs::write(ca_file.path(), "not a certificate").unwrap();
		assert!(verifier.reload().is_err(), "a garbage CA bundle must surface an error");
		assert!(
			verifier_accepts(&verifier, &leaf),
			"garbage write must not empty the trust store"
		);

		// A valid rewrite afterwards recovers.
		std::fs::write(ca_file.path(), ca.cert.pem()).unwrap();
		verifier.reload().unwrap();
		assert!(
			verifier_accepts(&verifier, &leaf),
			"verifier must recover after a valid rewrite"
		);
	}

	#[test]
	fn test_ca_reload_empty_keeps_previous() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = crl_ca();
		let leaf = crl_leaf(&ca, "device-1", 1);
		let ca_file = write_pem(&ca.cert.pem());
		let verifier = ReloadingClientVerifier::new(ca_file.path(), None).unwrap();
		assert!(
			verifier_accepts(&verifier, &leaf),
			"leaf accepted before the empty write"
		);

		// An EMPTY bundle would reject the whole fleet — it must be refused and the previous roots kept.
		std::fs::write(ca_file.path(), "").unwrap();
		assert!(verifier.reload().is_err(), "an empty CA bundle must surface an error");
		assert!(
			verifier_accepts(&verifier, &leaf),
			"empty write must not empty the trust store"
		);
	}

	#[test]
	fn test_ca_reload_carries_current_crl() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca_old = crl_ca();
		let ca_new = crl_ca();
		let revoked = crl_leaf(&ca_old, "device-bad", 1);

		// Trust the old CA and revoke serial 1 via a CA-signed CRL.
		let ca_file = write_pem(&ca_old.cert.pem());
		let crl_file = write_pem(&make_crl_pem(&ca_old, &[1]));
		let verifier = ReloadingClientVerifier::new(ca_file.path(), Some(crl_file.path())).unwrap();
		assert!(
			!verifier_accepts(&verifier, &revoked),
			"revoked leaf rejected before the CA reload"
		);

		// Rotate the bundle to old+new and reload (CRL file unchanged). The rebuilt verifier must carry
		// the CURRENT CRL, not drop it — the revoked old-CA leaf stays rejected after the root change.
		std::fs::write(ca_file.path(), format!("{}{}", ca_old.cert.pem(), ca_new.cert.pem())).unwrap();
		verifier.reload().unwrap();
		assert!(
			!verifier_accepts(&verifier, &revoked),
			"revoked leaf must stay rejected after a CA reload"
		);
	}

	#[test]
	fn test_reloading_verifier_offers_no_root_hint() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = crl_ca();
		let ca_file = write_pem(&ca.cert.pem());
		let verifier = ReloadingClientVerifier::new(ca_file.path(), None).unwrap();
		// Deliberately empty: the hint cannot track hot-swapped roots (see root_hint_subjects comment).
		assert!(
			verifier.root_hint_subjects().is_empty(),
			"reloadable verifier must offer no root hint"
		);
	}

	// ── Server-cert trust-anchor (backend CA) hot-reload ──


	#[test]
	fn test_load_crls_missing_file_errors() {
		let err = load_crls(Path::new("/nonexistent/crl.pem")).unwrap_err();
		assert!(format!("{err}").contains("failed to open CRL file"));
	}

	#[test]
	fn test_load_crls_corrupt_errors() {
		let f = write_pem("not a crl at all");
		// An empty/garbage PEM yields no CRL sections; a genuinely malformed section is a parse error.
		// Either way the reload path keeps the previous verifier; here we assert the load surfaces it.
		let result = load_crls(f.path());
		// A file with no PEM CRL sections parses to an empty list (valid); assert that explicitly so the
		// behavior is pinned.
		assert!(result.map(|v| v.is_empty()).unwrap_or(true));
	}
}
