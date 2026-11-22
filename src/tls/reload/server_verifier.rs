use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use solo::lease::Leased;
use tracing::info;

use super::Reloadable;
use crate::error::{ReductionError, Result};
use crate::lease::LEASES;
use crate::tls::load::load_ca_certs;

// Build a server-cert verifier from disk. An empty, absent or garbage bundle errors (load_ca_certs rejects
// empty). Thus a reload that reads nothing keeps the previous roots, and the trust store is never empty.
fn load_server_trust(ca_cert_path: &Path) -> Result<Arc<dyn ServerCertVerifier>> {
	let roots: RootCertStore = load_ca_certs(ca_cert_path)?;
	let verifier: Arc<dyn ServerCertVerifier> = WebPkiServerVerifier::builder(Arc::new(roots))
		.build()
		.map_err(|e| ReductionError::Config(format!("failed to build server verifier: {e}")))?;
	return Ok(verifier);
}

// mTLS server-cert verifier whose trust anchors (the CA bundle at `tls.client.ca_cert_path`) hot-swap
// with no rebuild of the ClientConfig. The `Arc<dyn ServerCertVerifier>` that rustls holds stays the
// same object across reloads. Only its inner `WebPkiServerVerifier` changes, through a `Leased`. The
// shared TlsConnector and connection pool then use new roots on the next backend handshake.
//
// This is the client-side twin of `ReloadingClientVerifier`. It needs no empty-hint workaround, because
// `ServerCertVerifier::root_hint_subjects` is not a required method that returns a borrow.
// `dyn ServerCertVerifier` is rustls's own API shape: the documented dependency exception to the rule
// against trait objects.
pub struct ReloadingServerVerifier {
	// Double Arc: Leased needs a Sized pointee, and this stores the builder's Arc<dyn> as-is with no new Box.
	inner: Leased<Arc<Arc<dyn ServerCertVerifier>>>,
	ca_cert_path: PathBuf,
}

impl ReloadingServerVerifier {
	pub fn new(ca_cert_path: &Path) -> Result<Arc<Self>> {
		let verifier: Arc<dyn ServerCertVerifier> = load_server_trust(ca_cert_path)?;
		return Ok(Arc::new(Self {
			inner: Leased::from_pointee(verifier, LEASES),
			ca_cert_path: ca_cert_path.to_path_buf(),
		}));
	}

	// On any read/parse failure (incl. an empty bundle) the caller keeps the previous verifier —
	// last-known-good, so a corrupt or empty file never disables nor empties server-cert verification.
	pub fn reload(&self) -> Result<()> {
		let verifier: Arc<dyn ServerCertVerifier> = load_server_trust(&self.ca_cert_path)?;
		self.inner.store(Arc::new(verifier));
		info!(ca = %self.ca_cert_path.display(), "backend trust anchors reloaded");
		return Ok(());
	}

	// Clones the inner Arc out, so the lease drops here and never spans a verification. Each reload gives a new Arc.
	#[must_use]
	pub fn current(&self) -> Arc<dyn ServerCertVerifier> {
		return Arc::clone(&self.inner.lease());
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
	use std::fs;
	use std::result::Result;

	use rustls::ClientConfig;
	use rustls::version::TLS12;
	use tempfile::NamedTempFile;

	use super::super::testutil::server_verifier_accepts;
	use super::*;
	use crate::test_support::handshake::{Observed, handshake, no_resumption, serving, trust_epoch};
	use crate::test_support::{generate_ca, generate_localhost_cert, write_pem};

	type Ca = rcgen::CertifiedKey<rcgen::KeyPair>;

	// A fresh CA and a localhost server leaf it signs.
	fn ca_and_server_leaf() -> Result<(Ca, Ca), String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca: Ca = generate_ca()?;
		return match generate_localhost_cert(&ca) {
			Ok(leaf) => Ok((ca, leaf)),
			Err(err) => Err(format!("generate_localhost_cert: {err}")),
		};
	}

	// The on-disk backend trust bundle that a ReloadingServerVerifier reads. Rewrite it to drive reloads.
	struct BackendTrust {
		verifier: Arc<ReloadingServerVerifier>,
		ca_file: NamedTempFile,
	}

	fn verifier_over(ca_pem: &str) -> Result<BackendTrust, String> {
		let ca_file: NamedTempFile = write_pem(ca_pem)?;
		return match ReloadingServerVerifier::new(ca_file.path()) {
			Ok(verifier) => Ok(BackendTrust { verifier, ca_file }),
			Err(err) => Err(format!("ReloadingServerVerifier::new: {err:?}")),
		};
	}

	// Overwrite the bundle with `contents`, then reload the verifier in place (same object).
	fn rewrite_and_reload(trust: &BackendTrust, contents: &str) -> Result<(), String> {
		fs::write(trust.ca_file.path(), contents).map_err(|err| format!("rewrite CA bundle: {err:?}"))?;
		return match trust.verifier.reload() {
			Ok(()) => Ok(()),
			Err(err) => Err(format!("verifier.reload(): {err:?}")),
		};
	}

	// Assert if the verifier accepts `leaf` (for name "localhost"). Err only if the check cannot run.
	fn expect_accepts(trust: &BackendTrust, leaf: &Ca, expected: bool, why: &str) -> Result<(), String> {
		return match server_verifier_accepts(&trust.verifier, leaf) {
			Ok(accepted) => {
				assert_eq!(accepted, expected, "{why}");
				Ok(())
			}
			Err(err) => Err(format!("server_verifier_accepts ({why}): {err}")),
		};
	}

	// What the rotation test holds. A client built once over a ReloadingServerVerifier that trusts the
	// old CA. Also a backend under each CA, and the CA the bundle rotates to.
	struct Rotation {
		trust: BackendTrust,
		client: Arc<ClientConfig>,
		old_backend: Arc<rustls::ServerConfig>,
		new_backend: Arc<rustls::ServerConfig>,
		ca_new: Ca,
	}

	fn rotation_fixture() -> Result<Rotation, String> {
		let ((ca_old, old_leaf), (ca_new, new_leaf)) = match (ca_and_server_leaf(), ca_and_server_leaf()) {
			(Ok(old), Ok(new)) => (old, new),
			(old, new) => return Err(format!("CAs: {:?} {:?}", old.err(), new.err())),
		};
		let (old_backend, new_backend) = match (serving(old_leaf), serving(new_leaf)) {
			(Ok(old), Ok(new)) => (old, new),
			(old, new) => return Err(format!("backends: {:?} {:?}", old.err(), new.err())),
		};
		let trust: BackendTrust = verifier_over(&ca_old.cert.pem())?;
		let live_verifier: Arc<ReloadingServerVerifier> = Arc::clone(&trust.verifier);
		let client: Arc<ClientConfig> = no_resumption(
			ClientConfig::builder()
				.dangerous()
				.with_custom_certificate_verifier(live_verifier)
				.with_no_client_auth(),
		);
		return Ok(Rotation {
			trust,
			client,
			old_backend,
			new_backend,
			ca_new,
		});
	}

	// Which backend(s) the client trusts right now.
	fn observe(rotation: &Rotation) -> Result<Observed, String> {
		let old_ok: bool = match handshake(Arc::clone(&rotation.old_backend), Arc::clone(&rotation.client)) {
			Ok(outcome) => outcome.is_ok(),
			Err(err) => return Err(format!("old-backend handshake harness: {err}")),
		};
		let new_ok: bool = match handshake(Arc::clone(&rotation.new_backend), Arc::clone(&rotation.client)) {
			Ok(outcome) => outcome.is_ok(),
			Err(err) => return Err(format!("new-backend handshake harness: {err}")),
		};
		return Ok(trust_epoch(old_ok, new_ok));
	}

	// Rotates the backend CA bundle old→new on disk under a ClientConfig built once, then handshakes against
	// an old-CA and a new-CA backend. `apply_reload` is the swap switch: off skips the store, on performs it.
	fn trusted_after_rotation(apply_reload: bool) -> Result<Observed, String> {
		let rotation: Rotation = rotation_fixture()?;
		let before: Observed = observe(&rotation)?;
		assert_eq!(
			before,
			Observed::Old,
			"only the old-CA backend is trusted before rotation"
		);
		fs::write(rotation.trust.ca_file.path(), rotation.ca_new.cert.pem())
			.map_err(|err| format!("write new CA over the bundle: {err:?}"))?;
		if apply_reload && let Err(err) = rotation.trust.verifier.reload() {
			return Err(format!("verifier.reload(): {err:?}"));
		}
		return match observe(&rotation) {
			Ok(value) => Ok(value),
			Err(err) => Err(format!("observe() after rotation: {err}")),
		};
	}

	#[test]
	fn test_handshake_trusts_rotated_ca_only_after_reload() -> Result<(), String> {
		let without_swap: Observed = trusted_after_rotation(false)?;
		let with_swap: Observed = trusted_after_rotation(true)?;
		assert_eq!(
			without_swap,
			Observed::Old,
			"no store: live client config still trusts only the old CA"
		);
		assert_eq!(
			with_swap,
			Observed::New,
			"after store: same live client config trusts only the new CA"
		);
		assert_ne!(
			without_swap, with_swap,
			"the swap is the only difference between the two runs"
		);
		return Ok(());
	}

	#[test]
	fn test_server_verifier_new_and_verify() -> Result<(), String> {
		let (ca, leaf) = ca_and_server_leaf()?;
		let trust: BackendTrust = verifier_over(&ca.cert.pem())?;
		// Positive-for-the-right-reason: the leaf chains to the trusted CA and its SAN matches the name.
		return expect_accepts(&trust, &leaf, true, "a CA-signed leaf with a matching name must verify");
	}

	#[test]
	fn test_server_verifier_wrong_name_rejected() -> Result<(), String> {
		let (ca, leaf) = ca_and_server_leaf()?;
		let trust: BackendTrust = verifier_over(&ca.cert.pem())?;
		// The chain is correct, but the requested name is not in the leaf's SANs. Verification must fail.
		// This proves that the positive test above passes on the name, and not only on the chain.
		let wrong: ServerName<'_> = ServerName::try_from("not-localhost.example")
			.map_err(|err| format!("ServerName::try_from(\"not-localhost.example\"): {err:?}"))?;
		let verified = trust
			.verifier
			.verify_server_cert(leaf.cert.der(), &[], &wrong, &[], UnixTime::now())
			.is_ok();
		assert!(!verified, "a name mismatch must be rejected");
		return Ok(());
	}

	#[test]
	fn test_server_ca_reload_accepts_after_rotation() -> Result<(), String> {
		let ((ca_old, _old_leaf), (ca_new, new_leaf)) = match (ca_and_server_leaf(), ca_and_server_leaf()) {
			(Ok(old), Ok(new)) => (old, new),
			(old, new) => return Err(format!("CAs: {:?} {:?}", old.err(), new.err())),
		};
		let trust: BackendTrust = verifier_over(&ca_old.cert.pem())?;
		// Functional diff, before: the new-CA server leaf is rejected (its issuer is not trusted).
		expect_accepts(&trust, &new_leaf, false, "new-CA server leaf rejected before rotation")?;
		// Rotate the backend trust bundle to the new CA and reload in place — no new verifier object.
		rewrite_and_reload(&trust, &ca_new.cert.pem())?;
		// After: the SAME leaf is now accepted. The reload is the only thing that changed acceptance.
		return expect_accepts(&trust, &new_leaf, true, "new-CA server leaf accepted after rotation");
	}

	#[test]
	fn test_server_ca_bundle_cross_sign_window() -> Result<(), String> {
		let ((ca_old, old_leaf), (ca_new, new_leaf)) = match (ca_and_server_leaf(), ca_and_server_leaf()) {
			(Ok(old), Ok(new)) => (old, new),
			(old, new) => return Err(format!("CAs: {:?} {:?}", old.err(), new.err())),
		};
		// Bundle = old + new roots (multi-PEM). Servers under both CAs verify simultaneously.
		let trust: BackendTrust = verifier_over(&format!("{}{}", ca_old.cert.pem(), ca_new.cert.pem()))?;
		let during = expect_accepts(&trust, &old_leaf, true, "old-CA server accepted during the window")
			.and_then(|()| expect_accepts(&trust, &new_leaf, true, "new-CA server accepted during the window"));
		during?;
		// Close the window: drop the old root from the bundle, reload.
		rewrite_and_reload(&trust, &ca_new.cert.pem())?;
		return expect_accepts(
			&trust,
			&old_leaf,
			false,
			"old-CA server rejected after the old root is removed",
		)
		.and_then(|()| expect_accepts(&trust, &new_leaf, true, "new-CA server still accepted"));
	}

	#[test]
	fn test_server_ca_reload_garbage_keeps_previous() -> Result<(), String> {
		let (ca, leaf) = ca_and_server_leaf()?;
		let trust: BackendTrust = verifier_over(&ca.cert.pem())?;
		expect_accepts(&trust, &leaf, true, "server leaf accepted before the bad write")?;
		// Garbage bundle → reload errors → previous roots stay in force (last-known-good).
		assert!(
			rewrite_and_reload(&trust, "not a certificate").is_err(),
			"a garbage backend CA bundle must surface an error"
		);
		expect_accepts(
			&trust,
			&leaf,
			true,
			"garbage write must not empty the backend trust store",
		)?;
		// A valid rewrite afterwards recovers.
		rewrite_and_reload(&trust, &ca.cert.pem())?;
		return expect_accepts(
			&trust,
			&leaf,
			true,
			"server verifier must recover after a valid rewrite",
		);
	}

	#[test]
	fn test_server_ca_reload_empty_keeps_previous() -> Result<(), String> {
		let (ca, leaf) = ca_and_server_leaf()?;
		let trust: BackendTrust = verifier_over(&ca.cert.pem())?;
		expect_accepts(&trust, &leaf, true, "server leaf accepted before the empty write")?;
		// An EMPTY bundle would make every backend unreachable. The reload must refuse it and keep the previous roots.
		assert!(
			rewrite_and_reload(&trust, "").is_err(),
			"an empty backend CA bundle must surface an error"
		);
		return expect_accepts(
			&trust,
			&leaf,
			true,
			"empty write must not empty the backend trust store",
		);
	}

	#[test]
	fn test_server_verifier_startup_empty_ca_errors() -> Result<(), String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		// At startup, an empty or garbage bundle fails fast. The proxy does not start with trust in no backend.
		let empty_ca = write_pem("")?;
		assert!(
			ReloadingServerVerifier::new(empty_ca.path()).is_err(),
			"empty CA at boot must fail fast"
		);
		return Ok(());
	}

	// A TLS 1.2-only client over `verifier`: its handshake signature goes through verify_tls12_signature.
	fn tls12_client(verifier: &Arc<ReloadingServerVerifier>) -> Result<Arc<ClientConfig>, String> {
		let live: Arc<ReloadingServerVerifier> = Arc::clone(verifier);
		return Ok(no_resumption(
			ClientConfig::builder_with_protocol_versions(&[&TLS12])
				.dangerous()
				.with_custom_certificate_verifier(live)
				.with_no_client_auth(),
		));
	}

	#[test]
	fn test_tls12_handshake_verifies_through_the_reloading_verifier() -> Result<(), String> {
		let ((ca, leaf), (_foreign_ca, foreign_leaf)) = match (ca_and_server_leaf(), ca_and_server_leaf()) {
			(Ok(own), Ok(foreign)) => (own, foreign),
			(own, foreign) => return Err(format!("CAs: {:?} {:?}", own.err(), foreign.err())),
		};
		let trust: BackendTrust = verifier_over(&ca.cert.pem())?;
		let client: Arc<ClientConfig> = tls12_client(&trust.verifier)?;
		let trusted = handshake(serving(leaf)?, Arc::clone(&client))?;
		assert!(trusted.is_ok(), "TLS 1.2 to a trusted backend must verify: {trusted:?}");
		let foreign = handshake(serving(foreign_leaf)?, client)?;
		assert!(foreign.is_err(), "TLS 1.2 to an untrusted backend must be refused");
		return Ok(());
	}

	#[test]
	fn test_reloadable_trait_reload_swaps_and_keeps_last_good() -> Result<(), String> {
		let ((ca_old, _old_leaf), (ca_new, new_leaf)) = match (ca_and_server_leaf(), ca_and_server_leaf()) {
			(Ok(old), Ok(new)) => (old, new),
			(old, new) => return Err(format!("CAs: {:?} {:?}", old.err(), new.err())),
		};
		let trust: BackendTrust = verifier_over(&ca_old.cert.pem())?;
		expect_accepts(&trust, &new_leaf, false, "new-CA leaf rejected before the trait reload")?;
		fs::write(trust.ca_file.path(), ca_new.cert.pem()).map_err(|err| format!("write new CA: {err:?}"))?;
		Reloadable::reload(&*trust.verifier).map_err(|err| format!("Reloadable::reload: {err:?}"))?;
		expect_accepts(&trust, &new_leaf, true, "the trait reload must swap in the new roots")?;
		fs::write(trust.ca_file.path(), "garbage").map_err(|err| format!("write garbage: {err:?}"))?;
		assert!(
			Reloadable::reload(&*trust.verifier).is_err(),
			"a garbage bundle surfaces through the trait"
		);
		return expect_accepts(
			&trust,
			&new_leaf,
			true,
			"a failed trait reload keeps the last good roots",
		);
	}

	#[test]
	fn test_schemes_and_raw_keys_delegate_to_the_inner_verifier() -> Result<(), String> {
		let (ca, _leaf) = ca_and_server_leaf()?;
		let trust: BackendTrust = verifier_over(&ca.cert.pem())?;
		let inner: Arc<dyn ServerCertVerifier> =
			load_server_trust(trust.ca_file.path()).map_err(|err| format!("load_server_trust: {err:?}"))?;
		let schemes: Vec<SignatureScheme> = trust.verifier.supported_verify_schemes();
		assert_eq!(schemes, inner.supported_verify_schemes());
		assert!(
			schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256),
			"rcgen's P-256 leaves need ECDSA P-256: {schemes:?}"
		);
		assert!(
			!trust.verifier.requires_raw_public_keys(),
			"a WebPKI verifier uses X.509 chains"
		);
		return Ok(());
	}

	#[test]
	fn test_debug_names_the_bundle_path() -> Result<(), String> {
		let (ca, _leaf) = ca_and_server_leaf()?;
		let trust: BackendTrust = verifier_over(&ca.cert.pem())?;
		let rendered: String = format!("{:?}", trust.verifier);
		assert!(rendered.starts_with("ReloadingServerVerifier"), "got: {rendered}");
		assert!(
			rendered.contains(&format!("{:?}", trust.ca_file.path())),
			"got: {rendered}"
		);
		return Ok(());
	}

	// A backend fixture must not come up with a key that cannot sign for its cert.
	#[test]
	fn test_serving_refuses_a_leaf_with_another_leafs_key() -> Result<(), String> {
		let (_ca, leaf) = ca_and_server_leaf()?;
		let (_other_ca, other) = ca_and_server_leaf()?;
		let (_intact_ca, intact) = ca_and_server_leaf()?;
		// Control: the fixture serves an intact pair from the same generator. The fixture function consumes it.
		serving(intact)?;
		let mismatched: Ca = Ca { cert: leaf.cert, signing_key: other.signing_key };
		let err: String = serving(mismatched)
			.err()
			.ok_or("a leaf paired with another leaf's key must be refused")?;
		assert!(err.contains("InconsistentKeys"), "got: {err}");
		return Ok(());
	}
}
