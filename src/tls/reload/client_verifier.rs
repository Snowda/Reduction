use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fmt, fs};

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, RootCertStore, SignatureScheme};
use solo::lease::Leased;
use tracing::info;

use super::Reloadable;
use crate::error::{ReductionError, Result};
use crate::lease::LEASES;
use crate::tls::load::load_ca_certs;

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
	// With CRLs, enforce nextUpdate so a stale CRL is rejected rather than trusted past its validity.
	let builder = if crls.is_empty() {
		builder
	} else {
		builder.with_crls(crls).enforce_revocation_expiration()
	};
	// Optional-mTLS: verify a presented cert but admit a peer that presents none. Required-mTLS omits this
	// (a nameless peer is refused at the handshake). Disabled builds no verifier at all.
	let builder = if allow_unauthenticated {
		builder.allow_unauthenticated()
	} else {
		builder
	};
	return builder
		.build()
		.map_err(|e| ReductionError::Config(format!("failed to build client verifier: {e}")));
}

// Load trust anchors and CRLs from disk. An empty, absent or garbage CA bundle errors (caller keeps last-known-good).
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

// mTLS client-cert verifier whose trust anchors and CRLs hot-swap with no rebuild of the server config.
// Only the inner verifier changes (via Leased). Live listeners then use new roots/CRLs on the next handshake.
pub struct ReloadingClientVerifier {
	// Double Arc: Leased needs a Sized pointee, and this stores the builder's Arc<dyn> as-is with no new Box.
	inner: Leased<Arc<Arc<dyn ClientCertVerifier>>>,
	ca_cert_path: PathBuf,
	// None = no handshake-level revocation (roots still hot-reload).
	crl_path: Option<PathBuf>,
	// Optional-mTLS flag, stored so reload() keeps the same policy across a CA rotation.
	allows_unauthenticated: bool,
}

impl ReloadingClientVerifier {
	// Mandatory mTLS: the handshake rejects a peer with no client cert.
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
			inner: Leased::from_pointee(verifier, LEASES),
			ca_cert_path: ca_cert_path.to_path_buf(),
			crl_path: crl_path.map(Path::to_path_buf),
			allows_unauthenticated: allow_unauthenticated,
		}));
	}

	// On any read/parse failure (incl. an empty CA bundle) the previous verifier is kept (last-known-good).
	pub fn reload(&self) -> Result<()> {
		let verifier: Arc<dyn ClientCertVerifier> =
			load_trust(&self.ca_cert_path, self.crl_path.as_deref(), self.allows_unauthenticated)?;
		self.inner.store(Arc::new(verifier));
		info!(
			ca = %self.ca_cert_path.display(),
			crl = ?self.crl_path.as_ref().map(|p| p.display().to_string()),
			"client trust anchors reloaded",
		);
		return Ok(());
	}

	// Clones the inner Arc out, so the lease drops here and never spans a verification.
	#[must_use]
	pub fn current(&self) -> Arc<dyn ClientCertVerifier> {
		return Arc::clone(&self.inner.lease());
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
	// Empty by design: the `&self` borrow can't reflect hot-swapped roots, and the hint is advisory anyway
	// (every device holds one cert and sends it regardless). Equivalent to clear_root_hint_subjects().
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
		// Delegate to the inherent method, explicit to rule out self-recursion through the trait method.
		return Self::reload(self);
	}
}

#[cfg(test)]
mod tests {
	use std::result::Result;

	use rustls::version::TLS12;
	use rustls::{ClientConfig, DEFAULT_VERSIONS, ServerConfig, SupportedProtocolVersion};
	use tempfile::NamedTempFile;

	use super::super::testutil::{crl_ca, crl_leaf, make_crl_pem, is_leaf_accepted};
	use super::*;
	use crate::test_support::handshake::{Observed, handshake, pkcs8, presenting, trust_epoch};
	use crate::test_support::{generate_ca, generate_localhost_cert, write_pem};

	type Ca = rcgen::CertifiedKey<rcgen::KeyPair>;

	// Client config of a device whose leaf (CN `cn`, CRL serial `serial`) is signed by `device_ca`.
	// It trusts `server_ca` for the server.
	fn device(server_ca: &Ca, device_ca: &Ca, cn: &str, serial: u64) -> Result<Arc<ClientConfig>, String> {
		let leaf: Ca = crl_leaf(device_ca, cn, serial)?;
		return presenting(server_ca, leaf);
	}

	// All that the rotation test holds. A server built once over a ReloadingClientVerifier that trusts
	// `ca_old` (from `ca_file`). Also a device under each CA, and the CA the bundle rotates to.
	struct Rotation {
		server: Arc<ServerConfig>,
		verifier: Arc<ReloadingClientVerifier>,
		ca_file: NamedTempFile,
		ca_new: Ca,
		old_device: Arc<ClientConfig>,
		new_device: Arc<ClientConfig>,
	}

	// A server limited to `versions` whose client verifier reloads from `ca_file`. It serves a localhost leaf of `server_ca`.
	fn server_over_verifier(
		server_ca: &Ca,
		ca_file: &NamedTempFile,
		versions: &[&'static SupportedProtocolVersion],
	) -> Result<(Arc<ServerConfig>, Arc<ReloadingClientVerifier>), String> {
		let server_leaf: Ca =
			generate_localhost_cert(server_ca)?;
		let verifier: Arc<ReloadingClientVerifier> = ReloadingClientVerifier::new(ca_file.path(), None)
			.map_err(|err| format!("ReloadingClientVerifier::new: {err:?}"))?;
		let live_verifier: Arc<ReloadingClientVerifier> = Arc::clone(&verifier);
		let server: ServerConfig = ServerConfig::builder_with_protocol_versions(versions)
			.with_client_cert_verifier(live_verifier)
			.with_single_cert(vec![CertificateDer::from(server_leaf.cert)], pkcs8(&server_leaf.signing_key))
			.map_err(|err| format!("ServerConfig with reloading verifier: {err:?}"))?;
		return Ok((Arc::new(server), verifier));
	}

	fn rotation_fixture() -> Result<Rotation, String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let server_ca: Ca = generate_ca()?;
		let ca_old: Ca = crl_ca()?;
		let ca_new: Ca = crl_ca()?;
		let old_device: Arc<ClientConfig> = device(&server_ca, &ca_old, "device-old", 1)?;
		let new_device: Arc<ClientConfig> = device(&server_ca, &ca_new, "device-new", 2)?;
		let ca_file: NamedTempFile = write_pem(&ca_old.cert.pem())?;
		let (server, verifier) = server_over_verifier(&server_ca, &ca_file, DEFAULT_VERSIONS)?;
		return Ok(Rotation {
			server,
			verifier,
			ca_file,
			ca_new,
			old_device,
			new_device,
		});
	}

	// Which device(s) the server admits right now.
	fn observe(rotation: &Rotation) -> Result<Observed, String> {
		let old_ok: bool = handshake(Arc::clone(&rotation.server), Arc::clone(&rotation.old_device))?
			.is_ok();
		let new_ok: bool = handshake(Arc::clone(&rotation.server), Arc::clone(&rotation.new_device))?
			.is_ok();
		return Ok(trust_epoch(old_ok, new_ok));
	}

	// Rotates the client-CA bundle old→new on disk under a ServerConfig built once, then handshakes with an
	// old-CA and a new-CA client cert. `apply_reload` is the swap switch: off skips the store, on performs it.
	fn admitted_after_rotation(apply_reload: bool) -> Result<Observed, String> {
		let rotation: Rotation = rotation_fixture()?;
		let before: Observed = observe(&rotation)?;
		assert_eq!(
			before,
			Observed::Old,
			"only the old-CA device is admitted before rotation"
		);
		fs::write(rotation.ca_file.path(), rotation.ca_new.cert.pem())
			.map_err(|err| format!("write new CA over the bundle: {err:?}"))?;
		if apply_reload {
			rotation
				.verifier
				.reload()
				.map_err(|err| format!("verifier.reload(): {err:?}"))?;
		}
		return observe(&rotation).map_err(|err| format!("observe() after rotation: {err}"));
	}

	#[test]
	fn test_handshake_admits_rotated_ca_only_after_reload() -> Result<(), String> {
		let without_swap: Observed =
			admitted_after_rotation(false)?;
		let with_swap: Observed =
			admitted_after_rotation(true)?;
		assert_eq!(
			without_swap,
			Observed::Old,
			"no store: live listener still admits only old-CA devices"
		);
		assert_eq!(
			with_swap,
			Observed::New,
			"after store: same live listener admits only new-CA devices"
		);
		assert_ne!(
			without_swap, with_swap,
			"the swap is the only difference between the two runs"
		);
		return Ok(());
	}

	// A TLS 1.2-only server checks the client's CertificateVerify through verify_tls12_signature.
	#[test]
	fn test_tls12_handshake_admits_trusted_device_only() -> Result<(), String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let server_ca: Ca = generate_ca()?;
		let device_ca: Ca = crl_ca()?;
		let stranger_ca: Ca = crl_ca()?;
		let ca_file: NamedTempFile = write_pem(&device_ca.cert.pem())?;
		let (server, _verifier) = server_over_verifier(&server_ca, &ca_file, &[&TLS12])?;
		let trusted: Arc<ClientConfig> = device(&server_ca, &device_ca, "device-tls12", 1)?;
		let stranger: Arc<ClientConfig> = device(&server_ca, &stranger_ca, "stranger-tls12", 1)?;

		let admitted = handshake(Arc::clone(&server), trusted)?;
		let refused = handshake(server, stranger)?;
		assert!(
			admitted.is_ok(),
			"TLS 1.2 must admit a device under the trusted CA: {:?}",
			admitted.err()
		);
		assert!(refused.is_err(), "TLS 1.2 must refuse a device under an untrusted CA");
		return Ok(());
	}

	#[test]
	fn test_crl_verifier_rejects_revoked_accepts_valid() -> Result<(), String> {
		let (ca, revoked) = ca_and_leaf("device-bad", 1)?;
		let good: Ca = crl_leaf(&ca, "device-good", 2)?;
		let revoking_crl: String = make_crl_pem(&ca, &[1])?;
		let trust: TrustFiles = verifier_over(&ca.cert.pem(), Some(&revoking_crl))?;
		// Functional diff: same CA and verifier. The only difference is if the leaf's serial is on the CRL.
		assert!(
			!is_leaf_accepted(&trust.verifier, &revoked),
			"a CRL-listed cert must be rejected"
		);
		assert!(
			is_leaf_accepted(&trust.verifier, &good),
			"an unlisted cert must still verify"
		);
		return Ok(());
	}

	// A fresh CRL-capable CA and one leaf it signs (CN `cn`, serial `serial`).
	fn ca_and_leaf(cn: &str, serial: u64) -> Result<(Ca, Ca), String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca: Ca = crl_ca()?;
		let leaf: Ca = crl_leaf(&ca, cn, serial)?;
		return Ok((ca, leaf));
	}

	// The on-disk trust material that a ReloadingClientVerifier reads. Keep it alive. Rewrite it to drive reloads.
	struct TrustFiles {
		verifier: Arc<ReloadingClientVerifier>,
		ca_file: NamedTempFile,
		crl_file: Option<NamedTempFile>,
	}

	// A ReloadingClientVerifier over `ca_pem` (one or more roots) and, when given, the CRL `crl_pem`.
	fn verifier_over(ca_pem: &str, crl_pem: Option<&str>) -> Result<TrustFiles, String> {
		let ca_file: NamedTempFile = write_pem(ca_pem)?;
		let crl_file: Option<NamedTempFile> = crl_pem
			.map(write_pem)
			.transpose()?;
		let crl_path: Option<&Path> = crl_file.as_ref().map(NamedTempFile::path);
		let verifier: Arc<ReloadingClientVerifier> = ReloadingClientVerifier::new(ca_file.path(), crl_path)
			.map_err(|err| format!("ReloadingClientVerifier::new: {err:?}"))?;
		return Ok(TrustFiles {
			verifier,
			ca_file,
			crl_file,
		});
	}

	// Overwrite `path` with `contents`, then reload `verifier` in place (same object, new trust material).
	fn rewrite_and_reload(verifier: &ReloadingClientVerifier, path: &Path, contents: &str) -> Result<(), String> {
		fs::write(path, contents).map_err(|err| format!("rewrite {}: {err:?}", path.display()))?;
		return verifier.reload().map_err(|err| format!("verifier.reload(): {err:?}"));
	}

	#[test]
	fn test_crl_verifier_reload_swaps_in_new_revocation() -> Result<(), String> {
		let (ca, leaf) = ca_and_leaf("device-1", 1)?;
		let empty_crl: String = make_crl_pem(&ca, &[])?;
		let revoking_crl: String = make_crl_pem(&ca, &[1])?;
		// Start with an empty CRL: the leaf verifies.
		let trust: TrustFiles = verifier_over(&ca.cert.pem(), Some(&empty_crl))?;
		assert!(
			is_leaf_accepted(&trust.verifier, &leaf),
			"with an empty CRL the leaf must verify"
		);

		// Overwrite the CRL to revoke the leaf's serial, and reload in place. The same verifier object
		// now rejects what it accepted a moment ago. A live handshake sees the same result.
		let Some(crl_file) = trust.crl_file.as_ref() else {
			return Err(String::from("CRL file present"));
		};
		rewrite_and_reload(&trust.verifier, crl_file.path(), &revoking_crl)?;
		assert!(
			!is_leaf_accepted(&trust.verifier, &leaf),
			"after reload the newly-revoked leaf must be rejected"
		);
		return Ok(());
	}

	#[test]
	fn test_ca_reload_accepts_after_rotation() -> Result<(), String> {
		let (ca_old, _old_leaf) = ca_and_leaf("device-old", 1)?;
		// A leaf signed by the NEW CA — not trusted while the bundle holds only the old root.
		let (ca_new, new_leaf) = ca_and_leaf("device-new", 1)?;
		let trust: TrustFiles = verifier_over(&ca_old.cert.pem(), None)?;
		// Functional diff, before: the new-CA leaf is rejected (its issuer is not in the trust bundle).
		assert!(
			!is_leaf_accepted(&trust.verifier, &new_leaf),
			"new-CA leaf must be rejected before rotation"
		);

		// Rotate the trust bundle to the new CA and reload in place — no new verifier object.
		rewrite_and_reload(&trust.verifier, trust.ca_file.path(), &ca_new.cert.pem())?;
		// After: the SAME leaf is now accepted. The reload is the only thing that changed acceptance.
		assert!(
			is_leaf_accepted(&trust.verifier, &new_leaf),
			"new-CA leaf must be accepted after rotation"
		);
		return Ok(());
	}

	#[test]
	fn test_ca_bundle_cross_sign_window() -> Result<(), String> {
		let (ca_old, old_leaf) = ca_and_leaf("device-old", 1)?;
		let (ca_new, new_leaf) = ca_and_leaf("device-new", 2)?;

		// Bundle = old + new roots (multi-PEM). Both CAs are trusted simultaneously.
		let trust: TrustFiles = verifier_over(&format!("{}{}", ca_old.cert.pem(), ca_new.cert.pem()), None)?;
		assert!(
			is_leaf_accepted(&trust.verifier, &old_leaf),
			"old-CA leaf accepted during the window"
		);
		assert!(
			is_leaf_accepted(&trust.verifier, &new_leaf),
			"new-CA leaf accepted during the window"
		);

		// Close the window: drop the old root from the bundle, reload.
		rewrite_and_reload(&trust.verifier, trust.ca_file.path(), &ca_new.cert.pem())?;
		assert!(
			!is_leaf_accepted(&trust.verifier, &old_leaf),
			"old-CA leaf rejected after the old root is removed"
		);
		assert!(
			is_leaf_accepted(&trust.verifier, &new_leaf),
			"new-CA leaf still accepted"
		);
		return Ok(());
	}

	#[test]
	fn test_ca_reload_garbage_keeps_previous() -> Result<(), String> {
		let (ca, leaf) = ca_and_leaf("device-1", 1)?;
		let trust: TrustFiles = verifier_over(&ca.cert.pem(), None)?;
		assert!(
			is_leaf_accepted(&trust.verifier, &leaf),
			"leaf accepted before the bad write"
		);

		// Garbage bundle → reload errors → previous roots stay in force (last-known-good).
		assert!(
			rewrite_and_reload(&trust.verifier, trust.ca_file.path(), "not a certificate").is_err(),
			"a garbage CA bundle must surface an error"
		);
		assert!(
			is_leaf_accepted(&trust.verifier, &leaf),
			"garbage write must not empty the trust store"
		);

		// A valid rewrite afterwards recovers.
		rewrite_and_reload(&trust.verifier, trust.ca_file.path(), &ca.cert.pem())?;
		assert!(
			is_leaf_accepted(&trust.verifier, &leaf),
			"verifier must recover after a valid rewrite"
		);
		return Ok(());
	}

	#[test]
	fn test_ca_reload_empty_keeps_previous() -> Result<(), String> {
		let (ca, leaf) = ca_and_leaf("device-1", 1)?;
		let trust: TrustFiles = verifier_over(&ca.cert.pem(), None)?;
		assert!(
			is_leaf_accepted(&trust.verifier, &leaf),
			"leaf accepted before the empty write"
		);

		// An EMPTY bundle would reject the whole fleet. The reload must refuse it and keep the previous roots.
		assert!(
			rewrite_and_reload(&trust.verifier, trust.ca_file.path(), "").is_err(),
			"an empty CA bundle must surface an error"
		);
		assert!(
			is_leaf_accepted(&trust.verifier, &leaf),
			"empty write must not empty the trust store"
		);
		return Ok(());
	}

	#[test]
	fn test_ca_reload_carries_current_crl() -> Result<(), String> {
		let (ca_old, revoked) = ca_and_leaf("device-bad", 1)?;
		let (ca_new, _new_leaf) = ca_and_leaf("device-new", 2)?;
		// Trust the old CA and revoke serial 1 via a CA-signed CRL.
		let revoking_crl: String =
			make_crl_pem(&ca_old, &[1])?;
		let trust: TrustFiles = verifier_over(&ca_old.cert.pem(), Some(&revoking_crl))?;
		assert!(
			!is_leaf_accepted(&trust.verifier, &revoked),
			"revoked leaf rejected before the CA reload"
		);

		// Rotate the bundle to old+new and reload (CRL file unchanged). The rebuilt verifier must keep
		// the CURRENT CRL. Thus the revoked old-CA leaf stays rejected after the root change.
		let both_roots: String = format!("{}{}", ca_old.cert.pem(), ca_new.cert.pem());
		rewrite_and_reload(&trust.verifier, trust.ca_file.path(), &both_roots)?;
		assert!(
			!is_leaf_accepted(&trust.verifier, &revoked),
			"revoked leaf must stay rejected after a CA reload"
		);
		return Ok(());
	}

	// A CRL that disappears between reloads must not silently lift every revocation.
	#[test]
	fn test_reload_missing_crl_keeps_previous_revocations() -> Result<(), String> {
		let (ca, revoked) = ca_and_leaf("device-bad", 1)?;
		let revoking_crl: String = make_crl_pem(&ca, &[1])?;
		let trust: TrustFiles = verifier_over(&ca.cert.pem(), Some(&revoking_crl))?;
		let Some(crl_file) = trust.crl_file.as_ref() else {
			return Err(String::from("CRL file present"));
		};
		fs::remove_file(crl_file.path()).map_err(|err| format!("remove CRL: {err:?}"))?;

		let reloaded = trust.verifier.reload();
		assert!(
			reloaded
				.as_ref()
				.is_err_and(|err| err.to_string().contains("failed to open CRL file")),
			"a missing CRL must fail the reload, got {reloaded:?}"
		);
		assert!(
			!is_leaf_accepted(&trust.verifier, &revoked),
			"the revoked leaf must stay rejected after a failed reload"
		);
		return Ok(());
	}

	// Optional mTLS stays optional across a CA rotation. Mandatory stays mandatory.
	#[test]
	fn test_optional_policy_survives_reload() -> Result<(), String> {
		let (ca, leaf) = ca_and_leaf("device-1", 1)?;
		let ca_file: NamedTempFile = write_pem(&ca.cert.pem())?;
		let optional: Arc<ReloadingClientVerifier> = ReloadingClientVerifier::new_optional(ca_file.path(), None)
			.map_err(|err| format!("ReloadingClientVerifier::new_optional: {err:?}"))?;
		let mandatory: Arc<ReloadingClientVerifier> = ReloadingClientVerifier::new(ca_file.path(), None)
			.map_err(|err| format!("ReloadingClientVerifier::new: {err:?}"))?;
		assert!(
			!optional.client_auth_mandatory(),
			"new_optional must admit a peer with no cert"
		);
		assert!(mandatory.client_auth_mandatory(), "new must refuse a peer with no cert");
		assert!(
			optional.offer_client_auth(),
			"optional mTLS still requests a client cert"
		);
		assert!(
			is_leaf_accepted(&optional, &leaf),
			"optional mTLS still verifies a presented cert"
		);

		optional.reload().map_err(|err| format!("optional.reload(): {err:?}"))?;
		mandatory
			.reload()
			.map_err(|err| format!("mandatory.reload(): {err:?}"))?;
		assert!(
			!optional.client_auth_mandatory(),
			"reload must keep the optional policy"
		);
		assert!(
			mandatory.client_auth_mandatory(),
			"reload must keep the mandatory policy"
		);
		return Ok(());
	}

	fn leaf_for(ca: &Ca, usage: rcgen::ExtendedKeyUsagePurpose) -> Result<Ca, String> {
		let key: rcgen::KeyPair = rcgen::KeyPair::generate().map_err(|err| format!("key: {err:?}"))?;
		let mut params = rcgen::CertificateParams::new(vec!["metrics-feed.molt".to_owned()]).map_err(|err| format!("params: {err:?}"))?;
		params.extended_key_usages = vec![usage];
		let issuer = rcgen::Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key).map_err(|err| format!("issuer: {err:?}"))?;
		let cert = params.signed_by(&key, &issuer).map_err(|err| format!("sign: {err:?}"))?;
		return Ok(rcgen::CertifiedKey { cert, signing_key: key });
	}

	// A CAS Service leaf carries serverAuth alone, so it cannot be a service's client certificate at this edge.
	#[test]
	fn a_server_auth_leaf_cannot_authenticate_as_a_client() -> Result<(), String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca: Ca = crl_ca()?;
		let trust: TrustFiles = verifier_over(&ca.cert.pem(), None)?;
		let client: Ca = leaf_for(&ca, rcgen::ExtendedKeyUsagePurpose::ClientAuth)?;
		assert!(is_leaf_accepted(&trust.verifier, &client), "the same leaf with clientAuth is the control");
		let server: Ca = leaf_for(&ca, rcgen::ExtendedKeyUsagePurpose::ServerAuth)?;
		assert!(!is_leaf_accepted(&trust.verifier, &server), "webpki requires clientAuth when an EKU is present");
		return Ok(());
	}

	// The wrapper answers capability queries exactly as a verifier built straight from the same roots.
	#[test]
	fn test_capability_queries_match_inner_verifier() -> Result<(), String> {
		let (ca, _) = ca_and_leaf("device-1", 1)?;
		let trust: TrustFiles = verifier_over(&ca.cert.pem(), None)?;
		let direct: Arc<dyn ClientCertVerifier> =
			load_trust(trust.ca_file.path(), None, false).map_err(|err| format!("load_trust: {err:?}"))?;
		assert_eq!(
			trust.verifier.supported_verify_schemes(),
			direct.supported_verify_schemes(),
			"signature schemes come from the inner verifier"
		);
		assert!(
			!trust.verifier.supported_verify_schemes().is_empty(),
			"a verifier offering no schemes cannot complete a handshake"
		);
		assert_eq!(
			trust.verifier.requires_raw_public_keys(),
			direct.requires_raw_public_keys(),
			"raw-public-key mode comes from the inner verifier"
		);
		assert!(
			!trust.verifier.requires_raw_public_keys(),
			"X.509 trust anchors never use raw public keys"
		);
		return Ok(());
	}

	#[test]
	fn test_debug_shows_paths() -> Result<(), String> {
		let (ca, _) = ca_and_leaf("device-1", 1)?;
		let empty_crl: String = make_crl_pem(&ca, &[])?;
		let with_crl: TrustFiles = verifier_over(&ca.cert.pem(), Some(&empty_crl))?;
		let without_crl: TrustFiles = verifier_over(&ca.cert.pem(), None)?;
		let Some(crl_file) = with_crl.crl_file.as_ref() else {
			return Err(String::from("CRL file present"));
		};

		let shown: String = format!("{:?}", with_crl.verifier);
		assert!(shown.starts_with("ReloadingClientVerifier"), "names the type: {shown}");
		assert!(
			shown.contains(&format!("{:?}", with_crl.ca_file.path())),
			"shows the CA path: {shown}"
		);
		assert!(
			shown.contains(&format!("Some({:?})", crl_file.path())),
			"shows the CRL path: {shown}"
		);
		let shown_without: String = format!("{:?}", without_crl.verifier);
		assert!(
			shown_without.contains("crl_path: None"),
			"shows an absent CRL as None: {shown_without}"
		);
		return Ok(());
	}

	#[test]
	fn test_reloading_verifier_offers_no_root_hint() -> Result<(), String> {
		let (ca, _) = ca_and_leaf("device-1", 1)?;
		let trust: TrustFiles = verifier_over(&ca.cert.pem(), None)?;
		// Deliberately empty: the hint cannot track hot-swapped roots (see root_hint_subjects comment).
		assert!(
			trust.verifier.root_hint_subjects().is_empty(),
			"reloadable verifier must offer no root hint"
		);
		return Ok(());
	}

	#[test]
	fn test_load_crls_missing_file_errors() -> Result<(), String> {
		let err = match load_crls(Path::new("/nonexistent/crl.pem")) {
			Ok(value) => return Err(format!("load_crls(missing): expected Err, got Ok({value:?})")),
			Err(err) => err,
		};
		assert!(
			format!("{err}").contains("failed to open CRL file"),
			"a missing file is an open error: {err}"
		);
		return Ok(());
	}

	#[test]
	fn test_load_crls_corrupt_errors() -> Result<(), String> {
		let f: NamedTempFile = write_pem("not a crl at all")?;
		// A file with no PEM CRL sections parses to an empty list (valid). Assert that explicitly, so the
		// behavior stays fixed.
		let result = load_crls(f.path());
		assert!(
			result.as_ref().is_ok_and(Vec::is_empty),
			"no CRL sections parse to an empty list, got {result:?}"
		);
		return Ok(());
	}

	#[test]
	fn test_load_crls_malformed_section_errors() -> Result<(), String> {
		let f: NamedTempFile = write_pem("-----BEGIN X509 CRL-----\n%%%%\n-----END X509 CRL-----\n")?;
		let result = load_crls(f.path());
		assert!(
			result
				.as_ref()
				.is_err_and(|err| err.to_string().contains("failed to parse CRLs")),
			"a CRL section with a bad body is a parse error, got {result:?}"
		);
		return Ok(());
	}

	// A device fixture must not show a cert that its key cannot sign for.
	#[test]
	fn test_presenting_refuses_a_leaf_with_another_leafs_key() -> Result<(), String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let server_ca: Ca = generate_ca()?;
		let leaf: Ca = generate_localhost_cert(&server_ca)?;
		let other: Ca = generate_localhost_cert(&server_ca)?;
		let intact: Ca = generate_localhost_cert(&server_ca)?;
		// Control: the fixture shows an intact pair from the same generator. The fixture function consumes it.
		presenting(&server_ca, intact)?;
		let mismatched: Ca = Ca { cert: leaf.cert, signing_key: other.signing_key };
		let err: String = presenting(&server_ca, mismatched)
			.err()
			.ok_or("a leaf paired with another leaf's key must be refused")?;
		assert!(err.contains("InconsistentKeys"), "got: {err}");
		return Ok(());
	}
}
