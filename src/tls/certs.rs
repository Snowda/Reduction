use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::client::ResolvesClientCert;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::config::ClientAuthPolicy;
use crate::error::{ReductionError, Result};
use crate::tls::reload::{ReloadingCertResolver, ReloadingClientVerifier, ReloadingServerVerifier};

// Load PEM-encoded certificates from a file.
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
	let file: fs::File = fs::File::open(path)
		.map_err(|e| ReductionError::Config(format!("failed to open cert file {}: {e}", path.display())))?;
	let reader: BufReader<fs::File> = BufReader::new(file);

	let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(reader)
		.collect::<std::result::Result<Vec<_>, _>>()
		.map_err(|e| ReductionError::Config(format!("failed to parse certs from {}: {e}", path.display())))?;

	if certs.is_empty() {
		return Err(ReductionError::Config(format!(
			"no certificates found in {}",
			path.display()
		)));
	}

	return Ok(certs);
}

// Load a PEM-encoded private key from a file.
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
	let file: fs::File = fs::File::open(path)
		.map_err(|e| ReductionError::Config(format!("failed to open key file {}: {e}", path.display())))?;
	let mut reader: BufReader<fs::File> = BufReader::new(file);

	let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(&mut reader)
		.map_err(|e| ReductionError::Config(format!("failed to parse private key from {}: {e}", path.display())))?;

	return Ok(key);
}

// Build a RootCertStore from a CA certificate file for mTLS client verification.
pub fn load_ca_certs(path: &Path) -> Result<RootCertStore> {
	let ca_certs: Vec<CertificateDer<'static>> = load_certs(path)?;
	let mut root_store: RootCertStore = RootCertStore::empty();

	for cert in ca_certs {
		root_store
			.add(cert)
			.map_err(|e| ReductionError::Config(format!("failed to add CA cert: {e}")))?;
	}

	return Ok(root_store);
}

// Build a rustls ServerConfig with mTLS and a reloadable cert resolver.
pub fn build_server_config(
	cert_path: &Path,
	key_path: &Path,
	ca_cert_path: &Path,
) -> Result<(ServerConfig, Arc<ReloadingCertResolver>)> {
	let resolver: Arc<ReloadingCertResolver> = Arc::new(ReloadingCertResolver::new(cert_path, key_path)?);
	let root_store: RootCertStore = load_ca_certs(ca_cert_path)?;

	let client_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
		WebPkiClientVerifier::builder(Arc::new(root_store))
			.build()
			.map_err(|e| ReductionError::Config(format!("failed to build client verifier: {e}")))?;

	let mut config: ServerConfig = ServerConfig::builder()
		.with_client_cert_verifier(client_verifier)
		.with_cert_resolver(resolver.clone());

	config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

	return Ok((config, resolver));
}

// Like build_server_config, but the CA bundle AND an optional CRL hot-swap without a restart; returns the
// verifier for watcher wiring. Use when the CA rotates live. `crl_path = None` → root reload, no revocation.
// Mandatory-mTLS (Required policy); delegates to build_server_config_for_policy.
pub fn build_server_config_reloadable(
	cert_path: &Path,
	key_path: &Path,
	ca_cert_path: &Path,
	crl_path: Option<&Path>,
) -> Result<(ServerConfig, Arc<ReloadingCertResolver>, Arc<ReloadingClientVerifier>)> {
	let (config, resolver, verifier) =
		build_server_config_for_policy(cert_path, key_path, ca_cert_path, crl_path, ClientAuthPolicy::Required)?;
	// Required always builds a verifier, so the Option is never None here.
	let verifier: Arc<ReloadingClientVerifier> =
		verifier.ok_or_else(|| ReductionError::Config("required mTLS produced no client verifier".to_owned()))?;
	return Ok((config, resolver, verifier));
}

// Inbound TLS server config honoring the client-auth policy. `Required`/`Optional` build a reloadable
// client-cert verifier (returned for watcher wiring); `Optional` additionally admits a peer presenting
// no cert. `Disabled` builds NO verifier — no CertificateRequest is sent, so an anonymous browser
// completes the handshake — and returns None (there is no inbound trust to watch). The server cert is
// always reloadable. The CA/CRL are read only for the verifier, so `Disabled` never touches them.
pub fn build_server_config_for_policy(
	cert_path: &Path,
	key_path: &Path,
	ca_cert_path: &Path,
	crl_path: Option<&Path>,
	policy: ClientAuthPolicy,
) -> Result<(ServerConfig, Arc<ReloadingCertResolver>, Option<Arc<ReloadingClientVerifier>>)> {
	let resolver: Arc<ReloadingCertResolver> = Arc::new(ReloadingCertResolver::new(cert_path, key_path)?);

	if !policy.builds_verifier() {
		let mut config: ServerConfig = ServerConfig::builder()
			.with_no_client_auth()
			.with_cert_resolver(resolver.clone());
		config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
		return Ok((config, resolver, None));
	}

	let verifier: Arc<ReloadingClientVerifier> = if policy.is_mandatory() {
		ReloadingClientVerifier::new(ca_cert_path, crl_path)?
	} else {
		ReloadingClientVerifier::new_optional(ca_cert_path, crl_path)?
	};

	let mut config: ServerConfig = ServerConfig::builder()
		.with_client_cert_verifier(verifier.clone())
		.with_cert_resolver(resolver.clone());

	config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

	return Ok((config, resolver, Some(verifier)));
}

// mTLS ClientConfig whose backend-server-cert trust uses a hot-reloadable ReloadingServerVerifier —
// returned for watcher wiring, so the backend CA rotates without a restart (root rollover, cross-sign).
pub fn build_client_config(
	cert_path: &Path,
	key_path: &Path,
	ca_cert_path: &Path,
) -> Result<(ClientConfig, Arc<ReloadingCertResolver>, Arc<ReloadingServerVerifier>)> {
	let resolver: Arc<ReloadingCertResolver> = Arc::new(ReloadingCertResolver::new(cert_path, key_path)?);
	let verifier: Arc<ReloadingServerVerifier> = ReloadingServerVerifier::new(ca_cert_path)?;

	// `dangerous()` only because rustls gates any custom verifier behind it — this is NOT an unsafe or
	// trust-weakening path: the verifier delegates to a real WebPkiServerVerifier doing full X.509 path
	// validation against the CA bundle. The wrapper exists solely to hot-swap the roots in place.
	let mut config: ClientConfig = ClientConfig::builder()
		.dangerous()
		.with_custom_certificate_verifier(verifier.clone())
		.with_client_cert_resolver(resolver.clone());

	config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

	return Ok((config, resolver, verifier));
}

// Client config from a caller-supplied resolver (e.g. a non-extractable TPM signer) instead of PEM key
// files. CA is still file-backed via a hot-reloadable verifier (returned for watcher wiring).
// `dyn ResolvesClientCert` is rustls's own resolver API — the documented trait-object exception.
pub fn build_client_config_with_resolver(
	resolver: Arc<dyn ResolvesClientCert>,
	ca_cert_path: &Path,
) -> Result<(ClientConfig, Arc<ReloadingServerVerifier>)> {
	let verifier: Arc<ReloadingServerVerifier> = ReloadingServerVerifier::new(ca_cert_path)?;

	// See build_client_config: dangerous() gates the custom verifier; validation is still full WebPKI.
	let mut config: ClientConfig = ClientConfig::builder()
		.dangerous()
		.with_custom_certificate_verifier(verifier.clone())
		.with_client_cert_resolver(resolver);

	config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

	return Ok((config, verifier));
}

// ACME provisions only the server cert; inbound client-cert trust still uses the hot-reloadable
// ReloadingClientVerifier (returned for watcher wiring). No CRL on this path — roots still hot-reload.
#[cfg(feature = "acme")]
pub fn build_acme_server_config(
	ca_cert_path: &Path,
	resolver: Arc<crate::tls::acme::AcmeCertResolver>,
) -> Result<(ServerConfig, Arc<ReloadingClientVerifier>)> {
	let (config, verifier) = build_acme_server_config_for_policy(ca_cert_path, resolver, ClientAuthPolicy::Required)?;
	let verifier: Arc<ReloadingClientVerifier> =
		verifier.ok_or_else(|| ReductionError::Config("required mTLS produced no client verifier".to_owned()))?;
	return Ok((config, verifier));
}

// ACME server config honoring the client-auth policy. Under `Disabled` (public-browser mode) no inbound
// verifier is built and an anonymous browser is served the ACME-provisioned cert with no CertificateRequest;
// `Required`/`Optional` build a reloadable client-cert verifier exactly as the manual path does. The
// tls-alpn-01 challenge is always answered by the separate no-client-auth challenge config, independent of
// this policy, so certificate provisioning is unaffected by the client-auth choice.
#[cfg(feature = "acme")]
pub fn build_acme_server_config_for_policy(
	ca_cert_path: &Path,
	resolver: Arc<crate::tls::acme::AcmeCertResolver>,
	policy: ClientAuthPolicy,
) -> Result<(ServerConfig, Option<Arc<ReloadingClientVerifier>>)> {
	if !policy.builds_verifier() {
		let mut config: ServerConfig = ServerConfig::builder()
			.with_no_client_auth()
			.with_cert_resolver(resolver);
		config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
		return Ok((config, None));
	}

	let verifier: Arc<ReloadingClientVerifier> = if policy.is_mandatory() {
		ReloadingClientVerifier::new(ca_cert_path, None)?
	} else {
		ReloadingClientVerifier::new_optional(ca_cert_path, None)?
	};

	let mut config: ServerConfig = ServerConfig::builder()
		.with_client_cert_verifier(verifier.clone())
		.with_cert_resolver(resolver);

	// Real traffic only. tls-alpn-01 validation is served by a separate no-client-auth config
	// (build_acme_challenge_config), selected per-ClientHello — the policy above governs real traffic only.
	config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

	return Ok((config, Some(verifier)));
}

// Build the config that answers ACME tls-alpn-01 validation: no client auth (the validator presents
// no certificate) and only the acme-tls/1 ALPN. The same resolver serves the challenge cert here
// (keyed by SNI) and the real cert on the mTLS config; the caller selects between the two per
// ClientHello so this config never carries application traffic.
#[cfg(feature = "acme")]
pub fn build_acme_challenge_config(resolver: Arc<crate::tls::acme::AcmeCertResolver>) -> ServerConfig {
	let mut config: ServerConfig = ServerConfig::builder()
		.with_no_client_auth()
		.with_cert_resolver(resolver);

	config.alpn_protocols = vec![b"acme-tls/1".to_vec()];

	return config;
}

#[cfg(test)]
mod tests {
	use rustls::client::ResolvesClientCert;
	#[cfg(feature = "acme")]
	use rustls::pki_types::UnixTime;
	#[cfg(feature = "acme")]
	use rustls::server::danger::ClientCertVerifier;
	use tempfile::NamedTempFile;

	use super::*;
	use crate::test_support::{generate_ca, generate_localhost_cert, write_pem};

	fn setup_pki() -> (NamedTempFile, NamedTempFile, NamedTempFile) {
		let ca = generate_ca();
		let leaf = generate_localhost_cert(&ca);

		let ca_file = write_pem(&ca.cert.pem());
		let cert_file = write_pem(&leaf.cert.pem());
		let key_file = write_pem(&leaf.signing_key.serialize_pem());

		return (cert_file, key_file, ca_file);
	}

	#[test]
	fn test_load_certs_valid() {
		let ca = generate_ca();
		let f = write_pem(&ca.cert.pem());
		let certs = load_certs(f.path()).unwrap();
		assert_eq!(certs.len(), 1);
	}

	#[test]
	fn test_load_certs_missing_file() {
		let result = load_certs(Path::new("/nonexistent/cert.pem"));
		assert!(result.is_err());
		let msg = format!("{}", result.unwrap_err());
		assert!(msg.contains("failed to open cert file"));
	}

	#[test]
	fn test_load_certs_empty_file() {
		let f = write_pem("");
		let result = load_certs(f.path());
		assert!(result.is_err());
		let msg = format!("{}", result.unwrap_err());
		assert!(msg.contains("no certificates found"));
	}

	#[test]
	fn test_load_certs_invalid_pem() {
		let f = write_pem("not a pem file at all");
		let result = load_certs(f.path());
		assert!(result.is_err());
	}

	#[test]
	fn test_load_private_key_valid() {
		let ca = generate_ca();
		let f = write_pem(&ca.signing_key.serialize_pem());
		let _key = load_private_key(f.path()).unwrap();
	}

	#[test]
	fn test_load_private_key_missing_file() {
		let result = load_private_key(Path::new("/nonexistent/key.pem"));
		assert!(result.is_err());
		let msg = format!("{}", result.unwrap_err());
		assert!(msg.contains("failed to open key file"));
	}

	#[test]
	fn test_load_private_key_invalid_pem() {
		let f = write_pem("garbage data");
		let result = load_private_key(f.path());
		assert!(result.is_err());
		let msg = format!("{}", result.unwrap_err());
		assert!(msg.contains("failed to parse private key"));
	}

	#[test]
	fn test_load_ca_certs_valid() {
		let ca = generate_ca();
		let f = write_pem(&ca.cert.pem());
		let store = load_ca_certs(f.path()).unwrap();
		assert!(!store.is_empty());
	}

	#[test]
	fn test_load_ca_certs_missing_file() {
		let result = load_ca_certs(Path::new("/nonexistent/ca.pem"));
		assert!(result.is_err());
	}

	#[test]
	fn test_build_server_config_valid() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let (cert_file, key_file, ca_file) = setup_pki();
		let result = build_server_config(cert_file.path(), key_file.path(), ca_file.path());
		assert!(result.is_ok());
		let (_config, resolver) = result.unwrap();
		assert!(!resolver.current().cert.is_empty());
	}

	#[test]
	fn test_build_server_config_bad_cert() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let ca_file = write_pem(&ca.cert.pem());
		let key_file = write_pem(&ca.signing_key.serialize_pem());
		let bad_cert = write_pem("not a cert");

		let result = build_server_config(bad_cert.path(), key_file.path(), ca_file.path());
		assert!(result.is_err());
	}

	#[test]
	fn test_build_client_config_valid() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let (cert_file, key_file, ca_file) = setup_pki();
		let result = build_client_config(cert_file.path(), key_file.path(), ca_file.path());
		assert!(result.is_ok());
		let (_config, resolver, _verifier) = result.unwrap();
		assert!(resolver.has_certs());
	}

	#[test]
	fn test_build_client_config_bad_key() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let cert_file = write_pem(&ca.cert.pem());
		let ca_file = write_pem(&ca.cert.pem());
		let bad_key = write_pem("not a key");

		let result = build_client_config(cert_file.path(), bad_key.path(), ca_file.path());
		assert!(result.is_err());
	}

	#[test]
	fn test_build_client_config_with_resolver() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let (cert_file, key_file, ca_file) = setup_pki();
		// Reuse the file-backed resolver as a stand-in for any ResolvesClientCert (e.g. a TPM
		// signer): the point is the config builds from a resolver + CA file, no client key path.
		let resolver: Arc<ReloadingCertResolver> =
			Arc::new(ReloadingCertResolver::new(cert_file.path(), key_file.path()).unwrap());
		let result = build_client_config_with_resolver(resolver, ca_file.path());
		assert!(result.is_ok());
	}

	#[test]
	fn test_build_client_config_with_resolver_bad_ca() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let (cert_file, key_file, _ca_file) = setup_pki();
		let resolver: Arc<ReloadingCertResolver> =
			Arc::new(ReloadingCertResolver::new(cert_file.path(), key_file.path()).unwrap());
		let result = build_client_config_with_resolver(resolver, Path::new("/nonexistent/ca.pem"));
		assert!(result.is_err());
	}

	fn empty_crl_pem(ca: &rcgen::CertifiedKey<rcgen::KeyPair>) -> String {
		let params = rcgen::CertificateRevocationListParams {
			this_update: rcgen::date_time_ymd(2020, 1, 1),
			next_update: rcgen::date_time_ymd(2100, 1, 1),
			crl_number: rcgen::SerialNumber::from(1u64),
			issuing_distribution_point: None,
			revoked_certs: vec![],
			key_identifier_method: rcgen::KeyIdMethod::Sha256,
		};
		let issuer = rcgen::Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key).unwrap();
		return params.signed_by(&issuer).unwrap().pem().unwrap();
	}

	#[test]
	fn test_build_server_config_reloadable_with_crl_valid() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let leaf = generate_localhost_cert(&ca);
		let cert_file = write_pem(&leaf.cert.pem());
		let key_file = write_pem(&leaf.signing_key.serialize_pem());
		let ca_file = write_pem(&ca.cert.pem());
		let crl_file = write_pem(&empty_crl_pem(&ca));

		let result =
			build_server_config_reloadable(cert_file.path(), key_file.path(), ca_file.path(), Some(crl_file.path()));
		assert!(result.is_ok(), "a valid CRL config must build");
		let (_config, resolver, _verifier) = result.unwrap();
		assert!(!resolver.current().cert.is_empty());
	}

	#[test]
	fn test_build_server_config_reloadable_no_crl_valid() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let (cert_file, key_file, ca_file) = setup_pki();
		// No CRL: roots still reload; verification just carries no handshake-level revocation.
		let result = build_server_config_reloadable(cert_file.path(), key_file.path(), ca_file.path(), None);
		assert!(result.is_ok(), "a reloadable config without a CRL must build");
	}

	#[test]
	fn test_build_server_config_reloadable_bad_crl_errors() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let (cert_file, key_file, ca_file) = setup_pki();
		let result = build_server_config_reloadable(
			cert_file.path(),
			key_file.path(),
			ca_file.path(),
			Some(Path::new("/nonexistent/crl.pem")),
		);
		assert!(result.is_err(), "a missing CRL file must fail the build");
	}

	#[test]
	fn test_build_server_config_reloadable_empty_ca_errors() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let leaf = generate_localhost_cert(&ca);
		let cert_file = write_pem(&leaf.cert.pem());
		let key_file = write_pem(&leaf.signing_key.serialize_pem());
		let empty_ca = write_pem("");
		// An empty CA bundle at boot must fail-fast rather than start with an empty trust store.
		let result = build_server_config_reloadable(cert_file.path(), key_file.path(), empty_ca.path(), None);
		assert!(result.is_err(), "an empty CA bundle must fail the build at boot");
	}

	// The client-auth policy governs whether an inbound verifier is built: Disabled builds none (public
	// browser mode), Required/Optional build one for watcher wiring. This is the structural half; the
	// functional half (an anonymous handshake actually succeeds under Disabled) lives in transport::tcp.
	#[test]
	fn test_build_server_config_for_policy_verifier_presence() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let (cert_file, key_file, ca_file) = setup_pki();

		let (_c, _r, disabled) =
			build_server_config_for_policy(cert_file.path(), key_file.path(), ca_file.path(), None, ClientAuthPolicy::Disabled)
				.unwrap();
		assert!(disabled.is_none(), "disabled policy must build no inbound client-cert verifier");

		let (_c, _r, required) =
			build_server_config_for_policy(cert_file.path(), key_file.path(), ca_file.path(), None, ClientAuthPolicy::Required)
				.unwrap();
		assert!(required.is_some(), "required policy must build an inbound client-cert verifier");

		let (_c, _r, optional) =
			build_server_config_for_policy(cert_file.path(), key_file.path(), ca_file.path(), None, ClientAuthPolicy::Optional)
				.unwrap();
		assert!(optional.is_some(), "optional policy must build an inbound client-cert verifier");
	}

	// Disabled builds no verifier even with a garbage CA path — the CA is unused in public-browser mode,
	// so an operator running a public blog needn't supply a valid client-CA bundle to serve anonymous traffic.
	#[test]
	fn test_build_server_config_for_policy_disabled_ignores_ca() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let (cert_file, key_file, _ca_file) = setup_pki();
		let result = build_server_config_for_policy(
			cert_file.path(),
			key_file.path(),
			Path::new("/nonexistent/ca.pem"),
			None,
			ClientAuthPolicy::Disabled,
		);
		assert!(result.is_ok(), "disabled policy must not read the client CA bundle");
		assert!(result.unwrap().2.is_none());
	}

	#[test]
	fn test_load_multiple_certs() {
		let ca1 = generate_ca();
		let ca2 = generate_ca();
		let combined = format!("{}{}", ca1.cert.pem(), ca2.cert.pem());
		let f = write_pem(&combined);
		let certs = load_certs(f.path()).unwrap();
		assert_eq!(certs.len(), 2);
	}

	// The ACME path provisions only the server cert; inbound client-cert trust must still hot-reload.
	// Functional diff: the verifier the ACME config trusts rejects a new-CA client leaf before the CA
	// bundle is rotated on disk and accepts the SAME leaf after reload() — proving build_acme_server_config
	// wires the reloadable verifier, not the old immutable one.
	#[test]
	#[cfg(feature = "acme")]
	fn test_build_acme_server_config_trust_hot_reloads() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca_old = generate_ca();
		let ca_new = generate_ca();
		let new_leaf = generate_localhost_cert(&ca_new);

		let ca_file = write_pem(&ca_old.cert.pem());
		let resolver: Arc<crate::tls::acme::AcmeCertResolver> = Arc::new(crate::tls::acme::AcmeCertResolver::new());
		let (_config, verifier) = build_acme_server_config(ca_file.path(), resolver).unwrap();

		assert!(
			verifier
				.verify_client_cert(new_leaf.cert.der(), &[], UnixTime::now())
				.is_err(),
			"new-CA client leaf must be rejected before rotation",
		);

		std::fs::write(ca_file.path(), ca_new.cert.pem()).unwrap();
		verifier.reload().unwrap();
		assert!(
			verifier
				.verify_client_cert(new_leaf.cert.der(), &[], UnixTime::now())
				.is_ok(),
			"new-CA client leaf must be accepted after rotating the ACME trust bundle",
		);
	}
}
