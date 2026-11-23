// The ACME server-cert resolver: the provisioned cert, swapped lock-free on renewal, plus live tls-alpn-01
// challenge certs served by SNI to the validator.
use std::sync::Arc;

use arrayvec::ArrayString;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use solo::lease::{Lease, Leased};
use vasco::tls::ACME_TLS_ALPN_PROTO;

use crate::config::MAX_HOST_LEN;
use crate::error::{ReductionError, Result};
use crate::lease::LEASES;
use crate::snapshot_map::SnapshotMap;

pub struct AcmeCertResolver {
	// Lock-free: read on every non-challenge handshake, stored only on provision/renewal.
	pub cert: Leased<Option<Arc<CertifiedKey>>>,
	// tls-alpn-01 certs keyed by SNI. A map, not one slot: instant-acme polls the whole order, so every
	// domain's challenge stays live at once.
	challenge_certs: SnapshotMap<ArrayString<MAX_HOST_LEN>, Arc<CertifiedKey>>,
}

impl std::fmt::Debug for AcmeCertResolver {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		return f
			.debug_struct("AcmeCertResolver")
			.field("has_cert", &self.has_cert())
			.finish();
	}
}

impl Default for AcmeCertResolver {
	fn default() -> Self {
		return Self::new();
	}
}

impl AcmeCertResolver {
	#[must_use]
	pub fn new() -> Self {
		return Self {
			cert: Leased::empty(LEASES),
			challenge_certs: SnapshotMap::new(),
		};
	}

	pub fn set_cert(&self, key: CertifiedKey) {
		self.cert.store(Some(Arc::new(key)));
	}

	// Install the tls-alpn-01 challenge cert for a single domain (SNI). It replaces an earlier cert for that
	// domain. Call it once per domain before you signal the challenge ready. All certs stay live until the order resolves.
	pub fn set_challenge_cert(&self, domain: &str, key: CertifiedKey) -> Result<()> {
		let name: ArrayString<MAX_HOST_LEN> = ArrayString::from(domain).map_err(|_| {
			return ReductionError::Acme(format!("challenge domain is over {MAX_HOST_LEN} bytes: {domain}").into());
		})?;
		let key: Arc<CertifiedKey> = Arc::new(key);
		let _replaced: Option<Arc<CertifiedKey>> = self.challenge_certs.update(|map| return map.insert(name, key));
		return Ok(());
	}

	// Drop every challenge cert once the order is ready (or on failure). After this, the resolver
	// serves only the real certificate.
	pub fn clear_challenge_certs(&self) {
		self.challenge_certs.update(|map| map.clear());
	}

	pub fn has_cert(&self) -> bool {
		return self.cert.load().is_some();
	}
}

impl ResolvesServerCert for AcmeCertResolver {
	fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		if let Some(alpn) = client_hello.alpn() {
			for proto in alpn {
				if proto == ACME_TLS_ALPN_PROTO {
					// The ACME validator connects with SNI set to the domain under validation; serve
					// that domain's challenge cert. No SNI / unknown domain → no challenge cert.
					let sni: &str = client_hello.server_name()?;
					return self.challenge_certs.read(sni, Arc::clone);
				}
			}
		}
		return Lease::into_inner(self.cert.lease());
	}
}

#[cfg(test)]
mod tests {
	use std::result::Result;

	use rcgen::{Certificate, CertificateParams, KeyPair};
	use rustls::{ClientConfig, ServerConfig};
	use rustls::crypto::aws_lc_rs::sign::any_ecdsa_type;
	use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
	use rustls::sign::SigningKey;

	use super::*;
	use crate::test_support::handshake::{Observed, handshake, no_resumption, roots_of, served_epoch, trusting};
	use crate::test_support::{generate_ca, generate_localhost_cert};
	use crate::tls::build_acme_challenge_config;
	use crate::tls::acme::build_certified_key_from_pem;

	fn to_certified(leaf: &rcgen::CertifiedKey<KeyPair>) -> Result<CertifiedKey, String> {
		return match build_certified_key_from_pem(&leaf.cert.pem(), &leaf.signing_key.serialize_pem()) {
			Ok(value) => Ok(value),
			Err(err) => Err(format!("build_certified_key_from_pem(leaf): {err:?}")),
		};
	}

	// The leaf `server` presents in one handshake with `client`.
	fn served_leaf(
		server: Arc<ServerConfig>,
		client: Arc<rustls::ClientConfig>,
	) -> Result<CertificateDer<'static>, String> {
		return match handshake(server, client) {
			Ok(Ok(value)) => Ok(value),
			Ok(Err(err)) => Err(format!("handshake(server, client): {err:?}")),
			Err(err) => Err(format!("handshake harness: {err}")),
		};
	}

	// A CA with two localhost leaves under it: the provisioned (old) cert and its renewal (new).
	fn ca_with_renewal() -> Result<[rcgen::CertifiedKey<KeyPair>; 3], String> {
		let ca: rcgen::CertifiedKey<KeyPair> = match generate_ca() {
			Ok(value) => value,
			Err(err) => return Err(format!("generate_ca(): {err}")),
		};
		let old_leaf: rcgen::CertifiedKey<KeyPair> = match generate_localhost_cert(&ca) {
			Ok(value) => value,
			Err(err) => return Err(format!("generate_localhost_cert(&ca): {err}")),
		};
		return match generate_localhost_cert(&ca) {
			Ok(new_leaf) => Ok([ca, old_leaf, new_leaf]),
			Err(err) => Err(format!("generate_localhost_cert(&ca): {err}")),
		};
	}

	// Renews the served cert under a ServerConfig built once, then handshakes again. `apply_swap` is the
	// switch: off skips set_cert (no Leased store), on installs the renewed cert.
	fn served_after_renewal(apply_swap: bool) -> Result<Observed, String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let [ca, old_leaf, new_leaf] = match ca_with_renewal() {
			Ok(value) => value,
			Err(err) => return Err(format!("ca_with_renewal(): {err}")),
		};

		let resolver: Arc<AcmeCertResolver> = Arc::new(AcmeCertResolver::new());
		resolver.set_cert(match to_certified(&old_leaf) {
			Ok(value) => value,
			Err(err) => return Err(format!("to_certified(&old_leaf): {err}")),
		});
		let live_resolver: Arc<AcmeCertResolver> = Arc::clone(&resolver);
		let server: Arc<ServerConfig> = Arc::new(
			ServerConfig::builder()
				.with_no_client_auth()
				.with_cert_resolver(live_resolver),
		);
		let client: Arc<ClientConfig> = match trusting(&ca) {
			Ok(value) => value,
			Err(err) => return Err(format!("trusting(&ca): {err}")),
		};

		let before: CertificateDer<'static> = match served_leaf(Arc::clone(&server), Arc::clone(&client)) {
			Ok(value) => value,
			Err(err) => return Err(format!("served_leaf before renewal: {err}")),
		};
		assert_eq!(
			served_epoch(&before, &old_leaf, &new_leaf),
			Observed::Old,
			"the provisioned cert is served before renewal"
		);

		let renewed: CertifiedKey = match to_certified(&new_leaf) {
			Ok(value) => value,
			Err(err) => return Err(format!("to_certified(&new_leaf): {err}")),
		};
		if apply_swap {
			resolver.set_cert(renewed);
		}
		let after: CertificateDer<'static> = match served_leaf(server, client) {
			Ok(value) => value,
			Err(err) => return Err(format!("served_leaf after renewal: {err}")),
		};
		return Ok(served_epoch(&after, &old_leaf, &new_leaf));
	}

	#[test]
	fn test_handshake_serves_renewed_cert_only_after_set_cert() -> Result<(), String> {
		let without_swap: Observed = match served_after_renewal(false) {
			Ok(value) => value,
			Err(err) => return Err(format!("served_after_renewal(false): {err}")),
		};
		let with_swap: Observed = match served_after_renewal(true) {
			Ok(value) => value,
			Err(err) => return Err(format!("served_after_renewal(true): {err}")),
		};
		assert_eq!(
			without_swap,
			Observed::Old,
			"no store: the live config keeps serving the old cert"
		);
		assert_eq!(
			with_swap,
			Observed::New,
			"after store: the same live config serves the renewed cert"
		);
		assert_ne!(
			without_swap, with_swap,
			"the swap is the only difference between the two runs"
		);
		return Ok(());
	}

	#[test]
	fn test_resolver_returns_none_initially() {
		let resolver: AcmeCertResolver = AcmeCertResolver::new();
		assert!(!resolver.has_cert());
	}

	#[test]
	fn test_resolver_set_and_get_cert() -> Result<(), String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

		let resolver: AcmeCertResolver = AcmeCertResolver::new();

		let key_pair: KeyPair = match KeyPair::generate() {
			Ok(value) => value,
			Err(err) => return Err(format!("KeyPair::generate(): {err:?}")),
		};
		let params: CertificateParams = match CertificateParams::new(vec!["test.example.com".to_owned()]) {
			Ok(value) => value,
			Err(err) => return Err(format!("CertificateParams::new(vec![\"test.example.com\"...: {err:?}")),
		};
		let cert: Certificate = match params.self_signed(&key_pair) {
			Ok(value) => value,
			Err(err) => return Err(format!("params.self_signed(&key_pair): {err:?}")),
		};
		let cert_der: CertificateDer<'static> = CertificateDer::from(cert.der().to_vec());
		let key_der: PrivatePkcs8KeyDer<'static> = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
		let signing_key: Arc<dyn SigningKey> = match any_ecdsa_type(&PrivateKeyDer::Pkcs8(key_der)) {
			Ok(value) => value,
			Err(err) => return Err(format!("any_ecdsa_type(&PrivateKeyDer::Pkcs8(key_der)): {err:?}")),
		};
		let certified: CertifiedKey = CertifiedKey::new(vec![cert_der], signing_key);

		resolver.set_cert(certified);
		assert!(resolver.has_cert());
		return Ok(());
	}

	fn dummy_certified_key(domain: &str) -> Result<CertifiedKey, String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let key_pair: KeyPair = match KeyPair::generate() {
			Ok(value) => value,
			Err(err) => return Err(format!("KeyPair::generate(): {err:?}")),
		};
		let params: CertificateParams = match CertificateParams::new(vec![domain.to_owned()]) {
			Ok(value) => value,
			Err(err) => return Err(format!("CertificateParams::new(vec![domain.to_string()]): {err:?}")),
		};
		let cert: Certificate = match params.self_signed(&key_pair) {
			Ok(value) => value,
			Err(err) => return Err(format!("params.self_signed(&key_pair): {err:?}")),
		};
		let cert_der: CertificateDer<'static> = CertificateDer::from(cert.der().to_vec());
		let key_der: PrivatePkcs8KeyDer<'static> = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
		let signing_key: Arc<dyn SigningKey> = match any_ecdsa_type(&PrivateKeyDer::Pkcs8(key_der)) {
			Ok(value) => value,
			Err(err) => return Err(format!("any_ecdsa_type(&PrivateKeyDer::Pkcs8(key_der)): {err:?}")),
		};
		return Ok(CertifiedKey::new(vec![cert_der], signing_key));
	}

	// Install a fresh self-signed challenge cert for `domain`. Returns its leaf DER, so a test can tell certs apart.
	fn install(resolver: &AcmeCertResolver, domain: &str) -> Result<CertificateDer<'static>, String> {
		let key: CertifiedKey = dummy_certified_key(domain).map_err(|err| format!("dummy_certified_key({domain}): {err}"))?;
		let leaf: CertificateDer<'static> = key.cert.first().cloned().ok_or("dummy cert has no leaf")?;
		resolver
			.set_challenge_cert(domain, key)
			.map_err(|err| format!("set_challenge_cert({domain}): {err}"))?;
		return Ok(leaf);
	}

	fn stored_leaf(resolver: &AcmeCertResolver, domain: &str) -> Option<CertificateDer<'static>> {
		return resolver.challenge_certs.read(domain, |key| return key.cert.first().cloned()).flatten();
	}

	#[test]
	fn test_challenge_certs_stored_per_domain() -> Result<(), String> {
		let resolver: AcmeCertResolver = AcmeCertResolver::new();
		let a: CertificateDer<'static> = install(&resolver, "a.example.com")?;
		let b: CertificateDer<'static> = install(&resolver, "b.example.com")?;
		assert_eq!(resolver.challenge_certs.len(), 2);
		assert_eq!(stored_leaf(&resolver, "a.example.com"), Some(a));
		assert_eq!(stored_leaf(&resolver, "b.example.com"), Some(b));
		return Ok(());
	}

	#[test]
	fn test_set_challenge_cert_overwrites_same_domain() -> Result<(), String> {
		let resolver: AcmeCertResolver = AcmeCertResolver::new();
		let first: CertificateDer<'static> = install(&resolver, "a.example.com")?;
		let second: CertificateDer<'static> = install(&resolver, "a.example.com")?;
		assert_ne!(first, second, "the fixture must make two distinct certs");
		assert_eq!(resolver.challenge_certs.len(), 1);
		assert_eq!(stored_leaf(&resolver, "a.example.com"), Some(second), "the later cert replaces the earlier");
		return Ok(());
	}

	#[test]
	fn test_clear_challenge_certs_empties_map() -> Result<(), String> {
		let resolver: AcmeCertResolver = AcmeCertResolver::new();
		install(&resolver, "a.example.com")?;
		install(&resolver, "b.example.com")?;
		resolver.clear_challenge_certs();
		assert!(resolver.challenge_certs.is_empty());
		return Ok(());
	}

	#[test]
	fn test_challenge_certs_do_not_affect_real_cert() -> Result<(), String> {
		let resolver: AcmeCertResolver = AcmeCertResolver::new();
		install(&resolver, "a.example.com")?;
		// A challenge cert must not make the resolver report a provisioned real cert.
		assert!(!resolver.has_cert());
		return Ok(());
	}

	#[test]
	fn test_set_challenge_cert_refuses_a_domain_over_the_dns_limit() -> Result<(), String> {
		let resolver: AcmeCertResolver = AcmeCertResolver::new();
		let at_limit: String = "a".repeat(MAX_HOST_LEN);
		let over_limit: String = "a".repeat(MAX_HOST_LEN + 1);
		let key: CertifiedKey = dummy_certified_key("a.example.com")?;
		assert!(resolver.set_challenge_cert(&at_limit, key).is_ok(), "{MAX_HOST_LEN} bytes fits");
		let key: CertifiedKey = dummy_certified_key("a.example.com")?;
		assert!(matches!(resolver.set_challenge_cert(&over_limit, key), Err(ReductionError::Acme(_))));
		assert_eq!(resolver.challenge_certs.len(), 1, "the refused domain stores nothing");
		return Ok(());
	}

	// A tls-alpn-01 validator: offers only acme-tls/1 and trusts `ca`.
	fn validator(ca: &rcgen::CertifiedKey<KeyPair>) -> Result<Arc<ClientConfig>, String> {
		let mut config: ClientConfig = ClientConfig::builder()
			.with_root_certificates(roots_of(ca)?)
			.with_no_client_auth();
		config.alpn_protocols = vec![ACME_TLS_ALPN_PROTO.to_vec()];
		return Ok(no_resumption(config));
	}

	// Through the production challenge config: the validator gets the cert stored for its SNI, and nothing
	// before that cert is set or after the clear. A client without acme-tls/1 always gets the real cert.
	#[test]
	fn test_validator_is_served_its_sni_challenge_cert_until_cleared() -> Result<(), String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let [ca, real_leaf, challenge_leaf] = ca_with_renewal()?;
		let resolver: Arc<AcmeCertResolver> = Arc::new(AcmeCertResolver::new());
		resolver.set_cert(to_certified(&real_leaf)?);
		let server: Arc<ServerConfig> = Arc::new(build_acme_challenge_config(Arc::clone(&resolver)));
		let acme: Arc<ClientConfig> = validator(&ca)?;
		let plain: Arc<ClientConfig> = trusting(&ca)?;

		install(&resolver, "other.example.com")?;
		let other_sni: Result<CertificateDer<'static>, rustls::Error> = handshake(Arc::clone(&server), Arc::clone(&acme))?;
		assert!(other_sni.is_err(), "a cert for another domain must not answer SNI localhost");

		resolver
			.set_challenge_cert("localhost", to_certified(&challenge_leaf)?)
			.map_err(|err| format!("set_challenge_cert(localhost): {err}"))?;
		let served: CertificateDer<'static> = served_leaf(Arc::clone(&server), Arc::clone(&acme))?;
		assert_eq!(served_epoch(&served, &real_leaf, &challenge_leaf), Observed::New, "the validator gets the challenge cert");
		let real: CertificateDer<'static> = served_leaf(Arc::clone(&server), Arc::clone(&plain))?;
		assert_eq!(served_epoch(&real, &real_leaf, &challenge_leaf), Observed::Old, "other clients get the real cert");

		resolver.clear_challenge_certs();
		let cleared: Result<CertificateDer<'static>, rustls::Error> = handshake(Arc::clone(&server), acme)?;
		assert!(cleared.is_err(), "after the clear the validator gets no cert");
		let real: CertificateDer<'static> = served_leaf(server, plain)?;
		assert_eq!(served_epoch(&real, &real_leaf, &challenge_leaf), Observed::Old, "the clear keeps the real cert");
		return Ok(());
	}
}
