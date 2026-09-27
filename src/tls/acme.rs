use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use instant_acme::{
	Account, AccountBuilder, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, KeyAuthorization,
	NewAccount, NewOrder, Order, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::crypto::aws_lc_rs::sign::any_ecdsa_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::{Error as RustlsError, InconsistentKeys};
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{error, info, warn};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::config::AcmeTlsConfig;
use crate::error::{ReductionError, Result};
use crate::metrics::ProxyMetrics;
use crate::tls::secret_state::{AcmeSecretState, SecretStore};

const ACME_TLS_ALPN_PROTO: &[u8] = b"acme-tls/1";
const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];
const ACME_RENEWAL_BUFFER_SECS: u64 = 30 * 24 * 60 * 60;
const ACME_RETRY_INTERVAL_SECS: u64 = 43200;
// Exponential backoff floor after consecutive failed renewals. A cert inside the renewal window
// makes time_until_renewal_from_certified return ZERO, so without this floor a failing renewal
// re-orders immediately in a hot loop — exhausting the CA's failed-validation rate limit (Let's
// Encrypt: 5/hour) exactly when the remaining cert runway is shortest. 5 min doubling to a 6 h cap
// keeps the first hour at ≤4 attempts.
const ACME_FAILURE_BACKOFF_BASE_SECS: u64 = 300;
const ACME_FAILURE_BACKOFF_MAX_SECS: u64 = 21_600;
// Cap the doublings well below the shift width; the seconds cap is reached long before this.
const ACME_FAILURE_BACKOFF_MAX_DOUBLINGS: u32 = 16;
const ACME_POLL_INTERVAL_SECS: u64 = 5;
const ACME_MAX_POLL_ATTEMPTS: u32 = 60;
// DER OCTET STRING wrapping a SHA-256 digest: 1-byte tag + 1-byte length + 32-byte digest.
const SHA256_DIGEST_DER_OCTET_STRING_LEN: usize = 34;
// Backoff factor of 1.0 keeps a fixed poll interval, matching the previous manual loop's cadence.
const RETRY_CONSTANT_BACKOFF: f32 = 1.0;
const LETS_ENCRYPT_PRODUCTION_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LETS_ENCRYPT_STAGING_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

pub struct AcmeCertResolver {
	pub cert: parking_lot::RwLock<Option<Arc<CertifiedKey>>>,
	// tls-alpn-01 challenge certs, keyed by the SNI hostname the ACME server validates against. A
	// map (not a single slot) is required because instant-acme's order-level readiness polling keeps
	// every domain's challenge live simultaneously rather than validating one authorization at a time.
	challenge_certs: parking_lot::RwLock<HashMap<String, Arc<CertifiedKey>>>,
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
			cert: parking_lot::RwLock::new(None),
			challenge_certs: parking_lot::RwLock::new(HashMap::new()),
		};
	}

	pub fn set_cert(&self, key: CertifiedKey) {
		let mut guard = self.cert.write();
		*guard = Some(Arc::new(key));
	}

	// Install the tls-alpn-01 challenge cert for a single domain (SNI). Called once per domain
	// before signalling the challenge ready; all installed certs stay live until the order resolves.
	pub fn set_challenge_cert(&self, domain: &str, key: CertifiedKey) {
		let mut guard = self.challenge_certs.write();
		guard.insert(domain.to_owned(), Arc::new(key));
	}

	// Drop every challenge cert once the order is ready (or on failure), returning the resolver to
	// serving only the real certificate.
	pub fn clear_challenge_certs(&self) {
		let mut guard = self.challenge_certs.write();
		guard.clear();
	}

	pub fn has_cert(&self) -> bool {
		return self.cert.read().is_some();
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
					return self.challenge_certs.read().get(sni).cloned();
				}
			}
		}
		return self.cert.read().clone();
	}
}

pub struct AcmeRenewalTask {
	config: AcmeTlsConfig,
	resolver: Arc<AcmeCertResolver>,
	shutdown: watch::Receiver<()>,
	metrics: ProxyMetrics,
	// Opaque secret-state custody: a plaintext cache-dir file, or Barrel (env-in, pinned-command-out).
	// Chosen from `config` at construction so the renewal loop never touches the filesystem directly.
	store: SecretStore,
}

impl AcmeRenewalTask {
	pub fn new(
		config: AcmeTlsConfig,
		resolver: Arc<AcmeCertResolver>,
		shutdown: watch::Receiver<()>,
		metrics: ProxyMetrics,
	) -> Self {
		let store: SecretStore = SecretStore::from_acme_config(&config);
		return Self {
			config,
			resolver,
			shutdown,
			metrics,
			store,
		};
	}

	pub async fn provision_initial_cert(&self) -> Result<()> {
		let mut cached: Option<CertifiedKey> = self.load_cached_cert();
		if let Some(certified_key) = cached.take() {
			let renewal_in: Duration = time_until_renewal_from_certified(&certified_key);
			if renewal_in > Duration::ZERO {
				info!(renewal_in_secs = renewal_in.as_secs(), "loaded cached ACME certificate");
				self.resolver.set_cert(certified_key);
				return Ok(());
			}
			info!("cached ACME certificate is within renewal window, provisioning new one");
			cached = Some(certified_key);
		}

		return match self.provision_cert().await {
			Ok(certified_key) => {
				self.metrics.acme_renewals_total.add(1, &[]);
				self.resolver.set_cert(certified_key);
				Ok(())
			}
			Err(e) => {
				self.metrics.acme_renewal_failures_total.add(1, &[]);
				self.serve_stale_or_fail(cached, e)
			}
		};
	}

	// Serve-stale: a restart during a CA outage must not brick the proxy while it holds a cert that is
	// merely inside the renewal window, not expired. Serve the cached cert and let the renewal loop
	// (with failure backoff) keep retrying; propagate the error only when no still-valid cached cert
	// remains to fall back to.
	fn serve_stale_or_fail(&self, cached: Option<CertifiedKey>, e: ReductionError) -> Result<()> {
		return match cached {
			Some(certified_key) if time_until_expiry_from_certified(&certified_key) > Duration::ZERO => {
				warn!(error = %e, "initial ACME provisioning failed; serving still-valid cached certificate");
				self.resolver.set_cert(certified_key);
				Ok(())
			}
			_ => Err(e),
		};
	}

	// tokio::select! expands to a large poll state machine that inflates clippy's cognitive-complexity
	// score far past the threshold; the real control flow here (sleep-or-shutdown, then record the
	// renewal outcome) is simple. Documented allow rather than contorting the loop to fool the metric.
	#[allow(clippy::cognitive_complexity)]
	pub async fn run(mut self) {
		let mut consecutive_failures: u32 = 0;
		loop {
			let sleep_duration: Duration = self.next_renewal_sleep(consecutive_failures);

			info!(
				sleep_secs = sleep_duration.as_secs(),
				consecutive_failures, "ACME renewal loop sleeping"
			);

			tokio::select! {
				_ = sleep(sleep_duration) => {}
				_ = self.shutdown.changed() => {
					info!("ACME renewal task shutting down");
					return;
				}
			}

			match self.provision_cert().await {
				Ok(certified_key) => {
					consecutive_failures = 0;
					self.metrics.acme_renewals_total.add(1, &[]);
					info!("ACME certificate renewed successfully");
					self.resolver.set_cert(certified_key);
				}
				Err(e) => {
					consecutive_failures = consecutive_failures.saturating_add(1);
					self.metrics.acme_renewal_failures_total.add(1, &[]);
					error!(error = %e, consecutive_failures,
                        "ACME certificate renewal failed, backing off before retry");
				}
			}
		}
	}

	// Sleep before the next renewal attempt: the cert's own renewal window, floored by the failure
	// backoff so a failing renewal cannot spin in a zero-delay order storm.
	fn next_renewal_sleep(&self, consecutive_failures: u32) -> Duration {
		let renewal_in: Duration = {
			let cert_guard = self.resolver.cert.read();
			match cert_guard.as_ref() {
				Some(key) => time_until_renewal_from_certified(key),
				None => Duration::from_secs(ACME_RETRY_INTERVAL_SECS),
			}
		};
		return renewal_in.max(failure_backoff(consecutive_failures));
	}

	async fn provision_cert(&self) -> Result<CertifiedKey> {
		// A configured directory URL (private ACME CA / pebble) wins; otherwise pick the Let's
		// Encrypt endpoint by staging flag.
		let directory_url: &str = match self.config.directory_url.as_deref() {
			Some(url) => url,
			None if self.config.staging => LETS_ENCRYPT_STAGING_URL,
			None => LETS_ENCRYPT_PRODUCTION_URL,
		};

		// Load the current opaque state once (account creds + any cached cert/key), then thread it
		// through account setup and finalize so each persist writes the whole blob atomically.
		let mut state: AcmeSecretState = self.store.load()?.unwrap_or_default();

		let account: Account = self.get_or_create_account(directory_url, &mut state).await?;

		let identifiers: Vec<Identifier> = self
			.config
			.domains
			.iter()
			.map(|d| Identifier::Dns(d.to_string()))
			.collect();

		let mut order = account
			.new_order(&NewOrder::new(&identifiers))
			.await
			.map_err(|e| ReductionError::Acme(format!("failed to create order: {e}")))?;

		// Fixed-cadence retry budget preserving the previous manual loop (interval × max attempts).
		let retry_policy: RetryPolicy = RetryPolicy::default()
			.initial_delay(Duration::from_secs(ACME_POLL_INTERVAL_SECS))
			.backoff(RETRY_CONSTANT_BACKOFF)
			.timeout(Duration::from_secs(
				ACME_POLL_INTERVAL_SECS * u64::from(ACME_MAX_POLL_ATTEMPTS),
			));

		// instant-acme locks each authorization handle once its challenge is taken, so readiness is
		// polled at order level (below), not per-authz — hence the per-SNI challenge-cert map.
		{
			let mut authorizations = order.authorizations();
			while let Some(result) = authorizations.next().await {
				let mut authz =
					result.map_err(|e| ReductionError::Acme(format!("failed to get authorization: {e}")))?;
				match authz.status {
					AuthorizationStatus::Valid => continue,
					AuthorizationStatus::Pending => {}
					status => {
						self.resolver.clear_challenge_certs();
						return Err(ReductionError::Acme(format!(
							"unexpected authorization status: {status:?}"
						)));
					}
				}

				let mut challenge = authz
					.challenge(ChallengeType::TlsAlpn01)
					.ok_or_else(|| ReductionError::Acme("no tls-alpn-01 challenge found".to_owned()))?;

				let domain: String = match challenge.identifier().identifier {
					Identifier::Dns(dns) => dns.clone(),
					_ => {
						self.resolver.clear_challenge_certs();
						return Err(ReductionError::Acme("tls-alpn-01 requires a DNS identifier".to_owned()));
					}
				};

				let key_auth: KeyAuthorization = challenge.key_authorization();
				let challenge_cert: CertifiedKey = build_tls_alpn_challenge_cert(&domain, &key_auth)?;
				self.resolver.set_challenge_cert(&domain, challenge_cert);

				challenge
					.set_ready()
					.await
					.map_err(|e| ReductionError::Acme(format!("failed to signal challenge ready: {e}")))?;
			}
		}

		// Poll the whole order to ready; clear challenge certs regardless of the outcome.
		let ready = order.poll_ready(&retry_policy).await;
		self.resolver.clear_challenge_certs();
		let status: OrderStatus =
			ready.map_err(|e| ReductionError::Acme(format!("failed waiting for order ready: {e}")))?;
		if !matches!(status, OrderStatus::Ready) {
			return Err(ReductionError::Acme(format!("unexpected order status: {status:?}")));
		}

		return self.finalize_and_cache(&mut order, &retry_policy, &mut state).await;
	}

	// Generate our own key, finalize the order with a CSR, download the issued chain, persist the cert +
	// key (alongside the account creds already in `state`) atomically through the store, and build the
	// resolver's certified key.
	async fn finalize_and_cache(
		&self,
		order: &mut Order,
		retry_policy: &RetryPolicy,
		state: &mut AcmeSecretState,
	) -> Result<CertifiedKey> {
		let cert_key: KeyPair =
			KeyPair::generate().map_err(|e| ReductionError::Acme(format!("failed to generate cert key: {e}")))?;

		let domains: Vec<String> = self.config.domains.iter().map(|d| d.to_string()).collect();

		let csr_params: CertificateParams = CertificateParams::new(domains)
			.map_err(|e| ReductionError::Acme(format!("failed to create CSR params: {e}")))?;

		let csr_der: Vec<u8> = csr_params
			.serialize_request(&cert_key)
			.map_err(|e| ReductionError::Acme(format!("failed to serialize CSR: {e}")))?
			.der()
			.to_vec();

		// finalize_csr keeps our own key (we persist cert_key below); finalize() would have instant-acme
		// generate and own the private key instead.
		order
			.finalize_csr(&csr_der)
			.await
			.map_err(|e| ReductionError::Acme(format!("failed to finalize order: {e}")))?;

		let cert_chain_pem: String = order
			.poll_certificate(retry_policy)
			.await
			.map_err(|e| ReductionError::Acme(format!("failed to download cert: {e}")))?;

		let key_pem: String = cert_key.serialize_pem();

		// Persist the whole state (account + new cert/key) atomically through the store.
		state.cert_chain_pem = Some(cert_chain_pem.clone());
		state.key_pem = Some(key_pem.clone());
		self.store.persist(state).await?;

		info!("ACME certificate provisioned and persisted to the secret-state store");

		return build_certified_key_from_pem(&cert_chain_pem, &key_pem);
	}

	// Restore the ACME account from the opaque state's credentials, or create a new one and record its
	// credentials into `state`, persisting the state so the account survives a restart (a new account
	// each boot would churn Let's Encrypt's account rate limits). Persisting here keeps the account
	// durable even if certificate finalize later fails.
	async fn get_or_create_account(&self, directory_url: &str, state: &mut AcmeSecretState) -> Result<Account> {
		if let Some(json) = state.account_credentials.as_deref() {
			let credentials: AccountCredentials = serde_json::from_str(json)
				.map_err(|e| ReductionError::Acme(format!("failed to parse account credentials: {e}")))?;

			let account: Account = self
				.account_builder()?
				.from_credentials(credentials)
				.await
				.map_err(|e| ReductionError::Acme(format!("failed to restore account: {e}")))?;

			info!("restored existing ACME account");
			return Ok(account);
		}

		let email: String = format!("mailto:{}", self.config.acme_email.as_str());
		let (account, credentials) = self
			.account_builder()?
			.create(
				&NewAccount {
					contact: &[&email],
					terms_of_service_agreed: true,
					only_return_existing: false,
				},
				directory_url.to_owned(),
				None,
			)
			.await
			.map_err(|e| ReductionError::Acme(format!("failed to create ACME account: {e}")))?;

		let serialized: String = serde_json::to_string(&credentials)
			.map_err(|e| ReductionError::Acme(format!("failed to serialize credentials: {e}")))?;

		state.account_credentials = Some(serialized);
		self.store.persist(state).await?;

		info!("created new ACME account and persisted its credentials to the secret-state store");
		return Ok(account);
	}

	// Build an instant-acme account client, trusting a custom root for the ACME server's HTTPS
	// endpoint when configured (private ACME CA / pebble); otherwise the system roots.
	fn account_builder(&self) -> Result<AccountBuilder> {
		return match &self.config.directory_ca_cert {
			Some(path) => Account::builder_with_root(path)
				.map_err(|e| ReductionError::Acme(format!("failed to build account client with root: {e}"))),
			None => {
				Account::builder().map_err(|e| ReductionError::Acme(format!("failed to build account client: {e}")))
			}
		};
	}

	// Load a previously-persisted cert+key from the store, if present. A load error or a state with no
	// cert/key yields None (treated as "no cache" → provision), never a discard of good state.
	fn load_cached_cert(&self) -> Option<CertifiedKey> {
		let state: AcmeSecretState = match self.store.load() {
			Ok(Some(state)) => state,
			Ok(None) => return None,
			Err(e) => {
				warn!(error = %e, "failed to load ACME secret state; treating as no cache");
				return None;
			}
		};
		let (cert_pem, key_pem): (String, String) = match (state.cert_chain_pem, state.key_pem) {
			(Some(cert), Some(key)) => (cert, key),
			_ => return None,
		};

		return match build_certified_key_from_pem(&cert_pem, &key_pem) {
			Ok(key) => Some(key),
			Err(e) => {
				warn!(error = %e, "failed to load cached ACME certificate");
				None
			}
		};
	}
}

// Backoff floor after N consecutive renewal failures: 0 for none, then base doubling per failure,
// capped. Pure so the pacing policy is unit-testable.
fn failure_backoff(consecutive_failures: u32) -> Duration {
	if consecutive_failures == 0 {
		return Duration::ZERO;
	}
	let doublings: u32 = (consecutive_failures - 1).min(ACME_FAILURE_BACKOFF_MAX_DOUBLINGS);
	let secs: u64 = ACME_FAILURE_BACKOFF_BASE_SECS
		.saturating_mul(1_u64 << doublings)
		.min(ACME_FAILURE_BACKOFF_MAX_SECS);
	return Duration::from_secs(secs);
}

// Remaining validity (now → not_after), no renewal buffer. ZERO when expired or unparseable.
fn time_until_expiry_from_certified(certified_key: &CertifiedKey) -> Duration {
	let cert_der: &[u8] = match certified_key.cert.first() {
		Some(c) => c.as_ref(),
		None => return Duration::ZERO,
	};

	return match X509Certificate::from_der(cert_der) {
		Ok((_, cert)) => {
			let not_after: i64 = cert.validity().not_after.timestamp();
			let now: i64 = i64::try_from(
				SystemTime::now()
					.duration_since(UNIX_EPOCH)
					.unwrap_or(Duration::ZERO)
					.as_secs(),
			)
			.unwrap_or(i64::MAX);
			let remaining_secs: i64 = not_after.saturating_sub(now);
			// Negative (expired) saturates to ZERO via the failed conversion.
			Duration::from_secs(u64::try_from(remaining_secs).unwrap_or(0))
		}
		Err(e) => {
			warn!(error = %e, "failed to parse certificate for expiry calculation");
			Duration::ZERO
		}
	};
}

fn time_until_renewal_from_certified(certified_key: &CertifiedKey) -> Duration {
	return time_until_expiry_from_certified(certified_key)
		.saturating_sub(Duration::from_secs(ACME_RENEWAL_BUFFER_SECS));
}

fn build_tls_alpn_challenge_cert(domain: &str, key_auth: &KeyAuthorization) -> Result<CertifiedKey> {
	let key_pair: KeyPair =
		KeyPair::generate().map_err(|e| ReductionError::Acme(format!("challenge cert keygen: {e}")))?;

	let mut params: CertificateParams = CertificateParams::new(vec![domain.to_owned()])
		.map_err(|e| ReductionError::Acme(format!("challenge cert params: {e}")))?;

	let digest = key_auth.digest();
	let digest_bytes: &[u8] = digest.as_ref();
	let digest_len: u8 = u8::try_from(digest_bytes.len())
		.map_err(|_| ReductionError::Acme("challenge digest too long for ASN.1 length".to_owned()))?;

	// ASN.1 DER encoding: OCTET STRING wrapping the SHA-256 digest
	let mut asn1_value: Vec<u8> = Vec::with_capacity(SHA256_DIGEST_DER_OCTET_STRING_LEN);
	asn1_value.push(0x04); // OCTET STRING tag
	asn1_value.push(digest_len);
	asn1_value.extend_from_slice(digest_bytes);

	let oid: Vec<u64> = ACME_IDENTIFIER_OID.to_vec();
	let mut ext: CustomExtension = CustomExtension::from_oid_content(&oid, asn1_value);
	// RFC 8737 §3: the acmeIdentifier extension MUST be critical; validators (incl. pebble) reject it otherwise.
	ext.set_criticality(true);
	params.custom_extensions.push(ext);

	let cert = params
		.self_signed(&key_pair)
		.map_err(|e| ReductionError::Acme(format!("challenge cert sign: {e}")))?;

	let cert_der: CertificateDer<'static> = CertificateDer::from(cert.der().to_vec());
	let key_der: PrivatePkcs8KeyDer<'static> = PrivatePkcs8KeyDer::from(key_pair.serialize_der());

	let signing_key = any_ecdsa_type(&PrivateKeyDer::Pkcs8(key_der))
		.map_err(|e| ReductionError::Acme(format!("challenge cert signing key: {e}")))?;

	return Ok(CertifiedKey::new(vec![cert_der], signing_key));
}

fn build_certified_key_from_pem(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey> {
	use std::io::BufReader;

	let cert_reader = BufReader::new(cert_pem.as_bytes());
	let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(cert_reader)
		.collect::<std::result::Result<Vec<_>, _>>()
		.map_err(|e| ReductionError::Acme(format!("failed to parse cert PEM: {e}")))?;

	if certs.is_empty() {
		return Err(ReductionError::Acme("no certificates in PEM".to_owned()));
	}

	let key_reader = &mut BufReader::new(key_pem.as_bytes());
	let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(key_reader)
		.map_err(|e| ReductionError::Acme(format!("failed to parse key PEM: {e}")))?;

	let signing_key =
		any_ecdsa_type(&key).map_err(|e| ReductionError::Acme(format!("failed to create signing key: {e}")))?;

	// CertifiedKey::new performs no key/cert consistency check (unlike from_der), so a cache torn by
	// a crash between the separate cert and key writes — new cert next to a stale key — would load
	// clean here and then fail every TLS handshake for the life of the cert. Reject a proven mismatch
	// so load_cached_cert maps it to "no cache" and re-provisions. Unknown (key type can't expose its
	// SPKI) is tolerated exactly as CertifiedKey::from_der does, to never reject a usable pair.
	let certified = CertifiedKey::new(certs, signing_key);
	match certified.keys_match() {
		Ok(()) | Err(RustlsError::InconsistentKeys(InconsistentKeys::Unknown)) => {}
		Err(e) => return Err(ReductionError::Acme(format!("cached cert/key mismatch: {e}"))),
	}
	return Ok(certified);
}

#[cfg(test)]
mod tests {
	use std::path::Path;

	use arrayvec::ArrayString;

	use super::*;

	#[test]
	fn test_resolver_returns_none_initially() {
		let resolver = AcmeCertResolver::new();
		assert!(!resolver.has_cert());
	}

	#[test]
	fn test_resolver_set_and_get_cert() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

		let resolver = AcmeCertResolver::new();

		let key_pair = KeyPair::generate().unwrap();
		let params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
		let cert = params.self_signed(&key_pair).unwrap();
		let cert_der = CertificateDer::from(cert.der().to_vec());
		let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
		let signing_key = any_ecdsa_type(&PrivateKeyDer::Pkcs8(key_der)).unwrap();
		let certified = CertifiedKey::new(vec![cert_der], signing_key);

		resolver.set_cert(certified);
		assert!(resolver.has_cert());
	}

	// A cache torn by a crash between the two writes pairs a fresh cert with a stale key. The loader
	// must reject that mismatch instead of returning a CertifiedKey that fails every handshake.
	#[test]
	fn test_build_certified_key_rejects_mismatched_pair() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

		let key_a = KeyPair::generate().unwrap();
		let params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
		let cert_a_pem: String = params.self_signed(&key_a).unwrap().pem();

		let key_b_pem: String = KeyPair::generate().unwrap().serialize_pem();

		let err = build_certified_key_from_pem(&cert_a_pem, &key_b_pem).unwrap_err();
		assert!(matches!(err, ReductionError::Acme(_)));
		assert!(format!("{err}").contains("mismatch"));
	}

	// Guards the happy path against the mismatch check: a genuine cert/key pair still loads.
	#[test]
	fn test_build_certified_key_accepts_matched_pair() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

		let key = KeyPair::generate().unwrap();
		let params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
		let cert_pem: String = params.self_signed(&key).unwrap().pem();
		let key_pem: String = key.serialize_pem();

		build_certified_key_from_pem(&cert_pem, &key_pem).unwrap();
	}

	fn dummy_certified_key(domain: &str) -> CertifiedKey {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let key_pair = KeyPair::generate().unwrap();
		let params = CertificateParams::new(vec![domain.to_string()]).unwrap();
		let cert = params.self_signed(&key_pair).unwrap();
		let cert_der = CertificateDer::from(cert.der().to_vec());
		let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
		let signing_key = any_ecdsa_type(&PrivateKeyDer::Pkcs8(key_der)).unwrap();
		return CertifiedKey::new(vec![cert_der], signing_key);
	}

	#[test]
	fn test_challenge_certs_stored_per_domain() {
		let resolver = AcmeCertResolver::new();
		resolver.set_challenge_cert("a.example.com", dummy_certified_key("a.example.com"));
		resolver.set_challenge_cert("b.example.com", dummy_certified_key("b.example.com"));

		let guard = resolver.challenge_certs.read();
		assert_eq!(guard.len(), 2);
		assert!(guard.contains_key("a.example.com"));
		assert!(guard.contains_key("b.example.com"));
	}

	#[test]
	fn test_set_challenge_cert_overwrites_same_domain() {
		let resolver = AcmeCertResolver::new();
		resolver.set_challenge_cert("a.example.com", dummy_certified_key("a.example.com"));
		resolver.set_challenge_cert("a.example.com", dummy_certified_key("a.example.com"));
		assert_eq!(resolver.challenge_certs.read().len(), 1);
	}

	#[test]
	fn test_clear_challenge_certs_empties_map() {
		let resolver = AcmeCertResolver::new();
		resolver.set_challenge_cert("a.example.com", dummy_certified_key("a.example.com"));
		resolver.set_challenge_cert("b.example.com", dummy_certified_key("b.example.com"));
		resolver.clear_challenge_certs();
		assert!(resolver.challenge_certs.read().is_empty());
	}

	#[test]
	fn test_challenge_certs_do_not_affect_real_cert() {
		let resolver = AcmeCertResolver::new();
		resolver.set_challenge_cert("a.example.com", dummy_certified_key("a.example.com"));
		// Installing a challenge cert must not make the resolver report a provisioned real cert.
		assert!(!resolver.has_cert());
	}

	#[test]
	fn test_failure_backoff_zero_failures_is_zero() {
		assert_eq!(failure_backoff(0), Duration::ZERO);
	}

	#[test]
	fn test_failure_backoff_doubles_from_base_and_caps() {
		assert_eq!(failure_backoff(1), Duration::from_secs(ACME_FAILURE_BACKOFF_BASE_SECS));
		assert_eq!(
			failure_backoff(2),
			Duration::from_secs(ACME_FAILURE_BACKOFF_BASE_SECS * 2)
		);
		assert_eq!(
			failure_backoff(3),
			Duration::from_secs(ACME_FAILURE_BACKOFF_BASE_SECS * 4)
		);
		assert_eq!(failure_backoff(10), Duration::from_secs(ACME_FAILURE_BACKOFF_MAX_SECS));
		assert_eq!(
			failure_backoff(u32::MAX),
			Duration::from_secs(ACME_FAILURE_BACKOFF_MAX_SECS)
		);
	}

	// Rate-limit safety: within the first hour of failures, cumulative backoff must permit at most
	// 4 provisioning attempts (Let's Encrypt allows 5 failed validations/hour).
	#[test]
	fn test_failure_backoff_first_hour_stays_under_ca_rate_limit() {
		let mut elapsed: Duration = Duration::ZERO;
		let mut attempts: u32 = 1; // the initial failing attempt at t=0
		let mut failures: u32 = 1;
		while elapsed + failure_backoff(failures) < Duration::from_secs(3600) {
			elapsed += failure_backoff(failures);
			attempts += 1;
			failures += 1;
		}
		assert!(attempts <= 4, "backoff allows {attempts} attempts in the first hour");
	}

	// Days-to-civil conversion (Hinnant's algorithm) so tests can mint a cert whose not_after lands
	// a fixed number of days from now — inside the renewal window without being expired.
	fn ymd_from_unix_secs(secs: i64) -> (i32, u8, u8) {
		let days: i64 = secs.div_euclid(86_400);
		let z: i64 = days + 719_468;
		let era: i64 = z.div_euclid(146_097);
		let doe: i64 = z - era * 146_097;
		let yoe: i64 = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
		let y: i64 = yoe + era * 400;
		let doy: i64 = doe - (365 * yoe + yoe / 4 - yoe / 100);
		let mp: i64 = (5 * doy + 2) / 153;
		let d: i64 = doy - (153 * mp + 2) / 5 + 1;
		let m: i64 = if mp < 10 { mp + 3 } else { mp - 9 };
		let year: i64 = if m <= 2 { y + 1 } else { y };
		return (
			i32::try_from(year).unwrap(),
			u8::try_from(m).unwrap(),
			u8::try_from(d).unwrap(),
		);
	}

	fn certified_key_expiring_in_days(domain: &str, days_from_now: i64) -> (CertifiedKey, String, String) {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let now_secs: i64 = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
		let (y, m, d) = ymd_from_unix_secs(now_secs + days_from_now * 86_400);
		let key_pair = KeyPair::generate().unwrap();
		let mut params = CertificateParams::new(vec![domain.to_string()]).unwrap();
		params.not_before = rcgen::date_time_ymd(2020, 1, 1);
		params.not_after = rcgen::date_time_ymd(y, m, d);
		let cert = params.self_signed(&key_pair).unwrap();
		let cert_pem: String = cert.pem();
		let key_pem: String = key_pair.serialize_pem();
		let certified: CertifiedKey = build_certified_key_from_pem(&cert_pem, &key_pem).unwrap();
		return (certified, cert_pem, key_pem);
	}

	#[test]
	fn test_expiry_positive_and_renewal_subtracts_buffer() {
		// ~60 days out: expiry is positive and renewal is expiry minus the 30-day buffer.
		let (certified, _, _) = certified_key_expiring_in_days("fresh.example.com", 60);
		let expiry: Duration = time_until_expiry_from_certified(&certified);
		let renewal: Duration = time_until_renewal_from_certified(&certified);
		assert!(expiry > Duration::from_secs(50 * 86_400));
		assert_eq!(
			renewal,
			expiry.saturating_sub(Duration::from_secs(ACME_RENEWAL_BUFFER_SECS))
		);
		assert!(renewal > Duration::ZERO);
	}

	#[test]
	fn test_expiry_in_renewal_window_renewal_zero_expiry_positive() {
		// 10 days out: inside the 30-day renewal window (renewal ZERO) but not expired.
		let (certified, _, _) = certified_key_expiring_in_days("window.example.com", 10);
		assert_eq!(time_until_renewal_from_certified(&certified), Duration::ZERO);
		assert!(time_until_expiry_from_certified(&certified) > Duration::ZERO);
	}

	fn unreachable_acme_config(cache_dir: &Path) -> AcmeTlsConfig {
		return AcmeTlsConfig {
			domains: vec![ArrayString::from("stale.example.com").unwrap()],
			acme_email: ArrayString::from("ops@example.com").unwrap(),
			ca_cert_path: Some(cache_dir.join("unused-ca.pem")),
			cache_dir: cache_dir.to_path_buf(),
			staging: false,
			// Nothing listens on port 1: provisioning fails fast with connection refused.
			directory_url: Some("https://127.0.0.1:1/directory".to_owned()),
			directory_ca_cert: None,
			barrel_state: None,
		};
	}

	// Seed the file store's cache with a cert+key blob, mirroring what a prior provision would persist.
	async fn seed_cached_cert(cache_dir: &Path, cert_pem: &str, key_pem: &str) {
		let state = crate::tls::secret_state::AcmeSecretState {
			account_credentials: None,
			cert_chain_pem: Some(cert_pem.to_owned()),
			key_pem: Some(key_pem.to_owned()),
		};
		let store = crate::tls::secret_state::SecretStore::File {
			cache_dir: cache_dir.to_path_buf(),
		};
		store.persist(&state).await.unwrap();
	}

	// Serve-stale: boot during a CA outage with a cached cert inside the renewal window but still
	// valid must serve the cached cert (Ok + resolver populated), not brick the proxy.
	#[tokio::test]
	async fn test_provision_initial_cert_serves_stale_cache_when_provisioning_fails() {
		let dir: tempfile::TempDir = tempfile::tempdir().unwrap();
		let (_, cert_pem, key_pem) = certified_key_expiring_in_days("stale.example.com", 10);
		seed_cached_cert(dir.path(), &cert_pem, &key_pem).await;

		let resolver = Arc::new(AcmeCertResolver::new());
		let (_shutdown_tx, shutdown_rx) = watch::channel(());
		let task = AcmeRenewalTask::new(unreachable_acme_config(dir.path()), resolver.clone(), shutdown_rx, ProxyMetrics::new());

		let result: Result<()> = task.provision_initial_cert().await;
		assert!(
			result.is_ok(),
			"boot must serve the still-valid cached cert: {result:?}"
		);
		assert!(resolver.has_cert(), "resolver must hold the cached cert");
	}

	// Fail-closed counterpart: an EXPIRED cached cert must not be served — provisioning failure
	// still propagates and the resolver stays empty.
	#[tokio::test]
	async fn test_provision_initial_cert_rejects_expired_cache_when_provisioning_fails() {
		let dir: tempfile::TempDir = tempfile::tempdir().unwrap();
		let (_, cert_pem, key_pem) = certified_key_expiring_in_days("dead.example.com", -10);
		seed_cached_cert(dir.path(), &cert_pem, &key_pem).await;

		let resolver = Arc::new(AcmeCertResolver::new());
		let (_shutdown_tx, shutdown_rx) = watch::channel(());
		let task = AcmeRenewalTask::new(unreachable_acme_config(dir.path()), resolver.clone(), shutdown_rx, ProxyMetrics::new());

		let result: Result<()> = task.provision_initial_cert().await;
		assert!(result.is_err(), "an expired cached cert must not be served");
		assert!(!resolver.has_cert(), "resolver must stay empty on fail-closed boot");
	}

	// Renewal survives a restart: a cert persisted to the store (well outside the renewal window) is
	// loaded and served by a FRESH task on the same store, without any contact to the (unreachable) CA.
	// This is the store-abstraction proof that persisted ACME state outlives a process restart.
	#[tokio::test]
	async fn persisted_cert_survives_restart_via_store() {
		let dir: tempfile::TempDir = tempfile::tempdir().unwrap();
		let (_, cert_pem, key_pem) = certified_key_expiring_in_days("survives.example.com", 60);
		seed_cached_cert(dir.path(), &cert_pem, &key_pem).await;

		let resolver = Arc::new(AcmeCertResolver::new());
		let (_shutdown_tx, shutdown_rx) = watch::channel(());
		let task = AcmeRenewalTask::new(unreachable_acme_config(dir.path()), resolver.clone(), shutdown_rx, ProxyMetrics::new());

		// 60 days out is well past the 30-day renewal buffer, so boot loads-and-serves without provisioning.
		task.provision_initial_cert()
			.await
			.expect("a fresh task must load the persisted cert on boot");
		assert!(resolver.has_cert(), "persisted state must survive a restart");
	}

	#[test]
	fn test_time_until_renewal_expired_cert() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

		let key_pair = KeyPair::generate().unwrap();
		let mut params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
		params.not_before = rcgen::date_time_ymd(2020, 1, 1);
		params.not_after = rcgen::date_time_ymd(2020, 1, 2);
		let cert = params.self_signed(&key_pair).unwrap();
		let cert_der = CertificateDer::from(cert.der().to_vec());
		let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
		let signing_key = any_ecdsa_type(&PrivateKeyDer::Pkcs8(key_der)).unwrap();
		let certified = CertifiedKey::new(vec![cert_der], signing_key);

		let duration = time_until_renewal_from_certified(&certified);
		assert_eq!(duration, Duration::ZERO);
	}
}
