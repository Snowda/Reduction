use std::sync::Arc;
use std::time::Duration;

use core_utils::time::current_unix;
use instant_acme::{
	Account, AccountBuilder, AccountCredentials, AuthorizationHandle, AuthorizationStatus, Authorizations,
	ChallengeHandle, ChallengeType, Error as AcmeError, Identifier, KeyAuthorization, NewAccount, NewOrder, Order,
	OrderStatus, RetryPolicy,
};
use rcgen::{Certificate, CertificateParams, CustomExtension, KeyPair};
use rustls::crypto::aws_lc_rs::sign::any_ecdsa_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::{Error as RustlsError, InconsistentKeys};
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{error, info, warn};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::backoff::Backoff;
use crate::config::AcmeTlsConfig;
use crate::error::{ReductionError, Result};
use crate::metrics::ProxyMetrics;
use crate::tls::secret_state::{AcmeSecretState, SecretStore};

// The cert resolver (provisioned cert plus tls-alpn-01 challenge certs) lives in a submodule.
mod resolver;

pub use resolver::AcmeCertResolver;

const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];
const ACME_RENEWAL_BUFFER: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const ACME_RETRY_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);
// Inside the renewal window the renewal delay is ZERO. Without this floor, a failed renewal re-orders in a
// hot loop and burns the CA's failed-validation limit (Let's Encrypt: 5/hour). The floor starts at 5 min and
// doubles to a 6 h cap, so the first hour has at most 4 attempts.
const ACME_FAILURE_BACKOFF: Backoff = Backoff::new(Duration::from_secs(5 * 60), Duration::from_secs(6 * 60 * 60));
const ACME_POLL_INTERVAL: Duration = Duration::from_secs(5);
const ACME_MAX_POLL_ATTEMPTS: u32 = 60;
// DER OCTET STRING that holds a SHA-256 digest: 1-byte tag + 1-byte length + 32-byte digest.
const SHA256_DIGEST_DER_OCTET_STRING_LEN: usize = 34;
// Backoff factor of 1.0 keeps a fixed poll interval, the same cadence as the previous manual loop.
const RETRY_CONSTANT_BACKOFF: f32 = 1.0;

pub struct AcmeRenewalTask {
	config: AcmeTlsConfig,
	resolver: Arc<AcmeCertResolver>,
	shutdown: watch::Receiver<()>,
	metrics: ProxyMetrics,
}

impl AcmeRenewalTask {
	pub const fn new(
		config: AcmeTlsConfig,
		resolver: Arc<AcmeCertResolver>,
		shutdown: watch::Receiver<()>,
		metrics: ProxyMetrics,
	) -> Self {
		return Self {
			config,
			resolver,
			shutdown,
			metrics,
		};
	}

	// Cache-dir file or Barrel, borrowed from `config` so the task holds no second copy of its fields.
	fn store(&self) -> SecretStore<'_> {
		return SecretStore::from_acme_config(&self.config);
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

	// A restart during a CA outage must not brick the proxy. Serve a cached cert that is not yet expired
	// and let the renewal loop retry; fail only when no valid cached cert remains.
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

	// The renewal loop: sleep until the next renewal (or shut down), renew, record the outcome, repeat.
	pub async fn run(mut self) {
		let mut consecutive_failures: u32 = 0;
		loop {
			let sleep_duration: Duration = self.next_renewal_sleep(consecutive_failures);
			info!(
				sleep_secs = sleep_duration.as_secs(),
				consecutive_failures, "ACME renewal loop sleeping"
			);
			if !self.has_slept_without_shutdown(sleep_duration).await {
				return;
			}
			let renewed: Result<CertifiedKey> = self.provision_cert().await;
			consecutive_failures = self.record_renewal(renewed, consecutive_failures);
		}
	}

	// Sleep for `duration`. Returns false (and logs) when the shutdown signal arrives first.
	async fn has_slept_without_shutdown(&mut self, duration: Duration) -> bool {
		return tokio::select! {
			_ = sleep(duration) => true,
			_ = self.shutdown.changed() => {
				info!("ACME renewal task shutting down");
				false
			}
		};
	}

	// Install a renewed cert or count the failure. Returns the new consecutive-failure count.
	fn record_renewal(&self, renewed: Result<CertifiedKey>, consecutive_failures: u32) -> u32 {
		return match renewed {
			Ok(certified_key) => {
				self.metrics.acme_renewals_total.add(1, &[]);
				info!("ACME certificate renewed successfully");
				self.resolver.set_cert(certified_key);
				0
			}
			Err(e) => {
				let failures: u32 = consecutive_failures.saturating_add(1);
				self.metrics.acme_renewal_failures_total.add(1, &[]);
				error!(error = %e, consecutive_failures = failures,
					"ACME certificate renewal failed, backing off before retry");
				failures
			}
		};
	}

	// Sleep until the renewal window of the cert opens, but not less than the failure backoff.
	// Then a renewal that fails cannot spin in a zero-delay order storm.
	fn next_renewal_sleep(&self, consecutive_failures: u32) -> Duration {
		let renewal_in: Duration = match self.resolver.cert.load_full().as_deref() {
			Some(key) => time_until_renewal_from_certified(key),
			None => ACME_RETRY_INTERVAL,
		};
		return renewal_in.max(failure_backoff(consecutive_failures));
	}

	async fn provision_cert(&self) -> Result<CertifiedKey> {
		let directory_url: &str = self.config.directory.url();

		// Load the current opaque state once: account creds + any cached cert/key. Pass it through
		// account setup and finalize. Then each persist writes the whole blob atomically.
		let mut state: AcmeSecretState = self.store().load()?.unwrap_or_default();

		let account: Account = self.get_or_create_account(directory_url, &mut state).await?;

		let identifiers: Vec<Identifier> = self
			.config
			.domains
			.iter()
			.map(|d| Identifier::Dns(d.to_string()))
			.collect();

		let mut order: Order = account
			.new_order(&NewOrder::new(&identifiers))
			.await
			.map_err(|e| ReductionError::Acme(format!("failed to create order: {e}").into()))?;

		// Fixed-cadence retry budget. It keeps the budget of the previous manual loop (interval × max attempts).
		let retry_policy: RetryPolicy = RetryPolicy::default()
			.initial_delay(ACME_POLL_INTERVAL)
			.backoff(RETRY_CONSTANT_BACKOFF)
			.timeout(ACME_POLL_INTERVAL.saturating_mul(ACME_MAX_POLL_ATTEMPTS));

		self.install_challenges(&mut order).await?;

		// Poll the whole order to ready; clear challenge certs regardless of the outcome.
		let ready: std::result::Result<OrderStatus, AcmeError> = order.poll_ready(&retry_policy).await;
		self.resolver.clear_challenge_certs();
		let status: OrderStatus =
			ready.map_err(|e| ReductionError::Acme(format!("failed waiting for order ready: {e}").into()))?;
		if !matches!(status, OrderStatus::Ready) {
			return Err(ReductionError::Acme(format!("unexpected order status: {status:?}").into()));
		}

		return self.finalize_and_cache(&mut order, &retry_policy, &mut state).await;
	}

	// instant-acme locks each authorization after we take its challenge, so the caller polls the whole
	// order, not each authz. This is why the resolver keeps a challenge-cert map per SNI.
	async fn install_challenges(&self, order: &mut Order) -> Result<()> {
		let mut authorizations: Authorizations<'_> = order.authorizations();
		while let Some(result) = authorizations.next().await {
			let mut authz: AuthorizationHandle<'_> =
				result.map_err(|e| ReductionError::Acme(format!("failed to get authorization: {e}").into()))?;
			match authz.status {
				AuthorizationStatus::Valid => continue,
				AuthorizationStatus::Pending => {}
				status => {
					self.resolver.clear_challenge_certs();
					return Err(ReductionError::Acme(format!(
						"unexpected authorization status: {status:?}"
					).into()));
				}
			}

			let mut challenge: ChallengeHandle<'_> = authz
				.challenge(ChallengeType::TlsAlpn01)
				.ok_or_else(|| ReductionError::Acme("no tls-alpn-01 challenge found".into()))?;

			let domain: String = match challenge.identifier().identifier {
				Identifier::Dns(dns) => dns.clone(),
				_ => {
					self.resolver.clear_challenge_certs();
					return Err(ReductionError::Acme("tls-alpn-01 requires a DNS identifier".into()));
				}
			};

			let key_auth: KeyAuthorization = challenge.key_authorization();
			let challenge_cert: CertifiedKey = build_tls_alpn_challenge_cert(&domain, &key_auth)?;
			if let Err(err) = self.resolver.set_challenge_cert(&domain, challenge_cert) {
				self.resolver.clear_challenge_certs();
				return Err(err);
			}

			challenge
				.set_ready()
				.await
				.map_err(|e| ReductionError::Acme(format!("failed to signal challenge ready: {e}").into()))?;
		}
		return Ok(());
	}

	// Finalize with a CSR for our own key, then persist cert + key atomically beside the account creds.
	async fn finalize_and_cache(
		&self,
		order: &mut Order,
		retry_policy: &RetryPolicy,
		state: &mut AcmeSecretState,
	) -> Result<CertifiedKey> {
		let cert_key: KeyPair =
			KeyPair::generate().map_err(|e| ReductionError::Acme(format!("failed to generate cert key: {e}").into()))?;

		let domains: Vec<String> = self.config.domains.iter().map(|d| d.to_string()).collect();

		let csr_params: CertificateParams = CertificateParams::new(domains)
			.map_err(|e| ReductionError::Acme(format!("failed to create CSR params: {e}").into()))?;

		let csr_der: Vec<u8> = csr_params
			.serialize_request(&cert_key)
			.map_err(|e| ReductionError::Acme(format!("failed to serialize CSR: {e}").into()))?
			.der()
			.to_vec();

		// finalize_csr keeps our own key (we persist cert_key below); finalize() would have instant-acme
		// generate and own the private key instead.
		order
			.finalize_csr(&csr_der)
			.await
			.map_err(|e| ReductionError::Acme(format!("failed to finalize order: {e}").into()))?;

		let cert_chain_pem: String = order
			.poll_certificate(retry_policy)
			.await
			.map_err(|e| ReductionError::Acme(format!("failed to download cert: {e}").into()))?;

		let key_pem: String = cert_key.serialize_pem();

		// Parsed before the PEMs move into the state; a persist failure still wins over a parse failure.
		let certified: Result<CertifiedKey> = build_certified_key_from_pem(&cert_chain_pem, &key_pem);
		// Persist the whole state (account + new cert/key) atomically through the store.
		state.cert_chain_pem = Some(cert_chain_pem);
		state.key_pem = Some(key_pem);
		self.store().persist(state).await?;

		info!("ACME certificate provisioned and persisted to the secret-state store");

		return certified;
	}

	// A new account per boot would churn Let's Encrypt account rate limits. Persist new creds here so the
	// account stays durable even if finalize fails later.
	async fn get_or_create_account(&self, directory_url: &str, state: &mut AcmeSecretState) -> Result<Account> {
		if let Some(json) = state.account_credentials.as_deref() {
			let credentials: AccountCredentials = serde_json::from_str(json)
				.map_err(|e| ReductionError::Acme(format!("failed to parse account credentials: {e}").into()))?;

			let account: Account = self
				.account_builder()?
				.from_credentials(credentials)
				.await
				.map_err(|e| ReductionError::Acme(format!("failed to restore account: {e}").into()))?;

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
			.map_err(|e| ReductionError::Acme(format!("failed to create ACME account: {e}").into()))?;

		let serialized: String = serde_json::to_string(&credentials)
			.map_err(|e| ReductionError::Acme(format!("failed to serialize credentials: {e}").into()))?;

		state.account_credentials = Some(serialized);
		self.store().persist(state).await?;

		info!("created new ACME account and persisted its credentials to the secret-state store");
		return Ok(account);
	}

	// Build an instant-acme account client. It trusts the configured custom root for the HTTPS endpoint
	// of the ACME server (private ACME CA / pebble). Without one, it trusts the system roots.
	fn account_builder(&self) -> Result<AccountBuilder> {
		return match &self.config.directory_ca_cert {
			Some(path) => Account::builder_with_root(path)
				.map_err(|e| ReductionError::Acme(format!("failed to build account client with root: {e}").into())),
			None => {
				Account::builder().map_err(|e| ReductionError::Acme(format!("failed to build account client: {e}").into()))
			}
		};
	}

	// Load a previously-persisted cert+key from the store, if present. A load error or a state with no
	// cert/key yields None (treated as "no cache" → provision), never a discard of good state.
	fn load_cached_cert(&self) -> Option<CertifiedKey> {
		let state: AcmeSecretState = match self.store().load() {
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

// Backoff floor after N consecutive renewal failures: 0 for none. After that, the base doubles per
// failure up to the cap. It is pure so that unit tests can check the backoff policy.
fn failure_backoff(consecutive_failures: u32) -> Duration {
	if consecutive_failures == 0 {
		return Duration::ZERO;
	}
	return ACME_FAILURE_BACKOFF.nth(consecutive_failures - 1);
}

// Validity left (now → not_after), no renewal buffer. ZERO when expired or unparseable.
fn time_until_expiry_from_certified(certified_key: &CertifiedKey) -> Duration {
	let cert_der: &[u8] = match certified_key.cert.first() {
		Some(c) => c.as_ref(),
		None => return Duration::ZERO,
	};

	return match X509Certificate::from_der(cert_der) {
		Ok((_, cert)) => {
			let not_after: i64 = cert.validity().not_after.timestamp();
			let now: i64 = i64::try_from(current_unix()).unwrap_or(i64::MAX);
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
		.saturating_sub(ACME_RENEWAL_BUFFER);
}

fn build_tls_alpn_challenge_cert(domain: &str, key_auth: &KeyAuthorization) -> Result<CertifiedKey> {
	let key_pair: KeyPair =
		KeyPair::generate().map_err(|e| ReductionError::Acme(format!("challenge cert keygen: {e}").into()))?;

	let mut params: CertificateParams = CertificateParams::new(vec![domain.to_owned()])
		.map_err(|e| ReductionError::Acme(format!("challenge cert params: {e}").into()))?;

	let digest = key_auth.digest();
	let digest_bytes: &[u8] = digest.as_ref();
	let digest_len: u8 = u8::try_from(digest_bytes.len())
		.map_err(|_| ReductionError::Acme("challenge digest too long for ASN.1 length".into()))?;

	// ASN.1 DER: an OCTET STRING that holds the SHA-256 digest
	let mut asn1_value: Vec<u8> = Vec::with_capacity(SHA256_DIGEST_DER_OCTET_STRING_LEN);
	asn1_value.push(0x04); // OCTET STRING tag
	asn1_value.push(digest_len);
	asn1_value.extend_from_slice(digest_bytes);

	let oid: Vec<u64> = ACME_IDENTIFIER_OID.to_vec();
	let mut ext: CustomExtension = CustomExtension::from_oid_content(&oid, asn1_value);
	// RFC 8737 §3: the acmeIdentifier extension MUST be critical; validators (incl. pebble) reject it otherwise.
	ext.set_criticality(true);
	params.custom_extensions.push(ext);

	let cert: Certificate = params
		.self_signed(&key_pair)
		.map_err(|e| ReductionError::Acme(format!("challenge cert sign: {e}").into()))?;

	let cert_der: CertificateDer<'static> = CertificateDer::from(cert.der().to_vec());
	let key_der: PrivatePkcs8KeyDer<'static> = PrivatePkcs8KeyDer::from(key_pair.serialize_der());

	let signing_key: Arc<dyn SigningKey> = any_ecdsa_type(&PrivateKeyDer::Pkcs8(key_der))
		.map_err(|e| ReductionError::Acme(format!("challenge cert signing key: {e}").into()))?;

	return Ok(CertifiedKey::new(vec![cert_der], signing_key));
}

fn build_certified_key_from_pem(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey> {
	use std::io::BufReader;

	let cert_reader: BufReader<&[u8]> = BufReader::new(cert_pem.as_bytes());
	let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(cert_reader)
		.collect::<std::result::Result<Vec<_>, _>>()
		.map_err(|e| ReductionError::Acme(format!("failed to parse cert PEM: {e}").into()))?;

	if certs.is_empty() {
		return Err(ReductionError::Acme("no certificates in PEM".into()));
	}

	let key_reader: &mut BufReader<&[u8]> = &mut BufReader::new(key_pem.as_bytes());
	let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(key_reader)
		.map_err(|e| ReductionError::Acme(format!("failed to parse key PEM: {e}").into()))?;

	let signing_key: Arc<dyn SigningKey> =
		any_ecdsa_type(&key).map_err(|e| ReductionError::Acme(format!("failed to create signing key: {e}").into()))?;

	// CertifiedKey::new skips the key/cert check. A torn write can pair a new cert with a stale key that
	// loads clean but fails every handshake. Reject a proven mismatch to force a fresh provision, but
	// accept Unknown (no SPKI exposed), as CertifiedKey::from_der does.
	let certified: CertifiedKey = CertifiedKey::new(certs, signing_key);
	match certified.keys_match() {
		Ok(()) | Err(RustlsError::InconsistentKeys(InconsistentKeys::Unknown)) => {}
		Err(e) => return Err(ReductionError::Acme(format!("cached cert/key mismatch: {e}").into())),
	}
	return Ok(certified);
}

#[cfg(test)]
mod tests {
	use std::path::Path;
	use std::result::Result;
	use std::time::SystemTime;

	use arrayvec::ArrayString;

	use super::*;
	use crate::config::AcmeDirectory;

	// A cache torn by a crash between the two writes pairs a fresh cert with a stale key. The loader
	// must reject that mismatch. It must not return a CertifiedKey that fails every handshake.
	#[test]
	fn test_build_certified_key_rejects_mismatched_pair() -> Result<(), String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

		let key_a: KeyPair = match KeyPair::generate() {
			Ok(value) => value,
			Err(err) => return Err(format!("KeyPair::generate(): {err:?}")),
		};
		let params: CertificateParams = match CertificateParams::new(vec!["test.example.com".to_owned()]) {
			Ok(value) => value,
			Err(err) => return Err(format!("CertificateParams::new(vec![\"test.example.com\"...: {err:?}")),
		};
		let cert_a_pem: String = (match params.self_signed(&key_a) {
			Ok(value) => value,
			Err(err) => return Err(format!("params.self_signed(&key_a): {err:?}")),
		})
		.pem();

		let key_b_pem: String = (match KeyPair::generate() {
			Ok(value) => value,
			Err(err) => return Err(format!("KeyPair::generate(): {err:?}")),
		})
		.serialize_pem();

		let err: ReductionError = match build_certified_key_from_pem(&cert_a_pem, &key_b_pem) {
			Ok(value) => return Err(format!("build_certified_key_from...: expected Err, got Ok({value:?})")),
			Err(err) => err,
		};
		assert!(matches!(err, ReductionError::Acme(_)));
		assert!(format!("{err}").contains("mismatch"));
		return Ok(());
	}

	// Guards the happy path against the mismatch check: a genuine cert/key pair still loads.
	#[test]
	fn test_build_certified_key_accepts_matched_pair() -> Result<(), String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

		let key: KeyPair = match KeyPair::generate() {
			Ok(value) => value,
			Err(err) => return Err(format!("KeyPair::generate(): {err:?}")),
		};
		let params: CertificateParams = match CertificateParams::new(vec!["test.example.com".to_owned()]) {
			Ok(value) => value,
			Err(err) => return Err(format!("CertificateParams::new(vec![\"test.example.com\"...: {err:?}")),
		};
		let cert_pem: String = (match params.self_signed(&key) {
			Ok(value) => value,
			Err(err) => return Err(format!("params.self_signed(&key): {err:?}")),
		})
		.pem();
		let key_pem: String = key.serialize_pem();

		match build_certified_key_from_pem(&cert_pem, &key_pem) {
			Ok(value) => value,
			Err(err) => return Err(format!("build_certified_key_from_pem(&cert_pem, &key_pem): {err:?}")),
		};
		return Ok(());
	}

	#[test]
	fn test_failure_backoff_zero_failures_is_zero() {
		assert_eq!(failure_backoff(0), Duration::ZERO);
	}

	#[test]
	fn test_failure_backoff_doubles_from_base_and_caps() {
		assert_eq!(failure_backoff(1), Duration::from_secs(300));
		assert_eq!(failure_backoff(2), Duration::from_secs(600));
		assert_eq!(failure_backoff(3), Duration::from_secs(1200));
		assert_eq!(failure_backoff(7), Duration::from_secs(19_200), "the last step under the cap");
		assert_eq!(failure_backoff(8), Duration::from_secs(21_600), "6 h cap");
		assert_eq!(failure_backoff(10), Duration::from_secs(21_600));
		assert_eq!(failure_backoff(u32::MAX), Duration::from_secs(21_600));
	}

	// Rate-limit safety: in the first hour of failures, the total backoff must permit at most
	// 4 provision attempts. Let's Encrypt allows 5 failed validations/hour.
	#[test]
	fn test_failure_backoff_first_hour_stays_under_ca_rate_limit() {
		let mut elapsed: Duration = Duration::ZERO;
		let mut attempts: u32 = 1; // the first attempt, which fails at t=0
		let mut failures: u32 = 1;
		while elapsed + failure_backoff(failures) < Duration::from_secs(3600) {
			elapsed += failure_backoff(failures);
			attempts += 1;
			failures += 1;
		}
		assert!(attempts <= 4, "backoff allows {attempts} attempts in the first hour");
	}

	// A cert whose not_after is `days_from_now` days away. A negative count makes an expired cert.
	fn certified_key_expiring_in_days(
		domain: &str,
		days_from_now: i64,
	) -> Result<(CertifiedKey, String, String), String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let offset: Duration = Duration::from_secs(days_from_now.unsigned_abs().saturating_mul(86_400));
		let now: SystemTime = SystemTime::now();
		let shifted: Option<SystemTime> = if days_from_now < 0 {
			now.checked_sub(offset)
		} else {
			now.checked_add(offset)
		};
		let not_after: SystemTime = match shifted {
			Some(value) => value,
			None => return Err(format!("not_after {days_from_now} days from now is out of range")),
		};
		let key_pair: KeyPair = match KeyPair::generate() {
			Ok(value) => value,
			Err(err) => return Err(format!("KeyPair::generate(): {err:?}")),
		};
		let mut params: CertificateParams = match CertificateParams::new(vec![domain.to_owned()]) {
			Ok(value) => value,
			Err(err) => return Err(format!("CertificateParams::new(vec![domain.to_string()]): {err:?}")),
		};
		params.not_before = rcgen::date_time_ymd(2020, 1, 1);
		params.not_after = not_after.into();
		let cert: Certificate = match params.self_signed(&key_pair) {
			Ok(value) => value,
			Err(err) => return Err(format!("params.self_signed(&key_pair): {err:?}")),
		};
		let cert_pem: String = cert.pem();
		let key_pem: String = key_pair.serialize_pem();
		let certified: CertifiedKey = match build_certified_key_from_pem(&cert_pem, &key_pem) {
			Ok(value) => value,
			Err(err) => return Err(format!("build_certified_key_from_pem(&cert_pem, &key_pem): {err:?}")),
		};
		return Ok((certified, cert_pem, key_pem));
	}

	#[test]
	fn test_expiry_positive_and_renewal_subtracts_buffer() -> Result<(), String> {
		// ~60 days out: expiry is positive and renewal is expiry minus the 30-day buffer.
		let (certified, _, _) = match certified_key_expiring_in_days("fresh.example.com", 60) {
			Ok(value) => value,
			Err(err) => return Err(format!("certified_key_expiring_in_days(\"fresh.example.com...: {err}")),
		};
		let expiry: Duration = time_until_expiry_from_certified(&certified);
		let renewal: Duration = time_until_renewal_from_certified(&certified);
		assert!(expiry > Duration::from_secs(50 * 86_400));
		assert_eq!(
			renewal,
			expiry.saturating_sub(Duration::from_secs(30 * 86_400))
		);
		assert!(renewal > Duration::ZERO);
		return Ok(());
	}

	#[test]
	fn test_expiry_in_renewal_window_renewal_zero_expiry_positive() -> Result<(), String> {
		// 10 days out: inside the 30-day renewal window (renewal ZERO) but not expired.
		let (certified, _, _) = match certified_key_expiring_in_days("window.example.com", 10) {
			Ok(value) => value,
			Err(err) => return Err(format!("certified_key_expiring_in_days(\"window.example.co...: {err}")),
		};
		assert_eq!(time_until_renewal_from_certified(&certified), Duration::ZERO);
		assert!(time_until_expiry_from_certified(&certified) > Duration::ZERO);
		return Ok(());
	}

	fn unreachable_acme_config(cache_dir: &Path) -> Result<AcmeTlsConfig, String> {
		return Ok(AcmeTlsConfig {
			domains: vec![match ArrayString::from("stale.example.com") {
				Ok(value) => value,
				Err(err) => return Err(format!("ArrayString::from(\"stale.example.com\"): {err:?}")),
			}],
			acme_email: match ArrayString::from("ops@example.com") {
				Ok(value) => value,
				Err(err) => return Err(format!("ArrayString::from(\"ops@example.com\"): {err:?}")),
			},
			ca_cert_path: Some(cache_dir.join("unused-ca.pem")),
			cache_dir: cache_dir.to_path_buf(),
			// Nothing listens on port 1: the provision fails fast with connection refused.
			directory: AcmeDirectory::Custom("https://127.0.0.1:1/directory".to_owned()),
			directory_ca_cert: None,
			barrel_state: None,
		});
	}

	// Seed the file store cache with a cert+key blob, the same blob that a prior provision would persist.
	async fn seed_cached_cert(cache_dir: &Path, cert_pem: String, key_pem: String) -> Result<(), String> {
		let state: AcmeSecretState = crate::tls::secret_state::AcmeSecretState {
			account_credentials: None,
			cert_chain_pem: Some(cert_pem),
			key_pem: Some(key_pem),
		};
		let store: SecretStore = crate::tls::secret_state::SecretStore::File {
			cache_dir,
		};
		match store.persist(&state).await {
			Ok(value) => value,
			Err(err) => return Err(format!("store.persist(&state).await: {err:?}")),
		};
		return Ok(());
	}

	// Serve-stale: a boot during a CA outage, with a cached cert that is inside the renewal window
	// but still valid. It must serve the cached cert (Ok + resolver populated), not brick the proxy.
	#[tokio::test]
	async fn test_provision_initial_cert_serves_stale_cache_when_provisioning_fails() -> Result<(), String> {
		let dir: tempfile::TempDir = match tempfile::tempdir() {
			Ok(value) => value,
			Err(err) => return Err(format!("tempfile::tempdir(): {err:?}")),
		};
		let (_, cert_pem, key_pem) = match certified_key_expiring_in_days("stale.example.com", 10) {
			Ok(value) => value,
			Err(err) => return Err(format!("certified_key_expiring_in_days(\"stale.example.com...: {err}")),
		};
		match seed_cached_cert(dir.path(), cert_pem, key_pem).await {
			Ok(()) => {}
			Err(err) => return Err(format!("seed_cached_cert(dir.path(), cert_pem, key_pem)....: {err}")),
		};

		let resolver: Arc<AcmeCertResolver> = Arc::new(AcmeCertResolver::new());
		let (_shutdown_tx, shutdown_rx) = watch::channel(());
		let task: AcmeRenewalTask = AcmeRenewalTask::new(
			match unreachable_acme_config(dir.path()) {
				Ok(value) => value,
				Err(err) => return Err(format!("unreachable_acme_config(dir.path()): {err}")),
			},
			Arc::clone(&resolver),
			shutdown_rx,
			ProxyMetrics::new(),
		);

		let result: Result<(), ReductionError> = task.provision_initial_cert().await;
		assert!(
			result.is_ok(),
			"boot must serve the still-valid cached cert: {result:?}"
		);
		assert!(resolver.has_cert(), "resolver must hold the cached cert");
		return Ok(());
	}

	// Fail-closed counterpart: the task must not serve an EXPIRED cached cert. The provision error
	// still propagates and the resolver stays empty.
	#[tokio::test]
	async fn test_provision_initial_cert_rejects_expired_cache_when_provisioning_fails() -> Result<(), String> {
		let dir: tempfile::TempDir = match tempfile::tempdir() {
			Ok(value) => value,
			Err(err) => return Err(format!("tempfile::tempdir(): {err:?}")),
		};
		let (_, cert_pem, key_pem) = match certified_key_expiring_in_days("dead.example.com", -10) {
			Ok(value) => value,
			Err(err) => return Err(format!("certified_key_expiring_in_days(\"dead.example.com...: {err}")),
		};
		match seed_cached_cert(dir.path(), cert_pem, key_pem).await {
			Ok(()) => {}
			Err(err) => return Err(format!("seed_cached_cert(dir.path(), cert_pem, key_pem)....: {err}")),
		};

		let resolver: Arc<AcmeCertResolver> = Arc::new(AcmeCertResolver::new());
		let (_shutdown_tx, shutdown_rx) = watch::channel(());
		let task: AcmeRenewalTask = AcmeRenewalTask::new(
			match unreachable_acme_config(dir.path()) {
				Ok(value) => value,
				Err(err) => return Err(format!("unreachable_acme_config(dir.path()): {err}")),
			},
			Arc::clone(&resolver),
			shutdown_rx,
			ProxyMetrics::new(),
		);

		let result: Result<(), ReductionError> = task.provision_initial_cert().await;
		assert!(result.is_err(), "an expired cached cert must not be served");
		assert!(!resolver.has_cert(), "resolver must stay empty on fail-closed boot");
		return Ok(());
	}

	// Renewal survives a restart. The test persists a cert to the store, well outside the renewal window.
	// A FRESH task on the same store loads and serves it, with no contact to the (unreachable) CA.
	// This is the store-abstraction proof that persisted ACME state outlives a process restart.
	#[tokio::test]
	async fn persisted_cert_survives_restart_via_store() -> Result<(), String> {
		let dir: tempfile::TempDir = match tempfile::tempdir() {
			Ok(value) => value,
			Err(err) => return Err(format!("tempfile::tempdir(): {err:?}")),
		};
		let (_, cert_pem, key_pem) = match certified_key_expiring_in_days("survives.example.com", 60) {
			Ok(value) => value,
			Err(err) => return Err(format!("certified_key_expiring_in_days(\"survives.example....: {err}")),
		};
		match seed_cached_cert(dir.path(), cert_pem, key_pem).await {
			Ok(()) => {}
			Err(err) => return Err(format!("seed_cached_cert(dir.path(), cert_pem, key_pem)....: {err}")),
		};

		let resolver: Arc<AcmeCertResolver> = Arc::new(AcmeCertResolver::new());
		let (_shutdown_tx, shutdown_rx) = watch::channel(());
		let task: AcmeRenewalTask = AcmeRenewalTask::new(
			match unreachable_acme_config(dir.path()) {
				Ok(value) => value,
				Err(err) => return Err(format!("unreachable_acme_config(dir.path()): {err}")),
			},
			Arc::clone(&resolver),
			shutdown_rx,
			ProxyMetrics::new(),
		);

		// 60 days out is well past the 30-day renewal buffer, so boot loads and serves it with no new provision.
		match task.provision_initial_cert().await {
			Ok(value) => value,
			Err(err) => return Err(format!("a fresh task must load the persisted cert on boot: {err:?}")),
		};
		assert!(resolver.has_cert(), "persisted state must survive a restart");
		return Ok(());
	}

	#[test]
	fn test_time_until_renewal_expired_cert() -> Result<(), String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

		let key_pair: KeyPair = match KeyPair::generate() {
			Ok(value) => value,
			Err(err) => return Err(format!("KeyPair::generate(): {err:?}")),
		};
		let mut params: CertificateParams = match CertificateParams::new(vec!["test.example.com".to_owned()]) {
			Ok(value) => value,
			Err(err) => return Err(format!("CertificateParams::new(vec![\"test.example.com\"...: {err:?}")),
		};
		params.not_before = rcgen::date_time_ymd(2020, 1, 1);
		params.not_after = rcgen::date_time_ymd(2020, 1, 2);
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

		let duration: Duration = time_until_renewal_from_certified(&certified);
		assert_eq!(duration, Duration::ZERO);
		return Ok(());
	}
}
