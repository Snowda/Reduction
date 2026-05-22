use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier,
    KeyAuthorization, NewAccount, NewOrder,
};
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{error, info, warn};
use x509_parser::prelude::*;

use crate::config::AcmeTlsConfig;
use crate::error::{ReductionError, Result};

const ACME_TLS_ALPN_PROTO: &[u8] = b"acme-tls/1";
const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];
const ACME_RENEWAL_BUFFER_SECS: u64 = 30 * 24 * 60 * 60;
const ACME_RETRY_INTERVAL_SECS: u64 = 43200;
const ACME_POLL_INTERVAL_SECS: u64 = 5;
const ACME_MAX_POLL_ATTEMPTS: u32 = 60;
const LETS_ENCRYPT_PRODUCTION_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LETS_ENCRYPT_STAGING_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const ACCOUNT_KEY_FILENAME: &str = "account_credentials.json";
const CERT_FILENAME: &str = "cert.pem";
const KEY_FILENAME: &str = "key.pem";

pub struct AcmeCertResolver {
    pub(crate) cert: parking_lot::RwLock<Option<Arc<CertifiedKey>>>,
    challenge_cert: parking_lot::RwLock<Option<Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for AcmeCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return f.debug_struct("AcmeCertResolver")
            .field("has_cert", &self.has_cert())
            .finish();
    }
}

impl AcmeCertResolver {
    pub fn new() -> Self {
        return Self {
            cert: parking_lot::RwLock::new(None),
            challenge_cert: parking_lot::RwLock::new(None),
        };
    }

    pub fn set_cert(&self, key: CertifiedKey) {
        let mut guard = self.cert.write();
        *guard = Some(Arc::new(key));
    }

    pub fn set_challenge_cert(&self, key: Option<CertifiedKey>) {
        let mut guard = self.challenge_cert.write();
        *guard = key.map(Arc::new);
    }

    pub fn has_cert(&self) -> bool {
        return self.cert.read().is_some();
    }
}

impl ResolvesServerCert for AcmeCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        if let Some(alpn) = client_hello.alpn() {
            for proto in alpn {
                if proto == ACME_TLS_ALPN_PROTO {
                    return self.challenge_cert.read().clone();
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
}

impl AcmeRenewalTask {
    pub fn new(
        config: AcmeTlsConfig,
        resolver: Arc<AcmeCertResolver>,
        shutdown: watch::Receiver<()>,
    ) -> Self {
        return Self { config, resolver, shutdown };
    }

    pub async fn provision_initial_cert(&self) -> Result<()> {
        if let Some(certified_key) = self.load_cached_cert() {
            let renewal_in: Duration = time_until_renewal_from_certified(&certified_key);
            if renewal_in > Duration::ZERO {
                info!(renewal_in_secs = renewal_in.as_secs(), "loaded cached ACME certificate");
                self.resolver.set_cert(certified_key);
                return Ok(());
            }
            info!("cached ACME certificate is within renewal window, provisioning new one");
        }

        let certified_key: CertifiedKey = self.provision_cert().await?;
        self.resolver.set_cert(certified_key);
        return Ok(());
    }

    pub async fn run(mut self) {
        loop {
            let sleep_duration: Duration = {
                let cert_guard = self.resolver.cert.read();
                match cert_guard.as_ref() {
                    Some(key) => time_until_renewal_from_certified(key),
                    None => Duration::from_secs(ACME_RETRY_INTERVAL_SECS),
                }
            };

            info!(sleep_secs = sleep_duration.as_secs(), "ACME renewal loop sleeping");

            tokio::select! {
                _ = sleep(sleep_duration) => {}
                _ = self.shutdown.changed() => {
                    info!("ACME renewal task shutting down");
                    return;
                }
            }

            match self.provision_cert().await {
                Ok(certified_key) => {
                    info!("ACME certificate renewed successfully");
                    self.resolver.set_cert(certified_key);
                }
                Err(e) => {
                    error!(error = %e, "ACME certificate renewal failed, retrying later");
                }
            }
        }
    }

    async fn provision_cert(&self) -> Result<CertifiedKey> {
        let directory_url: &str = if self.config.staging {
            LETS_ENCRYPT_STAGING_URL
        } else {
            LETS_ENCRYPT_PRODUCTION_URL
        };

        fs::create_dir_all(&self.config.cache_dir)
            .map_err(|e| ReductionError::Acme(format!("failed to create cache dir: {e}")))?;

        let account: Account = self.get_or_create_account(directory_url).await?;

        let identifiers: Vec<Identifier> = self.config.domains.iter()
            .map(|d| Identifier::Dns(d.to_string()))
            .collect();

        let mut order = account.new_order(&NewOrder { identifiers: &identifiers })
            .await
            .map_err(|e| ReductionError::Acme(format!("failed to create order: {e}")))?;

        let authorizations = order.authorizations()
            .await
            .map_err(|e| ReductionError::Acme(format!("failed to get authorizations: {e}")))?;

        for authz in &authorizations {
            match authz.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                status => {
                    return Err(ReductionError::Acme(
                        format!("unexpected authorization status: {status:?}")
                    ));
                }
            }

            let challenge = authz.challenges.iter()
                .find(|c| c.r#type == ChallengeType::TlsAlpn01)
                .ok_or_else(|| ReductionError::Acme(
                    "no tls-alpn-01 challenge found".to_string()
                ))?;

            let key_auth: KeyAuthorization = order.key_authorization(challenge);
            let Identifier::Dns(ref domain) = authz.identifier;

            let challenge_cert: CertifiedKey = build_tls_alpn_challenge_cert(domain, &key_auth)?;
            self.resolver.set_challenge_cert(Some(challenge_cert));

            order.set_challenge_ready(&challenge.url)
                .await
                .map_err(|e| ReductionError::Acme(format!("failed to signal challenge ready: {e}")))?;

            let mut attempts: u32 = 0;
            loop {
                sleep(Duration::from_secs(ACME_POLL_INTERVAL_SECS)).await;
                attempts += 1;
                if attempts > ACME_MAX_POLL_ATTEMPTS {
                    self.resolver.set_challenge_cert(None);
                    return Err(ReductionError::Acme(
                        "timed out waiting for challenge validation".to_string()
                    ));
                }

                let fresh_authz = order.authorizations()
                    .await
                    .map_err(|e| ReductionError::Acme(format!("poll authorizations: {e}")))?;

                let current = fresh_authz.iter()
                    .find(|a| {
                        let Identifier::Dns(ref d) = a.identifier;
                        d == domain
                    });

                match current.map(|a| &a.status) {
                    Some(AuthorizationStatus::Valid) => break,
                    Some(AuthorizationStatus::Pending) => continue,
                    Some(status) => {
                        self.resolver.set_challenge_cert(None);
                        return Err(ReductionError::Acme(
                            format!("challenge failed with status: {status:?}")
                        ));
                    }
                    None => {
                        self.resolver.set_challenge_cert(None);
                        return Err(ReductionError::Acme(
                            "authorization disappeared during polling".to_string()
                        ));
                    }
                }
            }

            self.resolver.set_challenge_cert(None);
        }

        let cert_key: KeyPair = KeyPair::generate()
            .map_err(|e| ReductionError::Acme(format!("failed to generate cert key: {e}")))?;

        let domains: Vec<String> = self.config.domains.iter()
            .map(|d| d.to_string())
            .collect();

        let csr_params: CertificateParams = CertificateParams::new(domains)
            .map_err(|e| ReductionError::Acme(format!("failed to create CSR params: {e}")))?;

        let csr_der: Vec<u8> = csr_params.serialize_request(&cert_key)
            .map_err(|e| ReductionError::Acme(format!("failed to serialize CSR: {e}")))?
            .der()
            .to_vec();

        order.finalize(&csr_der)
            .await
            .map_err(|e| ReductionError::Acme(format!("failed to finalize order: {e}")))?;

        let mut attempts: u32 = 0;
        let cert_chain_pem: String = loop {
            sleep(Duration::from_secs(ACME_POLL_INTERVAL_SECS)).await;
            attempts += 1;
            if attempts > ACME_MAX_POLL_ATTEMPTS {
                return Err(ReductionError::Acme(
                    "timed out waiting for certificate".to_string()
                ));
            }

            match order.certificate().await {
                Ok(Some(cert)) => break cert,
                Ok(None) => continue,
                Err(e) => {
                    return Err(ReductionError::Acme(
                        format!("failed to download cert: {e}")
                    ));
                }
            }
        };

        let key_pem: String = cert_key.serialize_pem();

        let cert_path: PathBuf = self.config.cache_dir.join(CERT_FILENAME);
        let key_path: PathBuf = self.config.cache_dir.join(KEY_FILENAME);

        fs::write(&cert_path, cert_chain_pem.as_bytes())
            .map_err(|e| ReductionError::Acme(format!("failed to write cert: {e}")))?;
        fs::write(&key_path, key_pem.as_bytes())
            .map_err(|e| ReductionError::Acme(format!("failed to write key: {e}")))?;

        info!(cert_path = %cert_path.display(), "ACME certificate provisioned and cached");

        return build_certified_key_from_pem(&cert_chain_pem, &key_pem);
    }

    async fn get_or_create_account(&self, directory_url: &str) -> Result<Account> {
        let account_key_path: PathBuf = self.config.cache_dir.join(ACCOUNT_KEY_FILENAME);

        if account_key_path.exists() {
            let json: String = fs::read_to_string(&account_key_path)
                .map_err(|e| ReductionError::Acme(format!("failed to read account credentials: {e}")))?;

            let credentials: AccountCredentials = serde_json::from_str(&json)
                .map_err(|e| ReductionError::Acme(format!("failed to parse account credentials: {e}")))?;

            let account: Account = Account::from_credentials(credentials)
                .await
                .map_err(|e| ReductionError::Acme(format!("failed to restore account: {e}")))?;

            info!("restored existing ACME account");
            return Ok(account);
        }

        let email: String = format!("mailto:{}", self.config.acme_email.as_str());
        let (account, credentials) = Account::create(
            &NewAccount {
                contact: &[&email],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
            .await
            .map_err(|e| ReductionError::Acme(format!("failed to create ACME account: {e}")))?;

        let serialized: String = serde_json::to_string(&credentials)
            .map_err(|e| ReductionError::Acme(format!("failed to serialize credentials: {e}")))?;

        let mut file = fs::File::create(&account_key_path)
            .map_err(|e| ReductionError::Acme(format!("failed to create account key file: {e}")))?;
        file.write_all(serialized.as_bytes())
            .map_err(|e| ReductionError::Acme(format!("failed to write account credentials: {e}")))?;

        info!(path = %account_key_path.display(), "created new ACME account");
        return Ok(account);
    }

    fn load_cached_cert(&self) -> Option<CertifiedKey> {
        let cert_path: PathBuf = self.config.cache_dir.join(CERT_FILENAME);
        let key_path: PathBuf = self.config.cache_dir.join(KEY_FILENAME);

        if !cert_path.exists() || !key_path.exists() {
            return None;
        }

        let cert_pem: String = fs::read_to_string(&cert_path).ok()?;
        let key_pem: String = fs::read_to_string(&key_path).ok()?;

        match build_certified_key_from_pem(&cert_pem, &key_pem) {
            Ok(key) => Some(key),
            Err(e) => {
                warn!(error = %e, "failed to load cached ACME certificate");
                None
            }
        }
    }
}

fn time_until_renewal_from_certified(certified_key: &CertifiedKey) -> Duration {
    let cert_der: &[u8] = match certified_key.cert.first() {
        Some(c) => c.as_ref(),
        None => return Duration::ZERO,
    };

    match X509Certificate::from_der(cert_der) {
        Ok((_, cert)) => {
            let not_after = cert.validity().not_after.timestamp();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs() as i64;

            let remaining_secs: i64 = not_after - now;
            let renewal_threshold: i64 = ACME_RENEWAL_BUFFER_SECS as i64;

            if remaining_secs <= renewal_threshold {
                return Duration::ZERO;
            }
            return Duration::from_secs((remaining_secs - renewal_threshold) as u64);
        }
        Err(e) => {
            warn!(error = %e, "failed to parse certificate for renewal calculation");
            return Duration::ZERO;
        }
    }
}

fn build_tls_alpn_challenge_cert(domain: &str, key_auth: &KeyAuthorization) -> Result<CertifiedKey> {
    let key_pair: KeyPair = KeyPair::generate()
        .map_err(|e| ReductionError::Acme(format!("challenge cert keygen: {e}")))?;

    let mut params: CertificateParams = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| ReductionError::Acme(format!("challenge cert params: {e}")))?;

    let digest = key_auth.digest();
    let digest_bytes: &[u8] = digest.as_ref();

    // ASN.1 DER encoding: OCTET STRING wrapping the SHA-256 digest
    let mut asn1_value: Vec<u8> = Vec::with_capacity(34);
    asn1_value.push(0x04); // OCTET STRING tag
    asn1_value.push(digest_bytes.len() as u8);
    asn1_value.extend_from_slice(digest_bytes);

    let oid: Vec<u64> = ACME_IDENTIFIER_OID.to_vec();
    let ext: CustomExtension = CustomExtension::from_oid_content(&oid, asn1_value);
    params.custom_extensions.push(ext);

    let cert = params.self_signed(&key_pair)
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
        return Err(ReductionError::Acme("no certificates in PEM".to_string()));
    }

    let key_reader = &mut BufReader::new(key_pem.as_bytes());
    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(key_reader)
        .map_err(|e| ReductionError::Acme(format!("failed to parse key PEM: {e}")))?;

    let signing_key = any_ecdsa_type(&key)
        .map_err(|e| ReductionError::Acme(format!("failed to create signing key: {e}")))?;

    return Ok(CertifiedKey::new(certs, signing_key));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolver_returns_none_initially() {
        let resolver = AcmeCertResolver::new();
        assert!(!resolver.has_cert());
    }

    #[test]
    fn test_resolver_set_and_get_cert() {
        let _ = rustls::crypto::ring::default_provider().install_default();

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

    #[test]
    fn test_time_until_renewal_expired_cert() {
        let _ = rustls::crypto::ring::default_provider().install_default();

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
