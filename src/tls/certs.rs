use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::error::{ReductionError, Result};
use crate::tls::reload::{ReloadingCertResolver, ReloadingClientCertResolver};

// Load PEM-encoded certificates from a file.
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file: fs::File = fs::File::open(path)
        .map_err(|e| ReductionError::Config(format!("failed to open cert file {}: {e}", path.display())))?;
    let reader: BufReader<fs::File> = BufReader::new(file);

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ReductionError::Config(format!("failed to parse certs from {}: {e}", path.display())))?;

    if certs.is_empty() {
        return Err(ReductionError::Config(format!("no certificates found in {}", path.display())));
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
        root_store.add(cert)
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
    let resolver: Arc<ReloadingCertResolver> =
        Arc::new(ReloadingCertResolver::new(cert_path, key_path)?);
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

// Build a rustls ClientConfig with mTLS and a reloadable cert resolver.
pub fn build_client_config(
    cert_path: &Path,
    key_path: &Path,
    ca_cert_path: &Path,
) -> Result<(ClientConfig, Arc<ReloadingClientCertResolver>)> {
    let resolver: Arc<ReloadingClientCertResolver> =
        Arc::new(ReloadingClientCertResolver::new(cert_path, key_path)?);
    let root_store: RootCertStore = load_ca_certs(ca_cert_path)?;

    let mut config: ClientConfig = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_cert_resolver(resolver.clone());

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    return Ok((config, resolver));
}

#[cfg(feature = "acme")]
pub fn build_acme_server_config(
    ca_cert_path: &Path,
    resolver: Arc<crate::tls::acme::AcmeCertResolver>,
) -> Result<ServerConfig> {
    let root_store: RootCertStore = load_ca_certs(ca_cert_path)?;

    let client_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
        WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| ReductionError::Config(format!("failed to build client verifier: {e}")))?;

    let mut config: ServerConfig = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_cert_resolver(resolver);

    config.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
        b"acme-tls/1".to_vec(),
    ];

    return Ok(config);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use rustls::client::ResolvesClientCert;
    use tempfile::NamedTempFile;

    fn generate_ca() -> rcgen::CertifiedKey<rcgen::KeyPair> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("Test CA".to_string()),
        );
        let cert = params.self_signed(&key).unwrap();
        return rcgen::CertifiedKey { cert, signing_key: key };
    }

    fn generate_signed_cert(ca: &rcgen::CertifiedKey<rcgen::KeyPair>) -> rcgen::CertifiedKey<rcgen::KeyPair> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("localhost".to_string()),
        );
        let issuer = rcgen::Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key).unwrap();
        let cert = params.signed_by(&key, &issuer).unwrap();
        return rcgen::CertifiedKey { cert, signing_key: key };
    }

    fn write_pem(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        return f;
    }

    fn setup_pki() -> (NamedTempFile, NamedTempFile, NamedTempFile) {
        let ca = generate_ca();
        let leaf = generate_signed_cert(&ca);

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
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert_file, key_file, ca_file) = setup_pki();
        let result = build_server_config(cert_file.path(), key_file.path(), ca_file.path());
        assert!(result.is_ok());
        let (_config, resolver) = result.unwrap();
        assert!(!resolver.current().cert.is_empty());
    }

    #[test]
    fn test_build_server_config_bad_cert() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = generate_ca();
        let ca_file = write_pem(&ca.cert.pem());
        let key_file = write_pem(&ca.signing_key.serialize_pem());
        let bad_cert = write_pem("not a cert");

        let result = build_server_config(bad_cert.path(), key_file.path(), ca_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_client_config_valid() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert_file, key_file, ca_file) = setup_pki();
        let result = build_client_config(cert_file.path(), key_file.path(), ca_file.path());
        assert!(result.is_ok());
        let (_config, resolver) = result.unwrap();
        assert!(resolver.has_certs());
    }

    #[test]
    fn test_build_client_config_bad_key() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = generate_ca();
        let cert_file = write_pem(&ca.cert.pem());
        let ca_file = write_pem(&ca.cert.pem());
        let bad_key = write_pem("not a key");

        let result = build_client_config(cert_file.path(), bad_key.path(), ca_file.path());
        assert!(result.is_err());
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
}
