use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::error::{ReductionError, Result};

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

// Build a rustls ServerConfig with mTLS (mutual TLS) requiring client certificates.
pub fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
    ca_cert_path: &Path,
) -> Result<ServerConfig> {
    let certs: Vec<CertificateDer<'static>> = load_certs(cert_path)?;
    let key: PrivateKeyDer<'static> = load_private_key(key_path)?;
    let root_store: RootCertStore = load_ca_certs(ca_cert_path)?;

    let client_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
        WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| ReductionError::Config(format!("failed to build client verifier: {e}")))?;

    let config: ServerConfig = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)?;

    return Ok(config);
}

// Build a rustls ClientConfig with mTLS for connecting to backends.
pub fn build_client_config(
    cert_path: &Path,
    key_path: &Path,
    ca_cert_path: &Path,
) -> Result<ClientConfig> {
    let certs: Vec<CertificateDer<'static>> = load_certs(cert_path)?;
    let key: PrivateKeyDer<'static> = load_private_key(key_path)?;
    let root_store: RootCertStore = load_ca_certs(ca_cert_path)?;

    let config: ClientConfig = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)?;

    return Ok(config);
}
