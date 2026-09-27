// Shared PKI fixtures for crate unit tests; generators return rcgen `CertifiedKey`s callers serialize to PEM.

use std::io::Write;

use rcgen::{BasicConstraints, CertificateParams, CertifiedKey, DnType, DnValue, IsCa, Issuer, KeyPair, SanType};
use tempfile::NamedTempFile;

// Self-signed CA for issuing leaf certs; the CN is never asserted on, only gives the issuer a DN.
pub fn generate_ca() -> CertifiedKey<KeyPair> {
	let key: KeyPair = KeyPair::generate().unwrap();
	let mut params: CertificateParams = CertificateParams::new(vec![]).unwrap();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	params
		.distinguished_name
		.push(DnType::CommonName, DnValue::Utf8String("Test CA".to_string()));
	let cert = params.self_signed(&key).unwrap();
	return CertifiedKey { cert, signing_key: key };
}

// Leaf signed by `ca` with explicit CN and SAN set; `sans` is applied verbatim (empty = no SANs).
pub fn generate_signed_cert(ca: &CertifiedKey<KeyPair>, cn: &str, sans: Vec<SanType>) -> CertifiedKey<KeyPair> {
	let key: KeyPair = KeyPair::generate().unwrap();
	let mut params: CertificateParams = CertificateParams::new(vec![]).unwrap();
	params
		.distinguished_name
		.push(DnType::CommonName, DnValue::Utf8String(cn.to_string()));
	params.subject_alt_names = sans;
	let issuer: Issuer<'_, &KeyPair> = Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key).unwrap();
	let cert = params.signed_by(&key, &issuer).unwrap();
	return CertifiedKey { cert, signing_key: key };
}

// Server leaf with CN and DNS SAN both "localhost" (matches a handshake against ServerName "localhost").
pub fn generate_localhost_cert(ca: &CertifiedKey<KeyPair>) -> CertifiedKey<KeyPair> {
	return generate_signed_cert(ca, "localhost", vec![SanType::DnsName("localhost".try_into().unwrap())]);
}

pub fn write_pem(content: &str) -> NamedTempFile {
	let mut f: NamedTempFile = NamedTempFile::new().unwrap();
	f.write_all(content.as_bytes()).unwrap();
	f.flush().unwrap();
	return f;
}
