use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::server::danger::ClientCertVerifier;

use super::{ReloadingClientVerifier, ReloadingServerVerifier};

pub fn crl_ca() -> rcgen::CertifiedKey<rcgen::KeyPair> {
	let key = rcgen::KeyPair::generate().unwrap();
	let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
	params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
	params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
	params.distinguished_name.push(
		rcgen::DnType::CommonName,
		rcgen::DnValue::Utf8String("CRL Test CA".to_string()),
	);
	let cert = params.self_signed(&key).unwrap();
	return rcgen::CertifiedKey { cert, signing_key: key };
}

// A client leaf with a caller-chosen serial so the CRL can name it precisely.
pub fn crl_leaf(
	ca: &rcgen::CertifiedKey<rcgen::KeyPair>,
	cn: &str,
	serial: u64,
) -> rcgen::CertifiedKey<rcgen::KeyPair> {
	let key = rcgen::KeyPair::generate().unwrap();
	let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
	params.serial_number = Some(rcgen::SerialNumber::from(serial));
	params
		.distinguished_name
		.push(rcgen::DnType::CommonName, rcgen::DnValue::Utf8String(cn.to_string()));
	let issuer = rcgen::Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key).unwrap();
	let cert = params.signed_by(&key, &issuer).unwrap();
	return rcgen::CertifiedKey { cert, signing_key: key };
}

// PEM of a CA-signed CRL revoking each of `revoked_serials`. next_update is far future so
// enforce_revocation_expiration accepts it at the real current time.
pub fn make_crl_pem(ca: &rcgen::CertifiedKey<rcgen::KeyPair>, revoked_serials: &[u64]) -> String {
	let revoked_certs: Vec<rcgen::RevokedCertParams> = revoked_serials
		.iter()
		.map(|s| rcgen::RevokedCertParams {
			serial_number: rcgen::SerialNumber::from(*s),
			revocation_time: rcgen::date_time_ymd(2020, 1, 1),
			reason_code: None,
			invalidity_date: None,
		})
		.collect();
	let params = rcgen::CertificateRevocationListParams {
		this_update: rcgen::date_time_ymd(2020, 1, 1),
		next_update: rcgen::date_time_ymd(2100, 1, 1),
		crl_number: rcgen::SerialNumber::from(1u64),
		issuing_distribution_point: None,
		revoked_certs,
		key_identifier_method: rcgen::KeyIdMethod::Sha256,
	};
	let issuer = rcgen::Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key).unwrap();
	return params.signed_by(&issuer).unwrap().pem().unwrap();
}

pub fn verifier_accepts(v: &ReloadingClientVerifier, leaf: &rcgen::CertifiedKey<rcgen::KeyPair>) -> bool {
	return v.verify_client_cert(leaf.cert.der(), &[], UnixTime::now()).is_ok();
}

// Verifies a backend/server leaf the way a real handshake would: a matching ServerName ("localhost",
// the SAN generate_signed_cert stamps) plus the full chain, so a positive result means name + chain
// both validated, not an accidental pass.
pub fn server_verifier_accepts(v: &ReloadingServerVerifier, leaf: &rcgen::CertifiedKey<rcgen::KeyPair>) -> bool {
	let name: ServerName<'_> = ServerName::try_from("localhost").unwrap();
	return v
		.verify_server_cert(leaf.cert.der(), &[], &name, &[], UnixTime::now())
		.is_ok();
}
