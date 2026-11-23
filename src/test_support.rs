// Shared PKI fixtures for crate unit tests. Generators return rcgen `CertifiedKey`s that callers serialize to PEM.

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use rcgen::{
	BasicConstraints, CertificateParams, CertifiedKey, DnType, DnValue, Error as RcgenError, IsCa, Issuer, KeyPair, SanType,
};
use rcgen::string::Ia5String;
use tempfile::NamedTempFile;

#[cfg(feature = "proxy")]
pub mod backend;
pub mod handshake;
#[cfg(feature = "proxy")]
pub mod probe;
pub mod quic;

// Self-signed CA that issues leaf certs. No test asserts the CN. It only gives the issuer a DN.
pub fn generate_ca() -> Result<CertifiedKey<KeyPair>, String> {
	return self_signed_ca().map_err(|err| format!("generate CA: {err:?}"));
}

fn self_signed_ca() -> Result<CertifiedKey<KeyPair>, RcgenError> {
	let key: KeyPair = KeyPair::generate()?;
	let mut params: CertificateParams = leaf_params("Test CA", vec![])?;
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let cert = params.self_signed(&key)?;
	return Ok(CertifiedKey { cert, signing_key: key });
}

// Params with CN `cn` and the SAN set `sans` applied verbatim (empty = no SANs).
fn leaf_params(cn: &str, sans: Vec<SanType>) -> Result<CertificateParams, RcgenError> {
	let mut params: CertificateParams = CertificateParams::new(vec![])?;
	params
		.distinguished_name
		.push(DnType::CommonName, DnValue::Utf8String(cn.to_owned()));
	params.subject_alt_names = sans;
	return Ok(params);
}

// Sign `params` with a fresh key under `ca`.
fn sign_leaf(ca: &CertifiedKey<KeyPair>, params: &CertificateParams) -> Result<CertifiedKey<KeyPair>, RcgenError> {
	let key: KeyPair = KeyPair::generate()?;
	let issuer: Issuer<'_, &KeyPair> = Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key)?;
	let cert = params.signed_by(&key, &issuer)?;
	return Ok(CertifiedKey { cert, signing_key: key });
}

// Leaf signed by `ca` with explicit CN and SAN set. The leaf takes `sans` verbatim (empty = no SANs).
pub fn generate_signed_cert(
	ca: &CertifiedKey<KeyPair>,
	cn: &str,
	sans: Vec<SanType>,
) -> Result<CertifiedKey<KeyPair>, String> {
	return leaf_params(cn, sans)
		.and_then(|params: CertificateParams| sign_leaf(ca, &params))
		.map_err(|err| format!("leaf {cn:?}: {err:?}"));
}

// RFC 4519 `uid` as rcgen arcs, as CAS writes it. tls::identity tests assert it encodes to 060a0992268993f22c640101.
pub const UID_OID_ARCS: [u64; 7] = [0, 9, 2342, 19_200_300, 100, 1, 1];

// Leaf signed by `ca` with a `uid` attribute, plus the given CN and SANs as name carriers.
pub fn generate_signed_uid_cert(
	ca: &CertifiedKey<KeyPair>,
	uid: &str,
	cn: &str,
	sans: Vec<SanType>,
) -> Result<CertifiedKey<KeyPair>, String> {
	return leaf_params(cn, sans)
		.and_then(|mut params: CertificateParams| {
			params.distinguished_name.push(
				DnType::CustomDnType(UID_OID_ARCS.to_vec()),
				DnValue::Utf8String(uid.to_owned()),
			);
			return sign_leaf(ca, &params);
		})
		.map_err(|err| format!("uid leaf {uid:?}: {err:?}"));
}

// Server leaf with CN and DNS SAN both "localhost" (matches a handshake against ServerName "localhost").
pub fn generate_localhost_cert(ca: &CertifiedKey<KeyPair>) -> Result<CertifiedKey<KeyPair>, String> {
	return Ia5String::try_from("localhost")
		.and_then(|name: Ia5String| leaf_params("localhost", vec![SanType::DnsName(name)]))
		.and_then(|params: CertificateParams| sign_leaf(ca, &params))
		.map_err(|err| format!("localhost leaf: {err:?}"));
}

/// 127.0.0.1 on an OS-chosen port: what tests bind to. It has no parse step, so it cannot fail.
pub const LOOPBACK_ANY: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

/// A leaf with its certificate and key written to PEM files. The files exist while this value lives.
pub struct LeafFiles {
	pub leaf: CertifiedKey<KeyPair>,
	pub cert: NamedTempFile,
	pub key: NamedTempFile,
}

pub fn leaf_files(leaf: CertifiedKey<KeyPair>) -> Result<LeafFiles, String> {
	let cert: NamedTempFile = write_pem(&leaf.cert.pem())?;
	let key: NamedTempFile = write_pem(&leaf.signing_key.serialize_pem())?;
	return Ok(LeafFiles { leaf, cert, key });
}

/// A CA written to a PEM file, a localhost server leaf and a client leaf, both signed by the CA.
pub struct Pki {
	pub ca_file: NamedTempFile,
	pub server: LeafFiles,
	pub client: LeafFiles,
}

// The client leaf has CN `client_cn` and no SANs.
pub fn pki(client_cn: &str) -> Result<Pki, String> {
	let ca: CertifiedKey<KeyPair> = generate_ca()?;
	let server: LeafFiles = generate_localhost_cert(&ca).and_then(leaf_files)?;
	let client: LeafFiles = generate_signed_cert(&ca, client_cn, vec![]).and_then(leaf_files)?;
	let ca_file: NamedTempFile = write_pem(&ca.cert.pem())?;
	return Ok(Pki {
		ca_file,
		server,
		client,
	});
}

pub fn write_pem(content: &str) -> Result<NamedTempFile, String> {
	return write_temp(content).map_err(|err| format!("write PEM to a temp file: {err:?}"));
}

fn write_temp(content: &str) -> io::Result<NamedTempFile> {
	let mut f: NamedTempFile = NamedTempFile::new()?;
	f.write_all(content.as_bytes())?;
	f.flush()?;
	return Ok(f);
}
