use std::fs;
use std::path::Path;
#[cfg(feature = "proxy")]
use std::thread;
#[cfg(feature = "proxy")]
use std::time::Duration;

use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::server::danger::ClientCertVerifier;

use server_utils::ctx::Ctx;

use super::{ReloadingClientVerifier, ReloadingServerVerifier};
use crate::test_support::{generate_ca, generate_localhost_cert};

pub fn crl_ca() -> Result<rcgen::CertifiedKey<rcgen::KeyPair>, String> {
	return self_signed_crl_ca().ctx("CRL CA");
}

fn self_signed_crl_ca() -> Result<rcgen::CertifiedKey<rcgen::KeyPair>, rcgen::Error> {
	let key = rcgen::KeyPair::generate()?;
	let mut params = rcgen::CertificateParams::new(vec![])?;
	params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
	params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
	params.distinguished_name.push(
		rcgen::DnType::CommonName,
		rcgen::DnValue::Utf8String("CRL Test CA".to_owned()),
	);
	let cert = params.self_signed(&key)?;
	return Ok(rcgen::CertifiedKey { cert, signing_key: key });
}

// A client leaf with a caller-chosen serial so the CRL can name it precisely.
pub fn crl_leaf(
	ca: &rcgen::CertifiedKey<rcgen::KeyPair>,
	cn: &str,
	serial: u64,
) -> Result<rcgen::CertifiedKey<rcgen::KeyPair>, String> {
	return serial_leaf(ca, cn, serial).map_err(|err| format!("CRL leaf {cn:?} serial {serial}: {err:?}"));
}

fn serial_leaf(
	ca: &rcgen::CertifiedKey<rcgen::KeyPair>,
	cn: &str,
	serial: u64,
) -> Result<rcgen::CertifiedKey<rcgen::KeyPair>, rcgen::Error> {
	let key = rcgen::KeyPair::generate()?;
	let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])?;
	params.serial_number = Some(rcgen::SerialNumber::from(serial));
	params
		.distinguished_name
		.push(rcgen::DnType::CommonName, rcgen::DnValue::Utf8String(cn.to_owned()));
	let issuer = rcgen::Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key)?;
	let cert = params.signed_by(&key, &issuer)?;
	return Ok(rcgen::CertifiedKey { cert, signing_key: key });
}

// PEM of a CA-signed CRL revoking each of `revoked_serials`. next_update is far future so
// enforce_revocation_expiration accepts it at the real current time.
pub fn make_crl_pem(ca: &rcgen::CertifiedKey<rcgen::KeyPair>, revoked_serials: &[u64]) -> Result<String, String> {
	return signed_crl_pem(ca, revoked_serials).map_err(|err| format!("CRL revoking {revoked_serials:?}: {err:?}"));
}

fn signed_crl_pem(ca: &rcgen::CertifiedKey<rcgen::KeyPair>, revoked_serials: &[u64]) -> Result<String, rcgen::Error> {
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
	let issuer = rcgen::Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key)?;
	return params.signed_by(&issuer)?.pem();
}

pub fn is_leaf_accepted(v: &ReloadingClientVerifier, leaf: &rcgen::CertifiedKey<rcgen::KeyPair>) -> bool {
	return v.verify_client_cert(leaf.cert.der(), &[], UnixTime::now()).is_ok();
}

// Verifies a backend/server leaf the way a real handshake would: a matching ServerName ("localhost",
// the SAN generate_signed_cert stamps) plus the full chain, so a positive result means name + chain
// both validated, not an accidental pass.
pub fn server_verifier_accepts(
	v: &ReloadingServerVerifier,
	leaf: &rcgen::CertifiedKey<rcgen::KeyPair>,
) -> Result<bool, String> {
	let name: ServerName<'_> = ServerName::try_from("localhost")
		.map_err(|err| format!("ServerName::try_from(\"localhost\"): {err:?}"))?;
	return Ok(v
		.verify_server_cert(leaf.cert.der(), &[], &name, &[], UnixTime::now())
		.is_ok());
}

// Cert fixtures and the write-until-reloaded poll, shared by the reload and reload::trust_watcher tests.
pub type Ca = rcgen::CertifiedKey<rcgen::KeyPair>;

// Poll interval must exceed fs_watch::RELOAD_DEBOUNCE so repeated writes aren't all debounced away.
#[cfg(feature = "proxy")]
pub const RELOAD_POLL_INTERVAL_MS: u64 = 500;
#[cfg(feature = "proxy")]
pub const RELOAD_MAX_ATTEMPTS: u32 = 20;
pub fn write_file(path: &Path, contents: &str) -> Result<(), String> {
	return match fs::write(path, contents) {
		Ok(()) => Ok(()),
		Err(err) => Err(format!("write {}: {err:?}", path.display())),
	};
}

// A fresh CA and `N` localhost server leaves it signs.
pub fn ca_and_leaves<const N: usize>() -> Result<(Ca, [Ca; N]), String> {
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	let ca: Ca = generate_ca()?;
	let leaves: Vec<Ca> = (0..N)
		.map(|_| generate_localhost_cert(&ca))
		.collect::<Result<Vec<Ca>, String>>()?;
	return match <[Ca; N]>::try_from(leaves) {
		Ok(leaves) => Ok((ca, leaves)),
		Err(_) => Err(format!("expected {N} leaves")),
	};
}

// Rewrites until the watcher picks the change up: a single write can race the debounce or be
// read mid-write, so retrying beats one write + one long sleep for flake resistance. Each round
// writes every `(path, contents)` pair, in order.
#[cfg(feature = "proxy")]
pub fn write_until<F: Fn() -> bool>(writes: &[(&Path, &str)], reloaded: F) -> Result<bool, String> {
	for _ in 0..RELOAD_MAX_ATTEMPTS {
		writes
			.iter()
			.try_for_each(|(path, contents)| write_file(path, contents))?;
		thread::sleep(Duration::from_millis(RELOAD_POLL_INTERVAL_MS));
		if reloaded() {
			return Ok(true);
		}
	}
	return Ok(false);
}
