// PEM material from disk or the environment. This file holds no TLS config, so the cert resolvers and ACME
// read it and do not depend on the config builders in `certs`.
use std::fs;
use std::io::BufReader;
use std::path::Path;

use rustls::RootCertStore;
use rustls::pki_types::pem::{Error as PemError, PemObject, ReadIter};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::KeySource;
use crate::error::{ReductionError, Result};

// ACME tls-alpn-01 shares the real-traffic port and differs only by this ALPN (RFC 8737).
pub const ACME_TLS_ALPN_PROTO: &[u8] = b"acme-tls/1";

// A PEM bundle that has at least one certificate, in file order: `leaf` is the first.
#[derive(Debug)]
pub struct CertChain {
	pub leaf: CertificateDer<'static>,
	pub rest: Vec<CertificateDer<'static>>,
}

impl CertChain {
	// The whole bundle in file order, leaf first, as rustls takes it.
	#[must_use]
	pub fn into_vec(self) -> Vec<CertificateDer<'static>> {
		let mut certs: Vec<CertificateDer<'static>> = Vec::with_capacity(1 + self.rest.len());
		certs.push(self.leaf);
		certs.extend(self.rest);
		return certs;
	}
}

// Load PEM-encoded certificates from a file; a bundle with no certificate is an error.
pub fn load_certs(path: &Path) -> Result<CertChain> {
	let file: fs::File = fs::File::open(path)
		.map_err(|e| ReductionError::Config(format!("failed to open cert file {}: {e}", path.display())))?;
	let parse_err = |e: PemError| -> ReductionError {
		return ReductionError::Config(format!("failed to parse certs from {}: {e}", path.display()));
	};

	// pem_reader_iter buffers the file itself.
	let mut pems: ReadIter<BufReader<fs::File>, CertificateDer<'static>> = CertificateDer::pem_reader_iter(file);
	let Some(first) = pems.next() else {
		return Err(ReductionError::Config(format!(
			"no certificates found in {}",
			path.display()
		)));
	};
	let leaf: CertificateDer<'static> = first.map_err(parse_err)?;
	let rest: Vec<CertificateDer<'static>> = pems.collect::<std::result::Result<Vec<_>, _>>().map_err(parse_err)?;

	return Ok(CertChain { leaf, rest });
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

// Load the private key from its file, or from the PEM that `barrel run` put in its env var.
pub fn load_key(source: &KeySource) -> Result<PrivateKeyDer<'static>> {
	return match source {
		KeySource::File(path) => load_private_key(path),
		KeySource::Env(var) => match barrel_client::var(var.as_str()) {
			Ok(pem) if !pem.is_empty() => parse_private_key_pem(var, &pem),
			_ => Err(ReductionError::Config(format!(
				"key_env {var} is unset or empty: run under `barrel run` with it in the vault"
			))),
		},
	};
}

// Parse the PEM held in env var `var`. The error names only the variable: a PEM error could echo part of the key.
pub fn parse_private_key_pem(var: &str, pem: &str) -> Result<PrivateKeyDer<'static>> {
	return PrivateKeyDer::from_pem_slice(pem.as_bytes())
		.map_err(|_| ReductionError::Config(format!("key_env {var} holds no PEM private key")));
}

// Build a RootCertStore from a CA certificate file for mTLS client verification.
pub fn load_ca_certs(path: &Path) -> Result<RootCertStore> {
	let ca_certs: Vec<CertificateDer<'static>> = load_certs(path)?.into_vec();
	let mut root_store: RootCertStore = RootCertStore::empty();

	for cert in ca_certs {
		root_store
			.add(cert)
			.map_err(|e| ReductionError::Config(format!("failed to add CA cert: {e}")))?;
	}

	return Ok(root_store);
}

#[cfg(test)]
mod tests {
	use std::result::Result;
	use std::slice;

	use arrayvec::ArrayString;
	use rcgen::{CertifiedKey, KeyPair};
	use tempfile::NamedTempFile;

	use super::*;
	use crate::test_support::{generate_ca, write_pem};

	#[test]
	fn test_load_certs_valid() -> Result<(), String> {
		let ca: CertifiedKey<KeyPair> = generate_ca()?;
		let f: NamedTempFile = write_pem(&ca.cert.pem())?;
		let chain: CertChain = load_certs(f.path()).map_err(|err| format!("load_certs(f.path()): {err:?}"))?;
		assert_eq!(&chain.leaf, ca.cert.der());
		assert!(chain.rest.is_empty());
		return Ok(());
	}

	#[test]
	fn test_load_certs_missing_file() -> Result<(), String> {
		let result: Result<CertChain, ReductionError> = load_certs(Path::new("/nonexistent/cert.pem"));
		assert!(result.is_err());
		let msg: String = format!(
			"{}",
			match result {
				Ok(value) => return Err(format!("result: expected Err, got Ok({value:?})")),
				Err(err) => err,
			}
		);
		assert!(msg.contains("failed to open cert file"));
		return Ok(());
	}

	#[test]
	fn test_load_certs_empty_file() -> Result<(), String> {
		let f: NamedTempFile = write_pem("")?;
		let result: Result<CertChain, ReductionError> = load_certs(f.path());
		assert!(result.is_err());
		let msg: String = format!(
			"{}",
			match result {
				Ok(value) => return Err(format!("result: expected Err, got Ok({value:?})")),
				Err(err) => err,
			}
		);
		assert!(msg.contains("no certificates found"));
		return Ok(());
	}

	#[test]
	fn test_load_certs_invalid_pem() -> Result<(), String> {
		let f: NamedTempFile = write_pem("not a pem file at all")?;
		let result: Result<CertChain, ReductionError> = load_certs(f.path());
		assert!(result.is_err());
		return Ok(());
	}

	#[test]
	fn test_load_private_key_valid() -> Result<(), String> {
		let ca: CertifiedKey<KeyPair> = generate_ca()?;
		let f: NamedTempFile = write_pem(&ca.signing_key.serialize_pem())?;
		let _key: PrivateKeyDer<'static> =
			load_private_key(f.path()).map_err(|err| format!("load_private_key(f.path()): {err:?}"))?;
		return Ok(());
	}

	#[test]
	fn test_load_key_from_a_file_source_is_load_private_key() -> Result<(), String> {
		let ca: CertifiedKey<KeyPair> = generate_ca()?;
		let f: NamedTempFile = write_pem(&ca.signing_key.serialize_pem())?;
		let from_source: PrivateKeyDer<'static> =
			load_key(&KeySource::File(f.path().to_path_buf())).map_err(|err| format!("{err:?}"))?;
		let direct: PrivateKeyDer<'static> = load_private_key(f.path()).map_err(|err| format!("{err:?}"))?;
		assert_eq!(
			from_source.secret_der(),
			direct.secret_der(),
			"a file source reads the same key as key_path always did"
		);
		return Ok(());
	}

	fn env_source(name: &str) -> Result<KeySource, String> {
		return ArrayString::from(name).map(KeySource::Env).map_err(|err| format!("env name {name}: {err:?}"));
	}

	// No env mutation (set_var is unsafe): an unset name, and a var cargo sets for every test run (not a PEM).
	#[test]
	fn test_load_key_from_env_reads_the_var_and_names_it_without_its_value() -> Result<(), String> {
		let unset: String = match load_key(&env_source("REDUCTION_TEST_NO_SUCH_KEY_VAR")?) {
			Ok(_) => return Err("an unset var gave a key".to_owned()),
			Err(err) => err.to_string(),
		};
		assert!(
			unset.contains("REDUCTION_TEST_NO_SUCH_KEY_VAR is unset or empty"),
			"names the missing var: {unset}"
		);
		let not_pem: String = match load_key(&env_source("CARGO_PKG_NAME")?) {
			Ok(_) => return Err("a crate name parsed as a key".to_owned()),
			Err(err) => err.to_string(),
		};
		assert!(
			not_pem.contains("CARGO_PKG_NAME holds no PEM private key"),
			"the var was read, then refused as no PEM: {not_pem}"
		);
		assert!(!not_pem.contains("reduction"), "the refusal never echoes the var's value: {not_pem}");
		return Ok(());
	}

	#[test]
	fn test_parse_private_key_pem_accepts_a_key_and_never_echoes_a_bad_one() -> Result<(), String> {
		let ca: CertifiedKey<KeyPair> = generate_ca()?;
		let pem: String = ca.signing_key.serialize_pem();
		let parsed: PrivateKeyDer<'static> = parse_private_key_pem("K", &pem).map_err(|err| format!("{err:?}"))?;
		assert_eq!(
			parsed.secret_der(),
			ca.signing_key.serialized_der(),
			"the env PEM is the same key as the file PEM"
		);
		let broken: String = pem.replace("-----END PRIVATE KEY-----", "");
		let refused: String = match parse_private_key_pem("K", &broken) {
			Ok(_) => return Err("a corrupt PEM parsed".to_owned()),
			Err(err) => err.to_string(),
		};
		let body_line: &str = pem.lines().nth(1).unwrap_or_default();
		assert!(!refused.contains(body_line), "the error never holds key material: {refused}");
		return Ok(());
	}

	#[test]
	fn test_load_private_key_missing_file() -> Result<(), String> {
		let result: Result<PrivateKeyDer<'static>, ReductionError> =
			load_private_key(Path::new("/nonexistent/key.pem"));
		assert!(result.is_err());
		let msg: String = format!(
			"{}",
			match result {
				Ok(value) => return Err(format!("result: expected Err, got Ok({value:?})")),
				Err(err) => err,
			}
		);
		assert!(msg.contains("failed to open key file"));
		return Ok(());
	}

	#[test]
	fn test_load_private_key_invalid_pem() -> Result<(), String> {
		let f: NamedTempFile = write_pem("garbage data")?;
		let result: Result<PrivateKeyDer<'static>, ReductionError> = load_private_key(f.path());
		assert!(result.is_err());
		let msg: String = format!(
			"{}",
			match result {
				Ok(value) => return Err(format!("result: expected Err, got Ok({value:?})")),
				Err(err) => err,
			}
		);
		assert!(msg.contains("failed to parse private key"));
		return Ok(());
	}

	#[test]
	fn test_load_ca_certs_valid() -> Result<(), String> {
		let ca: CertifiedKey<KeyPair> = generate_ca()?;
		let f: NamedTempFile = write_pem(&ca.cert.pem())?;
		let store: RootCertStore = load_ca_certs(f.path()).map_err(|err| format!("load_ca_certs(f.path()): {err:?}"))?;
		assert!(!store.is_empty());
		return Ok(());
	}

	#[test]
	fn test_load_ca_certs_missing_file() {
		let result: Result<RootCertStore, ReductionError> = load_ca_certs(Path::new("/nonexistent/ca.pem"));
		assert!(result.is_err());
	}

	#[test]
	fn test_load_multiple_certs() -> Result<(), String> {
		let ca1: CertifiedKey<KeyPair> = generate_ca()?;
		let ca2: CertifiedKey<KeyPair> = generate_ca()?;
		let combined: String = format!("{}{}", ca1.cert.pem(), ca2.cert.pem());
		let f: NamedTempFile = write_pem(&combined)?;
		let chain: CertChain = load_certs(f.path()).map_err(|err| format!("load_certs(f.path()): {err:?}"))?;
		assert_eq!(&chain.leaf, ca1.cert.der());
		assert_eq!(chain.rest.as_slice(), slice::from_ref(ca2.cert.der()));
		let all: Vec<CertificateDer<'static>> = chain.into_vec();
		assert_eq!(all.iter().collect::<Vec<&CertificateDer<'static>>>(), [ca1.cert.der(), ca2.cert.der()]);
		return Ok(());
	}

	// A bad block fails the parse whether it is the leaf or a later certificate.
	#[test]
	fn test_load_certs_bad_block_is_a_parse_error() -> Result<(), String> {
		let ca: CertifiedKey<KeyPair> = generate_ca()?;
		let bad: &str = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
		for pem in [bad.to_owned(), format!("{}{bad}", ca.cert.pem())] {
			let f: NamedTempFile = write_pem(&pem)?;
			let msg: String = match load_certs(f.path()) {
				Ok(value) => return Err(format!("expected Err, got Ok({value:?})")),
				Err(err) => err.to_string(),
			};
			assert!(msg.contains("failed to parse certs from"), "got: {msg}");
		}
		return Ok(());
	}
}
