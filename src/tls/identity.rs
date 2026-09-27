use arrayvec::ArrayString;
use aws_lc_rs::digest::{SHA256, digest};
use rustls::pki_types::CertificateDer;
use x509_parser::certificate::X509Certificate;
use x509_parser::parse_x509_certificate;

use crate::error::{ReductionError, Result};

// RFC 5280 ub-common-name; device IDs (UUIDs, serials) fit. Longer CNs are rejected, not
// truncated — a truncated identity is a silent authorization bug.
pub const MAX_COMMON_NAME_LEN: usize = 64;

// SHA-256 digest width in bytes.
pub const SPKI_SHA256_LEN: usize = 32;

// Hex encoding doubles the byte width.
pub const SPKI_HEX_LEN: usize = SPKI_SHA256_LEN * 2;

const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

// Handshake-proven mTLS peer identity, extracted once per connection from the leaf cert.
// `common_name` is the canonical client ID (device ID in the subject CN); `spki_sha256` is the
// raw hash disambiguating CN collisions — hex-encode only at the header boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
	pub common_name: ArrayString<MAX_COMMON_NAME_LEN>,
	pub spki_sha256: [u8; SPKI_SHA256_LEN],
}

impl PeerIdentity {
	// Parse a leaf cert (DER) into its identity. Fails noisily when unparseable, missing a CN,
	// or the CN exceeds MAX_COMMON_NAME_LEN.
	pub fn from_leaf_der(der: &[u8]) -> Result<Self> {
		let (_, cert): (&[u8], X509Certificate) =
			parse_x509_certificate(der).map_err(|e| ReductionError::Identity(format!("parse leaf cert: {e}")))?;

		let cn_attr = cert
			.subject()
			.iter_common_name()
			.next()
			.ok_or_else(|| ReductionError::Identity("leaf cert has no common name".to_owned()))?;

		let cn_str: &str = cn_attr
			.as_str()
			.map_err(|e| ReductionError::Identity(format!("common name not valid UTF-8: {e}")))?;

		let common_name: ArrayString<MAX_COMMON_NAME_LEN> = ArrayString::from(cn_str)
			.map_err(|_| ReductionError::Identity(format!("common name exceeds {MAX_COMMON_NAME_LEN} chars")))?;

		let spki_der: &[u8] = cert.public_key().raw;
		let hash = digest(&SHA256, spki_der);
		let spki_sha256: [u8; SPKI_SHA256_LEN] = hash
			.as_ref()
			.try_into()
			.map_err(|_| ReductionError::Identity("SPKI hash length mismatch".to_owned()))?;

		return Ok(Self {
			common_name,
			spki_sha256,
		});
	}

	// Extract identity from a completed server-side TLS handshake; the first peer cert is the leaf.
	// No peer cert reaching here is a bug — mTLS is mandatory.
	pub fn from_tls_stream<IO>(stream: &tokio_rustls::server::TlsStream<IO>) -> Result<Self> {
		let (_, conn) = stream.get_ref();
		let leaf: &CertificateDer = conn
			.peer_certificates()
			.and_then(|certs| certs.first())
			.ok_or_else(|| ReductionError::Identity("TLS peer presented no certificate".to_owned()))?;
		return Self::from_leaf_der(leaf.as_ref());
	}

	// Extract identity from a completed QUIC handshake. quinn stores the peer cert chain as
	// `Vec<CertificateDer>` behind its `Any` identity; the first element is the leaf.
	pub fn from_quic_connection(connection: &quinn::Connection) -> Result<Self> {
		let identity = connection
			.peer_identity()
			.ok_or_else(|| ReductionError::Identity("QUIC peer presented no identity".to_owned()))?;
		let certs: Vec<CertificateDer> = *identity
			.downcast::<Vec<CertificateDer>>()
			.map_err(|_| ReductionError::Identity("QUIC peer identity not a certificate chain".to_owned()))?;
		let leaf: &CertificateDer = certs
			.first()
			.ok_or_else(|| ReductionError::Identity("QUIC peer certificate chain empty".to_owned()))?;
		return Self::from_leaf_der(leaf.as_ref());
	}

	// Lowercase hex of the SPKI SHA-256, for the `x-reduction-client-spki` header boundary.
	#[must_use]
	pub fn spki_hex(&self) -> ArrayString<SPKI_HEX_LEN> {
		let mut out: ArrayString<SPKI_HEX_LEN> = ArrayString::new();
		for byte in self.spki_sha256 {
			let hi: usize = usize::from(byte >> 4);
			let lo: usize = usize::from(byte & 0x0f);
			out.push(char::from(HEX_ALPHABET[hi]));
			out.push(char::from(HEX_ALPHABET[lo]));
		}
		return out;
	}
}

#[cfg(test)]
mod tests {
	use std::net::SocketAddr;

	use rustls::pki_types::ServerName;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::{TcpListener, TcpStream};
	use tokio_rustls::{TlsAcceptor, TlsConnector};

	use super::*;
	use crate::test_support::{generate_ca, generate_signed_cert, write_pem};
	use crate::tls::certs::{build_client_config, build_server_config};

	fn generate_cert_with_cn(cn: &str) -> rcgen::CertifiedKey<rcgen::KeyPair> {
		let key = rcgen::KeyPair::generate().unwrap();
		let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
		params
			.distinguished_name
			.push(rcgen::DnType::CommonName, rcgen::DnValue::Utf8String(cn.to_string()));
		let cert = params.self_signed(&key).unwrap();
		return rcgen::CertifiedKey { cert, signing_key: key };
	}

	fn generate_cert_without_cn() -> rcgen::CertifiedKey<rcgen::KeyPair> {
		let key = rcgen::KeyPair::generate().unwrap();
		let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
		// rcgen defaults a CN when the DN is untouched; overwrite with a subject that carries only
		// an Organization so the leaf genuinely has no common-name attribute.
		params.distinguished_name = rcgen::DistinguishedName::new();
		params.distinguished_name.push(
			rcgen::DnType::OrganizationName,
			rcgen::DnValue::Utf8String("Acme Org".to_string()),
		);
		let cert = params.self_signed(&key).unwrap();
		return rcgen::CertifiedKey { cert, signing_key: key };
	}

	// Independent SPKI SHA-256 oracle: parse the cert and hash its raw SubjectPublicKeyInfo DER via
	// a fresh ring call, mirroring `openssl x509 -pubkey | openssl pkey -pubin -outform DER | sha256`.
	fn oracle_spki_hash(der: &[u8]) -> [u8; SPKI_SHA256_LEN] {
		let (_, cert) = parse_x509_certificate(der).unwrap();
		let hash = digest(&SHA256, cert.public_key().raw);
		return hash.as_ref().try_into().unwrap();
	}

	#[test]
	fn test_common_name_extracted_verbatim() {
		let ck = generate_cert_with_cn("device-42");
		let der = ck.cert.der();
		let identity = PeerIdentity::from_leaf_der(der).unwrap();
		assert_eq!(identity.common_name.as_str(), "device-42");
	}

	#[test]
	fn test_spki_hash_matches_independent_oracle() {
		let ck = generate_cert_with_cn("device-42");
		let der = ck.cert.der();
		let identity = PeerIdentity::from_leaf_der(der).unwrap();
		assert_eq!(identity.spki_sha256, oracle_spki_hash(der));
	}

	#[test]
	fn test_spki_hash_stable_across_reserialization() {
		let ck = generate_cert_with_cn("device-42");
		let der = ck.cert.der();
		let first = PeerIdentity::from_leaf_der(der).unwrap();
		// Re-serialize the same DER bytes into a fresh owned buffer and re-parse: the SPKI hash is
		// a property of the key, so it must be identical.
		let reserialized: Vec<u8> = der.as_ref().to_vec();
		let second = PeerIdentity::from_leaf_der(&reserialized).unwrap();
		assert_eq!(first.spki_sha256, second.spki_sha256);
	}

	#[test]
	fn test_distinct_keys_produce_distinct_spki_hashes() {
		let a = generate_cert_with_cn("device-a");
		let b = generate_cert_with_cn("device-b");
		let ia = PeerIdentity::from_leaf_der(a.cert.der()).unwrap();
		let ib = PeerIdentity::from_leaf_der(b.cert.der()).unwrap();
		assert_ne!(ia.spki_sha256, ib.spki_sha256);
	}

	#[test]
	fn test_cert_without_common_name_errors() {
		let ck = generate_cert_without_cn();
		let err = PeerIdentity::from_leaf_der(ck.cert.der()).unwrap_err();
		assert!(matches!(err, ReductionError::Identity(_)));
		assert!(format!("{err}").contains("no common name"));
	}

	#[test]
	fn test_garbage_der_errors() {
		let garbage: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03];
		let err = PeerIdentity::from_leaf_der(&garbage).unwrap_err();
		assert!(matches!(err, ReductionError::Identity(_)));
		assert!(format!("{err}").contains("parse leaf cert"));
	}

	#[test]
	fn test_empty_der_errors() {
		let err = PeerIdentity::from_leaf_der(&[]).unwrap_err();
		assert!(matches!(err, ReductionError::Identity(_)));
	}

	#[test]
	fn test_common_name_too_long_errors() {
		let long_cn: String = "x".repeat(MAX_COMMON_NAME_LEN + 1);
		let ck = generate_cert_with_cn(&long_cn);
		let err = PeerIdentity::from_leaf_der(ck.cert.der()).unwrap_err();
		assert!(matches!(err, ReductionError::Identity(_)));
		assert!(format!("{err}").contains("exceeds"));
	}

	#[test]
	fn test_common_name_at_max_len_ok() {
		let cn: String = "y".repeat(MAX_COMMON_NAME_LEN);
		let ck = generate_cert_with_cn(&cn);
		let identity = PeerIdentity::from_leaf_der(ck.cert.der()).unwrap();
		assert_eq!(identity.common_name.len(), MAX_COMMON_NAME_LEN);
	}

	#[test]
	fn test_spki_hex_is_lowercase_and_64_chars() {
		let ck = generate_cert_with_cn("device-42");
		let identity = PeerIdentity::from_leaf_der(ck.cert.der()).unwrap();
		let hex = identity.spki_hex();
		assert_eq!(hex.len(), SPKI_HEX_LEN);
		assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
	}

	#[test]
	fn test_spki_hex_matches_manual_encoding() {
		let ck = generate_cert_with_cn("device-42");
		let identity = PeerIdentity::from_leaf_der(ck.cert.der()).unwrap();
		let manual: String = identity.spki_sha256.iter().map(|b| format!("{b:02x}")).collect();
		assert_eq!(identity.spki_hex().as_str(), manual);
	}

	// End-to-end: a real mTLS handshake over loopback TCP, then extract identity from the accepted
	// server-side TlsStream. The client cert's CN must survive to the server, and the SPKI must match
	// the client leaf's independently computed hash (oracle: the client cert bytes, not the parse).
	#[tokio::test]
	async fn test_from_tls_stream_real_handshake_extracts_client_cn() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

		let ca = generate_ca();
		let server_leaf = generate_signed_cert(
			&ca,
			"localhost",
			vec![rcgen::SanType::DnsName("localhost".try_into().unwrap())],
		);
		let client_leaf = generate_signed_cert(
			&ca,
			"device-42",
			vec![rcgen::SanType::DnsName("localhost".try_into().unwrap())],
		);

		let ca_file = write_pem(&ca.cert.pem());
		let server_cert_file = write_pem(&server_leaf.cert.pem());
		let server_key_file = write_pem(&server_leaf.signing_key.serialize_pem());
		let client_cert_file = write_pem(&client_leaf.cert.pem());
		let client_key_file = write_pem(&client_leaf.signing_key.serialize_pem());

		let (server_config, _r1) =
			build_server_config(server_cert_file.path(), server_key_file.path(), ca_file.path()).unwrap();
		let (client_config, _r2, _v2) =
			build_client_config(client_cert_file.path(), client_key_file.path(), ca_file.path()).unwrap();

		// Independent oracle: hash the client leaf's SPKI directly from the cert we handed the client,
		// not from what the server parsed off the wire.
		let expected_spki: [u8; SPKI_SHA256_LEN] = {
			let (_, parsed) = parse_x509_certificate(client_leaf.cert.der()).unwrap();
			digest(&SHA256, parsed.public_key().raw).as_ref().try_into().unwrap()
		};

		let listener = TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
			.await
			.unwrap();
		let addr: SocketAddr = listener.local_addr().unwrap();
		let acceptor = TlsAcceptor::from(std::sync::Arc::new(server_config));

		let server = tokio::spawn(async move {
			let (tcp, _peer) = listener.accept().await.unwrap();
			let mut tls = acceptor.accept(tcp).await.unwrap();
			let identity = PeerIdentity::from_tls_stream(&tls).unwrap();
			// Drain the client's byte so the handshake fully completes on both ends.
			let mut buf = [0u8; 1];
			let _ = tls.read(&mut buf).await;
			return identity;
		});

		let connector = TlsConnector::from(std::sync::Arc::new(client_config));
		let tcp = TcpStream::connect(addr).await.unwrap();
		let server_name: ServerName = ServerName::try_from("localhost").unwrap();
		let mut tls = connector.connect(server_name, tcp).await.unwrap();
		tls.write_all(b"x").await.unwrap();
		tls.flush().await.unwrap();

		let identity = server.await.unwrap();
		assert_eq!(identity.common_name.as_str(), "device-42");
		assert_eq!(identity.spki_sha256, expected_spki);
	}
}
