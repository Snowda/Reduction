//! Demonstrates running the proxy with Let's Encrypt ACME (tls-alpn-01).
//!
//! Requires: port 443, public DNS, and `--features acme`.
//!
//! Usage:
//!   cargo run --features acme --example letsencrypt_demo
//!
//! This example writes a config TOML to a temporary file, then boots the proxy
//! using ACME for the server certificate and a local CA for client mTLS.

mod support;

#[cfg(feature = "acme")]
use std::io::Write;
#[cfg(feature = "acme")]
use std::path::PathBuf;

#[cfg(feature = "acme")]
use tempfile::NamedTempFile;
#[cfg(feature = "acme")]
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::support::Context;

// Show only the demo text and any warnings from the library.
const LIBRARY_LOG_LEVEL: &str = "warn";

#[cfg(feature = "acme")]
const INSTRUCTIONS: [&str; 17] = [
	"",
	"To run the proxy with this config:",
	"  cargo run --features acme -- {config}",
	"",
	"Requirements:",
	"  1. Port 443 must be accessible from the internet",
	"  2. DNS for 'proxy.example.com' must point to this server",
	"  3. Set directory = \"production\" for production certificates",
	"",
	"The ACME flow:",
	"  1. On first start, provisions a certificate via tls-alpn-01",
	"  2. Caches cert + key in ./acme_cache/",
	"  3. Auto-renews 30 days before expiry",
	"  4. Client mTLS is still enforced (clients need certs from the private CA)",
	"",
	"=== Config TOML ===",
	"{toml}",
];

// Write `contents` to a fresh temp file that lives as long as the returned handle.
#[cfg(feature = "acme")]
fn temp_file_with(contents: &str, what: &str) -> Result<NamedTempFile, String> {
	let mut file = NamedTempFile::new().context(&format!("create {what} temp file"))?;
	file.write_all(contents.as_bytes()).context(&format!("write {what}"))?;
	file.flush().context(&format!("flush {what}"))?;
	return Ok(file);
}

// The client-mTLS files the config points at. The temp files stay on disk while this value lives.
#[cfg(feature = "acme")]
struct ClientPki {
	ca: NamedTempFile,
	client_cert: NamedTempFile,
	client_key: NamedTempFile,
}

#[cfg(feature = "acme")]
fn client_pki() -> Result<ClientPki, String> {
	// In a real deployment, the client CA cert would be pre-distributed to all
	// authorized clients. Here we generate one for illustration purposes.
	let ca_key = rcgen::KeyPair::generate().context("CA key")?;
	let mut ca_params = rcgen::CertificateParams::new(vec![]).context("CA params")?;
	ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
	ca_params.distinguished_name.push(
		rcgen::DnType::CommonName,
		rcgen::DnValue::Utf8String("Reduction Client CA".to_owned()),
	);
	let ca_cert = ca_params.self_signed(&ca_key).context("self-sign CA")?;

	// Generate a client cert signed by the CA (for mTLS)
	let client_key = rcgen::KeyPair::generate().context("client key")?;
	let client_params = rcgen::CertificateParams::new(vec!["client-1".to_owned()]).context("client params")?;
	let issuer = rcgen::Issuer::from_ca_cert_der(ca_cert.der(), &ca_key).context("CA issuer")?;
	let client_cert = client_params
		.signed_by(&client_key, &issuer)
		.context("sign client cert")?;

	return Ok(ClientPki {
		ca: temp_file_with(&ca_cert.pem(), "CA cert")?,
		client_cert: temp_file_with(&client_cert.pem(), "client cert")?,
		client_key: temp_file_with(&client_key.serialize_pem(), "client key")?,
	});
}

#[cfg(feature = "acme")]
fn main() -> Result<(), String> {
	tracing_subscriber::registry()
		.with(support::output_layer(LIBRARY_LOG_LEVEL))
		.init();

	let pki: ClientPki = client_pki()?;
	let ca_path: PathBuf = pki.ca.path().to_path_buf();

	// Write a config TOML using ACME for the server cert
	let config_toml: String = format!(
		r#"
[listen]
address = "0.0.0.0:443"
transport = "tcp"

[tls.server.acme]
# ACME mode: provide domains and email instead of cert_path/key_path
domains = ["proxy.example.com"]
acme_email = "ops@example.com"
ca_cert_path = "{ca_path}"
cache_dir = "./acme_cache"
directory = "staging"  # Use Let's Encrypt staging for testing

[tls.client]
cert_path = "{client_cert}"
key_path = "{client_key}"
ca_cert_path = "{ca_path}"

[[backends]]
id = "api"
address = "127.0.0.1:8080"
weight = 1.0
transport = "tcp"

[[routes]]
path_prefix = "/"
backend_id = "api"
"#,
		ca_path = ca_path.display(),
		client_cert = pki.client_cert.path().display(),
		client_key = pki.client_key.path().display(),
	);

	let config_file = temp_file_with(&config_toml, "config")?;
	let config_shown: String = config_file.path().display().to_string();

	info!("=== Let's Encrypt Demo Configuration ===");
	info!("");
	info!("Config written to: {config_shown}");
	INSTRUCTIONS
		.iter()
		.map(|line| line.replace("{config}", &config_shown).replace("{toml}", &config_toml))
		.for_each(|line| info!("{line}"));
	return Ok(());
}

#[cfg(not(feature = "acme"))]
fn main() -> Result<(), String> {
	tracing_subscriber::registry()
		.with(support::output_layer(LIBRARY_LOG_LEVEL))
		.init();
	return Err::<(), &str>(
		"this example requires the 'acme' feature; run with: cargo run --features acme --example letsencrypt_demo",
	)
	.context("letsencrypt_demo");
}
