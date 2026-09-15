//! Demonstrates running the proxy with Let's Encrypt ACME (tls-alpn-01).
//!
//! Requires: port 443, public DNS, and `--features acme`.
//!
//! Usage:
//!   cargo run --features acme --example letsencrypt_demo
//!
//! This example writes a config TOML to a temporary file, then boots the proxy
//! using ACME for the server certificate and a local CA for client mTLS.

// Demo/example code: printing to stdout/stderr is the point of a runnable demo.
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]
#![allow(clippy::dbg_macro)]

#[cfg(feature = "acme")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
	use std::io::Write;
	use std::path::PathBuf;

	use tempfile::NamedTempFile;

	// In a real deployment, the client CA cert would be pre-distributed to all
	// authorized clients. Here we generate one for illustration purposes.
	let ca_key = rcgen::KeyPair::generate()?;
	let mut ca_params = rcgen::CertificateParams::new(vec![])?;
	ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
	ca_params.distinguished_name.push(
		rcgen::DnType::CommonName,
		rcgen::DnValue::Utf8String("Reduction Client CA".to_owned()),
	);
	let ca_cert = ca_params.self_signed(&ca_key)?;

	let mut ca_file = NamedTempFile::new()?;
	ca_file.write_all(ca_cert.pem().as_bytes())?;
	ca_file.flush()?;
	let ca_path: PathBuf = ca_file.path().to_path_buf();

	// Generate a client cert signed by the CA (for mTLS)
	let client_key = rcgen::KeyPair::generate()?;
	let client_params = rcgen::CertificateParams::new(vec!["client-1".to_owned()])?;
	let issuer = rcgen::Issuer::from_ca_cert_der(ca_cert.der(), &ca_key)?;
	let client_cert = client_params.signed_by(&client_key, &issuer)?;

	let mut client_cert_file = NamedTempFile::new()?;
	client_cert_file.write_all(client_cert.pem().as_bytes())?;
	client_cert_file.flush()?;

	let mut client_key_file = NamedTempFile::new()?;
	client_key_file.write_all(client_key.serialize_pem().as_bytes())?;
	client_key_file.flush()?;

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
staging = true  # Use Let's Encrypt staging for testing

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
		client_cert = client_cert_file.path().display(),
		client_key = client_key_file.path().display(),
	);

	let mut config_file = NamedTempFile::new()?;
	config_file.write_all(config_toml.as_bytes())?;
	config_file.flush()?;

	println!("=== Let's Encrypt Demo Configuration ===");
	println!();
	println!("Config written to: {}", config_file.path().display());
	println!();
	println!("To run the proxy with this config:");
	println!("  cargo run --features acme -- {}", config_file.path().display());
	println!();
	println!("Requirements:");
	println!("  1. Port 443 must be accessible from the internet");
	println!("  2. DNS for 'proxy.example.com' must point to this server");
	println!("  3. Set staging = false for production certificates");
	println!();
	println!("The ACME flow:");
	println!("  1. On first start, provisions a certificate via tls-alpn-01");
	println!("  2. Caches cert + key in ./acme_cache/");
	println!("  3. Auto-renews 30 days before expiry");
	println!("  4. Client mTLS is still enforced (clients need certs from the private CA)");
	println!();
	println!("=== Config TOML ===");
	println!("{config_toml}");
	return Ok(());
}

#[cfg(not(feature = "acme"))]
fn main() {
	eprintln!("This example requires the 'acme' feature.");
	eprintln!("Run with: cargo run --features acme --example letsencrypt_demo");
	std::process::exit(1);
}
