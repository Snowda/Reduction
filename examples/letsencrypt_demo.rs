//! Demonstrates running the proxy with Let's Encrypt ACME (tls-alpn-01).
//!
//! Requires: port 443, public DNS, and `--features acme`.
//!
//! Usage:
//!   cargo run --features acme --example letsencrypt_demo
//!
//! This example writes a config TOML to a temporary file, then boots the proxy
//! using ACME for the server certificate and a local CA for client mTLS.

#[cfg(feature = "acme")]
fn main() {
    use std::io::Write;
    use std::path::PathBuf;

    use tempfile::NamedTempFile;

    // In a real deployment, the client CA cert would be pre-distributed to all
    // authorized clients. Here we generate one for illustration purposes.
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("Reduction Client CA".to_string()),
    );
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut ca_file = NamedTempFile::new().unwrap();
    ca_file.write_all(ca_cert.pem().as_bytes()).unwrap();
    ca_file.flush().unwrap();
    let ca_path: PathBuf = ca_file.path().to_path_buf();

    // Generate a client cert signed by the CA (for mTLS)
    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_params = rcgen::CertificateParams::new(vec!["client-1".to_string()]).unwrap();
    let issuer = rcgen::Issuer::from_ca_cert_der(ca_cert.der(), &ca_key).unwrap();
    let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

    let mut client_cert_file = NamedTempFile::new().unwrap();
    client_cert_file.write_all(client_cert.pem().as_bytes()).unwrap();
    client_cert_file.flush().unwrap();

    let mut client_key_file = NamedTempFile::new().unwrap();
    client_key_file.write_all(client_key.serialize_pem().as_bytes()).unwrap();
    client_key_file.flush().unwrap();

    // Write a config TOML using ACME for the server cert
    let config_toml: String = format!(
        r#"
[listen]
address = "0.0.0.0:443"
transport = "tcp"

[tls.server]
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

    let mut config_file = NamedTempFile::new().unwrap();
    config_file.write_all(config_toml.as_bytes()).unwrap();
    config_file.flush().unwrap();

    println!("=== Let's Encrypt Demo Configuration ===");
    println!();
    println!("Config written to: {}", config_file.path().display());
    println!();
    println!("To run the proxy with this config:");
    println!("  cargo run --features acme -- --config {}", config_file.path().display());
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
}

#[cfg(not(feature = "acme"))]
fn main() {
    eprintln!("This example requires the 'acme' feature.");
    eprintln!("Run with: cargo run --features acme --example letsencrypt_demo");
    std::process::exit(1);
}
