//! End-to-end ACME provisioning against a local pebble server (tls-alpn-01).
//!
//! Gated on `integration_tests` + `acme`. Self-contained: the test brings up a local pebble ACME
//! server + mock DNS in Docker via testcontainers, so no external orchestration is needed. Requires
//! a reachable Docker daemon. Run with:
//!   cargo test --features integration_tests,acme --test acme_pebble_tests -- --nocapture
//!
//! What it proves that a compile/unit check cannot: a real ACME server drives our client through
//! account creation, an order, a tls-alpn-01 challenge served by AcmeCertResolver over a genuine TLS
//! handshake, finalize, and certificate download — and the issued leaf actually certifies the domain.

mod support;

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arrayvec::ArrayString;
use reduction::config::{AcmeDirectory, AcmeTlsConfig};
use reduction::tls::acme::{AcmeCertResolver, AcmeRenewalTask};
use reduction::tls::{build_acme_challenge_config, build_acme_server_config};
use reduction::transport::listener::Listener;
use reduction::transport::tcp::TcpListener;
use tempfile::TempDir;
use testcontainers::core::{ExecCommand, Host, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::sync::watch;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

use crate::support::Context;

const PEBBLE_IMAGE: &str = "ghcr.io/letsencrypt/pebble";
const CHALLTESTSRV_IMAGE: &str = "ghcr.io/letsencrypt/pebble-challtestsrv";
const HELPER_IMAGE: &str = "alpine";
const IMAGE_TAG: &str = "latest";
// pebble's ACME directory listener (pebble-config.json listenAddress).
const DIRECTORY_PORT: u16 = 14000;
// challtestsrv's DNS server port; pebble is pointed here via -dnsserver.
const DNS_PORT: u16 = 8053;
// pebble-config.json tlsPort — the port pebble's VA dials back for tls-alpn-01.
const TLS_ALPN_PORT: u16 = 5001;
// Path inside the pebble image to the CA root that signs pebble's own HTTPS listener cert.
const MINICA_PATH: &str = "/test/certs/pebble.minica.pem";
// Any name works; challtestsrv answers every A query with the host address regardless.
const TEST_DOMAIN: &str = "reduction-pebble-test.example";
// Hostname Docker resolves to the host gateway from inside a container.
const HOST_GATEWAY_HOSTNAME: &str = "host.docker.internal";
// Bounds the throwaway resolver container so it never lingers if the test aborts mid-run.
const HELPER_KEEPALIVE_SECS: &str = "30";

struct PebbleEnv {
	directory: String,
	ca_cert: PathBuf,
	domain: String,
	responder_bind: SocketAddr,
}

// Holds the running containers alive for the duration of the test; dropping this tears the containers
// (and the network testcontainers created for them) back down.
struct PebbleContainers {
	_challtestsrv: ContainerAsync<GenericImage>,
	pebble: ContainerAsync<GenericImage>,
	directory_port: u16,
}

// The extracted CA cert lives in `_cert_dir`, so the env stays valid while this value lives.
struct PebbleFixture {
	_cert_dir: TempDir,
	env: PebbleEnv,
}

// Resolve the IPv4 the host is reachable at from inside a container on `network`. challtestsrv hands
// this to pebble as the answer for the challenge domain, so pebble's tls-alpn-01 validation loops
// back to the host-side responder the test runs. Resolving on the same network pebble uses means the
// gateway address matches the one pebble routes through.
async fn resolve_host_gateway_ip(network: &str) -> Result<IpAddr, String> {
	let helper = GenericImage::new(HELPER_IMAGE, IMAGE_TAG)
		.with_network(network)
		.with_host(HOST_GATEWAY_HOSTNAME, Host::HostGateway)
		.with_cmd(["sleep", HELPER_KEEPALIVE_SECS])
		.start()
		.await
		.context("start alpine resolver")?;
	let mut exec = helper
		.exec(ExecCommand::new(["getent", "ahostsv4", HOST_GATEWAY_HOSTNAME]))
		.await
		.context("exec getent in resolver")?;
	let out = exec.stdout_to_vec().await.context("read getent stdout")?;
	let text = String::from_utf8_lossy(&out);
	let addr = text.split_whitespace().next().context("getent address")?;
	return addr.parse().context("parse host gateway ip");
}

// Bring up pebble + mock DNS in Docker.
async fn start_pebble() -> Result<PebbleContainers, String> {
	// Unique per test process so concurrent runs never collide on network / container names.
	let unique = std::process::id();
	let network = format!("reduction-acme-{unique}");
	let challtestsrv_name = format!("reduction-challtestsrv-{unique}");

	let host_ip = resolve_host_gateway_ip(&network).await?;

	// Mock DNS: answer every name with the host gateway (v6 disabled so pebble doesn't try an
	// unreachable AAAA first). pebble reaches it by container name over the shared network.
	let challtestsrv = GenericImage::new(CHALLTESTSRV_IMAGE, IMAGE_TAG)
		.with_network(&network)
		.with_container_name(&challtestsrv_name)
		.with_cmd([
			"-defaultIPv4".to_owned(),
			host_ip.to_string(),
			"-defaultIPv6".to_owned(),
			String::new(),
		])
		.start()
		.await
		.context("start challtestsrv")?;

	// pebble: PEBBLE_VA_NOSLEEP shortens validation, -dnsserver points at the mock DNS by name.
	let pebble = GenericImage::new(PEBBLE_IMAGE, IMAGE_TAG)
		.with_exposed_port(DIRECTORY_PORT.tcp())
		.with_wait_for(WaitFor::message_on_stdout("ACME directory available at:"))
		.with_network(&network)
		.with_host(HOST_GATEWAY_HOSTNAME, Host::HostGateway)
		.with_env_var("PEBBLE_VA_NOSLEEP", "1")
		.with_cmd([
			"-config".to_owned(),
			"test/config/pebble-config.json".to_owned(),
			"-dnsserver".to_owned(),
			format!("{challtestsrv_name}:{DNS_PORT}"),
		])
		.start()
		.await
		.context("start pebble")?;

	let directory_port = pebble
		.get_host_port_ipv4(DIRECTORY_PORT.tcp())
		.await
		.context("map pebble directory port")?;

	return Ok(PebbleContainers {
		_challtestsrv: challtestsrv,
		pebble,
		directory_port,
	});
}

// Point the test at the running pebble: trust its minica root and dial its directory.
fn pebble_fixture(directory_port: u16, minica: &[u8]) -> Result<PebbleFixture, String> {
	let cert_dir = tempfile::tempdir().context("cert dir")?;
	let ca_cert = cert_dir.path().join("pebble.minica.pem");
	fs::write(&ca_cert, minica).context("write minica")?;

	let responder_bind: SocketAddr = format!("0.0.0.0:{TLS_ALPN_PORT}")
		.parse()
		.context("parse responder bind")?;

	let env = PebbleEnv {
		directory: format!("https://localhost:{directory_port}/dir"),
		ca_cert,
		domain: TEST_DOMAIN.to_owned(),
		responder_bind,
	};
	return Ok(PebbleFixture {
		_cert_dir: cert_dir,
		env,
	});
}

// Run the *production* TCP listener: mandatory client mTLS for real traffic, plus the no-client-auth
// tls-alpn-01 challenge config selected per ClientHello. This is the exact code path the fix targets
// — validation must succeed on the same listener that enforces mTLS. A single accept() call drives
// it: challenge connections are handled internally and never returned, and pebble makes no others.
fn spawn_production_listener(mut listener: TcpListener) {
	tokio::spawn(async move {
		let _ = Listener::accept(&mut listener).await;
	});
}

#[tokio::test]
#[cfg_attr(not(feature = "integration_tests"), ignore = "needs a pebble ACME server container")]
async fn pebble_provisions_certificate_via_tls_alpn() -> Result<(), String> {
	let containers = match start_pebble().await {
		Ok(value) => value,
		Err(err) => return Err(format!("start_pebble().await: {err:?}")),
	};
	// Pull the CA root out of the image so the client can trust pebble's own HTTPS listener. The
	// pebble image is distroless (no `cat` binary to exec), so copy the file out via Docker's
	// archive endpoint instead of shelling into the container. testcontainers returns a future that
	// is not Send for this copy, so the test body awaits it directly, not inside a helper.
	let minica: Vec<u8> = match containers.pebble.copy_file_from(MINICA_PATH, Vec::new()).await {
		Ok(value) => value,
		Err(err) => return Err(format!("containers.pebble.copy_file_from(MINICA_PATH, Ve...: {err:?}")),
	};
	let fixture = match pebble_fixture(containers.directory_port, &minica) {
		Ok(value) => value,
		Err(err) => return Err(format!("pebble_fixture(containers.directory_port, &minica): {err:?}")),
	};
	let env = &fixture.env;

	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

	let resolver: Arc<AcmeCertResolver> = Arc::new(AcmeCertResolver::new());

	// The mTLS config's client verifier needs a CA; the pebble minica serves as a stand-in (no real
	// mTLS client connects during the test — only pebble's anonymous acme-tls/1 validation).
	let (mtls_cfg, _client_verifier) = match build_acme_server_config(&env.ca_cert, Arc::clone(&resolver)) {
		Ok(value) => value,
		Err(err) => return Err(format!("mtls config: {err:?}")),
	};
	let mtls_config = Arc::new(mtls_cfg);
	let challenge_config = Arc::new(build_acme_challenge_config(Arc::clone(&resolver)));

	// Bind the listener before provisioning so the validator's callback always finds it listening.
	let listener = match TcpListener::bind(env.responder_bind, mtls_config, Some(challenge_config)).await {
		Ok(value) => value,
		Err(err) => return Err(format!("bind listener: {err:?}")),
	};
	spawn_production_listener(listener);

	let cache_dir = match tempfile::tempdir() {
		Ok(value) => value,
		Err(err) => return Err(format!("cache dir: {err:?}")),
	};

	let config = AcmeTlsConfig {
		domains: vec![match ArrayString::from(env.domain.as_str()) {
			Ok(value) => value,
			Err(err) => return Err(format!("domain fits: {err:?}")),
		}],
		acme_email: match ArrayString::from("ops@example.com") {
			Ok(value) => value,
			Err(err) => return Err(format!("email fits: {err:?}")),
		},
		// Unused by provisioning; point it at any real PEM (inbound client-cert CA under mandatory mTLS).
		ca_cert_path: Some(env.ca_cert.clone()),
		cache_dir: cache_dir.path().to_path_buf(),
		directory: AcmeDirectory::Custom(env.directory.clone()),
		directory_ca_cert: Some(env.ca_cert.clone()),
		barrel_state: None,
	};

	let (_shutdown_tx, shutdown_rx) = watch::channel(());
	let task = AcmeRenewalTask::new(
		config,
		Arc::clone(&resolver),
		shutdown_rx,
		reduction::metrics::ProxyMetrics::new(),
	);

	// The whole ACME dance, bounded so a hung validation fails the test instead of hanging CI.
	let provisioned = match tokio::time::timeout(Duration::from_secs(90), task.provision_initial_cert()).await {
		Ok(value) => value,
		Err(err) => return Err(format!("provisioning timed out: {err:?}")),
	};
	match provisioned {
		Ok(value) => value,
		Err(err) => return Err(format!("provisioning failed: {err:?}")),
	};

	// Feature actually did something: the resolver now holds a real cert (not the challenge slot).
	assert!(resolver.has_cert(), "resolver has no provisioned certificate");

	// Functional invariant against an external oracle (the cert pebble issued): the leaf's SAN must
	// certify the domain we asked for. A no-op provisioning path cannot satisfy this.
	let certified = match resolver.cert.load_full() {
		Some(value) => value,
		None => return Err(String::from("provisioned cert present")),
	};
	let leaf = match certified.cert.first() {
		Some(value) => value,
		None => return Err(String::from("leaf certificate present")),
	};
	let (_, parsed) = match parse_x509_certificate(leaf.as_ref()) {
		Ok(value) => value,
		Err(err) => return Err(format!("parse issued leaf: {err:?}")),
	};
	let san = match parsed.subject_alternative_name() {
		Ok(Some(value)) => value,
		Ok(None) => return Err(String::from("SAN present")),
		Err(err) => return Err(format!("SAN parse: {err:?}")),
	};
	let certifies_domain = san
		.value
		.general_names
		.iter()
		.any(|gn| matches!(gn, GeneralName::DNSName(d) if *d == env.domain));
	assert!(certifies_domain, "issued cert does not certify {}", env.domain);
	return Ok(());
}
