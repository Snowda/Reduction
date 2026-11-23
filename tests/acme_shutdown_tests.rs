//! ACME renewal-task graceful-shutdown behaviour.
//!
//! Gated on `integration_tests` + `acme`. Unlike acme_pebble_tests, this needs NO Docker or network:
//! it drives the real `AcmeRenewalTask::run()` loop with an unreachable ACME directory and asserts the
//! task terminates when — and only when — its shutdown channel is signalled. Run with:
//!   cargo test --features integration_tests,acme --test acme_shutdown_tests -- --nocapture
//!
//! What it proves that a compile/unit check cannot: the renewal loop's `select!` on
//! `shutdown.changed()` actually wins over its (12-hour) sleep, so main's CancellationToken→watch
//! bridge can stop cert renewal on ctrl-c/SIGTERM. The negative control proves the exit is *caused*
//! by the signal rather than the task ending on its own — the receipt for the fix, not just that it ran.

mod support;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arrayvec::ArrayString;
use reduction::config::{AcmeDirectory, AcmeTlsConfig};
use reduction::tls::acme::{AcmeCertResolver, AcmeRenewalTask};
use tempfile::TempDir;
use tokio::sync::watch;
use tokio::time::timeout;

use crate::support::Context;

// Grace window for run() to return after shutdown fires. Orders of magnitude above the near-instant
// select! resolution, so a pass is unambiguous and a hang is caught rather than waited on.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
// Control window: with no cached cert, run() sleeps ACME_RETRY_INTERVAL (12h) before it would
// ever provision, so any return inside this window would mean run() exited without a signal.
const LIVENESS_WINDOW: Duration = Duration::from_millis(500);

// A config whose ACME directory is unreachable (nothing listens on port 1): if provisioning were ever
// reached it would fail fast, so a clean task exit can only come from the shutdown path.
fn unreachable_acme_config(cache_dir: &Path) -> Result<AcmeTlsConfig, String> {
	return Ok(AcmeTlsConfig {
		domains: vec![ArrayString::from("shutdown.example.com").context("domain")?],
		acme_email: ArrayString::from("ops@example.com").context("email")?,
		ca_cert_path: Some(cache_dir.join("unused-ca.pem")),
		cache_dir: cache_dir.to_path_buf(),
		directory: AcmeDirectory::Custom("https://127.0.0.1:1/directory".to_owned()),
		directory_ca_cert: None,
		barrel_state: None,
	});
}

// Firing the shutdown watch (exactly what main's CancellationToken bridge does) must make run() return.
#[tokio::test]
#[cfg_attr(not(feature = "integration_tests"), ignore = "runs the real ACME renewal loop")]
async fn renewal_task_exits_when_shutdown_signalled() -> Result<(), String> {
	let dir: TempDir = match tempfile::tempdir() {
		Ok(value) => value,
		Err(err) => return Err(format!("tempfile::tempdir(): {err:?}")),
	};
	let resolver: Arc<AcmeCertResolver> = Arc::new(AcmeCertResolver::new());
	let (shutdown_tx, shutdown_rx): (watch::Sender<()>, watch::Receiver<()>) = watch::channel(());
	let task: AcmeRenewalTask = AcmeRenewalTask::new(
		match unreachable_acme_config(dir.path()) {
			Ok(value) => value,
			Err(err) => return Err(format!("unreachable_acme_config(dir.path()): {err:?}")),
		},
		resolver,
		shutdown_rx,
		reduction::metrics::ProxyMetrics::new(),
	);

	let handle = tokio::spawn(task.run());
	match shutdown_tx.send(()) {
		Ok(value) => value,
		Err(err) => return Err(format!("receiver lives inside the spawned task: {err:?}")),
	};

	let joined = timeout(SHUTDOWN_GRACE, handle).await;
	assert!(joined.is_ok(), "run() must return promptly once shutdown is signalled");
	match joined {
		Ok(Ok(value)) => value,
		Ok(Err(err)) => return Err(format!("run() must not panic on the shutdown path: {err:?}")),
		Err(err) => return Err(format!("joined: {err:?}")),
	};
	return Ok(());
}

// Negative control: with no signal, run() must stay alive (it is sleeping until the 12h retry). This is
// the diff against the fix disabled — it proves the exit above is caused by the signal, not inevitable.
#[tokio::test]
#[cfg_attr(not(feature = "integration_tests"), ignore = "runs the real ACME renewal loop")]
async fn renewal_task_stays_alive_without_shutdown() -> Result<(), String> {
	let dir: TempDir = match tempfile::tempdir() {
		Ok(value) => value,
		Err(err) => return Err(format!("tempfile::tempdir(): {err:?}")),
	};
	let resolver: Arc<AcmeCertResolver> = Arc::new(AcmeCertResolver::new());
	// Keep the sender bound (never send) so the task's receiver is not dropped either.
	let (_shutdown_tx, shutdown_rx): (watch::Sender<()>, watch::Receiver<()>) = watch::channel(());
	let task: AcmeRenewalTask = AcmeRenewalTask::new(
		match unreachable_acme_config(dir.path()) {
			Ok(value) => value,
			Err(err) => return Err(format!("unreachable_acme_config(dir.path()): {err:?}")),
		},
		resolver,
		shutdown_rx,
		reduction::metrics::ProxyMetrics::new(),
	);

	let handle = tokio::spawn(task.run());
	let abort = handle.abort_handle();

	let joined = timeout(LIVENESS_WINDOW, handle).await;
	assert!(joined.is_err(), "run() must keep running until shutdown is signalled");

	// Dropping a JoinHandle detaches rather than aborts; stop the task so it cannot outlive the test.
	abort.abort();
	return Ok(());
}
