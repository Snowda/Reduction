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
#![cfg(all(feature = "integration_tests", feature = "acme"))]
// Integration-test crate: unwrap/expect are the idiomatic way to fail a test loudly. The project's
// deny-level restriction lints auto-exempt inline #[cfg(test)] modules but not standalone test crates.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arrayvec::ArrayString;
use reduction::config::AcmeTlsConfig;
use reduction::tls::acme::{AcmeCertResolver, AcmeRenewalTask};
use tempfile::TempDir;
use tokio::sync::watch;
use tokio::time::timeout;

// Grace window for run() to return after shutdown fires. Orders of magnitude above the near-instant
// select! resolution, so a pass is unambiguous and a hang is caught rather than waited on.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
// Control window: with no cached cert, run() sleeps ACME_RETRY_INTERVAL_SECS (12h) before it would
// ever provision, so any return inside this window would mean run() exited without a signal.
const LIVENESS_WINDOW: Duration = Duration::from_millis(500);

// A config whose ACME directory is unreachable (nothing listens on port 1): if provisioning were ever
// reached it would fail fast, so a clean task exit can only come from the shutdown path.
fn unreachable_acme_config(cache_dir: &Path) -> AcmeTlsConfig {
	return AcmeTlsConfig {
		domains: vec![ArrayString::from("shutdown.example.com").unwrap()],
		acme_email: ArrayString::from("ops@example.com").unwrap(),
		ca_cert_path: Some(cache_dir.join("unused-ca.pem")),
		cache_dir: cache_dir.to_path_buf(),
		staging: false,
		directory_url: Some("https://127.0.0.1:1/directory".to_owned()),
		directory_ca_cert: None,
		barrel_state: None,
	};
}

// Firing the shutdown watch (exactly what main's CancellationToken bridge does) must make run() return.
#[tokio::test]
async fn renewal_task_exits_when_shutdown_signalled() {
	let dir: TempDir = tempfile::tempdir().unwrap();
	let resolver: Arc<AcmeCertResolver> = Arc::new(AcmeCertResolver::new());
	let (shutdown_tx, shutdown_rx): (watch::Sender<()>, watch::Receiver<()>) = watch::channel(());
	let task: AcmeRenewalTask = AcmeRenewalTask::new(unreachable_acme_config(dir.path()), resolver, shutdown_rx, reduction::metrics::ProxyMetrics::new());

	let handle = tokio::spawn(task.run());
	shutdown_tx.send(()).expect("receiver lives inside the spawned task");

	let joined = timeout(SHUTDOWN_GRACE, handle).await;
	assert!(joined.is_ok(), "run() must return promptly once shutdown is signalled");
	joined.unwrap().expect("run() must not panic on the shutdown path");
}

// Negative control: with no signal, run() must stay alive (it is sleeping until the 12h retry). This is
// the diff against the fix disabled — it proves the exit above is caused by the signal, not inevitable.
#[tokio::test]
async fn renewal_task_stays_alive_without_shutdown() {
	let dir: TempDir = tempfile::tempdir().unwrap();
	let resolver: Arc<AcmeCertResolver> = Arc::new(AcmeCertResolver::new());
	// Keep the sender bound (never send) so the task's receiver is not dropped either.
	let (_shutdown_tx, shutdown_rx): (watch::Sender<()>, watch::Receiver<()>) = watch::channel(());
	let task: AcmeRenewalTask = AcmeRenewalTask::new(unreachable_acme_config(dir.path()), resolver, shutdown_rx, reduction::metrics::ProxyMetrics::new());

	let handle = tokio::spawn(task.run());
	let abort = handle.abort_handle();

	let joined = timeout(LIVENESS_WINDOW, handle).await;
	assert!(joined.is_err(), "run() must keep running until shutdown is signalled");

	// Dropping a JoinHandle detaches rather than aborts; stop the task so it cannot outlive the test.
	abort.abort();
}
