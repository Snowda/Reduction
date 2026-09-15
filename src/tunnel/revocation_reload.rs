use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::{Event, RecommendedWatcher};
use tokio::sync::watch;
use tracing::{error, info};

use crate::error::{ReductionError, Result};
use crate::fs_watch::{WatchSetupFailure, spawn_trailing_edge_watcher};
use crate::metrics::ProxyMetrics;
use crate::tunnel::revocation::RevocationSet;

// Coalesce the burst of fs events an editor/writer emits for one logical save, matching CertWatcher.
const REVOCATION_RELOAD_DEBOUNCE_MS: u64 = 300;

// Read and parse the revocation file at `path`. Absent file surfaces as an io error; malformed content
// surfaces as a parse error — the caller decides how each maps to the in-memory set.
pub fn load_revocation_file(path: &Path) -> Result<RevocationSet> {
	let contents: String = std::fs::read_to_string(path)?;
	return RevocationSet::parse(&contents);
}

// Strict startup load. Once an operator configures a revocation path, missing or malformed data must
// stop startup: silently replacing the denylist with an empty set would re-authorize every revoked
// identity after a restart. Runtime reloads remain last-known-good below.
pub fn load_initial(path: &Path, metrics: &ProxyMetrics) -> Result<RevocationSet> {
	match load_revocation_file(path) {
		Ok(set) => {
			info!(path = %path.display(), entries = set.len(), "revocation denylist loaded");
			return Ok(set);
		}
		Err(e) => {
			metrics.revocation_load_errors.add(1, &[]);
			error!(path = %path.display(), error = %e, "revocation file unavailable or invalid at startup");
			return Err(ReductionError::Config(format!(
				"failed to load configured revocation file {}: {e}",
				path.display(),
			)));
		}
	}
}

// Watches the revocation file and republishes the parsed denylist through a watch channel on change.
pub struct RevocationWatcher {
	_watcher: RecommendedWatcher,
}

impl RevocationWatcher {
	// Watch `path`; on each modify/create re-read and parse, publishing a new set through `tx`. On a
	// parse failure the PREVIOUS set is kept (last-known-good — never fail-open by un-revoking, never
	// fail-closed by bricking the fleet) and `revocation_load_errors` is incremented. `tx` must already
	// carry the startup set (see load_initial). The watcher watches the parent directory (files are
	// often replaced by rename, which fires no event on the file node itself) and filters by exact path.
	pub fn new(path: &Path, tx: watch::Sender<RevocationSet>, metrics: ProxyMetrics) -> Result<Self> {
		let debounce: Duration = Duration::from_millis(REVOCATION_RELOAD_DEBOUNCE_MS);
		let reload_path: PathBuf = path.to_path_buf();
		let watcher: RecommendedWatcher = spawn_trailing_edge_watcher(
			&[path.to_path_buf()],
			debounce,
			"revocation",
			WatchSetupFailure::Warn,
			move |_event: &Event| match load_revocation_file(&reload_path) {
				Ok(set) => {
					let entries: usize = set.len();
					if tx.send(set).is_ok() {
						info!(path = %reload_path.display(), entries, "revocation denylist hot-reloaded");
					}
				}
				Err(e) => {
					metrics.revocation_load_errors.add(1, &[]);
					error!(path = %reload_path.display(), error = %e,
						"revocation reload failed; keeping previous denylist");
				}
			},
		)?;

		info!(path = %path.display(), "watching revocation file for hot-reload");
		return Ok(Self { _watcher: watcher });
	}
}

#[cfg(test)]
mod tests {
	use std::thread;

	use aws_lc_rs::digest::{SHA256, digest};
	use tempfile::TempDir;

	use super::*;
	use crate::tls::identity::SPKI_SHA256_LEN;

	// Poll interval exceeds the debounce so a write has time to settle before the assertion.
	const RELOAD_POLL_INTERVAL_MS: u64 = 500;
	const RELOAD_MAX_ATTEMPTS: u32 = 20;
	const SETTLE_MS: u64 = 1000;

	fn spki_hex(seed: &[u8]) -> String {
		let hash: [u8; SPKI_SHA256_LEN] = digest(&SHA256, seed).as_ref().try_into().unwrap();
		return hash.iter().map(|b| format!("{b:02x}")).collect();
	}

	fn revocation_toml(seed: &[u8]) -> String {
		return format!("[[revoked]]\nspki = \"{}\"\nreason = \"clone\"\n", spki_hex(seed));
	}

	// Rewrite until the watcher publishes the expected change. Retrying keeps these filesystem-watcher
	// tests reliable across platforms where save notifications may be coalesced.
	fn write_until<F: Fn() -> bool>(path: &Path, contents: &str, done: F) -> bool {
		for _ in 0..RELOAD_MAX_ATTEMPTS {
			std::fs::write(path, contents).unwrap();
			thread::sleep(Duration::from_millis(RELOAD_POLL_INTERVAL_MS));
			if done() {
				return true;
			}
		}
		return false;
	}

	fn wait_until<F: Fn() -> bool>(done: F) -> bool {
		for _ in 0..RELOAD_MAX_ATTEMPTS {
			thread::sleep(Duration::from_millis(RELOAD_POLL_INTERVAL_MS));
			if done() {
				return true;
			}
		}
		return false;
	}

	fn dir_and_path() -> (TempDir, std::path::PathBuf) {
		let dir: TempDir = tempfile::tempdir().unwrap();
		let path: std::path::PathBuf = dir.path().join("revoked.toml");
		return (dir, path);
	}

	#[test]
	fn test_load_initial_absent_is_error() {
		let _ = crate::metrics::init_metrics(&crate::config::MetricsConfig { otlp_endpoint: None });
		let (_dir, path) = dir_and_path();
		let metrics = ProxyMetrics::new();
		let result = load_initial(&path, &metrics);
		assert!(result.is_err(), "a configured but missing denylist must stop startup");
	}

	#[test]
	fn test_load_initial_valid_parses() {
		let _ = crate::metrics::init_metrics(&crate::config::MetricsConfig { otlp_endpoint: None });
		let (_dir, path) = dir_and_path();
		std::fs::write(&path, revocation_toml(b"key-1")).unwrap();
		let set = load_initial(&path, &ProxyMetrics::new()).unwrap();
		assert_eq!(set.len(), 1);
	}

	#[test]
	fn test_load_initial_corrupt_is_error() {
		let _ = crate::metrics::init_metrics(&crate::config::MetricsConfig { otlp_endpoint: None });
		let (_dir, path) = dir_and_path();
		std::fs::write(&path, "this = = not toml").unwrap();
		let result = load_initial(&path, &ProxyMetrics::new());
		assert!(
			result.is_err(),
			"a corrupt denylist must not silently re-authorize revoked identities"
		);
	}

	// The identity a given seed's SPKI would carry, for asserting is_revoked against the published set.
	fn identity_for(seed: &[u8]) -> crate::tls::PeerIdentity {
		use arrayvec::ArrayString;
		let hash: [u8; SPKI_SHA256_LEN] = digest(&SHA256, seed).as_ref().try_into().unwrap();
		return crate::tls::PeerIdentity {
			common_name: ArrayString::from("device-x").unwrap(),
			spki_sha256: hash,
		};
	}

	#[test]
	fn test_watcher_hot_swaps_on_overwrite() {
		let _ = crate::metrics::init_metrics(&crate::config::MetricsConfig { otlp_endpoint: None });
		let (_dir, path) = dir_and_path();
		std::fs::write(&path, revocation_toml(b"first")).unwrap();

		let initial = load_initial(&path, &ProxyMetrics::new()).unwrap();
		let (tx, rx) = watch::channel(initial);
		// Before the overwrite, only "first" is revoked.
		assert!(rx.borrow().is_revoked(&identity_for(b"first")));
		assert!(!rx.borrow().is_revoked(&identity_for(b"second")));

		let _watcher = RevocationWatcher::new(&path, tx, ProxyMetrics::new()).unwrap();

		// Overwrite the file to revoke "second" instead; the set must swap with no restart.
		let swapped = write_until(&path, &revocation_toml(b"second"), || {
			rx.borrow().is_revoked(&identity_for(b"second"))
		});
		assert!(swapped, "watcher never published the overwritten revocation set");
		assert!(
			!rx.borrow().is_revoked(&identity_for(b"first")),
			"old entry must be gone after swap"
		);
	}

	#[test]
	fn test_watcher_uses_final_write_after_a_burst() {
		let _ = crate::metrics::init_metrics(&crate::config::MetricsConfig { otlp_endpoint: None });
		let (_dir, path) = dir_and_path();
		std::fs::write(&path, revocation_toml(b"first")).unwrap();

		let initial = load_initial(&path, &ProxyMetrics::new()).unwrap();
		let (tx, rx) = watch::channel(initial);
		let _watcher = RevocationWatcher::new(&path, tx, ProxyMetrics::new()).unwrap();

		// Simulate an editor's partial write followed shortly by its complete replacement. A leading-edge
		// debounce could read the invalid data then discard this final event, leaving the old set live.
		std::fs::write(&path, "garbage = = not toml").unwrap();
		thread::sleep(Duration::from_millis(100));
		std::fs::write(&path, revocation_toml(b"final")).unwrap();

		let swapped = wait_until(|| rx.borrow().is_revoked(&identity_for(b"final")));
		assert!(swapped, "the final settled write must be published after a burst");
	}

	#[test]
	fn test_watcher_keeps_previous_on_corrupt_overwrite() {
		let _ = crate::metrics::init_metrics(&crate::config::MetricsConfig { otlp_endpoint: None });
		let (_dir, path) = dir_and_path();
		std::fs::write(&path, revocation_toml(b"good")).unwrap();

		let initial = load_initial(&path, &ProxyMetrics::new()).unwrap();
		let (tx, rx) = watch::channel(initial);
		assert!(rx.borrow().is_revoked(&identity_for(b"good")));

		let _watcher = RevocationWatcher::new(&path, tx, ProxyMetrics::new()).unwrap();

		// A corrupt overwrite must NOT clear the denylist — the previous set stays enforced.
		std::fs::write(&path, "garbage = = not toml").unwrap();
		thread::sleep(Duration::from_millis(SETTLE_MS));
		assert!(
			rx.borrow().is_revoked(&identity_for(b"good")),
			"corrupt overwrite must not un-revoke the previous set",
		);

		// And the watcher recovers: a subsequent valid write is picked up.
		let recovered = write_until(&path, &revocation_toml(b"next"), || {
			rx.borrow().is_revoked(&identity_for(b"next"))
		});
		assert!(recovered, "watcher did not recover after a corrupt overwrite");
	}
}
