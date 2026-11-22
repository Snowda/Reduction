// Hot reload of trust anchors: a watcher over the CA bundle (and server-side CRL) that reloads either verifier.
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use notify::{Event, RecommendedWatcher};
use opentelemetry::KeyValue;
use tracing::{error, info};

use super::Reloadable;
use crate::error::Result;
use crate::fs_watch::{RELOAD_DEBOUNCE, WatchSetupFailure, spawn_trailing_edge_watcher};

const TRUST_SIDE_ATTR: &str = "side";

// The trust store that a watcher reloads, as the `side` metric attribute. Server verifies inbound client
// certs (`tls.server.ca_cert_path`). Client verifies the backend certs that this proxy dials (`tls.client.ca_cert_path`).
// The two egress sides are the CA files of `[egress.uplink]` and `[egress.uplink_listener]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustSide {
	Server,
	Client,
	EgressUplink,
	EgressUplinkListener,
}

impl TrustSide {
	#[must_use]
	pub const fn as_str(self) -> &'static str {
		return match self {
			Self::Server => "server",
			Self::Client => "client",
			Self::EgressUplink => "egress_uplink",
			Self::EgressUplinkListener => "egress_uplink_listener",
		};
	}

	fn attr(self) -> KeyValue {
		return KeyValue::new(TRUST_SIDE_ATTR, self.as_str());
	}
}

// Watches the trust files (a CA bundle and, on the server side, an optional CRL) and reloads the
// wrapped verifier in place when one changes. It is generic over `Reloadable`, so it drives both verifier sides.
// A failed reload keeps the last-known-good trust material and increments `ca_bundle_load_errors`. A good
// reload increments `ca_bundle_reloads`, and both metrics carry the `side` attribute. It watches the parent
// directory of each trigger file, because a rename-replace fires no event on the file. It filters to the trigger paths.
pub struct TrustWatcher {
	_watcher: RecommendedWatcher,
}

impl TrustWatcher {
	pub fn new<R: Reloadable + 'static, P: AsRef<Path>>(
		reloadable: Arc<R>,
		trigger_paths: &[P],
		side: TrustSide,
		metrics: crate::metrics::ProxyMetrics,
	) -> Result<Self> {
		let debounce: Duration = RELOAD_DEBOUNCE;
		let watcher: RecommendedWatcher = spawn_trailing_edge_watcher(
			trigger_paths,
			debounce,
			"trust",
			WatchSetupFailure::Warn,
			move |_event: &Event| match reloadable.reload() {
				Ok(()) => {
					metrics.ca_bundle_reloads.add(1, &[side.attr()]);
					info!(side = side.as_str(), "trust anchors hot-reloaded");
				}
				Err(e) => {
					metrics.ca_bundle_load_errors.add(1, &[side.attr()]);
					error!(error = %e, side = side.as_str(), "failed to reload trust anchors, keeping previous");
				}
			},
		)?;
		info!(side = side.as_str(), files = trigger_paths.len(), "watching trust files for hot-reload");
		return Ok(Self { _watcher: watcher });
	}
}

#[cfg(test)]
mod tests {
	#[cfg(feature = "proxy")]
	use std::path::PathBuf;
	use std::result::Result;
	use std::sync::atomic::{AtomicU32, Ordering};

	use tempfile::TempDir;

	use super::*;
	use crate::error::Result as ReductionResult;
	use crate::tls::reload::testutil::{
		Ca, ca_and_leaves, crl_ca, crl_leaf, make_crl_pem, server_verifier_accepts, is_leaf_accepted, write_file,
		write_until,
	};
	use crate::tls::reload::{ReloadingClientVerifier, ReloadingServerVerifier};

	// ── Trust watchers (handshake-level revocation and CA rotation) ──

	// Write the files into a new TempDir, which has no other fs events. Returns the paths in order.
	#[cfg(feature = "proxy")]
	fn trust_dir(files: &[(&str, &str)]) -> Result<(TempDir, Vec<PathBuf>), String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let _ = crate::metrics::init_metrics(&crate::config::MetricsConfig { otlp_endpoint: None });
		let dir: TempDir = tempfile::tempdir().map_err(|err| format!("tempfile::tempdir(): {err:?}"))?;
		let paths: Vec<PathBuf> = files.iter().map(|(name, _)| dir.path().join(name)).collect();
		files
			.iter()
			.zip(&paths)
			.try_for_each(|((_, contents), path)| write_file(path, contents))?;
		return Ok((dir, paths));
	}

	#[test]
	fn trust_side_labels_are_the_published_attribute_values() {
		assert_eq!(TrustSide::Server.attr(), KeyValue::new("side", "server"));
		assert_eq!(TrustSide::Client.attr(), KeyValue::new("side", "client"));
		assert_eq!(TrustSide::EgressUplink.attr(), KeyValue::new("side", "egress_uplink"));
		assert_eq!(TrustSide::EgressUplinkListener.attr(), KeyValue::new("side", "egress_uplink_listener"));
	}

	#[cfg(feature = "proxy")]
	fn start_trust_watcher<V: Reloadable + 'static>(
		verifier: &Arc<V>,
		paths: &[PathBuf],
		side: TrustSide,
	) -> Result<TrustWatcher, String> {
		return TrustWatcher::new(Arc::clone(verifier), paths, side, crate::metrics::ProxyMetrics::new())
			.map_err(|err| format!("TrustWatcher::new: {err:?}"));
	}

	// Two CRLs over the CA: one empty, and one that revokes serial 1.
	#[cfg(feature = "proxy")]
	fn crl_pair(ca: &Ca) -> Result<(String, String), String> {
		let empty: String = make_crl_pem(ca, &[])?;
		let revoking: String = make_crl_pem(ca, &[1])?;
		return Ok((empty, revoking));
	}

	// A CA and one client leaf it signs (serial 1).
	#[cfg(feature = "proxy")]
	fn ca_and_client_leaf(cn: &str) -> Result<(Ca, Ca), String> {
		let ca: Ca = crl_ca()?;
		let leaf: Ca = crl_leaf(&ca, cn, 1)?;
		return Ok((ca, leaf));
	}

	// Wraps a real verifier and counts failed reloads. The watcher's error metric goes to the global
	// meter, so this count is how a test sees the failure arm run.
	#[cfg(feature = "proxy")]
	struct FailureCounting<R> {
		inner: Arc<R>,
		failures: AtomicU32,
	}

	#[cfg(feature = "proxy")]
	impl<R: Reloadable> Reloadable for FailureCounting<R> {
		fn reload(&self) -> ReductionResult<()> {
			let result: ReductionResult<()> = self.inner.reload();
			if result.is_err() {
				self.failures.fetch_add(1, Ordering::AcqRel);
			}
			return result;
		}
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_trust_watcher_hot_reloads_crl() -> Result<(), String> {
		let (ca, leaf) = ca_and_client_leaf("device-1")?;
		let (empty_crl, revoking) = crl_pair(&ca)?;
		// Empty CRL initially.
		let (_dir, paths) = trust_dir(&[("ca.pem", &ca.cert.pem()), ("revoked.crl.pem", &empty_crl)])?;
		let verifier = ReloadingClientVerifier::new(&paths[0], Some(&paths[1]))
			.map_err(|err| format!("ReloadingClientVerifier::new: {err:?}"))?;
		assert!(is_leaf_accepted(&verifier, &leaf), "leaf accepted before revocation");
		let _watcher = start_trust_watcher(&verifier, &paths, TrustSide::Server)?;

		// Write a CRL that revokes the leaf. The watcher must swap it in with no restart.
		let rejected: bool = write_until(&[(&paths[1], &revoking)], || !is_leaf_accepted(&verifier, &leaf))?;
		assert!(rejected, "trust watcher never applied the CRL revocation");
		return Ok(());
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_trust_watcher_hot_reloads_ca_bundle() -> Result<(), String> {
		let ca_old: Ca = crl_ca()?;
		let (ca_new, new_leaf) = ca_and_client_leaf("device-new")?;
		let (_dir, paths) = trust_dir(&[("ca.pem", &ca_old.cert.pem())])?;
		let verifier = ReloadingClientVerifier::new(&paths[0], None)
			.map_err(|err| format!("ReloadingClientVerifier::new: {err:?}"))?;
		assert!(
			!is_leaf_accepted(&verifier, &new_leaf),
			"new-CA leaf rejected before rotation"
		);
		let _watcher = start_trust_watcher(&verifier, &paths, TrustSide::Server)?;

		// Rotate the CA bundle on disk. The watcher must swap in the trust anchors with no restart.
		let new_ca_pem: String = ca_new.cert.pem();
		let accepted: bool = write_until(&[(&paths[0], &new_ca_pem)], || is_leaf_accepted(&verifier, &new_leaf))?;
		assert!(accepted, "trust watcher never applied the CA rotation");
		return Ok(());
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_trust_watcher_hot_reloads_server_ca_bundle() -> Result<(), String> {
		let (ca_old, _) = ca_and_leaves::<0>()?;
		let (ca_new, [new_leaf]) = ca_and_leaves::<1>()?;
		let (_dir, paths) = trust_dir(&[("ca.pem", &ca_old.cert.pem())])?;
		let verifier =
			ReloadingServerVerifier::new(&paths[0]).map_err(|err| format!("ReloadingServerVerifier::new: {err:?}"))?;
		let accepts_new = || -> bool { matches!(server_verifier_accepts(&verifier, &new_leaf), Ok(true)) };
		assert!(!accepts_new(), "new-CA server leaf rejected before rotation");

		// The generic watcher drives the server-cert verifier (client side) exactly as it does the
		// client-cert verifier (server side) — same file, no restart, client metric tag.
		let _watcher = start_trust_watcher(&verifier, &paths, TrustSide::Client)?;
		let new_ca_pem: String = ca_new.cert.pem();
		let accepted: bool = write_until(&[(&paths[0], &new_ca_pem)], accepts_new)?;
		assert!(accepted, "trust watcher never applied the backend CA rotation");
		return Ok(());
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_trust_watcher_failed_reload_keeps_previous_then_recovers() -> Result<(), String> {
		let (ca_old, old_leaf) = ca_and_client_leaf("device-old")?;
		let (ca_new, new_leaf) = ca_and_client_leaf("device-new")?;
		let (_dir, paths) = trust_dir(&[("ca.pem", &ca_old.cert.pem())])?;
		let verifier = ReloadingClientVerifier::new(&paths[0], None)
			.map_err(|err| format!("ReloadingClientVerifier::new: {err:?}"))?;
		let counting: Arc<FailureCounting<ReloadingClientVerifier>> = Arc::new(FailureCounting {
			inner: Arc::clone(&verifier),
			failures: AtomicU32::new(0),
		});
		let _watcher = start_trust_watcher(&counting, &paths, TrustSide::Server)?;

		// The watcher must try to load a garbage bundle and reach its failure arm.
		let attempted: bool = write_until(&[(&paths[0], "not a certificate")], || {
			counting.failures.load(Ordering::Acquire) > 0
		})?;
		assert!(attempted, "watcher never attempted a reload of the garbage CA bundle");
		assert!(
			is_leaf_accepted(&verifier, &old_leaf),
			"a failed reload must keep the previous trust anchors"
		);

		// The watcher outlives the failure: the next valid bundle replaces the old anchors outright.
		let new_ca_pem: String = ca_new.cert.pem();
		let recovered: bool = write_until(&[(&paths[0], &new_ca_pem)], || is_leaf_accepted(&verifier, &new_leaf))?;
		assert!(recovered, "watcher did not recover after a failed reload");
		assert!(
			!is_leaf_accepted(&verifier, &old_leaf),
			"rotation must drop the old CA, not merge it in"
		);
		return Ok(());
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_trust_watcher_tolerates_unwatchable_directory() -> Result<(), String> {
		let (ca, _) = ca_and_leaves::<0>()?;
		let (dir, paths) = trust_dir(&[("ca.pem", &ca.cert.pem())])?;
		let verifier =
			ReloadingServerVerifier::new(&paths[0]).map_err(|err| format!("ReloadingServerVerifier::new: {err:?}"))?;
		let missing: PathBuf = dir.path().join("absent").join("ca.pem");

		// Trust hot reload is best-effort. If the watcher cannot watch a directory, it warns and startup continues.
		let started = start_trust_watcher(&verifier, &[missing], TrustSide::Client);
		assert!(
			started.is_ok(),
			"an unwatchable trust directory must not fail watcher setup: {:?}",
			started.err()
		);
		return Ok(());
	}
}
