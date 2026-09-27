use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{error, warn};

use crate::error::{ReductionError, Result};

// Whether a failed directory-watch registration at setup is fatal (config reload is startup-critical)
// or merely warned (cert/trust/revocation are best-effort hot-reload).
#[derive(Clone, Copy)]
pub enum WatchSetupFailure {
	Fatal,
	Warn,
}

// Trailing-edge debounced filesystem watcher shared by every hot-reload path (config, certs, trust,
// revocation): coalesces a save's event burst and, after `debounce` of quiet, invokes `on_reload`
// once with the winning event, so a reload always reads the settled file. Each trigger's PARENT
// directory is watched NonRecursive (files are replaced by rename, which fires no event on the node).
// `context` names the watcher in logs; the caller must keep the returned watcher alive.
pub fn spawn_trailing_edge_watcher<F>(
	trigger_paths: &[PathBuf],
	debounce: Duration,
	context: &'static str,
	on_setup_failure: WatchSetupFailure,
	on_reload: F,
) -> Result<RecommendedWatcher>
where
	F: Fn(&Event) + Send + Sync + 'static,
{
	// Each accepted event bumps the generation; its worker reloads only if still newest after the quiet period.
	let generation: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
	let trigger_set: Vec<PathBuf> = trigger_paths.to_vec();
	let on_reload: Arc<F> = Arc::new(on_reload);

	let mut watcher: RecommendedWatcher =
		notify::recommended_watcher(move |result: std::result::Result<Event, notify::Error>| {
			let event: Event = match result {
				Ok(event) => event,
				Err(e) => {
					error!(error = %e, context, "fs watcher error");
					return;
				}
			};
			if !matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
				return;
			}
			// Filter to our files before scheduling, so unrelated writes can't consume the debounce window.
			if !event.paths.iter().any(|p| trigger_set.contains(p)) {
				return;
			}

			let my_generation: u64 = generation.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
			let generation_state: Arc<AtomicU64> = Arc::clone(&generation);
			let reload: Arc<F> = Arc::clone(&on_reload);
			std::thread::spawn(move || {
				std::thread::sleep(debounce);
				if generation_state.load(Ordering::Acquire) != my_generation {
					return;
				}
				reload(&event);
			});
		})
		.map_err(|e| ReductionError::Config(format!("{context} watcher init: {e}")))?;

	// Watch each distinct parent directory once; trigger files may share a directory.
	let mut watched_parents: Vec<PathBuf> = Vec::new();
	for path in trigger_paths {
		let parent: Option<&Path> = path.parent().filter(|p| !p.as_os_str().is_empty());
		let parent: PathBuf = match parent {
			Some(parent) => parent.to_path_buf(),
			None => match on_setup_failure {
				WatchSetupFailure::Fatal => {
					return Err(ReductionError::Config(format!(
						"{context}: cannot watch {} without a parent directory",
						path.display()
					)));
				}
				WatchSetupFailure::Warn => {
					warn!(path = %path.display(), context, "cannot watch file without parent directory");
					continue;
				}
			},
		};
		if watched_parents.contains(&parent) {
			continue;
		}
		if let Err(e) = watcher.watch(&parent, RecursiveMode::NonRecursive) {
			match on_setup_failure {
				WatchSetupFailure::Fatal => {
					return Err(ReductionError::Config(format!(
						"{context}: failed to watch {}: {e}",
						parent.display()
					)));
				}
				WatchSetupFailure::Warn => {
					warn!(path = %parent.display(), error = %e, context, "failed to watch directory");
				}
			}
		} else {
			watched_parents.push(parent);
		}
	}
	return Ok(watcher);
}

#[cfg(test)]
mod tests {
	use std::path::PathBuf;
	use std::time::Duration;

	use notify::Event;
	use tempfile::tempdir;

	use super::{WatchSetupFailure, spawn_trailing_edge_watcher};

	const TEST_DEBOUNCE: Duration = Duration::from_millis(10);

	fn noop_reload() -> impl Fn(&Event) + Send + Sync + 'static {
		return |_event: &Event| {};
	}

	#[test]
	fn fatal_setup_fails_for_path_without_parent() {
		// A bare filename has an empty parent, which the Fatal policy treats as unrecoverable.
		let result = spawn_trailing_edge_watcher(
			&[PathBuf::from("bare-file")],
			TEST_DEBOUNCE,
			"test",
			WatchSetupFailure::Fatal,
			noop_reload(),
		);
		assert!(result.is_err(), "a parentless trigger under Fatal must error");
	}

	#[test]
	fn warn_setup_tolerates_path_without_parent() {
		// The same parentless trigger under Warn is skipped, yielding a live (empty) watcher.
		let result = spawn_trailing_edge_watcher(
			&[PathBuf::from("bare-file")],
			TEST_DEBOUNCE,
			"test",
			WatchSetupFailure::Warn,
			noop_reload(),
		);
		assert!(result.is_ok(), "a parentless trigger under Warn is skipped, not fatal");
	}

	#[test]
	fn fatal_setup_fails_when_parent_directory_missing() {
		let missing: PathBuf = PathBuf::from("does-not-exist-9f3a1c").join("watched.toml");
		let result = spawn_trailing_edge_watcher(
			&[missing],
			TEST_DEBOUNCE,
			"test",
			WatchSetupFailure::Fatal,
			noop_reload(),
		);
		assert!(result.is_err(), "watching a missing directory under Fatal must error");
	}

	#[test]
	fn warn_setup_tolerates_missing_parent_directory() {
		let missing: PathBuf = PathBuf::from("does-not-exist-9f3a1c").join("watched.toml");
		let result = spawn_trailing_edge_watcher(
			&[missing],
			TEST_DEBOUNCE,
			"test",
			WatchSetupFailure::Warn,
			noop_reload(),
		);
		assert!(result.is_ok(), "a missing directory under Warn warns and continues");
	}

	#[test]
	fn watches_existing_parent_directory() {
		let dir = tempdir().unwrap();
		let trigger: PathBuf = dir.path().join("config.toml");
		let result = spawn_trailing_edge_watcher(
			&[trigger],
			TEST_DEBOUNCE,
			"test",
			WatchSetupFailure::Fatal,
			noop_reload(),
		);
		assert!(result.is_ok(), "an existing parent directory registers successfully");
	}

	#[test]
	fn deduplicates_triggers_sharing_one_parent() {
		// Two triggers in the same directory must register that parent once, not fail on the second.
		let dir = tempdir().unwrap();
		let a: PathBuf = dir.path().join("cert.pem");
		let b: PathBuf = dir.path().join("key.pem");
		let result = spawn_trailing_edge_watcher(
			&[a, b],
			TEST_DEBOUNCE,
			"test",
			WatchSetupFailure::Fatal,
			noop_reload(),
		);
		assert!(result.is_ok(), "two files sharing a parent register that parent once");
	}
}
