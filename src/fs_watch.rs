// File watcher that reports a change after the writes stop; each hot-reload path (config, certs, trust, revocation) uses it.
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{error, warn};

use crate::error::{ReductionError, Result};

// Quiet period every hot-reload path waits for, so one editor save's burst of events reloads once.
pub const RELOAD_DEBOUNCE: Duration = Duration::from_millis(300);

// Whether a failed directory-watch registration at setup is fatal (config reload is startup-critical)
// or merely warned (cert/trust/revocation are best-effort hot-reload).
#[derive(Clone, Copy)]
pub enum WatchSetupFailure {
	Fatal,
	Warn,
}

// Debounced filesystem watcher for every hot-reload path (config, certs, trust, revocation).
// One worker thread per watcher merges a burst and calls `on_reload` once after `debounce` of quiet.
// It watches the PARENT directory of each trigger, because a rename-replace fires no event on the file.
// `context` names the watcher in logs. The caller must keep the returned watcher alive.
pub fn spawn_trailing_edge_watcher<P, F>(
	trigger_paths: &[P],
	debounce: Duration,
	context: &'static str,
	on_setup_failure: WatchSetupFailure,
	on_reload: F,
) -> Result<RecommendedWatcher>
where
	P: AsRef<Path>,
	F: Fn(&Event) + Send + 'static,
{
	let trigger_set: Vec<PathBuf> = trigger_paths.iter().map(|path: &P| return path.as_ref().to_path_buf()).collect();
	let (event_tx, event_rx): (Sender<Event>, Receiver<Event>) = mpsc::channel();
	// The worker exits when the watcher (which owns `event_tx`) is dropped.
	thread::Builder::new()
		.name(format!("fs-watch-{context}"))
		.spawn(move || return run_debounce_worker(&event_rx, debounce, on_reload))
		.map_err(|e| ReductionError::Config(format!("{context} debounce worker spawn: {e}").into()))?;

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

			if event_tx.send(event).is_err() {
				error!(context, "fs watcher debounce worker is gone; reload dropped");
			}
		})
		.map_err(|e| ReductionError::Config(format!("{context} watcher init: {e}").into()))?;

	// Watch each distinct parent directory once; trigger files may share a directory.
	let mut watched_parents: Vec<PathBuf> = Vec::new();
	trigger_paths.iter().try_for_each(|path: &P| -> Result<()> {
		let path: &Path = path.as_ref();
		let parent: Option<&Path> = path.parent().filter(|p| !p.as_os_str().is_empty());
		let parent: PathBuf = match parent {
			Some(parent) => parent.to_path_buf(),
			None => match on_setup_failure {
				WatchSetupFailure::Fatal => {
					return Err(ReductionError::Config(format!(
						"{context}: cannot watch {} without a parent directory",
						path.display()
					).into()));
				}
				WatchSetupFailure::Warn => {
					warn!(path = %path.display(), context, "cannot watch file without parent directory");
					return Ok(());
				}
			},
		};
		if watched_parents.contains(&parent) {
			return Ok(());
		}
		if let Err(e) = watcher.watch(&parent, RecursiveMode::NonRecursive) {
			match on_setup_failure {
				WatchSetupFailure::Fatal => {
					return Err(ReductionError::Config(format!(
						"{context}: failed to watch {}: {e}",
						parent.display()
					).into()));
				}
				WatchSetupFailure::Warn => {
					warn!(path = %parent.display(), error = %e, context, "failed to watch directory");
				}
			}
		} else {
			watched_parents.push(parent);
		}
		return Ok(());
	})?;
	return Ok(watcher);
}

// Waits for a burst and restarts the quiet timer on each event. Calls `on_reload` once per burst.
// Returns the reload count when the channel closes. A burst cut short by the close is not reloaded.
fn run_debounce_worker<F: Fn(&Event)>(events: &Receiver<Event>, debounce: Duration, on_reload: F) -> u64 {
	let mut reloads: u64 = 0;
	while let Ok(first) = events.recv() {
		let mut pending: Event = first;
		loop {
			match events.recv_timeout(debounce) {
				Ok(next) => pending = merge_burst(pending, next),
				Err(RecvTimeoutError::Timeout) => break,
				Err(RecvTimeoutError::Disconnected) => return reloads,
			}
		}
		on_reload(&pending);
		reloads = reloads.saturating_add(1);
	}
	return reloads;
}

// The latest event wins, but keeps every path of the burst, so a reload sees each file that changed.
fn merge_burst(earlier: Event, mut latest: Event) -> Event {
	earlier.paths.into_iter().for_each(|path: PathBuf| {
		if !latest.paths.contains(&path) {
			latest.paths.push(path);
		}
	});
	return latest;
}

#[cfg(test)]
mod tests {
	use std::fs;
	use std::iter;
	use std::path::PathBuf;
	use std::slice;
	use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
	use std::thread::{self, JoinHandle};
	use std::time::Duration;

	use notify::event::{EventKind, ModifyKind};
	use notify::{Event, RecommendedWatcher};
	use tempfile::tempdir;

	use core_utils::ctx::Ctx;

	use super::{WatchSetupFailure, run_debounce_worker, spawn_trailing_edge_watcher};

	const TEST_DEBOUNCE: Duration = Duration::from_millis(10);
	// Far longer than TEST_DEBOUNCE, so a slow CI host still sees the reload.
	const REPORT_TIMEOUT: Duration = Duration::from_secs(5);
	// A storm of this size makes a thread per event easy to see.
	const STORM_EVENTS: u32 = 10_000;
	// A real directory is quiet once no event lands for this long.
	const QUIET: Duration = Duration::from_millis(300);

	fn noop_reload() -> impl Fn(&Event) + Send + 'static {
		return |_event: &Event| {};
	}

	fn modify_event(path: &str) -> Event {
		return Event::new(EventKind::Modify(ModifyKind::Any)).add_path(PathBuf::from(path));
	}

	// Runs the worker on its own thread and reports each reloaded event on the returned channel.
	fn start_worker(events: Receiver<Event>) -> (JoinHandle<u64>, Receiver<Event>) {
		let (report_tx, report_rx): (Sender<Event>, Receiver<Event>) = mpsc::channel();
		let worker: JoinHandle<u64> = thread::spawn(move || {
			return run_debounce_worker(&events, TEST_DEBOUNCE, move |event: &Event| {
				let _sent: Result<(), mpsc::SendError<Event>> = report_tx.send(event.clone());
			});
		});
		return (worker, report_rx);
	}

	fn join_worker(worker: JoinHandle<u64>) -> Result<u64, String> {
		return worker.join().map_err(|_panic| return "debounce worker panicked".to_owned());
	}

	#[test]
	fn a_storm_reloads_once_with_every_path_of_the_burst() -> Result<(), String> {
		let (tx, rx): (Sender<Event>, Receiver<Event>) = mpsc::channel();
		// Queue the whole storm before the worker starts, so it is one burst however slow the host is.
		(0..STORM_EVENTS).try_for_each(|i: u32| {
			let path: &str = if i.is_multiple_of(2) { "/w/cert.pem" } else { "/w/key.pem" };
			return tx.send(modify_event(path)).ctx("send");
		})?;
		let (worker, reports): (JoinHandle<u64>, Receiver<Event>) = start_worker(rx);

		let reloaded: Event = reports.recv_timeout(REPORT_TIMEOUT).ctx("no reload")?;
		assert_eq!(
			reloaded.paths,
			vec![PathBuf::from("/w/key.pem"), PathBuf::from("/w/cert.pem")],
			"the latest event leads, and the burst's other path is merged in once"
		);
		assert_eq!(
			reports.recv_timeout(TEST_DEBOUNCE * 5),
			Err(RecvTimeoutError::Timeout),
			"a single burst must reload once"
		);
		drop(tx);
		assert_eq!(join_worker(worker)?, 1, "the worker exits on close and counts one reload");
		return Ok(());
	}

	#[test]
	fn bursts_separated_by_quiet_reload_separately() -> Result<(), String> {
		let (tx, rx): (Sender<Event>, Receiver<Event>) = mpsc::channel();
		let (worker, reports): (JoinHandle<u64>, Receiver<Event>) = start_worker(rx);
		tx.send(modify_event("/w/a")).ctx("send")?;
		let first: Event = reports.recv_timeout(REPORT_TIMEOUT).ctx("first")?;
		tx.send(modify_event("/w/b")).ctx("send")?;
		let second: Event = reports.recv_timeout(REPORT_TIMEOUT).ctx("second")?;
		assert_eq!(first.paths, vec![PathBuf::from("/w/a")], "a reloaded burst does not leak into the next");
		assert_eq!(second.paths, vec![PathBuf::from("/w/b")], "a reloaded burst does not leak into the next");
		drop(tx);
		assert_eq!(join_worker(worker)?, 2, "two quiet-separated bursts are two reloads");
		return Ok(());
	}

	#[test]
	fn close_mid_burst_exits_without_reload() -> Result<(), String> {
		let (tx, rx): (Sender<Event>, Receiver<Event>) = mpsc::channel();
		tx.send(modify_event("/w/a")).ctx("send")?;
		drop(tx);
		let (worker, reports): (JoinHandle<u64>, Receiver<Event>) = start_worker(rx);
		assert_eq!(join_worker(worker)?, 0, "a dropped watcher must not reload");
		assert!(reports.try_recv().is_err(), "a dropped watcher must not reload");
		return Ok(());
	}

	// Only a create or modify of a trigger reloads. A bystander in the same directory and a trigger removal do not.
	#[test]
	fn a_real_write_to_a_trigger_reaches_on_reload() -> Result<(), String> {
		let dir = tempdir().ctx("tempdir()")?;
		let trigger: PathBuf = dir.path().join("watched.toml");
		let bystander: PathBuf = dir.path().join("bystander.toml");
		let (report_tx, report_rx): (Sender<Event>, Receiver<Event>) = mpsc::channel();
		let _watcher: RecommendedWatcher = spawn_trailing_edge_watcher(
			slice::from_ref(&trigger),
			TEST_DEBOUNCE,
			"test",
			WatchSetupFailure::Fatal,
			move |event: &Event| {
				let _sent: Result<(), mpsc::SendError<Event>> = report_tx.send(event.clone());
			},
		)
		.ctx("watcher")?;
		fs::write(&bystander, b"b = 1").ctx("write bystander")?;
		fs::write(&trigger, b"a = 1").ctx("write")?;
		let first: Event = report_rx.recv_timeout(REPORT_TIMEOUT).ctx("no reload")?;
		// The write can arrive as more than one burst: take every reload until the directory is quiet.
		let reloads: Vec<Event> = iter::once(first).chain(iter::from_fn(|| return report_rx.recv_timeout(QUIET).ok())).collect();
		assert!(
			reloads.iter().all(|event: &Event| {
				return matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) && event.paths == slice::from_ref(&trigger);
			}),
			"only the trigger's own modify/create events reach on_reload: {reloads:?}"
		);
		fs::remove_file(&trigger).ctx("remove")?;
		let after_remove: Result<Event, RecvTimeoutError> = report_rx.recv_timeout(QUIET);
		assert_eq!(after_remove.map(|event: Event| return event.kind), Err(RecvTimeoutError::Timeout), "a removal is not a reload");
		return Ok(());
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
	fn watches_existing_parent_directory() -> Result<(), String> {
		let dir = match tempdir() {
			Ok(value) => value,
			Err(err) => return Err(format!("tempdir(): {err:?}")),
		};
		let trigger: PathBuf = dir.path().join("config.toml");
		let result = spawn_trailing_edge_watcher(
			&[trigger],
			TEST_DEBOUNCE,
			"test",
			WatchSetupFailure::Fatal,
			noop_reload(),
		);
		assert!(result.is_ok(), "an existing parent directory registers successfully");
		return Ok(());
	}

	#[test]
	fn deduplicates_triggers_sharing_one_parent() -> Result<(), String> {
		// Two triggers in the same directory must register that parent once, not fail on the second.
		let dir = match tempdir() {
			Ok(value) => value,
			Err(err) => return Err(format!("tempdir(): {err:?}")),
		};
		let a: PathBuf = dir.path().join("cert.pem");
		let b: PathBuf = dir.path().join("key.pem");
		let result =
			spawn_trailing_edge_watcher(&[a, b], TEST_DEBOUNCE, "test", WatchSetupFailure::Fatal, noop_reload());
		assert!(result.is_ok(), "two files sharing a parent register that parent once");
		return Ok(());
	}
}
