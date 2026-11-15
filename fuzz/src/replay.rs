//! Stable replay: every seed and regression input runs through its harness on each plain test run. A unit-test
//! module, not tests/, so `--lib` coverage runs it and cargo never builds the fuzz_targets bins for it.

use std::fs::{self, DirEntry};
use std::path::{Path, PathBuf};

use super::{
	egress_connect, envelope_decode, fastlane_chunked, fastlane_classify, fastlane_response, health_route, proxy_request,
	redirect, upstream_send,
};

// A replayable input: a regular, non-hidden file.
fn is_input(entry: &DirEntry) -> bool {
	let is_hidden: bool = entry.file_name().to_string_lossy().starts_with('.');
	return !is_hidden && entry.path().is_file();
}

// Run `harness` over every non-hidden file in seeds/<target>/ and regressions/<target>/; returns how many ran.
fn replay(target: &str, harness: fn(&[u8])) -> Result<usize, String> {
	let root: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
	let mut ran: usize = 0;
	for dir in ["seeds", "regressions"] {
		let Ok(entries) = fs::read_dir(root.join(dir).join(target)) else {
			continue;
		};
		for entry in entries.flatten().filter(is_input) {
			let bytes: Vec<u8> = fs::read(entry.path()).map_err(|e| format!("read {}: {e}", entry.path().display()))?;
			harness(&bytes);
			ran += 1;
		}
	}
	return Ok(ran);
}

// Replay one target and fail if its seed directory held nothing to run.
fn replay_nonempty(target: &str, harness: fn(&[u8])) -> Result<(), String> {
	let ran: usize = replay(target, harness)?;
	if ran == 0 {
		return Err(format!("fuzz/seeds/{target}/ holds no seed inputs"));
	}
	return Ok(());
}

#[test]
fn fuzz_replay_envelope_decode() -> Result<(), String> {
	return replay_nonempty("envelope_decode", envelope_decode);
}

#[test]
fn fuzz_replay_proxy_request() -> Result<(), String> {
	return replay_nonempty("proxy_request", proxy_request);
}

#[test]
fn fuzz_replay_upstream_send() -> Result<(), String> {
	return replay_nonempty("upstream_send", upstream_send);
}

#[test]
fn fuzz_replay_redirect() -> Result<(), String> {
	return replay_nonempty("redirect", redirect);
}

#[test]
fn fuzz_replay_health_route() -> Result<(), String> {
	return replay_nonempty("health_route", health_route);
}

#[test]
fn fuzz_replay_egress_connect() -> Result<(), String> {
	return replay_nonempty("egress_connect", egress_connect);
}

#[test]
fn fuzz_replay_fastlane_chunked()-> Result<(), String> {
	return replay_nonempty("fastlane_chunked", fastlane_chunked);
}

#[test]
fn fuzz_replay_fastlane_response() -> Result<(), String> {
	return replay_nonempty("fastlane_response", fastlane_response);
}

#[test]
fn fuzz_replay_fastlane_classify() -> Result<(), String> {
	return replay_nonempty("fastlane_classify", fastlane_classify);
}
