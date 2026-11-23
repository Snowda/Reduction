use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use tracing::warn;

use crate::error::{ReductionError, Result};

// Random temp names make a clash unlikely. These retries cover the rare clash.
const TEMP_ATTEMPTS: usize = 4;

// Writes the data to a new file in the same directory, then renames it onto `dest`. A reader sees all old or all new bytes.
pub fn atomic_write(dest: &Path, data: &[u8]) -> Result<()> {
	let parent: &Path = dest
		.parent()
		.ok_or_else(|| ReductionError::Config(format!("atomic_write: no parent directory for {}", dest.display()).into()))?;

	let (tmp_path, file): (PathBuf, File) = create_temp_in(parent)?;
	if let Err(err) = write_then_rename(file, data, &tmp_path, dest) {
		remove_leftover(&tmp_path);
		return Err(ReductionError::Io(err));
	}
	return Ok(());
}

fn write_then_rename(mut file: File, data: &[u8], tmp_path: &Path, dest: &Path) -> io::Result<()> {
	file.write_all(data)?;
	// Close the file before the rename. Windows cannot rename a file while this handle holds it open.
	drop(file);
	return fs::rename(tmp_path, dest);
}

fn remove_leftover(tmp_path: &Path) {
	if let Err(err) = fs::remove_file(tmp_path) {
		warn!(path = %tmp_path.display(), error = %err, "atomic_write: could not remove the temp file");
	}
}

// A new file in `dir` that no other writer holds. A name clash makes a new name and tries again.
fn create_temp_in(dir: &Path) -> io::Result<(PathBuf, File)> {
	let rng: SystemRandom = SystemRandom::new();
	return (0..TEMP_ATTEMPTS)
		.map(|_| try_create_temp(dir, &rng))
		.find(|attempt| !matches!(attempt, Err(err) if err.kind() == ErrorKind::AlreadyExists))
		.unwrap_or_else(|| Err(io::Error::from(ErrorKind::AlreadyExists)));
}

fn try_create_temp(dir: &Path, rng: &SystemRandom) -> io::Result<(PathBuf, File)> {
	let mut nonce: [u8; 8] = [0; 8];
	rng.fill(&mut nonce).map_err(|_| io::Error::other("system random source failed"))?;
	let path: PathBuf = dir.join(format!(".tmp{:016x}", u64::from_le_bytes(nonce)));
	let file: File = private_new_file().open(&path)?;
	return Ok((path, file));
}

// Exclusive create. On Unix the mode is 0600, because the file can hold a private key.
fn private_new_file() -> OpenOptions {
	let mut options: OpenOptions = OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
	return options;
}

// Read and parse an operator-owned file. Never mutate it: a bad edit stays on disk for the operator to fix.
pub fn load_toml<T, F>(path: &Path, parse_fn: F) -> Result<T>
where
	F: FnOnce(&str) -> std::result::Result<T, toml::de::Error>,
{
	let contents: String = match fs::read_to_string(path) {
		Ok(c) => c,
		Err(e) if e.kind() == ErrorKind::NotFound => {
			return Err(ReductionError::Io(e));
		}
		Err(e) => {
			warn!(path = %path.display(), error = %e, "failed to read file");
			return Err(ReductionError::Io(e));
		}
	};

	return parse_fn(&contents).map_err(|parse_err: toml::de::Error| {
		warn!(path = %path.display(), error = %parse_err, "failed to parse file; left in place");
		return ReductionError::ConfigParse(parse_err);
	});
}

#[cfg(test)]
mod tests {
	use std::ffi::OsString;
	use std::path::PathBuf;
	use std::result::Result;

	use serde::Deserialize;
	use tempfile::TempDir;

	use super::*;

	const VALID: &str = "name = \"hello\"\nvalue = 99\n";
	const CORRUPT: &str = "this is not valid toml {{{";

	#[derive(Debug, PartialEq, Deserialize)]
	struct TestConfig {
		name: String,
		value: u32,
	}

	fn parse_test_config(s: &str) -> Result<TestConfig, toml::de::Error> {
		return toml::from_str(s);
	}

	fn temp_dir() -> Result<TempDir, String> {
		return tempfile::tempdir().map_err(|err| format!("tempfile::tempdir(): {err:?}"));
	}

	// A fresh dir holding `name` with `contents`; returns the dir (keep it alive) and the file path.
	fn dir_with(name: &str, contents: &str) -> Result<(TempDir, PathBuf), String> {
		let dir: TempDir = temp_dir()?;
		let path: PathBuf = dir.path().join(name);
		fs::write(&path, contents).map_err(|err| format!("fs::write({name}): {err:?}"))?;
		return Ok((dir, path));
	}

	fn entry_names(dir: &Path) -> Result<Vec<OsString>, String> {
		let mut names: Vec<OsString> = fs::read_dir(dir)
			.map_err(|err| format!("fs::read_dir: {err:?}"))?
			.filter_map(|entry| entry.ok().map(|e| e.file_name()))
			.collect();
		names.sort();
		return Ok(names);
	}

	fn read(path: &Path) -> Result<String, String> {
		return fs::read_to_string(path).map_err(|err| format!("fs::read_to_string({}): {err:?}", path.display()));
	}

	#[test]
	fn test_atomic_write_round_trip() -> Result<(), String> {
		let dir: TempDir = temp_dir()?;
		let dest: PathBuf = dir.path().join("output.toml");
		let data: &[u8] = b"name = \"test\"\nvalue = 42\n";

		atomic_write(&dest, data).map_err(|err| format!("atomic_write: {err:?}"))?;

		assert_eq!(read(&dest)?.as_bytes(), data);
		assert_eq!(
			entry_names(dir.path())?,
			[OsString::from("output.toml")],
			"the temp file is renamed into place, never left beside it"
		);
		return Ok(());
	}

	#[test]
	fn test_atomic_write_overwrites_existing() -> Result<(), String> {
		let (_dir, dest) = dir_with("output.toml", "old content")?;
		atomic_write(&dest, b"new content").map_err(|err| format!("atomic_write: {err:?}"))?;
		assert_eq!(read(&dest)?, "new content");
		return Ok(());
	}

	// The rename fails when a directory holds the target name. The temp file must not stay behind.
	#[test]
	fn test_atomic_write_failed_rename_leaves_no_temp_file() -> Result<(), String> {
		let dir: TempDir = temp_dir()?;
		fs::create_dir(dir.path().join("output.toml")).map_err(|err| format!("fs::create_dir: {err:?}"))?;
		let result = atomic_write(&dir.path().join("output.toml"), b"data");
		assert!(matches!(&result, Err(ReductionError::Io(_))), "a rename over a directory fails, got {result:?}");
		assert_eq!(entry_names(dir.path())?, [OsString::from("output.toml")], "only the directory is left");
		return Ok(());
	}

	// The file can hold an ACME private key, so only the owner can read it.
	#[cfg(unix)]
	#[test]
	fn test_atomic_write_file_is_owner_only() -> Result<(), String> {
		use std::os::unix::fs::PermissionsExt;
		let dir: TempDir = temp_dir()?;
		let dest: PathBuf = dir.path().join("acme_state.json");
		atomic_write(&dest, b"secret").map_err(|err| format!("atomic_write: {err:?}"))?;
		let mode: u32 = fs::metadata(&dest).map_err(|err| format!("fs::metadata: {err:?}"))?.permissions().mode();
		assert_eq!(mode & 0o777, 0o600, "got {mode:o}");
		return Ok(());
	}

	#[test]
	fn test_atomic_write_nonexistent_parent_fails() {
		let dest = Path::new("/nonexistent/dir/file.toml");
		let result = atomic_write(dest, b"data");
		assert!(result.is_err(), "a missing parent directory cannot hold the temp file");
	}

	#[test]
	fn test_atomic_write_path_without_parent_is_a_config_error() {
		let result = atomic_write(Path::new(""), b"data");
		assert!(
			matches!(&result, Err(ReductionError::Config(msg)) if msg.contains("no parent directory")),
			"a parentless path must be refused before any temp file is made, got {result:?}"
		);
	}

	#[test]
	fn test_load_toml_valid_file() -> Result<(), String> {
		let (_dir, path) = dir_with("config.toml", VALID)?;

		let config: TestConfig =
			load_toml(&path, parse_test_config).map_err(|err| format!("load_toml: {err:?}"))?;
		assert_eq!(
			config,
			TestConfig {
				name: String::from("hello"),
				value: 99
			}
		);
		assert_eq!(read(&path)?, VALID, "a file that parses is left in place");
		return Ok(());
	}

	#[test]
	fn test_load_toml_missing_file() -> Result<(), String> {
		let dir: TempDir = temp_dir()?;
		let path: PathBuf = dir.path().join("missing.toml");

		let result = load_toml::<TestConfig, _>(&path, parse_test_config);
		assert!(
			matches!(&result, Err(ReductionError::Io(e)) if e.kind() == ErrorKind::NotFound),
			"expected Io(NotFound), got {result:?}"
		);
		return Ok(());
	}

	// A path that exists but cannot be read as a file surfaces the I/O error and changes nothing.
	#[test]
	fn test_load_toml_unreadable_path_is_io_error() -> Result<(), String> {
		let dir: TempDir = temp_dir()?;
		let subdir: PathBuf = dir.path().join("config.toml");
		fs::create_dir(&subdir).map_err(|err| format!("fs::create_dir: {err:?}"))?;

		let result = load_toml::<TestConfig, _>(&subdir, parse_test_config);
		assert!(
			matches!(&result, Err(ReductionError::Io(e)) if e.kind() != ErrorKind::NotFound),
			"reading a directory is an I/O error other than NotFound, got {result:?}"
		);
		assert!(subdir.is_dir(), "an unreadable path is never renamed");
		assert_eq!(entry_names(dir.path())?, [OsString::from("config.toml")]);
		return Ok(());
	}

	// The operator owns the file: a bad edit stays where they made it, byte for byte, with nothing beside it.
	#[test]
	fn test_load_toml_corrupt_file_is_left_in_place() -> Result<(), String> {
		let (dir, path) = dir_with("bad.toml", CORRUPT)?;

		let result = load_toml::<TestConfig, _>(&path, parse_test_config);
		assert!(
			matches!(result, Err(ReductionError::ConfigParse(_))),
			"a parse failure is a ConfigParse error, got {result:?}"
		);
		assert_eq!(read(&path)?, CORRUPT, "the bad edit is kept at its own path");
		assert_eq!(
			entry_names(dir.path())?,
			[OsString::from("bad.toml")],
			"a parse failure creates and renames nothing"
		);
		return Ok(());
	}

	// Repeated failures in one second must not collide or pile up: each one leaves the directory unchanged.
	#[test]
	fn test_load_toml_repeated_parse_failures_keep_the_file() -> Result<(), String> {
		let (dir, path) = dir_with("bad.toml", CORRUPT)?;
		let failures: usize = (0..3)
			.filter(|_| load_toml::<TestConfig, _>(&path, parse_test_config).is_err())
			.count();
		assert_eq!(failures, 3, "the same bad bytes fail to parse every time");
		assert_eq!(read(&path)?, CORRUPT);
		assert_eq!(entry_names(dir.path())?, [OsString::from("bad.toml")]);
		return Ok(());
	}
}
