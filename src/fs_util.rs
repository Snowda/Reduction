use std::fs;
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tempfile::NamedTempFile;
use tracing::{error, warn};

use crate::error::{ReductionError, Result};

pub fn atomic_write(dest: &Path, data: &[u8]) -> Result<()> {
    let parent = dest.parent()
        .ok_or_else(|| ReductionError::Config(
            format!("atomic_write: no parent directory for {}", dest.display()),
        ))?;

    let mut tmp = NamedTempFile::new_in(parent)?;
    tmp.write_all(data)?;
    tmp.flush()?;
    tmp.persist(dest).map_err(|e| e.error)?;

    return Ok(());
}

pub fn load_or_recover<T, F>(
    path: &Path,
    parse_fn: F,
) -> Result<T>
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

    match parse_fn(&contents) {
        Ok(value) => return Ok(value),
        Err(parse_err) => {
            let timestamp: u64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let mut corrupt_path = path.as_os_str().to_owned();
            corrupt_path.push(format!(".corrupt.{timestamp}"));

            if let Err(rename_err) = fs::rename(path, &corrupt_path) {
                error!(
                    path = %path.display(),
                    rename_error = %rename_err,
                    "failed to quarantine corrupt config file",
                );
            } else {
                warn!(
                    path = %path.display(),
                    quarantined = %Path::new(&corrupt_path).display(),
                    "quarantined corrupt config file",
                );
            }

            return Err(ReductionError::ConfigParse(parse_err));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use serde::Deserialize;

    use super::*;

    #[derive(Debug, PartialEq, Deserialize)]
    struct TestConfig {
        name: String,
        value: u32,
    }

    fn parse_test_config(s: &str) -> std::result::Result<TestConfig, toml::de::Error> {
        return toml::from_str(s);
    }

    #[test]
    fn test_atomic_write_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("output.toml");
        let data: &[u8] = b"name = \"test\"\nvalue = 42\n";

        atomic_write(&dest, data).unwrap();

        let read_back: String = fs::read_to_string(&dest).unwrap();
        assert_eq!(read_back.as_bytes(), data);
    }

    #[test]
    fn test_atomic_write_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("output.toml");

        fs::write(&dest, b"old content").unwrap();
        atomic_write(&dest, b"new content").unwrap();

        let read_back: String = fs::read_to_string(&dest).unwrap();
        assert_eq!(read_back, "new content");
    }

    #[test]
    fn test_atomic_write_nonexistent_parent_fails() {
        let dest = Path::new("/nonexistent/dir/file.toml");
        let result = atomic_write(dest, b"data");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_or_recover_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "name = \"hello\"\nvalue = 99\n").unwrap();

        let config: TestConfig = load_or_recover(&path, parse_test_config).unwrap();
        assert_eq!(config.name, "hello");
        assert_eq!(config.value, 99);
    }

    #[test]
    fn test_load_or_recover_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.toml");

        let result = load_or_recover::<TestConfig, _>(&path, parse_test_config);
        assert!(result.is_err());
        match result.unwrap_err() {
            ReductionError::Io(e) => assert_eq!(e.kind(), ErrorKind::NotFound),
            other => panic!("expected Io(NotFound), got: {other}"),
        }
    }

    #[test]
    fn test_load_or_recover_corrupt_file_quarantines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        fs::write(&path, "this is not valid toml {{{").unwrap();

        let result = load_or_recover::<TestConfig, _>(&path, parse_test_config);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ReductionError::ConfigParse(_)));

        assert!(!path.exists(), "original file should have been renamed");

        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1);

        let quarantined_name: String = entries[0].file_name().to_string_lossy().to_string();
        assert!(
            quarantined_name.starts_with("bad.toml.corrupt."),
            "quarantined file should match pattern, got: {quarantined_name}",
        );

        let quarantined_content: String = fs::read_to_string(entries[0].path()).unwrap();
        assert_eq!(quarantined_content, "this is not valid toml {{{");
    }
}
