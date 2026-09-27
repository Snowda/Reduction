use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{info, warn};

use crate::error::{ReductionError, Result};
use crate::fs_util::atomic_write;

// Filename for the File store's single opaque blob (one atomically-written unit).
const ACME_STATE_FILENAME: &str = "acme_state.json";
// Default env var the Barrel agent injects the opaque ACME state into at launch.
pub const DEFAULT_ACME_STATE_ENV: &str = "REDUCTION_ACME_STATE";

// The opaque ACME secret state — account credentials, cert chain, and private key — loaded and persisted
// as one atomic unit so no torn combination is ever observed. Single-line JSON, safe for one env var.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeSecretState {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub account_credentials: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cert_chain_pem: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub key_pem: Option<String>,
}

impl AcmeSecretState {
	pub fn to_json(&self) -> Result<Vec<u8>> {
		return serde_json::to_vec(self).map_err(|e| ReductionError::Acme(format!("serialize acme state: {e}")));
	}

	fn from_json(bytes: &[u8]) -> Result<Self> {
		return serde_json::from_slice(bytes).map_err(|e| ReductionError::Acme(format!("parse acme state: {e}")));
	}

	// True when no field is set — the first-run state, before an account or cert exists.
	#[must_use]
	pub const fn is_empty(&self) -> bool {
		return self.account_credentials.is_none() && self.cert_chain_pem.is_none() && self.key_pem.is_none();
	}
}

// Where the opaque ACME secret state lives and how it is loaded and atomically persisted. `File` keeps it
// in a cache directory. `Barrel` custody reads the blob from an injected env var and persists renewed state
// via a hash-pinned command on stdin — no plaintext on a persistent filesystem, and no file fallback (a
// failed store command fails closed, leaving Barrel's last-known-good untouched).
pub enum SecretStore {
	File { cache_dir: PathBuf },
	Barrel { env_var: String, persist_command: Vec<String> },
}

impl SecretStore {
	// Barrel custody when `[tls.server.acme.barrel_state]` is set, otherwise the `cache_dir` file store.
	#[must_use]
	pub fn from_acme_config(config: &crate::config::AcmeTlsConfig) -> Self {
		return match &config.barrel_state {
			Some(barrel) => Self::Barrel {
				env_var: barrel.env_var.clone(),
				persist_command: barrel.persist_command.clone(),
			},
			None => Self::File {
				cache_dir: config.cache_dir.clone(),
			},
		};
	}

	// Load the current state, or None on first run. A corrupt source errors (never silently discarded).
	pub fn load(&self) -> Result<Option<AcmeSecretState>> {
		return match self {
			Self::File { cache_dir } => load_from_file(cache_dir),
			Self::Barrel { env_var, .. } => load_from_env(env_var),
		};
	}

	// Persist the whole state atomically. On the Barrel path a non-zero store command fails closed.
	pub async fn persist(&self, state: &AcmeSecretState) -> Result<()> {
		return match self {
			Self::File { cache_dir } => persist_to_file(cache_dir, state),
			Self::Barrel { persist_command, .. } => persist_via_command(persist_command, state).await,
		};
	}
}

fn load_from_file(cache_dir: &Path) -> Result<Option<AcmeSecretState>> {
	let path: PathBuf = cache_dir.join(ACME_STATE_FILENAME);
	if !path.exists() {
		return Ok(None);
	}
	let bytes: Vec<u8> =
		std::fs::read(&path).map_err(|e| ReductionError::Acme(format!("read acme state {}: {e}", path.display())))?;
	return AcmeSecretState::from_json(&bytes).map(Some);
}

fn persist_to_file(cache_dir: &Path, state: &AcmeSecretState) -> Result<()> {
	std::fs::create_dir_all(cache_dir)
		.map_err(|e| ReductionError::Acme(format!("create cache dir {}: {e}", cache_dir.display())))?;
	let path: PathBuf = cache_dir.join(ACME_STATE_FILENAME);
	atomic_write(&path, &state.to_json()?).map_err(|e| ReductionError::Acme(format!("write acme state: {e}")))?;
	info!(path = %path.display(), "ACME secret state persisted to file store");
	return Ok(());
}

fn load_from_env(env_var: &str) -> Result<Option<AcmeSecretState>> {
	let raw: String = match std::env::var(env_var) {
		Ok(value) if !value.is_empty() => value,
		// Unset or empty: first run under Barrel custody (nothing stored yet).
		_ => return Ok(None),
	};
	return parse_env_blob(&raw);
}

// Parse a non-empty injected blob into state; split from the env read so it is testable without env mutation.
fn parse_env_blob(raw: &str) -> Result<Option<AcmeSecretState>> {
	return AcmeSecretState::from_json(raw.as_bytes()).map(Some);
}

// Run the hash-pinned Barrel store command, writing the JSON blob to its stdin. Any failure errors so the
// renewal loop keeps the in-memory cert and Barrel's last-known-good is never overwritten with garbage.
async fn persist_via_command(command: &[String], state: &AcmeSecretState) -> Result<()> {
	let (program, args): (&String, &[String]) = command
		.split_first()
		.ok_or_else(|| ReductionError::Acme("barrel persist_command is empty".to_owned()))?;

	let blob: Vec<u8> = state.to_json()?;

	let mut child = Command::new(program)
		.args(args)
		.stdin(Stdio::piped())
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.spawn()
		.map_err(|e| ReductionError::Acme(format!("spawn barrel store command '{program}': {e}")))?;

	// Take stdin, write the blob, then drop it so the child sees EOF before we await its exit.
	{
		let mut stdin = child
			.stdin
			.take()
			.ok_or_else(|| ReductionError::Acme("barrel store command has no stdin".to_owned()))?;
		stdin
			.write_all(&blob)
			.await
			.map_err(|e| ReductionError::Acme(format!("write acme state to barrel store command: {e}")))?;
		stdin
			.shutdown()
			.await
			.map_err(|e| ReductionError::Acme(format!("close barrel store command stdin: {e}")))?;
	}

	let status = child
		.wait()
		.await
		.map_err(|e| ReductionError::Acme(format!("await barrel store command: {e}")))?;
	if !status.success() {
		warn!(program = %program, ?status, "barrel store command failed; keeping last-known-good state");
		return Err(ReductionError::Acme(format!(
			"barrel store command '{program}' exited unsuccessfully: {status}"
		)));
	}
	info!(program = %program, "ACME secret state persisted via barrel store command");
	return Ok(());
}

#[cfg(test)]
mod tests {
	use tempfile::TempDir;

	use super::*;

	fn sample_state() -> AcmeSecretState {
		return AcmeSecretState {
			account_credentials: Some("{\"acct\":\"abc\"}".to_owned()),
			cert_chain_pem: Some("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_owned()),
			key_pem: Some("-----BEGIN PRIVATE KEY-----\nMIGH\n-----END PRIVATE KEY-----\n".to_owned()),
		};
	}

	#[test]
	fn json_round_trips_including_pem_newlines() {
		let state = sample_state();
		let bytes = state.to_json().unwrap();
		// Single-line JSON: safe to carry in one env var (PEM newlines are escaped, not literal).
		assert!(!bytes.contains(&b'\n'), "the blob must be single-line for env transport");
		let restored = AcmeSecretState::from_json(&bytes).unwrap();
		assert_eq!(restored, state);
	}

	#[test]
	fn empty_state_predicate() {
		assert!(AcmeSecretState::default().is_empty());
		assert!(!sample_state().is_empty());
	}

	#[test]
	fn file_store_load_missing_is_none() {
		let dir = TempDir::new().unwrap();
		let store = SecretStore::File { cache_dir: dir.path().to_path_buf() };
		assert!(store.load().unwrap().is_none(), "an empty cache dir yields no state");
	}

	#[tokio::test]
	async fn file_store_persist_then_load_round_trips() {
		let dir = TempDir::new().unwrap();
		let store = SecretStore::File { cache_dir: dir.path().join("nested") };
		let state = sample_state();
		store.persist(&state).await.unwrap();
		let loaded = store.load().unwrap().expect("state must load after persist");
		assert_eq!(loaded, state);
	}

	#[test]
	fn env_store_load_unset_is_none() {
		let store = SecretStore::Barrel {
			env_var: "REDUCTION_ACME_STATE_TEST_UNSET".to_owned(),
			persist_command: vec!["true".to_owned()],
		};
		// The var is not set in this process, so the first-run None branch is taken.
		assert!(store.load().unwrap().is_none());
	}

	#[test]
	fn env_blob_parses_to_state() {
		// Parse the injected blob directly (no env mutation) to prove it round-trips to state.
		let state = sample_state();
		let blob = String::from_utf8(state.to_json().unwrap()).unwrap();
		let loaded = parse_env_blob(&blob).unwrap().expect("injected blob must parse to state");
		assert_eq!(loaded, state);
	}

	// Exact-bytes capture: a store command copying stdin to a file proves the precise blob is delivered.
	// Unix-only (portable shell redirect); the cross-platform success path is the next test.
	#[cfg(unix)]
	#[tokio::test]
	async fn barrel_persist_feeds_exact_blob_to_command_stdin() {
		let dir = TempDir::new().unwrap();
		let out = dir.path().join("captured.json");
		let state = sample_state();
		let store = SecretStore::Barrel {
			env_var: DEFAULT_ACME_STATE_ENV.to_owned(),
			persist_command: vec!["sh".to_owned(), "-c".to_owned(), format!("cat > {}", out.display())],
		};
		store.persist(&state).await.expect("persist via command must succeed");

		let captured = std::fs::read(&out).expect("store command must have written the blob");
		let restored = AcmeSecretState::from_json(&captured).expect("captured blob must parse");
		assert_eq!(restored, state, "the command must receive the exact state blob on stdin");
	}

	// Portable success path: a command that consumes all of stdin and exits 0 (Unix `cat`, Windows
	// `sort`) — persist must drive it to a successful completion.
	#[tokio::test]
	async fn barrel_persist_succeeds_when_command_consumes_stdin() {
		#[cfg(unix)]
		let command = vec!["cat".to_owned()];
		#[cfg(windows)]
		let command = vec!["cmd".to_owned(), "/C".to_owned(), "sort".to_owned()];

		let store = SecretStore::Barrel {
			env_var: DEFAULT_ACME_STATE_ENV.to_owned(),
			persist_command: command,
		};
		store.persist(&sample_state()).await.expect("a stdin-consuming command must persist successfully");
	}

	#[tokio::test]
	async fn barrel_persist_fails_closed_on_nonzero_exit() {
		let state = sample_state();
		#[cfg(unix)]
		let command = vec!["sh".to_owned(), "-c".to_owned(), "exit 3".to_owned()];
		#[cfg(windows)]
		let command = vec!["cmd".to_owned(), "/C".to_owned(), "exit 3".to_owned()];

		let store = SecretStore::Barrel {
			env_var: DEFAULT_ACME_STATE_ENV.to_owned(),
			persist_command: command,
		};
		let result = store.persist(&state).await;
		assert!(result.is_err(), "a non-zero store command must fail closed, not silently succeed");
	}

	#[tokio::test]
	async fn barrel_persist_empty_command_errors() {
		let store = SecretStore::Barrel {
			env_var: DEFAULT_ACME_STATE_ENV.to_owned(),
			persist_command: vec![],
		};
		assert!(store.persist(&sample_state()).await.is_err(), "an empty persist_command must error");
	}
}
