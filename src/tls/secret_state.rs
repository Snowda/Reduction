use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStdin, Command};
use tracing::{info, warn};

use crate::error::{ReductionError, Result};
use crate::fs_util::atomic_write;

// Filename for the File store's single opaque blob (one atomically-written unit).
const ACME_STATE_FILENAME: &str = "acme_state.json";

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
pub enum SecretStore<'a> {
	File {
		cache_dir: &'a Path,
	},
	Barrel {
		env_var: &'a str,
		persist_command: &'a [String],
	},
}

impl<'a> SecretStore<'a> {
	// Barrel custody when `[tls.server.acme.barrel_state]` is set, otherwise the `cache_dir` file store.
	#[must_use]
	pub fn from_acme_config(config: &'a crate::config::AcmeTlsConfig) -> Self {
		return match &config.barrel_state {
			Some(barrel) => Self::Barrel {
				env_var: &barrel.env_var,
				persist_command: &barrel.persist_command,
			},
			None => Self::File {
				cache_dir: &config.cache_dir,
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

	let mut child: Child = Command::new(program)
		.args(args)
		.stdin(Stdio::piped())
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.spawn()
		.map_err(|e| ReductionError::Acme(format!("spawn barrel store command '{program}': {e}")))?;

	// Take stdin, write the blob, then drop it so the child sees EOF before we await its exit.
	{
		let mut stdin: ChildStdin = child
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

	let status: ExitStatus = child
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
	use std::result::Result;

	use tempfile::TempDir;

	use super::*;
	use crate::config::DEFAULT_ACME_STATE_ENV;

	fn sample_state() -> AcmeSecretState {
		return AcmeSecretState {
			account_credentials: Some("{\"acct\":\"abc\"}".to_owned()),
			cert_chain_pem: Some("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_owned()),
			key_pem: Some("-----BEGIN PRIVATE KEY-----\nMIGH\n-----END PRIVATE KEY-----\n".to_owned()),
		};
	}

	#[test]
	fn json_round_trips_including_pem_newlines() -> Result<(), String> {
		let state: AcmeSecretState = sample_state();
		let bytes: Vec<u8> = match state.to_json() {
			Ok(value) => value,
			Err(err) => return Err(format!("state.to_json(): {err:?}")),
		};
		// Single-line JSON: safe to carry in one env var (PEM newlines are escaped, not literal).
		assert!(
			!bytes.contains(&b'\n'),
			"the blob must be single-line for env transport"
		);
		let restored: AcmeSecretState = match AcmeSecretState::from_json(&bytes) {
			Ok(value) => value,
			Err(err) => return Err(format!("AcmeSecretState::from_json(&bytes): {err:?}")),
		};
		assert_eq!(restored, state);
		return Ok(());
	}

	#[test]
	fn empty_state_predicate() {
		assert!(AcmeSecretState::default().is_empty());
		assert!(!sample_state().is_empty());
	}

	#[test]
	fn file_store_load_missing_is_none() -> Result<(), String> {
		let dir: TempDir = match TempDir::new() {
			Ok(value) => value,
			Err(err) => return Err(format!("TempDir::new(): {err:?}")),
		};
		let store: SecretStore = SecretStore::File {
			cache_dir: dir.path(),
		};
		assert!(
			(match store.load() {
				Ok(value) => value,
				Err(err) => return Err(format!("store.load(): {err:?}")),
			})
			.is_none(),
			"an empty cache dir yields no state"
		);
		return Ok(());
	}

	#[tokio::test]
	async fn file_store_persist_then_load_round_trips() -> Result<(), String> {
		let dir: TempDir = match TempDir::new() {
			Ok(value) => value,
			Err(err) => return Err(format!("TempDir::new(): {err:?}")),
		};
		let nested: PathBuf = dir.path().join("nested");
		let store: SecretStore = SecretStore::File {
			cache_dir: &nested,
		};
		let state: AcmeSecretState = sample_state();
		match store.persist(&state).await {
			Ok(value) => value,
			Err(err) => return Err(format!("store.persist(&state).await: {err:?}")),
		};
		let loaded: AcmeSecretState = match store.load() {
			Ok(Some(value)) => value,
			Ok(None) => return Err(String::from("state must load after persist")),
			Err(err) => return Err(format!("store.load(): {err:?}")),
		};
		assert_eq!(loaded, state);
		return Ok(());
	}

	#[test]
	fn env_store_load_unset_is_none() -> Result<(), String> {
		let store: SecretStore = SecretStore::Barrel {
			env_var: "REDUCTION_ACME_STATE_TEST_UNSET",
			persist_command: &["true".to_owned()],
		};
		// The var is not set in this process, so the first-run None branch is taken.
		assert!(
			(match store.load() {
				Ok(value) => value,
				Err(err) => return Err(format!("store.load(): {err:?}")),
			})
			.is_none()
		);
		return Ok(());
	}

	#[test]
	fn env_blob_parses_to_state() -> Result<(), String> {
		// Parse the injected blob directly (no env mutation) to prove it round-trips to state.
		let state: AcmeSecretState = sample_state();
		let blob: String = match String::from_utf8(match state.to_json() {
			Ok(value) => value,
			Err(err) => return Err(format!("state.to_json(): {err:?}")),
		}) {
			Ok(value) => value,
			Err(err) => return Err(format!("String::from_utf8(state.to_json()): {err:?}")),
		};
		let loaded: AcmeSecretState = match parse_env_blob(&blob) {
			Ok(Some(value)) => value,
			Ok(None) => return Err(String::from("injected blob must parse to state")),
			Err(err) => return Err(format!("parse_env_blob(&blob): {err:?}")),
		};
		assert_eq!(loaded, state);
		return Ok(());
	}

	// Exact-bytes capture: a store command copying stdin to a file proves the precise blob is delivered.
	// Unix-only (portable shell redirect); the cross-platform success path is the next test.
	#[cfg(unix)]
	#[tokio::test]
	async fn barrel_persist_feeds_exact_blob_to_command_stdin() -> Result<(), String> {
		let dir: TempDir = match TempDir::new() {
			Ok(value) => value,
			Err(err) => return Err(format!("TempDir::new(): {err:?}")),
		};
		let out: PathBuf = dir.path().join("captured.json");
		let state: AcmeSecretState = sample_state();
		let store: SecretStore = SecretStore::Barrel {
			env_var: DEFAULT_ACME_STATE_ENV,
			persist_command: &["sh".to_owned(), "-c".to_owned(), format!("cat > {}", out.display())],
		};
		match store.persist(&state).await {
			Ok(value) => value,
			Err(err) => return Err(format!("persist via command must succeed: {err:?}")),
		};

		let captured: Vec<u8> = match std::fs::read(&out) {
			Ok(value) => value,
			Err(err) => return Err(format!("store command must have written the blob: {err:?}")),
		};
		let restored: AcmeSecretState = match AcmeSecretState::from_json(&captured) {
			Ok(value) => value,
			Err(err) => return Err(format!("captured blob must parse: {err:?}")),
		};
		assert_eq!(
			restored, state,
			"the command must receive the exact state blob on stdin"
		);
		return Ok(());
	}

	// Portable success path: a command that consumes all of stdin and exits 0 (Unix `cat`, Windows
	// `sort`) — persist must drive it to a successful completion.
	#[tokio::test]
	async fn barrel_persist_succeeds_when_command_consumes_stdin() -> Result<(), String> {
		#[cfg(unix)]
		let command: Vec<String> = vec!["cat".to_owned()];
		#[cfg(windows)]
		let command: Vec<String> = vec!["cmd".to_owned(), "/C".to_owned(), "sort".to_owned()];

		let store: SecretStore = SecretStore::Barrel {
			env_var: DEFAULT_ACME_STATE_ENV,
			persist_command: &command,
		};
		match store.persist(&sample_state()).await {
			Ok(value) => value,
			Err(err) => return Err(format!("a stdin-consuming command must persist successfully: {err:?}")),
		};
		return Ok(());
	}

	#[tokio::test]
	async fn barrel_persist_fails_closed_on_nonzero_exit() {
		let state: AcmeSecretState = sample_state();
		#[cfg(unix)]
		let command: Vec<String> = vec!["sh".to_owned(), "-c".to_owned(), "exit 3".to_owned()];
		#[cfg(windows)]
		let command: Vec<String> = vec!["cmd".to_owned(), "/C".to_owned(), "exit 3".to_owned()];

		let store: SecretStore = SecretStore::Barrel {
			env_var: DEFAULT_ACME_STATE_ENV,
			persist_command: &command,
		};
		let result: Result<(), ReductionError> = store.persist(&state).await;
		assert!(
			result.is_err(),
			"a non-zero store command must fail closed, not silently succeed"
		);
	}

	#[tokio::test]
	async fn barrel_persist_empty_command_errors() {
		let store: SecretStore = SecretStore::Barrel {
			env_var: DEFAULT_ACME_STATE_ENV,
			persist_command: &[],
		};
		assert!(
			store.persist(&sample_state()).await.is_err(),
			"an empty persist_command must error"
		);
	}
}
