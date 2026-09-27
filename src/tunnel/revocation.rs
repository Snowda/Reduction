use std::collections::HashSet;

use arrayvec::ArrayString;
use serde::Deserialize;

use crate::error::{ReductionError, Result};
use crate::tls::identity::{PeerIdentity, SPKI_SHA256_LEN};

// Upper bound on a backend_id, matching the tunnel Register frame and route config field widths.
const MAX_BACKEND_ID_LEN: usize = 256;

// A revoked SPKI is the SHA-256 of a cert's SubjectPublicKeyInfo as hex, so the hash doubles in length.
const SPKI_HEX_LEN: usize = SPKI_SHA256_LEN * 2;

// Raw TOML shape: a top-level `[[revoked]]` array, each entry an optional SPKI hex and/or backend_id
// plus a mandatory reason. Private — callers see RevocationSet.
#[derive(Debug, Deserialize)]
struct RevocationFile {
	#[serde(default)]
	revoked: Vec<RevocationEntry>,
}

#[derive(Debug, Deserialize)]
struct RevocationEntry {
	spki: Option<String>,
	backend_id: Option<String>,
	// Required (an unexplained revocation is an audit hole); enforced by deserialization but not retained in memory.
	#[allow(dead_code)]
	reason: String,
}

// Decoded revocation denylist: compromised keys (by SPKI hash) and device names (by backend_id) denied service.
#[derive(Debug, Default, Clone)]
pub struct RevocationSet {
	spki: HashSet<[u8; SPKI_SHA256_LEN]>,
	backend_ids: HashSet<ArrayString<MAX_BACKEND_ID_LEN>>,
}

impl RevocationSet {
	// True when this handshake-proven identity is denied — either its key's SPKI hash is revoked, or
	// its certificate CN (the device name) is revoked outright.
	#[must_use]
	pub fn is_revoked(&self, identity: &PeerIdentity) -> bool {
		return self.spki.contains(&identity.spki_sha256) || self.backend_ids.contains(identity.common_name.as_str());
	}

	// Number of distinct revocation entries (SPKI hashes plus backend_ids). Diagnostic only.
	#[must_use]
	pub fn len(&self) -> usize {
		return self.spki.len() + self.backend_ids.len();
	}

	#[must_use]
	pub fn is_empty(&self) -> bool {
		return self.spki.is_empty() && self.backend_ids.is_empty();
	}

	// Pure parse (reused by initial load and hot-reload). Rejects — never silently drops — a bad hex SPKI,
	// an over-length backend_id, or an entry naming neither field.
	pub fn parse(toml_str: &str) -> Result<Self> {
		let file: RevocationFile = toml::from_str(toml_str)?;

		let mut spki: HashSet<[u8; SPKI_SHA256_LEN]> = HashSet::new();
		let mut backend_ids: HashSet<ArrayString<MAX_BACKEND_ID_LEN>> = HashSet::new();

		for (index, entry) in file.revoked.iter().enumerate() {
			if entry.spki.is_none() && entry.backend_id.is_none() {
				return Err(ReductionError::Config(format!(
					"revocation entry {index} names neither spki nor backend_id"
				)));
			}

			if let Some(hex) = entry.spki.as_deref() {
				spki.insert(decode_spki_hex(hex, index)?);
			}

			if let Some(id) = entry.backend_id.as_deref() {
				let parsed: ArrayString<MAX_BACKEND_ID_LEN> = ArrayString::from(id).map_err(|_| {
					ReductionError::Config(format!(
						"revocation entry {index}: backend_id exceeds {MAX_BACKEND_ID_LEN} chars"
					))
				})?;
				backend_ids.insert(parsed);
			}
		}

		return Ok(Self { spki, backend_ids });
	}
}

// Decode a hex SPKI hash into its 32 raw bytes, rejecting a wrong length or non-hex nibble (a truncated hash revokes the wrong key).
fn decode_spki_hex(hex: &str, index: usize) -> Result<[u8; SPKI_SHA256_LEN]> {
	let bytes: &[u8] = hex.as_bytes();
	if bytes.len() != SPKI_HEX_LEN {
		return Err(ReductionError::Config(format!(
			"revocation entry {index}: spki must be {SPKI_HEX_LEN} hex chars, got {}",
			bytes.len()
		)));
	}

	let mut out: [u8; SPKI_SHA256_LEN] = [0u8; SPKI_SHA256_LEN];
	for (i, out_byte) in out.iter_mut().enumerate() {
		let hi: u8 = hex_nibble(bytes[i * 2], index)?;
		let lo: u8 = hex_nibble(bytes[i * 2 + 1], index)?;
		*out_byte = (hi << 4) | lo;
	}
	return Ok(out);
}

// Map a single ASCII hex digit to its 0-15 value, rejecting anything else.
#[inline]
fn hex_nibble(byte: u8, index: usize) -> Result<u8> {
	return match byte {
		b'0'..=b'9' => Ok(byte - b'0'),
		b'a'..=b'f' => Ok(byte - b'a' + 10),
		b'A'..=b'F' => Ok(byte - b'A' + 10),
		other => Err(ReductionError::Config(format!(
			"revocation entry {index}: spki contains non-hex byte {other:#04x}"
		))),
	};
}

#[cfg(test)]
mod tests {
	use aws_lc_rs::digest::{SHA256, digest};

	use super::*;

	// Build a PeerIdentity directly from a CN and an SPKI hash, bypassing cert parsing — Phase 1 tests
	// the pure set, not the extraction (which identity.rs already covers).
	fn identity(cn: &str, spki: [u8; SPKI_SHA256_LEN]) -> PeerIdentity {
		return PeerIdentity {
			common_name: ArrayString::from(cn).unwrap(),
			spki_sha256: spki,
		};
	}

	// Lowercase hex of a 32-byte hash, mirroring how the fleet layer writes SPKI entries.
	fn to_hex(bytes: &[u8; SPKI_SHA256_LEN]) -> String {
		return bytes.iter().map(|b| format!("{b:02x}")).collect();
	}

	fn sample_spki(seed: &[u8]) -> [u8; SPKI_SHA256_LEN] {
		return digest(&SHA256, seed).as_ref().try_into().unwrap();
	}

	#[test]
	fn test_spki_hit() {
		let revoked_key: [u8; SPKI_SHA256_LEN] = sample_spki(b"compromised");
		let toml: String = format!(
			"[[revoked]]\nspki = \"{}\"\nreason = \"clone detected\"\n",
			to_hex(&revoked_key)
		);
		let set: RevocationSet = RevocationSet::parse(&toml).unwrap();
		assert!(set.is_revoked(&identity("edge-1", revoked_key)));
	}

	#[test]
	fn test_spki_hit_regardless_of_cn() {
		// SPKI revocation targets the key, so the CN presented alongside it is irrelevant.
		let revoked_key: [u8; SPKI_SHA256_LEN] = sample_spki(b"stolen");
		let toml: String = format!("[[revoked]]\nspki = \"{}\"\nreason = \"x\"\n", to_hex(&revoked_key));
		let set: RevocationSet = RevocationSet::parse(&toml).unwrap();
		assert!(set.is_revoked(&identity("any-name-at-all", revoked_key)));
	}

	#[test]
	fn test_backend_id_hit() {
		let toml: &str = "[[revoked]]\nbackend_id = \"edge-013\"\nreason = \"decommissioned\"\n";
		let set: RevocationSet = RevocationSet::parse(toml).unwrap();
		// Any key under this device name is denied.
		assert!(set.is_revoked(&identity("edge-013", sample_spki(b"whatever-key"))));
	}

	#[test]
	fn test_backend_id_hit_blocks_different_key_same_cn() {
		// The backend_id entry must block a *different* key presenting the same CN — the whole point of
		// a name revocation vs a key revocation.
		let toml: &str = "[[revoked]]\nbackend_id = \"edge-013\"\nreason = \"decommissioned\"\n";
		let set: RevocationSet = RevocationSet::parse(toml).unwrap();
		assert!(set.is_revoked(&identity("edge-013", sample_spki(b"key-a"))));
		assert!(set.is_revoked(&identity("edge-013", sample_spki(b"key-b"))));
	}

	#[test]
	fn test_miss() {
		let revoked_key: [u8; SPKI_SHA256_LEN] = sample_spki(b"revoked");
		let toml: String = format!(
			"[[revoked]]\nspki = \"{}\"\nreason = \"x\"\n[[revoked]]\nbackend_id = \"gone\"\nreason = \"y\"\n",
			to_hex(&revoked_key)
		);
		let set: RevocationSet = RevocationSet::parse(&toml).unwrap();
		// Neither the SPKI nor the CN of this identity is on the list.
		assert!(!set.is_revoked(&identity("edge-99", sample_spki(b"healthy"))));
	}

	#[test]
	fn test_empty_file_is_empty_set() {
		let set: RevocationSet = RevocationSet::parse("").unwrap();
		assert!(set.is_empty());
		assert_eq!(set.len(), 0);
		assert!(!set.is_revoked(&identity("edge-1", sample_spki(b"anything"))));
	}

	#[test]
	fn test_entry_with_both_fields_indexes_both() {
		let key: [u8; SPKI_SHA256_LEN] = sample_spki(b"dual");
		let toml: String = format!(
			"[[revoked]]\nspki = \"{}\"\nbackend_id = \"edge-7\"\nreason = \"both\"\n",
			to_hex(&key)
		);
		let set: RevocationSet = RevocationSet::parse(&toml).unwrap();
		assert_eq!(set.len(), 2);
		// Matches on the key even with a different CN...
		assert!(set.is_revoked(&identity("other", key)));
		// ...and on the CN even with a different key.
		assert!(set.is_revoked(&identity("edge-7", sample_spki(b"different"))));
	}

	#[test]
	fn test_malformed_hex_rejected() {
		// 'g' is not a hex digit.
		let bad: String = "g".repeat(SPKI_HEX_LEN);
		let toml: String = format!("[[revoked]]\nspki = \"{bad}\"\nreason = \"x\"\n");
		let err: ReductionError = RevocationSet::parse(&toml).unwrap_err();
		assert!(matches!(err, ReductionError::Config(_)));
		assert!(format!("{err}").contains("non-hex"));
	}

	#[test]
	fn test_wrong_length_hex_rejected() {
		let short: String = "ab".to_owned();
		let toml: String = format!("[[revoked]]\nspki = \"{short}\"\nreason = \"x\"\n");
		let err: ReductionError = RevocationSet::parse(&toml).unwrap_err();
		assert!(matches!(err, ReductionError::Config(_)));
		assert!(format!("{err}").contains("hex chars"));
	}

	#[test]
	fn test_entry_with_neither_field_rejected() {
		let toml: &str = "[[revoked]]\nreason = \"pointless\"\n";
		let err: ReductionError = RevocationSet::parse(toml).unwrap_err();
		assert!(matches!(err, ReductionError::Config(_)));
		assert!(format!("{err}").contains("neither spki nor backend_id"));
	}

	#[test]
	fn test_missing_reason_rejected() {
		// reason is mandatory; a missing one is a TOML deserialization failure.
		let toml: &str = "[[revoked]]\nbackend_id = \"edge-1\"\n";
		let err: ReductionError = RevocationSet::parse(toml).unwrap_err();
		assert!(matches!(err, ReductionError::ConfigParse(_)));
	}

	#[test]
	fn test_over_length_backend_id_rejected() {
		let long: String = "x".repeat(MAX_BACKEND_ID_LEN + 1);
		let toml: String = format!("[[revoked]]\nbackend_id = \"{long}\"\nreason = \"x\"\n");
		let err: ReductionError = RevocationSet::parse(&toml).unwrap_err();
		assert!(matches!(err, ReductionError::Config(_)));
		assert!(format!("{err}").contains("exceeds"));
	}

	#[test]
	fn test_uppercase_hex_accepted() {
		let key: [u8; SPKI_SHA256_LEN] = sample_spki(b"upper");
		let upper: String = to_hex(&key).to_uppercase();
		let toml: String = format!("[[revoked]]\nspki = \"{upper}\"\nreason = \"x\"\n");
		let set: RevocationSet = RevocationSet::parse(&toml).unwrap();
		// Uppercase hex decodes to the same bytes, so the lowercase-hashed identity still matches.
		assert!(set.is_revoked(&identity("edge-1", key)));
	}

	#[test]
	fn test_invalid_toml_rejected() {
		let err: ReductionError = RevocationSet::parse("this is = = not toml").unwrap_err();
		assert!(matches!(err, ReductionError::ConfigParse(_)));
	}
}
