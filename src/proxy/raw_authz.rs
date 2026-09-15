use std::collections::{HashMap, HashSet};

use arrayvec::ArrayString;

use crate::config::RawRelayAuthzEntry;
use crate::error::{ReductionError, Result};
use crate::tls::identity::{MAX_COMMON_NAME_LEN, PeerIdentity, SPKI_SHA256_LEN};

// backend_id width, matching the raw routing header and route/backend config field widths.
const MAX_BACKEND_ID_LEN: usize = 256;
// A SPKI SHA-256 hash is 32 bytes; hex encoding doubles that.
const SPKI_HEX_LEN: usize = SPKI_SHA256_LEN * 2;
// ASCII distance from an uppercase hex letter to its lowercase form.
const LOWERCASE_OFFSET: u8 = b'a' - b'A';

// Allowed identities for one backend: admitted if its cert CN or key SPKI hash is listed (either suffices).
#[derive(Debug)]
struct BackendPolicy {
	cns: HashSet<ArrayString<MAX_COMMON_NAME_LEN>>,
	spkis: HashSet<ArrayString<SPKI_HEX_LEN>>,
}

// Per-backend allowlist for which authenticated devices may open a raw QUIC relay to which backend, built
// from config at startup. Absent backend = denied to all (fail closed); present = only listed CNs/SPKIs.
// Gates the raw byte path at the edge, since the opaque relay can't forward device identity to the backend.
#[derive(Debug)]
pub struct RawRelayAuthz {
	by_backend: HashMap<ArrayString<MAX_BACKEND_ID_LEN>, BackendPolicy>,
}

impl RawRelayAuthz {
	// Validate and index config entries against the configured backend ids. Rejects at startup (not
	// silently at request time): an entry naming a non-existent backend (would leave the real backend
	// open to all devices — finding #62), a duplicate backend_id, an entry naming no identity, or bad SPKI hex.
	pub fn new(
		entries: &[RawRelayAuthzEntry],
		known_backend_ids: &HashSet<ArrayString<MAX_BACKEND_ID_LEN>>,
	) -> Result<Self> {
		let mut by_backend: HashMap<ArrayString<MAX_BACKEND_ID_LEN>, BackendPolicy> = HashMap::new();

		for entry in entries {
			if !known_backend_ids.contains(&entry.backend_id) {
				return Err(ReductionError::Config(format!(
					"raw_relay_authz entry names backend '{}', which is not a configured backend \
                     (no route/pool resolves to that id); the restriction would silently not apply",
					entry.backend_id,
				)));
			}

			if entry.allowed_cns.is_empty() && entry.allowed_spkis.is_empty() {
				return Err(ReductionError::Config(format!(
					"raw_relay_authz entry for backend '{}' names neither allowed_cns nor allowed_spkis",
					entry.backend_id,
				)));
			}

			let cns: HashSet<ArrayString<MAX_COMMON_NAME_LEN>> = entry.allowed_cns.iter().copied().collect();
			let mut spkis: HashSet<ArrayString<SPKI_HEX_LEN>> = HashSet::new();
			for spki in &entry.allowed_spkis {
				spkis.insert(normalize_spki_hex(spki, &entry.backend_id)?);
			}

			if by_backend
				.insert(entry.backend_id, BackendPolicy { cns, spkis })
				.is_some()
			{
				return Err(ReductionError::Config(format!(
					"duplicate raw_relay_authz entry for backend '{}'",
					entry.backend_id,
				)));
			}
		}

		return Ok(Self { by_backend });
	}

	// Whether `identity` may open a raw relay to `backend_id`. An absent policy denies (opaque streams mean
	// forwarding by default would grant any device every backend); a present one admits only a listed CN or SPKI.
	#[must_use]
	pub fn is_allowed(&self, backend_id: &str, identity: &PeerIdentity) -> bool {
		let Some(policy) = self.by_backend.get(backend_id) else {
			return false;
		};
		return policy.cns.contains(identity.common_name.as_str())
			|| policy.spkis.contains(identity.spki_hex().as_str());
	}

	// Number of backends carrying an explicit policy. Diagnostic only.
	#[must_use]
	pub fn len(&self) -> usize {
		return self.by_backend.len();
	}

	#[must_use]
	pub fn is_empty(&self) -> bool {
		return self.by_backend.is_empty();
	}
}

// Validate a SPKI hash is exactly 64 hex chars and return it lowercased to match PeerIdentity::spki_hex.
// Rejects a wrong length or non-hex byte — a truncated hash would authorize the wrong key.
fn normalize_spki_hex(hex: &str, backend_id: &str) -> Result<ArrayString<SPKI_HEX_LEN>> {
	if hex.len() != SPKI_HEX_LEN {
		return Err(ReductionError::Config(format!(
			"raw_relay_authz backend '{backend_id}': spki must be {SPKI_HEX_LEN} hex chars, got {}",
			hex.len(),
		)));
	}

	let mut out: ArrayString<SPKI_HEX_LEN> = ArrayString::new();
	for byte in hex.bytes() {
		let lowered: u8 = match byte {
			b'0'..=b'9' | b'a'..=b'f' => byte,
			b'A'..=b'F' => byte + LOWERCASE_OFFSET,
			other => {
				return Err(ReductionError::Config(format!(
					"raw_relay_authz backend '{backend_id}': spki contains non-hex byte {other:#04x}"
				)));
			}
		};
		out.push(char::from(lowered));
	}
	return Ok(out);
}

#[cfg(test)]
mod tests {
	use aws_lc_rs::digest::{SHA256, digest};

	use super::*;

	// Build a PeerIdentity from a CN and key seed, bypassing cert parsing — tests the allowlist, not extraction.
	fn identity(cn: &str, key_seed: &[u8]) -> PeerIdentity {
		let spki: [u8; SPKI_SHA256_LEN] = digest(&SHA256, key_seed).as_ref().try_into().unwrap();
		return PeerIdentity {
			common_name: ArrayString::from(cn).unwrap(),
			spki_sha256: spki,
		};
	}

	fn entry(backend_id: &str, cns: &[&str], spkis: &[&str]) -> RawRelayAuthzEntry {
		return RawRelayAuthzEntry {
			backend_id: ArrayString::from(backend_id).unwrap(),
			allowed_cns: cns.iter().map(|c| ArrayString::from(c).unwrap()).collect(),
			allowed_spkis: spkis.iter().map(|s| s.to_string()).collect(),
		};
	}

	// The set of configured (raw-reachable) backend ids the policy is validated against.
	fn known(ids: &[&str]) -> HashSet<ArrayString<MAX_BACKEND_ID_LEN>> {
		return ids.iter().map(|id| ArrayString::from(id).unwrap()).collect();
	}

	#[test]
	fn unlisted_backend_is_denied_to_any_device() {
		let authz = RawRelayAuthz::new(&[entry("locked", &["device-1"], &[])], &known(&["locked", "open"])).unwrap();
		assert!(!authz.is_allowed("open", &identity("whoever", b"k"))); // "open" has no policy: deny, don't grant implicitly
	}

	#[test]
	fn listed_backend_admits_allowed_cn_and_denies_others() {
		let authz = RawRelayAuthz::new(&[entry("svc", &["device-1", "device-2"], &[])], &known(&["svc"])).unwrap();
		assert!(authz.is_allowed("svc", &identity("device-1", b"k1")));
		assert!(authz.is_allowed("svc", &identity("device-2", b"k2")));
		assert!(
			!authz.is_allowed("svc", &identity("device-3", b"k3")),
			"an unlisted CN must be denied"
		);
	}

	#[test]
	fn listed_backend_admits_by_spki_regardless_of_cn() {
		let allowed = identity("some-cn", b"key-bytes");
		let authz = RawRelayAuthz::new(&[entry("svc", &[], &[allowed.spki_hex().as_str()])], &known(&["svc"])).unwrap();
		// Matched on key hash: same key passes under an unlisted name; a different key is denied under the same CN.
		assert!(authz.is_allowed("svc", &identity("some-cn", b"key-bytes")));
		assert!(!authz.is_allowed("svc", &identity("some-cn", b"other-key")));
	}

	#[test]
	fn spki_match_is_case_insensitive() {
		let dev = identity("dev", b"k");
		let upper: String = dev.spki_hex().as_str().to_uppercase();
		let authz = RawRelayAuthz::new(&[entry("svc", &[], &[&upper])], &known(&["svc"])).unwrap();
		// Uppercase config hex is normalized to lowercase and matches spki_hex (always lowercase).
		assert!(authz.is_allowed("svc", &dev));
	}

	#[test]
	fn empty_entry_is_rejected() {
		let err = RawRelayAuthz::new(&[entry("svc", &[], &[])], &known(&["svc"])).unwrap_err();
		assert!(matches!(err, ReductionError::Config(_)));
		assert!(format!("{err}").contains("neither allowed_cns nor allowed_spkis"));
	}

	#[test]
	fn duplicate_backend_entry_is_rejected() {
		let err = RawRelayAuthz::new(
			&[entry("svc", &["a"], &[]), entry("svc", &["b"], &[])],
			&known(&["svc"]),
		)
		.unwrap_err();
		assert!(format!("{err}").contains("duplicate"));
	}

	#[test]
	fn malformed_spki_hex_is_rejected() {
		let short = RawRelayAuthz::new(&[entry("svc", &[], &["abcd"])], &known(&["svc"])).unwrap_err(); // wrong length
		assert!(format!("{short}").contains("hex chars"));
		let bad: String = "g".repeat(SPKI_HEX_LEN); // right length, non-hex byte
		let non_hex = RawRelayAuthz::new(&[entry("svc", &[], &[&bad])], &known(&["svc"])).unwrap_err();
		assert!(format!("{non_hex}").contains("non-hex"));
	}

	// Regression for #62: an entry naming an unconfigured backend is rejected at build, so a typo can't
	// silently leave the real backend unprotected.
	#[test]
	fn entry_for_unknown_backend_is_rejected() {
		let err = RawRelayAuthz::new(&[entry("typo", &["device-1"], &[])], &known(&["svc"])).unwrap_err();
		assert!(matches!(err, ReductionError::Config(_)));
		assert!(format!("{err}").contains("not a configured backend"), "got: {err}");
	}

	// The check is against the exact pool key: a near-miss (case/suffix) is rejected, since header and lookup use the exact string.
	#[test]
	fn entry_backend_id_must_match_exactly() {
		assert!(RawRelayAuthz::new(&[entry("SVC", &["d"], &[])], &known(&["svc"])).is_err());
		assert!(RawRelayAuthz::new(&[entry("svc ", &["d"], &[])], &known(&["svc"])).is_err());
		assert!(RawRelayAuthz::new(&[entry("svc", &["d"], &[])], &known(&["svc"])).is_ok());
	}

	#[test]
	fn empty_policy_set_denies_everything() {
		let authz = RawRelayAuthz::new(&[], &known(&[])).unwrap();
		assert!(authz.is_empty());
		assert_eq!(authz.len(), 0);
		assert!(!authz.is_allowed("anything", &identity("dev", b"k")));
	}
}
