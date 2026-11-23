use std::net::IpAddr;

// FNV-1a (64-bit) constants. Chosen over std's DefaultHasher, whose algorithm is unspecified across
// Rust releases and would silently remap every client on a toolchain upgrade; FNV-1a is fixed forever.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

// Key-kind tags mixed into the hash so keys of different kinds (v4, v6, identity) can't collide on shared bytes.
const IPV4_TAG: u8 = 4;
const IPV6_TAG: u8 = 6;
const IDENTITY_TAG: u8 = b'I';
const REQUEST_TAG: u8 = b'R';
const SEGMENT_TAG: u8 = b'S';
// MurmurHash3's 64-bit finalizer (fmix64), for the stage-1 hash of a split.
const FMIX_SHIFT: u32 = 33;
const FMIX_MUL_1: u64 = 0xff51_afd7_ed55_8ccd;
const FMIX_MUL_2: u64 = 0xc4ce_b9fe_1a85_ec53;
// Ends an identity key: device ids are DNS labels and never hold NUL, so ("ab", "c") and ("a", "bc") differ.
const IDENTITY_TERMINATOR: u8 = 0;

// Fold a byte slice into a running FNV-1a accumulator.
#[inline]
fn fnv1a_update(hash: u64, bytes: &[u8]) -> u64 {
	return bytes
		.iter()
		.fold(hash, |acc, &b| (acc ^ u64::from(b)).wrapping_mul(FNV_PRIME));
}

// What a client sticks to a backend by. `seed` folds the key into the FNV accumulator before the backend id.
pub trait RendezvousKey: Copy {
	fn seed(self) -> u64;
}

// IPv4-mapped IPv6 is folded to IPv4 first so a client sticks to one backend across v4 and dual-stack [::] listeners.
impl RendezvousKey for IpAddr {
	#[inline]
	fn seed(self) -> u64 {
		return match self.to_canonical() {
			Self::V4(v4) => fnv1a_update(fnv1a_update(FNV_OFFSET_BASIS, &[IPV4_TAG]), &v4.octets()),
			Self::V6(v6) => fnv1a_update(fnv1a_update(FNV_OFFSET_BASIS, &[IPV6_TAG]), &v6.octets()),
		};
	}
}

// A device identity key (the `uid` value, or the CN before the cut-over): sticky across source addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityKey<'a>(pub &'a str);

impl RendezvousKey for IdentityKey<'_> {
	#[inline]
	fn seed(self) -> u64 {
		let tagged: u64 = fnv1a_update(fnv1a_update(FNV_OFFSET_BASIS, &[IDENTITY_TAG]), self.0.as_bytes());
		return fnv1a_update(tagged, &[IDENTITY_TERMINATOR]);
	}
}

// An object id from the request path (F13). It holds the seed, hashed once at route resolution, so it owns no bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathSegmentKey(u64);

impl PathSegmentKey {
	// The length goes in before the bytes, so ("ab", "c") and ("a", "bc") differ for any byte content.
	#[inline]
	#[must_use]
	pub fn new(segment: &[u8]) -> Self {
		let len: u64 = u64::try_from(segment.len()).unwrap_or(u64::MAX);
		let tagged: u64 = fnv1a_update(fnv1a_update(FNV_OFFSET_BASIS, &[SEGMENT_TAG]), &len.to_le_bytes());
		return Self(fnv1a_update(tagged, segment));
	}
}

impl RendezvousKey for PathSegmentKey {
	#[inline]
	fn seed(self) -> u64 {
		return self.0;
	}
}

// An HTTP request's stage-2 key: the device id when the handshake proved one, else the IP, or the object id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKey<'a> {
	Device(IdentityKey<'a>),
	Ip(IpAddr),
	Object(PathSegmentKey),
}

impl RendezvousKey for ClientKey<'_> {
	#[inline]
	fn seed(self) -> u64 {
		return match self {
			Self::Device(device) => device.seed(),
			Self::Ip(ip) => ip.seed(),
			Self::Object(object) => object.seed(),
		};
	}
}

// A key for one request only: a split with `stickiness = "none"` hashes a random value per request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestKey(pub u64);

impl RendezvousKey for RequestKey {
	#[inline]
	fn seed(self) -> u64 {
		return fnv1a_update(fnv1a_update(FNV_OFFSET_BASIS, &[REQUEST_TAG]), &self.0.to_le_bytes());
	}
}

// Stable 64-bit hash of a (key, backend_id) pair.
#[inline]
fn hash_pair<K: RendezvousKey>(key: K, backend_id: &str) -> u64 {
	return fnv1a_update(key.seed(), backend_id.as_bytes());
}

// Weighted-rendezvous score for a (key, backend_id) pair; higher = preferred. Logarithmic method:
// map the stable hash to h ∈ (0, 1), then score = -weight / ln(h). Since -ln(h) is Exponential(1), the
// max selects backend i with probability w_i / Σ w_j (so 2:1 gives 2/3 vs 1/3, not the linear method's
// 3/4 vs 1/4). A non-positive weight scores 0.0, treated as ineligible (see `select_backend`).
#[inline]
#[must_use]
pub fn rendezvous_score<K: RendezvousKey>(key: K, backend_id: &str, weight: f64) -> f64 {
	if weight <= 0.0 {
		return 0.0;
	}
	return score_hash(hash_pair(key, backend_id), weight);
}

// `rendezvous_score` with the hash finalized by fmix64. Plain FNV-1a ranks names that differ only in the last byte
// unevenly: three members `x-0`..`x-2` take 1/4, 1/4 and 1/2 (test below). Both users are new, so no client moves:
// - stage 1 of a split. Without the finalizer, a member named after its pool hashes like the pool.
// - stage 2 of a path_segment pool (F13).
#[inline]
#[must_use]
pub fn mixed_score<K: RendezvousKey>(key: K, name: &str, weight: f64) -> f64 {
	if weight <= 0.0 {
		return 0.0;
	}
	return score_hash(fmix64(hash_pair(key, name)), weight);
}

#[inline]
const fn fmix64(hash: u64) -> u64 {
	let first: u64 = (hash ^ (hash >> FMIX_SHIFT)).wrapping_mul(FMIX_MUL_1);
	let second: u64 = (first ^ (first >> FMIX_SHIFT)).wrapping_mul(FMIX_MUL_2);
	return second ^ (second >> FMIX_SHIFT);
}

// Map the hash to the open interval (0, 1): +0.5/+1.0 keep h strictly between 0 and 1 so ln(h) is finite and
// non-zero. The low-bit precision loss from the u64->f64 rounding is irrelevant here.
#[inline]
fn score_hash(hash: u64, weight: f64) -> f64 {
	let h: f64 = (u64_to_f64(hash) + 0.5) / (U64_MAX_F64 + 1.0);
	return -weight / h.ln();
}

/// `u64::MAX` rounded to the nearest f64, which is 2^64: the same value `u64::MAX as f64` gives.
pub const U64_MAX_F64: f64 = 18_446_744_073_709_551_616.0;
const U32_SPAN: f64 = 4_294_967_296.0;

/// `n` rounded to the nearest f64, bit-identical to `n as f64`. Both halves convert exactly, and the
/// one addition rounds the exact sum once, as the cast does.
#[inline]
#[must_use]
pub fn u64_to_f64(n: u64) -> f64 {
	let [b0, b1, b2, b3, b4, b5, b6, b7] = n.to_be_bytes();
	let high: u32 = u32::from_be_bytes([b0, b1, b2, b3]);
	let low: u32 = u32::from_be_bytes([b4, b5, b6, b7]);
	return f64::from(high) * U32_SPAN + f64::from(low);
}

// Best backend index for a key via weighted rendezvous hashing. A non-positive weight is ineligible;
// an empty slice or all-ineligible candidates return None so the caller surfaces "no backend available".
#[must_use]
pub fn select_backend<K: RendezvousKey>(key: K, backend_ids: &[&str], weights: &[f64]) -> Option<usize> {
	let best: Option<(usize, f64)> = backend_ids.iter().enumerate().fold(None, |best: Option<(usize, f64)>, (i, backend_id)| {
		let weight: f64 = weights.get(i).copied().unwrap_or(1.0);
		if weight <= 0.0 {
			return best;
		}
		let score: f64 = rendezvous_score(key, backend_id, weight);
		return if best.is_none_or(|(_, top): (usize, f64)| score > top) { Some((i, score)) } else { best };
	});

	return best.map(|(i, _): (usize, f64)| i);
}

#[cfg(test)]
mod tests {
	use super::*;

	fn test_ip() -> Result<IpAddr, String> {
		return Ok(match "192.168.1.100".parse() {
			Ok(value) => value,
			Err(err) => return Err(format!("\"192.168.1.100\".parse(): {err:?}")),
		});
	}

	fn test_backends() -> Vec<&'static str> {
		return vec!["backend-a", "backend-b", "backend-c"];
	}

	#[test]
	fn test_deterministic_selection() -> Result<(), String> {
		let ip: IpAddr = match test_ip() {
			Ok(value) => value,
			Err(err) => return Err(format!("test_ip(): {err}")),
		};
		let backends: Vec<&str> = test_backends();
		let weights: Vec<f64> = vec![1.0, 1.0, 1.0];

		let first: Option<usize> = select_backend(ip, &backends, &weights);
		let second: Option<usize> = select_backend(ip, &backends, &weights);

		assert_eq!(first, second);
		return Ok(());
	}

	#[test]
	fn test_all_backends_selected_across_ips() -> Result<(), String> {
		let backends: Vec<&str> = test_backends();
		let weights: Vec<f64> = vec![1.0, 1.0, 1.0];

		// Per-backend counts pre-sized to every backend: a never-selected one keeps its zero and fails
		// below (the old HashSet-len check let a starved backend slip through as an absent key).
		let mut counts: Vec<usize> = vec![0; backends.len()];
		(0..100u8).try_for_each(|i| -> Result<(), String> {
			let ip: IpAddr = match format!("10.0.0.{i}").parse() {
				Ok(value) => value,
				Err(err) => return Err(format!("format!(\"10.0.0.{{i}}\").parse(): {err:?}")),
			};
			if let Some(idx) = select_backend(ip, &backends, &weights) {
				counts[idx] += 1;
			}
			return Ok(());
		})?;

		counts
			.iter()
			.enumerate()
			.for_each(|(idx, &count)| assert!(count > 0, "backend {idx} was never selected across 100 IPs"));
		assert_eq!(
			counts.iter().sum::<usize>(),
			100,
			"every request resolved to some backend"
		);
		return Ok(());
	}

	#[test]
	fn test_weight_influences_selection() -> Result<(), String> {
		let backends: Vec<&str> = vec!["heavy", "light"];
		let weights: Vec<f64> = vec![100.0, 0.001];

		let mut heavy_count: usize = 0;
		(0..100u8).try_for_each(|i| -> Result<(), String> {
			let ip: IpAddr = match format!("10.0.0.{i}").parse() {
				Ok(value) => value,
				Err(err) => return Err(format!("format!(\"10.0.0.{{i}}\").parse(): {err:?}")),
			};
			if let Some(0) = select_backend(ip, &backends, &weights) {
				heavy_count += 1;
			}
			return Ok(());
		})?;

		assert!(heavy_count > 80, "heavily weighted backend should win most of the time");
		return Ok(());
	}

	#[test]
	fn test_ipv4_mapped_ipv6_routes_like_bare_ipv4() -> Result<(), String> {
		// Regression: ::ffff:192.168.1.100 must select the same backend/score as 192.168.1.100 (before canonicalizing they split routing).
		let backends: Vec<&str> = test_backends();
		let weights: Vec<f64> = vec![1.0, 1.0, 1.0];
		let bare: IpAddr = match "192.168.1.100".parse() {
			Ok(value) => value,
			Err(err) => return Err(format!("\"192.168.1.100\".parse(): {err:?}")),
		};
		let mapped: IpAddr = match "::ffff:192.168.1.100".parse() {
			Ok(value) => value,
			Err(err) => return Err(format!("\"::ffff:192.168.1.100\".parse(): {err:?}")),
		};

		assert_eq!(
			f64::to_bits(rendezvous_score(bare, "backend-a", 1.0)),
			f64::to_bits(rendezvous_score(mapped, "backend-a", 1.0))
		);
		assert_eq!(
			select_backend(bare, &backends, &weights),
			select_backend(mapped, &backends, &weights)
		);
		return Ok(());
	}

	#[test]
	fn test_empty_backends() -> Result<(), String> {
		let ip: IpAddr = match test_ip() {
			Ok(value) => value,
			Err(err) => return Err(format!("test_ip(): {err}")),
		};
		let result: Option<usize> = select_backend(ip, &[], &[]);
		assert_eq!(result, None);
		return Ok(());
	}

	#[test]
	fn test_single_backend() -> Result<(), String> {
		let ip: IpAddr = match test_ip() {
			Ok(value) => value,
			Err(err) => return Err(format!("test_ip(): {err}")),
		};
		let backends: Vec<&str> = vec!["only-one"];
		let weights: Vec<f64> = vec![1.0];

		let result: Option<usize> = select_backend(ip, &backends, &weights);
		assert_eq!(result, Some(0));
		return Ok(());
	}

	#[test]
	fn test_minimal_disruption_on_removal() -> Result<(), String> {
		let ip: IpAddr = match test_ip() {
			Ok(value) => value,
			Err(err) => return Err(format!("test_ip(): {err}")),
		};
		let backends_full: Vec<&str> = test_backends();
		let weights_full: Vec<f64> = vec![1.0, 1.0, 1.0];

		let original: Option<usize> = select_backend(ip, &backends_full, &weights_full);

		let backends_reduced: Vec<&str> = vec!["backend-a", "backend-c"]; // backend-b (index 1) removed
		let weights_reduced: Vec<f64> = vec![1.0, 1.0];

		let after_removal: Option<usize> = select_backend(ip, &backends_reduced, &weights_reduced);

		// Selecting an unremoved backend stays stable; backend-c (index 2) shifts down to index 1.
		if original == Some(0) {
			assert_eq!(after_removal, Some(0));
		}
		if original == Some(2) {
			assert_eq!(after_removal, Some(1));
		}
		return Ok(());
	}

	#[test]
	fn test_weight_two_to_one_is_proportional_not_linear() -> Result<(), String> {
		// Selection must be proportional to weight: 2:1 yields ~2/3 vs 1/3. The old linear `hash × weight`
		// gave 3/4, so the 0.72 upper bound excludes 0.75 — this passes only for WRH, not the linear formula.
		let backends: Vec<&str> = vec!["heavy", "light"];
		let weights: Vec<f64> = vec![2.0, 1.0];

		let mut heavy_wins: u32 = 0;
		let mut total: u32 = 0;
		(0..8u16)
			.flat_map(|b| (0..250u16).map(move |c| (b, c)))
			.try_for_each(|(b, c)| -> Result<(), String> {
				let ip: IpAddr = match format!("10.0.{b}.{c}").parse() {
					Ok(value) => value,
					Err(err) => return Err(format!("format!(\"10.0.{{b}}.{{c}}\").parse(): {err:?}")),
				};
				if select_backend(ip, &backends, &weights) == Some(0) {
					heavy_wins += 1;
				}
				total += 1;
				return Ok(());
			})?;

		let heavy_fraction: f64 = f64::from(heavy_wins) / f64::from(total);
		const PROPORTIONAL_LOWER: f64 = 0.60;
		const PROPORTIONAL_UPPER: f64 = 0.72; // < 0.75, the fraction the buggy linear formula produced
		assert!(
			heavy_fraction > PROPORTIONAL_LOWER && heavy_fraction < PROPORTIONAL_UPPER,
			"2:1 weighting should select heavy ~2/3 of the time, got {heavy_fraction}"
		);
		return Ok(());
	}

	#[test]
	fn test_all_zero_weights_selects_none() -> Result<(), String> {
		let ip: IpAddr = match test_ip() {
			Ok(value) => value,
			Err(err) => return Err(format!("test_ip(): {err}")),
		}; // all weights 0 (every backend dead) must yield no selection, not backends[0]
		let backends: Vec<&str> = test_backends();
		let weights: Vec<f64> = vec![0.0, 0.0, 0.0];
		assert_eq!(select_backend(ip, &backends, &weights), None);
		return Ok(());
	}

	#[test]
	fn test_zero_weight_backend_is_never_selected() -> Result<(), String> {
		// The one live backend among dead ones is always chosen, regardless of hash ordering.
		let backends: Vec<&str> = test_backends();
		let weights: Vec<f64> = vec![0.0, 1.0, 0.0];
		(0..100u8).try_for_each(|c| -> Result<(), String> {
			let ip: IpAddr = match format!("10.0.0.{c}").parse() {
				Ok(value) => value,
				Err(err) => return Err(format!("format!(\"10.0.0.{{c}}\").parse(): {err:?}")),
			};
			assert_eq!(select_backend(ip, &backends, &weights), Some(1));
			return Ok(());
		})?;
		return Ok(());
	}

	// Decimal text parses to the nearest f64 (correctly rounded), the same value an `as f64` cast gives,
	// so it is an oracle for u64_to_f64 that needs no cast.
	fn nearest_f64(n: u64) -> Result<f64, String> {
		return match n.to_string().parse::<f64>() {
			Ok(value) => Ok(value),
			Err(err) => Err(format!("parse {n} as f64: {err}")),
		};
	}

	// Rounding cases: exact values, the 2^53 boundary, halfway ties (round-half-even), and the top of the range.
	#[test]
	fn u64_to_f64_matches_nearest_f64() -> Result<(), String> {
		let two_53: u64 = 1 << 53;
		let samples: [u64; 12] = [
			0,
			1,
			u64::from(u32::MAX),
			two_53 - 1,
			two_53,
			two_53 + 1,
			two_53 + 3,
			(1 << 63) + (1 << 10),
			(1 << 63) + (1 << 10) + 1,
			u64::MAX - 1,
			u64::MAX,
			0x9E37_79B9_7F4A_7C15,
		];
		samples.into_iter().try_for_each(|n| -> Result<(), String> {
			let expected: f64 = match nearest_f64(n) {
				Ok(value) => value,
				Err(err) => return Err(format!("oracle for {n}: {err}")),
			};
			assert_eq!(u64_to_f64(n).to_bits(), expected.to_bits(), "u64_to_f64({n})");
			return Ok(());
		})?;
		return Ok(());
	}

	// The pre-generic IP hash, copied verbatim as the oracle: IP routing must not move by one bit.
	fn oracle_ip_hash(client_ip: IpAddr, backend_id: &str) -> u64 {
		let seeded: u64 = match client_ip.to_canonical() {
			IpAddr::V4(v4) => fnv1a_update(fnv1a_update(FNV_OFFSET_BASIS, &[IPV4_TAG]), &v4.octets()),
			IpAddr::V6(v6) => fnv1a_update(fnv1a_update(FNV_OFFSET_BASIS, &[IPV6_TAG]), &v6.octets()),
		};
		return fnv1a_update(seeded, backend_id.as_bytes());
	}

	#[test]
	fn ip_key_hashes_exactly_as_before_the_generic_key() -> Result<(), String> {
		let ips: [&str; 4] = ["192.168.1.100", "10.0.0.1", "::1", "2001:db8::42"];
		ips.into_iter().try_for_each(|text| -> Result<(), String> {
			let ip: IpAddr = match text.parse() {
				Ok(value) => value,
				Err(err) => return Err(format!("{text}.parse(): {err:?}")),
			};
			test_backends().into_iter().for_each(|backend| {
				assert_eq!(
					hash_pair(ip, backend),
					oracle_ip_hash(ip, backend),
					"{text} → {backend}"
				);
			});
			return Ok(());
		})?;
		return Ok(());
	}

	// Identity keys of different kinds never share a hash with an IP of the same bytes.
	#[test]
	fn identity_key_is_tagged_apart_from_ip_keys() -> Result<(), String> {
		let ip: IpAddr = match "10.0.0.1".parse() {
			Ok(value) => value,
			Err(err) => return Err(format!("\"10.0.0.1\".parse(): {err:?}")),
		};
		assert_ne!(hash_pair(IdentityKey("10.0.0.1"), "b"), hash_pair(ip, "b"));
		assert_ne!(
			hash_pair(IdentityKey("ab"), "c"),
			hash_pair(IdentityKey("a"), "bc"),
			"the terminator splits key from backend id"
		);
		return Ok(());
	}

	// A segment key never shares a hash with an IP, identity or request key over the same bytes.
	#[test]
	fn path_segment_key_is_tagged_apart_from_every_other_key() -> Result<(), String> {
		let ip: IpAddr = match "10.0.0.1".parse() {
			Ok(value) => value,
			Err(err) => return Err(format!("\"10.0.0.1\".parse(): {err:?}")),
		};
		let segment: u64 = hash_pair(PathSegmentKey::new(b"10.0.0.1"), "b");
		assert_ne!(segment, hash_pair(ip, "b"));
		assert_ne!(segment, hash_pair(IdentityKey("10.0.0.1"), "b"));
		assert_ne!(hash_pair(PathSegmentKey::new(&7u64.to_le_bytes()), "b"), hash_pair(RequestKey(7), "b"));
		assert_ne!(
			hash_pair(PathSegmentKey::new(b"ab"), "c"),
			hash_pair(PathSegmentKey::new(b"a"), "bc"),
			"the length prefix splits key from backend id"
		);
		assert_eq!(PathSegmentKey::new(b"obj-1"), PathSegmentKey::new(b"obj-1"), "the key depends on the bytes only");
		assert_eq!(ClientKey::Object(PathSegmentKey::new(b"obj-1")).seed(), PathSegmentKey::new(b"obj-1").seed());
		return Ok(());
	}

	const FLEET_SIZE: u32 = 10_000;
	const LAST_BYTE_MEMBERS: [&str; 3] = ["objects-0", "objects-1", "objects-2"];
	// 4σ of Binomial(n = 10 000, p = 1/3): σ = √(n·p·(1−p)) ≈ 47.1.
	const FOUR_SIGMA_THIRD: u32 = 189;

	// How many of FLEET_SIZE object ids each member of LAST_BYTE_MEMBERS wins under `score`.
	fn last_byte_shares(score: fn(PathSegmentKey, &str, f64) -> f64) -> [u32; 3] {
		return (0..FLEET_SIZE).fold([0; 3], |mut counts: [u32; 3], n| {
			let object: String = format!("obj-{n}");
			let key: PathSegmentKey = PathSegmentKey::new(object.as_bytes());
			let winner: usize = (1..LAST_BYTE_MEMBERS.len()).fold(0, |best, i| {
				return if score(key, LAST_BYTE_MEMBERS[i], 1.0) > score(key, LAST_BYTE_MEMBERS[best], 1.0) { i } else { best };
			});
			counts[winner] += 1;
			return counts;
		});
	}

	// Why a path_segment pool uses `mixed_score`: with members named `objects-0`..`objects-2`, plain FNV gives one
	// member half the ids. The finalized hash gives each member a third, inside a 4σ band.
	#[test]
	fn mixed_score_splits_members_that_differ_in_the_last_byte_evenly() {
		let third: u32 = FLEET_SIZE / 3;
		let mixed: [u32; 3] = last_byte_shares(mixed_score);
		assert!(mixed.iter().all(|count| count.abs_diff(third) <= FOUR_SIGMA_THIRD), "mixed shares {mixed:?}");
		let plain: [u32; 3] = last_byte_shares(rendezvous_score);
		assert!(plain.iter().any(|count| count.abs_diff(third) > FOUR_SIGMA_THIRD), "control: plain FNV shares {plain:?}");
	}
	// 4σ of Binomial(n = 10 000, p = 0.5): σ = √(n·p·(1−p)) = 50.
	const FOUR_SIGMA_DEVICES: u32 = 200;
	const HALF_FLEET: u32 = FLEET_SIZE / 2;

	fn device_id(n: u32) -> String {
		return format!("dev-{n:05}");
	}

	// Plan *Verification*: 10 k identities behind one IP over two instances split inside a 4σ binomial band.
	#[test]
	fn identity_keys_split_two_instances_inside_a_four_sigma_band() {
		let backends: [&str; 2] = ["consumption-a", "consumption-b"];
		let weights: [f64; 2] = [1.0, 1.0];
		let on_a: u32 = (0..FLEET_SIZE)
			.filter(|n| select_backend(IdentityKey(&device_id(*n)), &backends, &weights) == Some(0))
			.fold(0, |acc, _| acc + 1);
		assert!(
			on_a.abs_diff(HALF_FLEET) <= FOUR_SIGMA_DEVICES,
			"instance a holds {on_a} of {FLEET_SIZE}; 4σ band is {HALF_FLEET}±{FOUR_SIGMA_DEVICES}"
		);
	}

	#[test]
	fn u64_max_f64_is_two_pow_64() -> Result<(), String> {
		let expected: f64 = match nearest_f64(u64::MAX) {
			Ok(value) => value,
			Err(err) => return Err(format!("oracle for u64::MAX: {err}")),
		};
		assert_eq!(U64_MAX_F64.to_bits(), expected.to_bits());
		assert_eq!(
			U64_MAX_F64.to_bits(),
			(U64_MAX_F64 + 1.0).to_bits(),
			"+1.0 is absorbed at 2^64"
		);
		return Ok(());
	}
}
