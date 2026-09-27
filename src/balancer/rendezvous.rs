use std::net::IpAddr;

// FNV-1a (64-bit) constants. Chosen over std's DefaultHasher, whose algorithm is unspecified across
// Rust releases and would silently remap every client on a toolchain upgrade; FNV-1a is fixed forever.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

// Address-family tags mixed into the hash so an IPv4 address can't collide with an IPv6 one sharing a trailing pattern.
const IPV4_TAG: u8 = 4;
const IPV6_TAG: u8 = 6;

// Fold a byte slice into a running FNV-1a accumulator.
#[inline]
fn fnv1a_update(hash: u64, bytes: &[u8]) -> u64 {
	return bytes
		.iter()
		.fold(hash, |acc, &b| (acc ^ u64::from(b)).wrapping_mul(FNV_PRIME));
}

// Stable 64-bit hash of a (client_ip, backend_id) pair; IPv4-mapped IPv6 is folded to IPv4 first so a
// client sticks to one backend across v4 and dual-stack [::] listeners.
#[inline]
fn hash_pair(client_ip: IpAddr, backend_id: &str) -> u64 {
	let seeded: u64 = match client_ip.to_canonical() {
		IpAddr::V4(v4) => fnv1a_update(fnv1a_update(FNV_OFFSET_BASIS, &[IPV4_TAG]), &v4.octets()),
		IpAddr::V6(v6) => fnv1a_update(fnv1a_update(FNV_OFFSET_BASIS, &[IPV6_TAG]), &v6.octets()),
	};
	return fnv1a_update(seeded, backend_id.as_bytes());
}

// Weighted-rendezvous score for a (client_ip, backend_id) pair; higher = preferred. Logarithmic method:
// map the stable hash to h ∈ (0, 1), then score = -weight / ln(h). Since -ln(h) is Exponential(1), the
// max selects backend i with probability w_i / Σ w_j (so 2:1 gives 2/3 vs 1/3, not the linear method's
// 3/4 vs 1/4). A non-positive weight scores 0.0, treated as ineligible (see `select_backend`).
#[inline]
#[must_use]
pub fn rendezvous_score(client_ip: IpAddr, backend_id: &str, weight: f64) -> f64 {
	if weight <= 0.0 {
		return 0.0;
	}
	let hash: u64 = hash_pair(client_ip, backend_id);

	// Map the hash to the open interval (0, 1): +0.5/+1.0 keep h strictly between 0 and 1 so ln(h) is
	// finite and non-zero. The low-bit precision loss from the u64->f64 cast is irrelevant here.
	#[allow(clippy::as_conversions)]
	let h: f64 = ((hash as f64) + 0.5) / ((u64::MAX as f64) + 1.0);

	return -weight / h.ln();
}

// Best backend index for a client IP via weighted rendezvous hashing. A non-positive weight is ineligible;
// an empty slice or all-ineligible candidates return None so the caller surfaces "no backend available".
#[must_use]
pub fn select_backend(client_ip: IpAddr, backend_ids: &[&str], weights: &[f64]) -> Option<usize> {
	let mut best_index: Option<usize> = None;
	let mut best_score: f64 = f64::NEG_INFINITY;

	for (i, backend_id) in backend_ids.iter().enumerate() {
		let weight: f64 = weights.get(i).copied().unwrap_or(1.0);
		if weight <= 0.0 {
			continue;
		}
		let score: f64 = rendezvous_score(client_ip, backend_id, weight);
		if best_index.is_none() || score > best_score {
			best_score = score;
			best_index = Some(i);
		}
	}

	return best_index;
}

#[cfg(test)]
mod tests {
	use super::*;

	fn test_ip() -> IpAddr {
		return "192.168.1.100".parse().unwrap();
	}

	fn test_backends() -> Vec<&'static str> {
		return vec!["backend-a", "backend-b", "backend-c"];
	}

	#[test]
	fn test_deterministic_selection() {
		let ip: IpAddr = test_ip();
		let backends: Vec<&str> = test_backends();
		let weights: Vec<f64> = vec![1.0, 1.0, 1.0];

		let first: Option<usize> = select_backend(ip, &backends, &weights);
		let second: Option<usize> = select_backend(ip, &backends, &weights);

		assert_eq!(first, second);
	}

	#[test]
	fn test_all_backends_selected_across_ips() {
		let backends: Vec<&str> = test_backends();
		let weights: Vec<f64> = vec![1.0, 1.0, 1.0];

		// Per-backend counts pre-sized to every backend: a never-selected one keeps its zero and fails
		// below (the old HashSet-len check let a starved backend slip through as an absent key).
		let mut counts: Vec<usize> = vec![0; backends.len()];
		for i in 0..100u8 {
			let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
			if let Some(idx) = select_backend(ip, &backends, &weights) {
				counts[idx] += 1;
			}
		}

		for (idx, &count) in counts.iter().enumerate() {
			assert!(count > 0, "backend {idx} was never selected across 100 IPs");
		}
		assert_eq!(counts.iter().sum::<usize>(), 100, "every request resolved to some backend");
	}

	#[test]
	fn test_weight_influences_selection() {
		let backends: Vec<&str> = vec!["heavy", "light"];
		let weights: Vec<f64> = vec![100.0, 0.001];

		let mut heavy_count: usize = 0;
		for i in 0..100u8 {
			let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
			if let Some(0) = select_backend(ip, &backends, &weights) {
				heavy_count += 1;
			}
		}

		assert!(heavy_count > 80, "heavily weighted backend should win most of the time");
	}

	#[test]
	fn test_ipv4_mapped_ipv6_routes_like_bare_ipv4() {
		// Regression: ::ffff:192.168.1.100 must select the same backend/score as 192.168.1.100 (before canonicalizing they split routing).
		let backends: Vec<&str> = test_backends();
		let weights: Vec<f64> = vec![1.0, 1.0, 1.0];
		let bare: IpAddr = "192.168.1.100".parse().unwrap();
		let mapped: IpAddr = "::ffff:192.168.1.100".parse().unwrap();

		assert_eq!(
			rendezvous_score(bare, "backend-a", 1.0),
			rendezvous_score(mapped, "backend-a", 1.0)
		);
		assert_eq!(
			select_backend(bare, &backends, &weights),
			select_backend(mapped, &backends, &weights)
		);
	}

	#[test]
	fn test_empty_backends() {
		let ip: IpAddr = test_ip();
		let result: Option<usize> = select_backend(ip, &[], &[]);
		assert_eq!(result, None);
	}

	#[test]
	fn test_single_backend() {
		let ip: IpAddr = test_ip();
		let backends: Vec<&str> = vec!["only-one"];
		let weights: Vec<f64> = vec![1.0];

		let result: Option<usize> = select_backend(ip, &backends, &weights);
		assert_eq!(result, Some(0));
	}

	#[test]
	fn test_minimal_disruption_on_removal() {
		let ip: IpAddr = test_ip();
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
	}

	#[test]
	fn test_weight_two_to_one_is_proportional_not_linear() {
		// Selection must be proportional to weight: 2:1 yields ~2/3 vs 1/3. The old linear `hash × weight`
		// gave 3/4, so the 0.72 upper bound excludes 0.75 — this passes only for WRH, not the linear formula.
		let backends: Vec<&str> = vec!["heavy", "light"];
		let weights: Vec<f64> = vec![2.0, 1.0];

		let mut heavy_wins: u32 = 0;
		let mut total: u32 = 0;
		for b in 0..8u16 {
			for c in 0..250u16 {
				let ip: IpAddr = format!("10.0.{b}.{c}").parse().unwrap();
				if select_backend(ip, &backends, &weights) == Some(0) {
					heavy_wins += 1;
				}
				total += 1;
			}
		}

		let heavy_fraction: f64 = f64::from(heavy_wins) / f64::from(total);
		const PROPORTIONAL_LOWER: f64 = 0.60;
		const PROPORTIONAL_UPPER: f64 = 0.72; // < 0.75, the fraction the buggy linear formula produced
		assert!(
			heavy_fraction > PROPORTIONAL_LOWER && heavy_fraction < PROPORTIONAL_UPPER,
			"2:1 weighting should select heavy ~2/3 of the time, got {heavy_fraction}"
		);
	}

	#[test]
	fn test_all_zero_weights_selects_none() {
		let ip: IpAddr = test_ip(); // all weights 0 (every backend dead) must yield no selection, not backends[0]
		let backends: Vec<&str> = test_backends();
		let weights: Vec<f64> = vec![0.0, 0.0, 0.0];
		assert_eq!(select_backend(ip, &backends, &weights), None);
	}

	#[test]
	fn test_zero_weight_backend_is_never_selected() {
		// The one live backend among dead ones is always chosen, regardless of hash ordering.
		let backends: Vec<&str> = test_backends();
		let weights: Vec<f64> = vec![0.0, 1.0, 0.0];
		for c in 0..100u8 {
			let ip: IpAddr = format!("10.0.0.{c}").parse().unwrap();
			assert_eq!(select_backend(ip, &backends, &weights), Some(1));
		}
	}
}
