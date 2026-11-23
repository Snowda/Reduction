pub mod admit;
pub mod members;
pub mod queue;
pub mod rendezvous;
// Pool construction and the backend-count caps live in a submodule.
mod limits;
#[cfg(test)]
mod testutil;

use std::net::IpAddr;
use std::sync::Arc;

use arrayvec::{ArrayString, ArrayVec};
pub use members::MemberSet;
pub use queue::RequestQueue;
use rendezvous::{RendezvousKey, mixed_score, rendezvous_score};

use crate::config::{BackendConfig, MAX_BACKEND_ID_LEN, PoolAffinity, SplitTarget};
use crate::health::HealthState;

// HARD_MAX_BACKENDS as a usize capacity. A const context cannot convert u32 -> usize without `as`,
// so the value is written out; the test `max_backends_matches_hard_limit` keeps the two equal.
pub const MAX_BACKENDS: usize = 256;

#[derive(Debug, Clone)]
pub struct BackendPool {
	pub backends: Arc<[BackendConfig]>,
	// From `[[http_pool]]`: the key a request sticks by, and whether load may move it.
	pub affinity: PoolAffinity,
}

impl BackendPool {
	#[must_use]
	pub const fn with_affinity(mut self, affinity: PoolAffinity) -> Self {
		self.affinity = affinity;
		return self;
	}

	#[must_use]
	#[tracing::instrument(level = "debug", skip_all)]
	pub fn select(&self, client_ip: IpAddr, health: &HealthState) -> Option<&BackendConfig> {
		return self.select_with_pressure(client_ip, health, &|_| 0.0);
	}

	// `key` is what a client sticks by: its IP, or an `IdentityKey` for identity affinity.
	#[must_use]
	#[tracing::instrument(level = "debug", skip_all)]
	pub fn select_with_pressure<K, F>(&self, key: K, health: &HealthState, pressure_fn: &F) -> Option<&BackendConfig>
	where
		K: RendezvousKey,
		F: Fn(&BackendConfig) -> f64,
	{
		return self.select_with_pressure_excluding(key, health, pressure_fn, &MemberSet::EMPTY);
	}

	// Like `select_with_pressure` but skips every member in `excluded`. None = every backend excluded
	// or the pool is empty (out of untried backends, not a leftover pick). An empty `excluded` changes nothing.
	#[must_use]
	#[tracing::instrument(level = "debug", skip_all)]
	pub fn select_with_pressure_excluding<K, F>(
		&self,
		key: K,
		health: &HealthState,
		pressure_fn: &F,
		excluded: &MemberSet,
	) -> Option<&BackendConfig>
	where
		K: RendezvousKey,
		F: Fn(&BackendConfig) -> f64,
	{
		return self.best_position(key, health, pressure_fn, excluded).and_then(|i: usize| self.backends.get(i));
	}

	// The position `select_with_pressure_excluding` picks.
	fn best_position<K, F>(&self, key: K, health: &HealthState, pressure_fn: &F, excluded: &MemberSet) -> Option<usize>
	where
		K: RendezvousKey,
		F: Fn(&BackendConfig) -> f64,
	{
		if self.backends.is_empty() {
			return None;
		}

		let ids: ArrayVec<&str, MAX_BACKENDS> = self.backends.iter().map(|b| b.id.as_str()).collect();
		let weights: ArrayVec<f64, MAX_BACKENDS> = self.scored_weights(health, pressure_fn, &ids);
		// A path_segment pool is new, so it can take the finalized hash without a client moving.
		let score_of: fn(K, &str, f64) -> f64 = if self.affinity.is_path_segment() { mixed_score } else { rendezvous_score };

		// Highest score wins; ties keep the earlier index, as in `rendezvous::select_backend`. A weight <= 0
		// (offline or fully pressured) is ineligible. With no candidate left, best_index stays None and
		// the caller returns 503 instead of a dead backend.
		let best: Option<(usize, f64)> = ids.iter().enumerate().fold(None, |best: Option<(usize, f64)>, (i, id)| {
			if weights[i] <= 0.0 || excluded.contains(i) {
				return best;
			}
			let score: f64 = score_of(key, id, weights[i]);
			return if best.is_none_or(|(_, top): (usize, f64)| score > top) { Some((i, score)) } else { best };
		});

		return best.map(|(i, _): (usize, f64)| i);
	}

	// Base weight × health factor × (1 − connection pressure) — the per-backend weight the rendezvous
	// score is computed from. A backend that is offline (health factor 0) or fully pressured yields 0,
	// which `select_with_pressure_excluding` treats as ineligible.
	// A path_segment pool uses the base weight while online: load must not move an object to another member (F13).
	fn scored_weights<F>(&self, health: &HealthState, pressure_fn: &F, ids: &[&str]) -> ArrayVec<f64, MAX_BACKENDS>
	where
		F: Fn(&BackendConfig) -> f64,
	{
		let is_pinned: bool = self.affinity.is_path_segment();
		return self
			.backends
			.iter()
			.zip(ids.iter())
			.map(|(b, id)| {
				if is_pinned {
					return if health.is_online(id) { b.weight } else { 0.0 };
				}
				let health_weight: f64 = b.weight * health.weight_factor(id);
				let pressure: f64 = pressure_fn(b).clamp(0.0, 1.0);
				health_weight * (1.0 - pressure)
			})
			.collect();
	}
}

// Stage 1 of a split: the variant pool for `key`, by weight alone. Health and pressure must stay out: if they steer
// stage 1, a canary that fails gets less than its share, and its failures do not show.
// None when no variant has a positive weight. The first variant wins a tie, as in `rendezvous::select_backend`.
#[must_use]
pub fn select_variant<K: RendezvousKey>(key: K, variants: &[SplitTarget]) -> Option<&ArrayString<MAX_BACKEND_ID_LEN>> {
	return select_variant_where(key, variants, |_| true);
}

// `select_variant` over the variants whose pool passes `is_eligible`. The scores do not change, so the result is
// the choice stage 1 makes with the other variants removed.
#[must_use]
pub fn select_variant_where<K: RendezvousKey>(
	key: K,
	variants: &[SplitTarget],
	is_eligible: impl Fn(&str) -> bool,
) -> Option<&ArrayString<MAX_BACKEND_ID_LEN>> {
	return variants
		.iter()
		.filter(|variant| variant.weight > 0.0 && is_eligible(variant.backend_id.as_str()))
		.fold(None, |best: Option<(f64, &SplitTarget)>, variant| {
			let score: f64 = mixed_score(key, variant.backend_id.as_str(), variant.weight);
			return match best {
				Some((best_score, _)) if best_score >= score => best,
				_ => Some((score, variant)),
			};
		})
		.map(|(_, variant)| &variant.backend_id);
}

#[cfg(test)]
mod tests {
	use std::fmt::Debug;
	use std::result::Result;
	use std::str::FromStr;

	use arrayvec::ArrayString;

	use std::net::SocketAddr;

	use crate::fast_hash::FastMap;
	use super::rendezvous::{IdentityKey, PathSegmentKey, select_backend};
	use super::testutil::make_backends;
	use super::*;
	use crate::config::TransportKind;
	use crate::health::state::{Availability, BackendHealth, HealthBroadcast};

	// The split tests: device ids judged against a 4-sigma binomial band.
	const DEVICES: u32 = 10_000;
	const SIGMAS: f64 = 4.0;
	const REPEATS: u32 = 1_000;
	// Twice the 10% that a 90/10 to 80/20 reweight hands over: a bucket scheme that remaps the fleet passes it.
	const CHURN_LIMIT: f64 = 0.2;
	const FIRST_PORT: u16 = 9200;
	// The pressure and the reported health that the F13 tests put on one member: high, but not offline.
	const HOT: f64 = 0.9;
	const LOADED: f64 = 0.7;
	const SLOW_MS: u32 = 10_000;

	fn parsed<T: FromStr>(s: &str) -> Result<T, String>
	where
		T::Err: Debug,
	{
		return s.parse().map_err(|err| format!("parse {s:?}: {err:?}"));
	}

	fn id(s: &str) -> Result<ArrayString<MAX_BACKEND_ID_LEN>, String> {
		return ArrayString::from(s).map_err(|err| format!("ArrayString::from({s:?}): {err:?}"));
	}

	fn pool(backends: Vec<BackendConfig>) -> Result<BackendPool, String> {
		return BackendPool::new(backends).map_err(|err| format!("BackendPool::new: {err:?}"));
	}

	#[test]
	fn test_pool_select_deterministic() -> Result<(), String> {
		let pool: BackendPool = pool(make_backends(3)?)?;
		let health: HealthState = HealthState::new();
		let ip: IpAddr = parsed("192.168.1.1")?;

		let first: Option<&BackendConfig> = pool.select(ip, &health);
		let second: Option<&BackendConfig> = pool.select(ip, &health);

		assert_eq!(first.map(|b| &b.id), second.map(|b| &b.id));
		return Ok(());
	}

	#[test]
	fn test_pool_empty_backends() -> Result<(), String> {
		let pool: BackendPool = pool(vec![])?;
		let health: HealthState = HealthState::new();
		let ip: IpAddr = parsed("10.0.0.1")?;

		assert!(pool.select(ip, &health).is_none());
		return Ok(());
	}

	#[test]
	fn test_pool_distributes_across_backends() -> Result<(), String> {
		let pool: BackendPool = pool(make_backends(3)?)?;
		let health: HealthState = HealthState::new();
		let mut counts: FastMap<ArrayString<MAX_BACKEND_ID_LEN>, usize> = FastMap::default();

		(0..200u8).try_for_each(|i| -> Result<(), String> {
			let ip: IpAddr = parsed(&format!("10.0.{}.{}", i / 50, i % 50))?;
			if let Some(b) = pool.select(ip, &health) {
				*counts.entry(b.id).or_insert(0) += 1;
			}
			return Ok(());
		})?;

		counts.values().for_each(|count| assert!(*count > 0, "at least one backend got zero traffic"));
		return Ok(());
	}

	#[test]
	fn test_pool_respects_health_unavailable() -> Result<(), String> {
		let mut health: HealthState = HealthState::new();
		health.update(HealthBroadcast {
			entries: vec![
				BackendHealth {
					backend_id: id("backend-0")?,
					load: 0.0,
					latency_ms: 10,
					availability: Availability::Offline,
				},
				BackendHealth {
					backend_id: id("backend-1")?,
					load: 0.1,
					latency_ms: 10,
					availability: Availability::Online,
				},
			],
		});

		let pool: BackendPool = pool(make_backends(2)?)?;

		(0..50u8).try_for_each(|i| -> Result<(), String> {
			let ip: IpAddr = parsed(&format!("10.0.0.{i}"))?;
			let selected: &BackendConfig = pool.select(ip, &health)
				.ok_or_else(|| String::from("pool.select(ip, &health) is None"))?;
			assert_eq!(selected.id.as_str(), "backend-1");
			return Ok(());
		})?;
		return Ok(());
	}

	#[test]
	fn test_pool_all_offline_returns_none() -> Result<(), String> {
		// Every backend offline drives all effective weights to 0; the pool must return None (→ 503)
		// rather than latching onto backends[0].
		let mut health: HealthState = HealthState::new();
		health.update(HealthBroadcast {
			entries: vec![
				BackendHealth {
					backend_id: id("backend-0")?,
					load: 0.0,
					latency_ms: 10,
					availability: Availability::Offline,
				},
				BackendHealth {
					backend_id: id("backend-1")?,
					load: 0.0,
					latency_ms: 10,
					availability: Availability::Offline,
				},
			],
		});

		let pool: BackendPool = pool(make_backends(2)?)?;
		(0..50u8).try_for_each(|i| -> Result<(), String> {
			let ip: IpAddr = parsed(&format!("10.0.0.{i}"))?;
			assert!(
				pool.select(ip, &health).is_none(),
				"all-offline pool selected a backend for ip {i}"
			);
			return Ok(());
		})?;
		return Ok(());
	}

	#[test]
	fn test_pool_full_pressure_on_all_returns_none() -> Result<(), String> {
		// Full connection pressure on every backend zeroes all weights → no selection.
		let pool: BackendPool = pool(make_backends(3)?)?;
		let health: HealthState = HealthState::new();
		let ip: IpAddr = parsed("10.0.0.7")?;
		assert!(pool.select_with_pressure(ip, &health, &|_| 1.0).is_none());
		return Ok(());
	}

	#[test]
	fn test_pressure_steers_away_from_loaded_backend() -> Result<(), String> {
		let pool: BackendPool = pool(make_backends(2)?)?;
		let health: HealthState = HealthState::new();

		let pressure_fn = |b: &BackendConfig| -> f64 { if b.id.as_str() == "backend-0" { 0.95 } else { 0.0 } };

		let mut backend_1_count: usize = 0;
		(0..100u8).try_for_each(|i| -> Result<(), String> {
			let ip: IpAddr = parsed(&format!("10.0.0.{i}"))?;
			if let Some(b) = pool.select_with_pressure(ip, &health, &pressure_fn)
				&& b.id.as_str() == "backend-1"
			{
				backend_1_count += 1;
			}
			return Ok(());
		})?;
		assert!(
			backend_1_count > 80,
			"expected backend-1 to receive majority of traffic, got {backend_1_count}/100"
		);
		return Ok(());
	}

	#[test]
	fn test_exclude_empty_matches_select_with_pressure() -> Result<(), String> {
		let pool: BackendPool = pool(make_backends(4)?)?;
		let health: HealthState = HealthState::new();
		(0..64u8).try_for_each(|i| -> Result<(), String> {
			let ip: IpAddr = parsed(&format!("10.0.0.{i}"))?;
			let base: Option<&BackendConfig> = pool.select_with_pressure(ip, &health, &|_| 0.0);
			let excl: Option<&BackendConfig> = pool.select_with_pressure_excluding(ip, &health, &|_| 0.0, &MemberSet::EMPTY);
			assert_eq!(base.map(|b| b.id), excl.map(|b| b.id), "ip {i} diverged");
			return Ok(());
		})?;
		return Ok(());
	}

	#[test]
	fn test_exclude_steers_to_other_backend() -> Result<(), String> {
		let pool: BackendPool = pool(make_backends(3)?)?;
		let health: HealthState = HealthState::new();
		let ip: IpAddr = parsed("192.168.1.1")?;

		let chosen: ArrayString<MAX_BACKEND_ID_LEN> = (pool.select_with_pressure(ip, &health, &|_| 0.0)
			.ok_or_else(|| String::from("pool.select_with_pressure(ip, &health, &|_| 0.0) is None"))?)
		.id;
		let without_chosen: MemberSet = pool.members_where(|b: &BackendConfig| b.id == chosen);
		let after: ArrayString<MAX_BACKEND_ID_LEN> = pool
			.select_with_pressure_excluding(ip, &health, &|_| 0.0, &without_chosen)
			.ok_or("a pool of three keeps two members after one is excluded")?
			.id;
		assert_ne!(after, chosen, "excluded backend was reselected");
		return Ok(());
	}

	#[test]
	fn test_exclude_all_returns_none() -> Result<(), String> {
		let pool: BackendPool = pool(make_backends(2)?)?;
		let health: HealthState = HealthState::new();
		let ip: IpAddr = parsed("10.0.0.5")?;

		let all: MemberSet = pool.members_where(|_| true);
		assert!(
			pool.select_with_pressure_excluding(ip, &health, &|_| 0.0, &all)
				.is_none()
		);
		return Ok(());
	}

	// ── F13: a path_segment pool weighs members by membership and health only ──

	// The member each of DEVICES object ids picks under `pressure` and `health`.
	fn object_picks<F: Fn(&BackendConfig) -> f64>(
		pool: &BackendPool,
		health: &HealthState,
		pressure: &F,
	) -> Result<Vec<ArrayString<MAX_BACKEND_ID_LEN>>, String> {
		return (0..DEVICES)
			.map(|n| -> Result<ArrayString<MAX_BACKEND_ID_LEN>, String> {
				let object: String = format!("obj-{n:05}");
				let key: PathSegmentKey = PathSegmentKey::new(object.as_bytes());
				return pool.select_with_pressure(key, health, pressure).map(|b| b.id).ok_or_else(|| format!("{object}: no member"));
			})
			.collect();
	}

	fn moved(before: &[ArrayString<MAX_BACKEND_ID_LEN>], after: &[ArrayString<MAX_BACKEND_ID_LEN>]) -> usize {
		return before.iter().zip(after).filter(|(old, new)| old != new).count();
	}

	// `backend-1` reports high load and a latency far over the threshold, but stays online.
	fn loaded_but_online() -> Result<HealthState, String> {
		let mut health: HealthState = HealthState::new();
		health.update(HealthBroadcast {
			entries: vec![BackendHealth {
				backend_id: id("backend-1")?,
				load: LOADED,
				latency_ms: SLOW_MS,
				availability: Availability::Online,
			}],
		});
		return Ok(health);
	}

	// Check (2): no pressure pattern and no reported load moves an id on a path_segment pool. The control, the same
	// ids and members on a pool with the default affinity, moves ids under each one.
	#[test]
	fn pressure_and_load_never_move_an_id_on_a_path_segment_pool() -> Result<(), String> {
		let pinned: BackendPool = pool(make_backends(3)?)?.with_affinity(PoolAffinity::PathSegment(0));
		let control: BackendPool = pool(make_backends(3)?)?;
		let idle: HealthState = HealthState::new();
		let baseline: Vec<ArrayString<MAX_BACKEND_ID_LEN>> = object_picks(&pinned, &idle, &|_| 0.0)?;
		let control_baseline: Vec<ArrayString<MAX_BACKEND_ID_LEN>> = object_picks(&control, &idle, &|_| 0.0)?;
		let hot_member = |b: &BackendConfig| -> f64 { if b.id.as_str() == "backend-0" { HOT } else { 0.0 } };
		let graded = |b: &BackendConfig| -> f64 {
			return match b.id.as_str() {
				"backend-0" => 0.2,
				"backend-1" => 0.5,
				_ => 0.8,
			};
		};
		let loaded: HealthState = loaded_but_online()?;
		let cases: [(&str, Vec<ArrayString<MAX_BACKEND_ID_LEN>>, Vec<ArrayString<MAX_BACKEND_ID_LEN>>); 3] = [
			("one hot member", object_picks(&pinned, &idle, &hot_member)?, object_picks(&control, &idle, &hot_member)?),
			("graded pressure", object_picks(&pinned, &idle, &graded)?, object_picks(&control, &idle, &graded)?),
			("reported load", object_picks(&pinned, &loaded, &|_| 0.0)?, object_picks(&control, &loaded, &|_| 0.0)?),
		];
		cases.iter().for_each(|(case, on_pinned, on_control)| {
			assert_eq!(moved(&baseline, on_pinned), 0, "{case}: an id moved on the path_segment pool");
			assert!(moved(&control_baseline, on_control) > 0, "control, {case}: the default pool must move ids, or the case tests nothing");
		});
		return Ok(());
	}

	// Health still counts: an offline member's ids move to the others, and no other id moves.
	#[test]
	fn an_offline_member_moves_only_its_own_ids_on_a_path_segment_pool() -> Result<(), String> {
		let pinned: BackendPool = pool(make_backends(3)?)?.with_affinity(PoolAffinity::PathSegment(0));
		let baseline: Vec<ArrayString<MAX_BACKEND_ID_LEN>> = object_picks(&pinned, &HealthState::new(), &|_| 0.0)?;
		let mut down: HealthState = HealthState::new();
		down.update(HealthBroadcast {
			entries: vec![BackendHealth { backend_id: id("backend-2")?, load: 0.0, latency_ms: 0, availability: Availability::Offline }],
		});
		let after: Vec<ArrayString<MAX_BACKEND_ID_LEN>> = object_picks(&pinned, &down, &|_| 0.0)?;
		baseline.iter().zip(&after).for_each(|(old, new)| {
			assert_ne!(new.as_str(), "backend-2", "an offline member takes no id");
			assert!(old.as_str() == "backend-2" || old == new, "an id on a live member moved: {old} -> {new}");
		});
		assert!(moved(&baseline, &after) > 0, "the offline member held ids, and they moved");
		return Ok(());
	}

	#[test]
	fn test_zero_pressure_matches_select() -> Result<(), String> {
		let pool: BackendPool = pool(make_backends(3)?)?;
		let health: HealthState = HealthState::new();
		let ip: IpAddr = parsed("192.168.1.1")?;

		let normal: Option<&BackendConfig> = pool.select(ip, &health);
		let with_zero: Option<&BackendConfig> = pool.select_with_pressure(ip, &health, &|_| 0.0);

		assert_eq!(normal.map(|b| &b.id), with_zero.map(|b| &b.id));
		return Ok(());
	}

	// ── select_variant: stage 1 of a split ──


	fn split(pairs: &[(&str, f64)]) -> Result<Vec<SplitTarget>, String> {
		return pairs
			.iter()
			.map(|(pool, weight)| -> Result<SplitTarget, String> {
				return Ok(SplitTarget { backend_id: id(pool)?, weight: *weight });
			})
			.collect();
	}

	fn device(n: u32) -> String {
		return format!("device-{n:05}");
	}

	// The pool stage 1 picks for each of the DEVICES device ids, in order.
	fn picks(variants: &[SplitTarget]) -> Result<Vec<ArrayString<MAX_BACKEND_ID_LEN>>, String> {
		return (0..DEVICES)
			.map(|n| -> Result<ArrayString<MAX_BACKEND_ID_LEN>, String> {
				let name: String = device(n);
				return select_variant(IdentityKey(&name), variants)
					.copied()
					.ok_or_else(|| format!("{name}: a positive weight always picks a variant"));
			})
			.collect();
	}

	fn share_of(picked: &[ArrayString<MAX_BACKEND_ID_LEN>], pool: &str) -> f64 {
		let hits: u32 = picked.iter().fold(0, |hits, chosen| hits + u32::from(chosen.as_str() == pool));
		return f64::from(hits) / f64::from(DEVICES);
	}

	// SIGMAS standard deviations of a binomial share `p` over DEVICES trials.
	fn band(p: f64) -> f64 {
		return SIGMAS * (p * (1.0 - p) / f64::from(DEVICES)).sqrt();
	}

	// Check 2: the canary share converges on weight / total, at four splits.
	#[test]
	fn a_split_gives_each_variant_its_weighted_share() -> Result<(), String> {
		return [(90.0, 10.0), (80.0, 20.0), (50.0, 50.0), (99.0, 1.0)].iter().try_for_each(|(stable, canary)| -> Result<(), String> {
			let expected: f64 = canary / (stable + canary);
			let observed: f64 = share_of(&picks(&split(&[("stable", *stable), ("canary", *canary)])?)?, "canary");
			assert!(
				(observed - expected).abs() <= band(expected),
				"{stable}/{canary}: canary share {observed}, expected {expected} ± {}",
				band(expected)
			);
			return Ok(());
		});
	}

	// Weights are relative: 9/1 sends every device where 90/10 sends it.
	#[test]
	fn only_the_ratio_of_the_weights_matters() -> Result<(), String> {
		assert_eq!(picks(&split(&[("stable", 90.0), ("canary", 10.0)])?)?, picks(&split(&[("stable", 9.0), ("canary", 1.0)])?)?);
		return Ok(());
	}

	// Check 3: a reweight from 90/10 to 80/20 moves about the 10% that changed hands, and only toward the canary.
	// A modulo or cumulative-range bucket remaps far more and fails the hard limit.
	#[test]
	fn a_reweight_moves_only_the_share_that_changed() -> Result<(), String> {
		let before: Vec<ArrayString<MAX_BACKEND_ID_LEN>> = picks(&split(&[("stable", 90.0), ("canary", 10.0)])?)?;
		let after: Vec<ArrayString<MAX_BACKEND_ID_LEN>> = picks(&split(&[("stable", 80.0), ("canary", 20.0)])?)?;
		let moved: Vec<(&str, &str)> =
			before.iter().zip(after.iter()).filter(|(old, new)| old != new).map(|(old, new)| (old.as_str(), new.as_str())).collect();
		let churn: f64 = f64::from(u32::try_from(moved.len()).map_err(|err| format!("{err}"))?) / f64::from(DEVICES);
		let delta: f64 = 0.1;
		assert!((churn - delta).abs() <= band(delta), "churn {churn}, expected {delta} ± {}", band(delta));
		assert!(churn < CHURN_LIMIT, "churn {churn}: a reweight must not remap the fleet");
		assert!(moved.iter().all(|(old, new)| (*old, *new) == ("stable", "canary")), "a device left the canary as its weight rose");
		return Ok(());
	}

	// Checks 4 and 5: a zero weight gets no device, 100/0 matches a plain target, and the answer does not change.
	#[test]
	fn a_zero_weight_gets_nothing_and_the_choice_is_stable() -> Result<(), String> {
		let finished: Vec<SplitTarget> = split(&[("stable", 100.0), ("canary", 0.0)])?;
		let picked: Vec<ArrayString<MAX_BACKEND_ID_LEN>> = picks(&finished)?;
		assert_eq!(share_of(&picked, "canary"), 0.0, "a zero weight is ineligible");
		assert_eq!(share_of(&picked, "stable"), 1.0, "100/0 sends every device where a plain backend_id does");
		assert_eq!(select_variant(IdentityKey("x"), &split(&[("stable", 0.0), ("canary", 0.0)])?), None);
		assert_eq!(select_variant(IdentityKey("x"), &[]), None);
		let live: Vec<SplitTarget> = split(&[("stable", 90.0), ("canary", 10.0)])?;
		let first: Option<ArrayString<MAX_BACKEND_ID_LEN>> = select_variant(IdentityKey("device-00042"), &live).copied();
		assert!((0..REPEATS).all(|_| select_variant(IdentityKey("device-00042"), &live).copied() == first));
		return Ok(());
	}

	// A member named after its pool has the FNV hash of that pool's stage-1 entry. Without the finalizer, the devices
	// that stage 1 sends to "stable" then favor that member: 66.6% against 49.8% over all devices.
	// The invariant: a member's share among the devices its variant took equals its share over all devices.
	#[test]
	fn the_variant_choice_does_not_skew_the_backend_choice_inside_it() -> Result<(), String> {
		let names: [&str; 4] = ["stable", "stable-b", "stable-c", "stable-d"];
		let members: Vec<BackendConfig> = names
			.iter()
			.zip(FIRST_PORT..)
			.map(|(name, port)| -> Result<BackendConfig, String> {
				let addr: SocketAddr = SocketAddr::from(([10, 0, 0, 1], port));
				return BackendConfig::new(name, addr, 1.0, TransportKind::Tcp)
					.and_then(|b| b.with_pool("stable"))
					.map_err(|err| format!("{name}: {err:?}"));
			})
			.collect::<Result<_, _>>()?;
		let stable: BackendPool = pool(members)?;
		let health: HealthState = HealthState::new();
		let variants: Vec<SplitTarget> = split(&[("stable", 1.0), ("canary", 1.0)])?;
		// The namesake's share among the devices that `takes` sends to "stable".
		let namesake_share = |takes: &dyn Fn(IdentityKey<'_>) -> bool| -> Result<f64, String> {
			let (taken, namesake): (u32, u32) = (0..DEVICES).try_fold((0, 0), |(taken, namesake), n| -> Result<(u32, u32), String> {
				let name: String = device(n);
				let key: IdentityKey<'_> = IdentityKey(&name);
				if !takes(key) {
					return Ok((taken, namesake));
				}
				let member: &BackendConfig = stable.select_with_pressure(key, &health, &|_| 0.0).ok_or("a healthy pool picks")?;
				return Ok((taken + 1, namesake + u32::from(member.id.as_str() == "stable")));
			})?;
			return Ok(f64::from(namesake) / f64::from(taken));
		};
		let overall: f64 = namesake_share(&|_| true)?;
		let finalized: f64 = namesake_share(&|key| select_variant(key, &variants).is_some_and(|pool| pool.as_str() == "stable"))?;
		let plain: f64 = namesake_share(&|key| select_backend(key, &["stable", "canary"], &[1.0, 1.0]) == Some(0))?;
		// About half the devices reach the variant.
		let width: f64 = SIGMAS * (overall * (1.0 - overall) / (f64::from(DEVICES) / 2.0)).sqrt();
		assert!((finalized - overall).abs() <= width, "namesake share {finalized} inside its variant, {overall} overall ± {width}");
		assert!((plain - overall).abs() > width, "control: plain FNV gives {plain} inside the variant, {overall} overall");
		return Ok(());
	}

}
