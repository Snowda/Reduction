// Selection through the circuit breakers: the relay paths ask here, so an open backend leaves the client's
// rendezvous ranking and only that backend's clients move.
use super::rendezvous::RendezvousKey;
use super::{BackendPool, MemberSet};
use crate::circuit::{CircuitBreakers, CircuitState, HalfOpenGuard};
use crate::config::{BackendConfig, FailoverMode};
use crate::health::HealthState;

// A backend whose breaker let this client through; `probe` is held for the attempt on a half-open backend.
#[derive(Debug)]
pub struct Admitted<'a> {
	pub backend: &'a BackendConfig,
	pub probe: Option<HalfOpenGuard>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Refused {
	// Nothing to select: the pool is empty, offline, fully pressured, or fully `tried`.
	NoBackend,
	// A candidate exists, but its breaker turned the client away.
	CircuitOpen,
}

impl BackendPool {
	// The client's best backend that is neither in `tried` nor behind an open circuit. Half-open backends rank as
	// usual, so a recovering backend's own clients carry its probes; a refused probe falls to the next backend.
	#[must_use = "a dropped Admitted loses its half-open probe slot"]
	pub fn select_admitted<K, F>(
		&self,
		key: K,
		health: &HealthState,
		pressure_fn: &F,
		circuit: &CircuitBreakers,
		tried: &MemberSet,
	) -> Result<Admitted<'_>, Refused>
	where
		K: RendezvousKey,
		F: Fn(&BackendConfig) -> f64,
	{
		let first: usize = self.best_position(key, health, pressure_fn, tried).ok_or(Refused::NoBackend)?;
		if let Some(admitted) = self.backends.get(first).and_then(|backend: &BackendConfig| admit(backend, circuit)) {
			return Ok(admitted);
		}
		if circuit.failover() == FailoverMode::Pinned {
			return Err(Refused::CircuitOpen);
		}
		return self.next_admitted(key, health, pressure_fn, circuit, *tried, first);
	}

	// Walk the ranking past `refused`. Off the hot path: only clients of an open backend come here.
	#[cold]
	fn next_admitted<K, F>(
		&self,
		key: K,
		health: &HealthState,
		pressure_fn: &F,
		circuit: &CircuitBreakers,
		mut excluded: MemberSet,
		refused: usize,
	) -> Result<Admitted<'_>, Refused>
	where
		K: RendezvousKey,
		F: Fn(&BackendConfig) -> f64,
	{
		excluded.insert(refused);
		while let Some(position) = self.best_position(key, health, pressure_fn, &excluded) {
			if let Some(admitted) = self.backends.get(position).and_then(|backend: &BackendConfig| admit(backend, circuit)) {
				return Ok(admitted);
			}
			excluded.insert(position);
		}
		return Err(Refused::CircuitOpen);
	}
}

// For a relay path that does not weigh connection pressure.
#[must_use]
pub const fn no_pressure(_backend: &BackendConfig) -> f64 {
	return 0.0;
}

fn admit<'a>(backend: &'a BackendConfig, circuit: &CircuitBreakers) -> Option<Admitted<'a>> {
	return match circuit.check(backend.id.as_str()) {
		(CircuitState::Open, _) => None,
		(_, probe) => Some(Admitted { backend, probe }),
	};
}

#[cfg(test)]
mod tests {
	use std::net::{IpAddr, Ipv4Addr};
	use std::num::NonZeroU32;
	use std::result::Result;

	use arrayvec::ArrayString;

	use super::super::testutil::make_backends;
	use super::*;
	use crate::config::{CircuitBreakerConfig, MAX_BACKEND_ID_LEN};
	use crate::fast_hash::FastSet;

	const PEERS: u8 = 200;

	fn pool(count: usize) -> Result<BackendPool, String> {
		return BackendPool::new(make_backends(count)?).map_err(|err| format!("BackendPool::new: {err:?}"));
	}

	fn breakers(failover: FailoverMode, recovery_timeout_secs: u64) -> CircuitBreakers {
		return CircuitBreakers::new(&CircuitBreakerConfig {
			failure_threshold: NonZeroU32::MIN,
			recovery_timeout_secs,
			half_open_max_requests: NonZeroU32::MIN,
			failover,
			..CircuitBreakerConfig::default()
		});
	}

	fn peer(n: u8) -> IpAddr {
		return IpAddr::V4(Ipv4Addr::new(10, 0, 3, n));
	}

	fn pick(pool: &BackendPool, circuit: &CircuitBreakers, ip: IpAddr) -> Result<ArrayString<MAX_BACKEND_ID_LEN>, Refused> {
		return pool
			.select_admitted(ip, &HealthState::new(), &no_pressure, circuit, &MemberSet::EMPTY)
			.map(|admitted| admitted.backend.id);
	}

	fn home(pool: &BackendPool, ip: IpAddr) -> Result<ArrayString<MAX_BACKEND_ID_LEN>, String> {
		return pool
			.select(ip, &HealthState::new())
			.map(|backend| backend.id)
			.ok_or_else(|| String::from("a healthy pool selects a backend"));
	}

	#[test]
	fn all_closed_breakers_match_plain_selection() -> Result<(), String> {
		let pool: BackendPool = pool(4)?;
		let circuit: CircuitBreakers = breakers(FailoverMode::Reselect, 60);
		(0..PEERS).try_for_each(|n| -> Result<(), String> {
			assert_eq!(pick(&pool, &circuit, peer(n)), Ok(home(&pool, peer(n))?), "peer {n} moved with no open circuit");
			return Ok(());
		})?;
		return Ok(());
	}

	// Analytic: an open backend's clients land on their next pick, which is the rendezvous ranking without that
	// backend; every other client stays exactly where it was.
	#[test]
	fn an_open_backend_moves_only_its_own_clients_to_their_next_pick() -> Result<(), String> {
		let pool: BackendPool = pool(3)?;
		let circuit: CircuitBreakers = breakers(FailoverMode::Reselect, 60);
		let dead: ArrayString<MAX_BACKEND_ID_LEN> = pool.backends[0].id;
		circuit.record_failure(dead.as_str());
		let health: HealthState = HealthState::new();
		let without_dead: MemberSet = pool.members_where(|backend: &BackendConfig| backend.id == dead);
		let mut moved: u32 = 0;
		(0..PEERS).try_for_each(|n| -> Result<(), String> {
			let ip: IpAddr = peer(n);
			let was: ArrayString<MAX_BACKEND_ID_LEN> = home(&pool, ip)?;
			let now: Result<ArrayString<MAX_BACKEND_ID_LEN>, Refused> = pick(&pool, &circuit, ip);
			if was == dead {
				moved += 1;
				let next: Option<&BackendConfig> = pool.select_with_pressure_excluding(ip, &health, &no_pressure, &without_dead);
				assert_eq!(now.ok(), next.map(|backend| backend.id), "peer {n} left the ranking");
			} else {
				assert_eq!(now, Ok(was), "peer {n} was not on the open backend");
			}
			return Ok(());
		})?;
		assert!(moved > 0, "the seed must put clients on the open backend, or this proves nothing");
		return Ok(());
	}

	#[test]
	fn pinned_mode_turns_the_open_backends_clients_away() -> Result<(), String> {
		let pool: BackendPool = pool(3)?;
		let circuit: CircuitBreakers = breakers(FailoverMode::Pinned, 60);
		let dead: ArrayString<MAX_BACKEND_ID_LEN> = pool.backends[0].id;
		circuit.record_failure(dead.as_str());
		(0..PEERS).try_for_each(|n| -> Result<(), String> {
			let want: ArrayString<MAX_BACKEND_ID_LEN> = home(&pool, peer(n))?;
			let got: Result<ArrayString<MAX_BACKEND_ID_LEN>, Refused> = pick(&pool, &circuit, peer(n));
			assert_eq!(got, if want == dead { Err(Refused::CircuitOpen) } else { Ok(want) }, "peer {n}");
			return Ok(());
		})?;
		return Ok(());
	}

	#[test]
	fn every_circuit_open_is_refused_not_a_dead_pick() -> Result<(), String> {
		let pool: BackendPool = pool(2)?;
		let circuit: CircuitBreakers = breakers(FailoverMode::Reselect, 60);
		pool.backends.iter().for_each(|backend| circuit.record_failure(backend.id.as_str()));
		assert_eq!(pick(&pool, &circuit, peer(1)), Err(Refused::CircuitOpen));
		return Ok(());
	}

	#[test]
	fn an_empty_pool_is_no_backend() -> Result<(), String> {
		assert_eq!(pick(&pool(0)?, &breakers(FailoverMode::Reselect, 60), peer(1)), Err(Refused::NoBackend));
		return Ok(());
	}

	#[test]
	fn tried_backends_leave_the_ranking_until_none_is_left() -> Result<(), String> {
		let pool: BackendPool = pool(2)?;
		let circuit: CircuitBreakers = breakers(FailoverMode::Reselect, 60);
		let health: HealthState = HealthState::new();
		let ip: IpAddr = peer(1);
		let first: ArrayString<MAX_BACKEND_ID_LEN> = home(&pool, ip)?;
		let mut tried: MemberSet = MemberSet::EMPTY;
		pool.mark(&mut tried, first.as_str());
		let second = pool
			.select_admitted(ip, &health, &no_pressure, &circuit, &tried)
			.map(|admitted| admitted.backend.id);
		let other: ArrayString<MAX_BACKEND_ID_LEN> = second.map_err(|err| format!("the sibling must admit: {err:?}"))?;
		assert_ne!(other, first);
		pool.mark(&mut tried, other.as_str());
		let none: Result<Admitted<'_>, Refused> = pool.select_admitted(ip, &health, &no_pressure, &circuit, &tried);
		assert_eq!(none.err(), Some(Refused::NoBackend));
		return Ok(());
	}

	// Past the recovery window one client takes the probe; the rest of the backend's clients keep their next
	// pick until the probe closes the circuit. Without the guard path, a half-open backend would take them all.
	#[test]
	fn a_half_open_backend_takes_one_probe_and_its_other_clients_stay_moved() -> Result<(), String> {
		let pool: BackendPool = pool(3)?;
		let circuit: CircuitBreakers = breakers(FailoverMode::Reselect, 0);
		let dead: ArrayString<MAX_BACKEND_ID_LEN> = pool.backends[0].id;
		circuit.record_failure(dead.as_str());
		let health: HealthState = HealthState::new();
		let clients: Vec<IpAddr> = (0..PEERS).map(peer).filter(|ip| pool.select(*ip, &health).is_some_and(|b| b.id == dead)).collect();
		assert!(clients.len() >= 2, "the probe check needs two clients on the backend");

		let probe = pool
			.select_admitted(clients[0], &health, &no_pressure, &circuit, &MemberSet::EMPTY)
			.map_err(|err| format!("the first client must probe: {err:?}"))?;
		assert_eq!(probe.backend.id, dead);
		assert!(probe.probe.is_some(), "a half-open pick carries its slot");
		let bystanders: FastSet<ArrayString<MAX_BACKEND_ID_LEN>> =
			clients[1..].iter().filter_map(|ip| pick(&pool, &circuit, *ip).ok()).collect();
		assert!(!bystanders.is_empty() && !bystanders.contains(&dead), "probe slots are spent: {bystanders:?}");

		circuit.record_success(dead.as_str());
		drop(probe);
		assert!(clients.iter().all(|ip| pick(&pool, &circuit, *ip) == Ok(dead)), "a closed circuit takes them all back");
		return Ok(());
	}
}
