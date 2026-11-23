// A set of positions in one BackendPool: the members a request tried, or a walk must skip.
use super::{BackendPool, MAX_BACKENDS};
use crate::config::BackendConfig;

const WORD_BITS: usize = 64;
const WORDS: usize = MAX_BACKENDS.div_ceil(WORD_BITS);

// One bit per pool position, so a set over MAX_BACKENDS members is 32 B and needs no heap.
// A position is only meaningful against the pool it came from: keep that pool for the whole walk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemberSet([u64; WORDS]);

impl MemberSet {
	pub const EMPTY: Self = Self([0; WORDS]);

	#[must_use]
	pub fn is_empty(&self) -> bool {
		return self.0.iter().all(|word: &u64| *word == 0);
	}

	#[must_use]
	pub fn contains(&self, position: usize) -> bool {
		return self.0.get(position / WORD_BITS).is_some_and(|word: &u64| word & bit(position) != 0);
	}

	// A pool holds at most MAX_BACKENDS members, so a position past it names no member and is not kept.
	pub fn insert(&mut self, position: usize) {
		if let Some(word) = self.0.get_mut(position / WORD_BITS) {
			*word |= bit(position);
		}
	}
}

const fn bit(position: usize) -> u64 {
	return 1 << (position % WORD_BITS);
}

impl BackendPool {
	#[must_use]
	pub fn position(&self, id: &str) -> Option<usize> {
		return self.backends.iter().position(|backend: &BackendConfig| backend.id.as_str() == id);
	}

	// Add the member named `id`. An id this pool does not hold is never selected from it, so it is not kept.
	pub fn mark(&self, set: &mut MemberSet, id: &str) {
		if let Some(position) = self.position(id) {
			set.insert(position);
		}
	}

	#[must_use]
	pub fn members_where(&self, is_member: impl Fn(&BackendConfig) -> bool) -> MemberSet {
		return self.backends.iter().enumerate().filter(|(_, backend)| is_member(backend)).fold(
			MemberSet::EMPTY,
			|mut set: MemberSet, (position, _)| {
				set.insert(position);
				return set;
			},
		);
	}
}

#[cfg(test)]
mod tests {
	use std::mem::size_of;
	use std::result::Result;

	use super::super::testutil::make_backends;
	use super::*;
	use crate::config::HARD_MAX_BACKENDS;

	fn pool(count: usize) -> Result<BackendPool, String> {
		return BackendPool::with_max(make_backends(count)?, HARD_MAX_BACKENDS).map_err(|err| format!("pool: {err:?}"));
	}

	#[test]
	fn every_position_of_a_full_pool_has_its_own_bit() {
		(0..MAX_BACKENDS).for_each(|position: usize| {
			let mut set: MemberSet = MemberSet::EMPTY;
			set.insert(position);
			let held: Vec<usize> = (0..MAX_BACKENDS).filter(|other: &usize| set.contains(*other)).collect();
			assert_eq!(held, [position], "position {position} must set only its own bit");
		});
	}

	#[test]
	fn a_set_is_32_bytes_and_a_position_past_the_cap_is_not_kept() {
		assert_eq!(size_of::<MemberSet>(), 32, "four words cover MAX_BACKENDS");
		let mut set: MemberSet = MemberSet::EMPTY;
		set.insert(MAX_BACKENDS);
		assert!(set.is_empty(), "no member sits past MAX_BACKENDS");
		assert!(!set.contains(MAX_BACKENDS));
	}

	#[test]
	fn inserting_twice_keeps_one_member() {
		let mut once: MemberSet = MemberSet::EMPTY;
		once.insert(7);
		let mut twice: MemberSet = once;
		twice.insert(7);
		assert_eq!(once, twice, "a set has no duplicates");
		assert!(!once.is_empty());
	}

	#[test]
	fn mark_and_members_where_name_the_same_positions() -> Result<(), String> {
		let pool: BackendPool = pool(MAX_BACKENDS)?;
		let last: &str = pool.backends.last().map(|backend: &BackendConfig| backend.id.as_str()).ok_or("a full pool has a last member")?;
		let mut marked: MemberSet = MemberSet::EMPTY;
		pool.mark(&mut marked, "backend-0");
		pool.mark(&mut marked, last);
		pool.mark(&mut marked, "not-in-the-pool");
		let selected: MemberSet = pool.members_where(|backend: &BackendConfig| backend.id.as_str() == "backend-0" || backend.id.as_str() == last);
		assert_eq!(marked, selected);
		assert!(marked.contains(0) && marked.contains(MAX_BACKENDS - 1));
		assert_eq!((0..MAX_BACKENDS).filter(|position: &usize| marked.contains(*position)).count(), 2, "an unknown id adds nothing");
		return Ok(());
	}
}
