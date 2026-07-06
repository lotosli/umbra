//! Bounded replay cache for REALITY tokens.

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
};

use crate::RealityError;

/// Capacity and TTL bounded replay cache.
pub struct ReplayCache {
    capacity: usize,
    ttl_secs: u64,
    state: Mutex<ReplayState>,
}

#[derive(Default)]
struct ReplayState {
    entries: HashMap<[u8; 32], u64>,
    order: VecDeque<([u8; 32], u64)>,
}

impl ReplayCache {
    /// Create a replay cache with a fixed capacity and TTL in seconds.
    pub fn new(capacity: usize, ttl_secs: u64) -> Result<Self, RealityError> {
        if capacity == 0 {
            return Err(RealityError::InvalidReplayCapacity);
        }
        Ok(Self {
            capacity,
            ttl_secs,
            state: Mutex::new(ReplayState::default()),
        })
    }

    /// Insert a key or return replay if it is still active.
    pub fn insert_or_reject(&self, key: [u8; 32], now: u64) -> Result<(), RealityError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RealityError::ReplayCachePoisoned)?;
        cleanup_locked(&mut state, now, self.ttl_secs);
        if state.entries.contains_key(&key) {
            return Err(RealityError::Replay);
        }
        state.entries.insert(key, now);
        state.order.push_back((key, now));
        while state.entries.len() > self.capacity {
            let Some((old_key, old_seen)) = state.order.pop_front() else {
                break;
            };
            if state.entries.get(&old_key) == Some(&old_seen) {
                state.entries.remove(&old_key);
            }
        }
        Ok(())
    }

    /// Remove expired entries and return the number of active entries.
    pub fn cleanup(&self, now: u64) -> Result<usize, RealityError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RealityError::ReplayCachePoisoned)?;
        cleanup_locked(&mut state, now, self.ttl_secs);
        Ok(state.entries.len())
    }

    /// Return active entry count.
    pub fn len(&self) -> Result<usize, RealityError> {
        let state = self
            .state
            .lock()
            .map_err(|_| RealityError::ReplayCachePoisoned)?;
        Ok(state.entries.len())
    }

    /// Return true when the cache is empty.
    pub fn is_empty(&self) -> Result<bool, RealityError> {
        self.len().map(|len| len == 0)
    }
}

impl core::fmt::Debug for ReplayCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let len = self.len().unwrap_or(0);
        f.debug_struct("ReplayCache")
            .field("capacity", &self.capacity)
            .field("ttl_secs", &self.ttl_secs)
            .field("len", &len)
            .finish_non_exhaustive()
    }
}

fn cleanup_locked(state: &mut ReplayState, now: u64, ttl_secs: u64) {
    while let Some((key, seen_at)) = state.order.front().copied() {
        if now.saturating_sub(seen_at) <= ttl_secs {
            break;
        }
        state.order.pop_front();
        if state.entries.get(&key) == Some(&seen_at) {
            state.entries.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_replay_cache_helpers_enforce_capacity_ttl_and_redacted_debug() {
        assert!(ReplayCache::new(0, 5).is_err());

        let cache = ReplayCache::new(2, 5).expect("cache");
        assert!(cache.is_empty().expect("empty"));
        cache.insert_or_reject([1_u8; 32], 10).expect("first");
        assert!(!cache.is_empty().expect("not empty"));
        assert_eq!(cache.len().expect("len"), 1);

        cache.insert_or_reject([2_u8; 32], 11).expect("second");
        cache
            .insert_or_reject([3_u8; 32], 12)
            .expect("capacity evicts oldest");
        assert_eq!(cache.len().expect("bounded len"), 2);
        assert!(cache.insert_or_reject([2_u8; 32], 12).is_err());

        let debug = format!("{cache:?}");
        assert!(debug.contains("ReplayCache"));
        assert!(debug.contains("len"));
        assert!(!debug.contains("010101"));

        assert_eq!(cache.cleanup(17).expect("cleanup"), 1);
        assert_eq!(cache.cleanup(18).expect("cleanup all"), 0);
    }
}
