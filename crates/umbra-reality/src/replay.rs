//! Bounded replay cache for REALITY tokens.

use std::{collections::HashMap, sync::Mutex};

use crate::RealityError;

/// Capacity-bounded replay cache retaining keys through inclusive expiry deadlines.
pub struct ReplayCache {
    capacity: usize,
    ttl_secs: u64,
    state: Mutex<ReplayState>,
}

#[derive(Default)]
struct ReplayState {
    entries: HashMap<[u8; 32], u64>,
}

impl ReplayCache {
    /// Create a replay cache with a fixed capacity and default TTL in seconds.
    ///
    /// The TTL applies only to [`Self::insert_or_reject`]. Authentication uses
    /// [`Self::insert_or_reject_until`] with the validated token's own deadline.
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

    /// Insert a key with an inclusive expiry of `now + ttl_secs`.
    ///
    /// Returns [`RealityError::ReplayExpiryOverflow`] if that deadline overflows.
    /// Token authentication must instead use [`Self::insert_or_reject_until`]
    /// with a deadline derived from the validated token timestamp.
    pub fn insert_or_reject(&self, key: [u8; 32], now: u64) -> Result<(), RealityError> {
        let expires_at = now
            .checked_add(self.ttl_secs)
            .ok_or(RealityError::ReplayExpiryOverflow)?;
        self.insert_or_reject_until(key, now, expires_at)
    }

    /// Atomically reject a duplicate or insert a key through `expires_at` inclusive.
    ///
    /// Expired deadlines are rejected. Cleanup, duplicate checking, capacity
    /// checking, and insertion share one lock. A full cache returns
    /// [`RealityError::ReplayCacheFull`] without evicting any live entries.
    /// The caller must still validate token freshness independently of the cache.
    pub fn insert_or_reject_until(
        &self,
        key: [u8; 32],
        now: u64,
        expires_at: u64,
    ) -> Result<(), RealityError> {
        if expires_at < now {
            return Err(RealityError::Expired);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| RealityError::ReplayCachePoisoned)?;
        cleanup_locked(&mut state, now);
        if state.entries.contains_key(&key) {
            return Err(RealityError::Replay);
        }
        if state.entries.len() >= self.capacity {
            return Err(RealityError::ReplayCacheFull);
        }
        state.entries.insert(key, expires_at);
        Ok(())
    }

    /// Remove entries whose inclusive expiry is before `now` and return the remaining count.
    pub fn cleanup(&self, now: u64) -> Result<usize, RealityError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RealityError::ReplayCachePoisoned)?;
        cleanup_locked(&mut state, now);
        Ok(state.entries.len())
    }

    /// Return the stored entry count without removing expired entries.
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

fn cleanup_locked(state: &mut ReplayState, now: u64) {
    // Deadlines need not follow insertion order. Scan the capacity-bounded map
    // rather than keeping an insertion queue that could hide expired entries.
    state.entries.retain(|_, expires_at| now <= *expires_at);
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
        assert_eq!(
            cache.insert_or_reject([3_u8; 32], 12),
            Err(RealityError::ReplayCacheFull)
        );
        assert_eq!(cache.len().expect("bounded len"), 2);
        assert_eq!(
            cache.insert_or_reject([1_u8; 32], 12),
            Err(RealityError::Replay)
        );

        let debug = format!("{cache:?}");
        assert!(debug.contains("ReplayCache"));
        assert!(debug.contains("len"));
        assert!(!debug.contains("010101"));

        assert_eq!(cache.cleanup(15).expect("inclusive expiry"), 2);
        assert_eq!(cache.cleanup(16).expect("cleanup"), 1);
        assert_eq!(cache.cleanup(17).expect("cleanup all"), 0);
    }
}
