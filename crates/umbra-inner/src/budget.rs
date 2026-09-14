//! Shared, credential-group memory commitments for authenticated connections.
//!
//! Leases account for granted receive capacity, not just bytes already received.
//! A lease stays alive while the peer may still spend its credit.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use crate::InnerError;

/// Shared process and credential-group commitment limits.
#[derive(Clone)]
pub struct BudgetPool(Arc<Pool>);

struct Pool {
    total: usize,
    per_group: usize,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    used: usize,
    groups: BTreeMap<usize, usize>,
}

/// Owned reserved bytes; dropping returns the commitment exactly once.
#[derive(Clone)]
pub struct BudgetLease(Arc<Reservation>);

struct Reservation {
    pool: BudgetPool,
    group: usize,
    bytes: Mutex<usize>,
}

impl BudgetPool {
    /// Create positive bounded limits. Groups can borrow unused process capacity.
    pub fn new(total: usize, per_group: usize) -> Result<Self, InnerError> {
        if total == 0 || per_group == 0 || per_group > total {
            return Err(InnerError::WindowOverflow);
        }
        Ok(Self(Arc::new(Pool {
            total,
            per_group,
            state: Mutex::new(State::default()),
        })))
    }

    /// Reserve capacity before accepting ownership or advertising peer credit.
    #[must_use]
    pub fn reserve(&self, group: usize, bytes: usize) -> Option<BudgetLease> {
        if !self.take(group, bytes, false) {
            return None;
        }
        Some(BudgetLease(Arc::new(Reservation {
            pool: self.clone(),
            group,
            bytes: Mutex::new(bytes),
        })))
    }

    /// Current process-wide commitment, including credit not received yet.
    #[must_use]
    pub fn committed(&self) -> usize {
        self.0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .used
    }

    fn take(&self, group: usize, bytes: usize, growth: bool) -> bool {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let limit = if growth {
            self.0.total - self.0.total / 8
        } else {
            self.0.total
        };
        let used = state.groups.get(&group).copied().unwrap_or(0);
        if bytes > limit.saturating_sub(state.used) || bytes > self.0.per_group.saturating_sub(used)
        {
            return false;
        }
        state.used += bytes;
        *state.groups.entry(group).or_default() += bytes;
        true
    }
}

impl BudgetLease {
    /// Number of bytes still committed by this owner.
    #[must_use]
    pub fn bytes(&self) -> usize {
        *self
            .0
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Attempt to grow without revoking existing credit or blocking other I/O.
    pub fn grow_to(&mut self, bytes: usize) -> bool {
        let mut owned = self
            .0
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if bytes <= *owned {
            return true;
        }
        if !self.0.pool.take(self.0.group, bytes - *owned, true) {
            return false;
        }
        *owned = bytes;
        true
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let bytes = *self
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut state = self
            .pool
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.used -= bytes;
        if let Some(used) = state.groups.get_mut(&self.group) {
            *used -= bytes;
            if *used == 0 {
                state.groups.remove(&self.group);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_share_caps_and_drops_release_once() {
        let pool = BudgetPool::new(1024, 512).expect("limits");
        let mut one = pool.reserve(1, 256).expect("first outer");
        let two = pool.reserve(1, 256).expect("same group");
        assert!(pool.reserve(1, 1).is_none());
        assert!(!one.grow_to(257));
        let other = pool.reserve(2, 256).expect("other credential");
        assert_eq!(pool.committed(), 768);
        drop(two);
        assert!(one.grow_to(512));
        assert_eq!(pool.committed(), 768);
        let retained = one.clone();
        drop(one);
        drop(other);
        assert_eq!(pool.committed(), 512);
        drop(retained);
        assert_eq!(pool.committed(), 0);
    }

    #[test]
    fn growth_preserves_admission_reserve_and_cannot_revoke_credit() {
        let pool = BudgetPool::new(1024, 1024).expect("limits");
        let mut lease = pool.reserve(0, 512).expect("initial");
        assert!(lease.grow_to(896));
        assert!(!lease.grow_to(897));
        assert!(lease.grow_to(1));
        assert_eq!(lease.bytes(), 896);
        let newcomer = pool.reserve(1, 128).expect("reserved admission");
        assert!(pool.reserve(2, 1).is_none());
        drop(newcomer);
        drop(lease);
        assert_eq!(pool.committed(), 0);
        assert!(BudgetPool::new(0, 1).is_err());
        assert!(BudgetPool::new(1, 0).is_err());
        assert!(BudgetPool::new(1, 2).is_err());
    }
}
