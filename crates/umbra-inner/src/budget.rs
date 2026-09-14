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
    peak: usize,
    groups: BTreeMap<usize, GroupBudgetSnapshot>,
}

/// Resource usage and refusal counts for a canonical configured group.
#[derive(Debug, Clone, Default)]
pub struct GroupBudgetSnapshot {
    /// Opaque group index.
    pub group: usize,
    /// Current logical receive/storage commitment.
    pub committed: usize,
    /// Largest observed commitment.
    pub peak: usize,
    /// Initial reservations refused, including stream/UDP storage.
    pub admission_refusals: u64,
    /// Receive-window increases refused.
    pub growth_refusals: u64,
    /// Refusals in which the process limit (including growth headroom) was exceeded.
    pub process_limit_refusals: u64,
    /// Refusals in which the group ceiling was exceeded; causes may overlap.
    pub group_limit_refusals: u64,
}

/// Process-wide logical commitments, not RSS or kernel socket memory.
#[derive(Debug, Clone)]
pub struct BudgetSnapshot {
    /// Configured process ceiling.
    pub limit: usize,
    /// Configured per-group ceiling.
    pub group_limit: usize,
    /// Current committed bytes.
    pub committed: usize,
    /// Largest observed process commitment.
    pub peak: usize,
    /// Counters for previously used configured groups, retained after their last close.
    pub groups: Vec<GroupBudgetSnapshot>,
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

    /// Snapshot usage and refusals without changing available credit.
    pub fn snapshot(&self) -> BudgetSnapshot {
        let state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        BudgetSnapshot {
            limit: self.0.total,
            group_limit: self.0.per_group,
            committed: state.used,
            peak: state.peak,
            groups: state.groups.values().cloned().collect(),
        }
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
        let used = state.groups.get(&group).map_or(0, |usage| usage.committed);
        let process_full = bytes > limit.saturating_sub(state.used);
        let group_full = bytes > self.0.per_group.saturating_sub(used);
        if process_full || group_full {
            let usage = state.groups.entry(group).or_default();
            usage.group = group;
            if growth {
                usage.growth_refusals = usage.growth_refusals.saturating_add(1);
            } else {
                usage.admission_refusals = usage.admission_refusals.saturating_add(1);
            }
            usage.process_limit_refusals = usage
                .process_limit_refusals
                .saturating_add(u64::from(process_full));
            usage.group_limit_refusals = usage
                .group_limit_refusals
                .saturating_add(u64::from(group_full));
            return false;
        }
        state.used += bytes;
        state.peak = state.peak.max(state.used);
        let usage = state.groups.entry(group).or_default();
        usage.group = group;
        usage.committed += bytes;
        usage.peak = usage.peak.max(usage.committed);
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
        if let Some(usage) = state.groups.get_mut(&self.group) {
            usage.committed -= bytes;
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
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.groups[0].group, 1);
        assert_eq!(snapshot.groups[0].admission_refusals, 1);
        assert_eq!(snapshot.groups[0].growth_refusals, 1);
        assert_eq!(snapshot.groups[0].group_limit_refusals, 2);
        assert_eq!(snapshot.groups[0].process_limit_refusals, 0);
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
        assert_eq!(pool.snapshot().peak, 768);
        assert!(pool
            .snapshot()
            .groups
            .iter()
            .all(|group| group.committed == 0));
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
