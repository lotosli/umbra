//! Probe-resistance policies for timing, useless records, fallback, and RealSite behavior.

use std::time::Duration;

use tokio::time::{sleep, Instant};
use umbra_reality::prebuild::DestProfile;

use crate::CoreError;

/// First-byte timing alignment policy.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TimingAlignment {
    /// Allowed difference where no extra delay is needed.
    pub tolerance: Duration,
    /// Whether timing alignment is active.
    pub enabled: bool,
}

impl TimingAlignment {
    /// Create an enabled timing alignment policy.
    #[must_use]
    pub const fn enabled(tolerance: Duration) -> Self {
        Self {
            tolerance,
            enabled: true,
        }
    }

    /// Disable timing alignment.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            tolerance: Duration::ZERO,
            enabled: false,
        }
    }

    /// Compute how long the authenticated path should wait before first byte.
    #[must_use]
    pub fn delay_for(self, destination_rtt: Duration, elapsed: Duration) -> Duration {
        if !self.enabled {
            return Duration::ZERO;
        }
        let Some(remaining) = destination_rtt.checked_sub(elapsed) else {
            return Duration::ZERO;
        };
        if remaining <= self.tolerance {
            Duration::ZERO
        } else {
            remaining
        }
    }

    /// Wait until the authenticated path is aligned with the destination RTT profile.
    pub async fn wait_started_at(self, started_at: Instant, profile: &DestProfile) {
        let delay = self.delay_for(profile.rtt, started_at.elapsed());
        if !delay.is_zero() {
            sleep(delay).await;
        }
    }
}

impl Default for TimingAlignment {
    fn default() -> Self {
        Self::enabled(Duration::from_millis(5))
    }
}

/// Policy for useless TLS records observed before authentication.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UselessRecordPolicy {
    /// Maximum useless records tolerated before fallback action.
    pub max_useless_records: usize,
    /// Action after the limit is exceeded.
    pub action: UselessRecordAction,
}

impl UselessRecordPolicy {
    /// Validate a useless-record policy.
    pub fn validate(self) -> Result<(), CoreError> {
        if matches!(self.action, UselessRecordAction::Close) && self.max_useless_records == 0 {
            return Err(CoreError::InvalidConfig(
                "close policy requires a positive useless-record limit",
            ));
        }
        Ok(())
    }

    /// Return the action for the observed useless-record count.
    #[must_use]
    pub const fn action_for(self, observed: usize) -> Option<UselessRecordAction> {
        if observed > self.max_useless_records {
            Some(self.action)
        } else {
            None
        }
    }
}

impl Default for UselessRecordPolicy {
    fn default() -> Self {
        Self {
            max_useless_records: 0,
            action: UselessRecordAction::ForwardToDest,
        }
    }
}

/// Action taken after useless-record policy is exceeded.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UselessRecordAction {
    /// Forward to the configured destination without an Umbra response.
    ForwardToDest,
    /// Close without an Umbra-specific response.
    Close,
}

/// Probe-resistance runtime policy bundle.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct ProbeResistancePolicy {
    /// Authenticated-path timing alignment.
    pub timing: TimingAlignment,
    /// Useless-record handling.
    pub useless_records: UselessRecordPolicy,
    /// Fallback relay behavior.
    pub fallback: FallbackRelayPolicy,
}

impl ProbeResistancePolicy {
    /// Validate the policy before runtime startup.
    pub fn validate(self) -> Result<(), CoreError> {
        self.useless_records.validate()?;
        if !self.fallback.is_probe_resistant() {
            return Err(CoreError::InvalidConfig(
                "fallback relay must not rate-limit or early-close",
            ));
        }
        Ok(())
    }
}

/// Fallback relay behavior visible to unauthenticated traffic.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FallbackRelayPolicy {
    /// Whether Umbra-specific rate limiting is applied.
    pub rate_limited: bool,
    /// Whether garbage traffic causes an Umbra-specific early close.
    pub early_close_on_garbage: bool,
}

impl FallbackRelayPolicy {
    /// Return the ordinary unthrottled fallback relay policy.
    #[must_use]
    pub const fn ordinary() -> Self {
        Self {
            rate_limited: false,
            early_close_on_garbage: false,
        }
    }

    /// Return true when fallback is indistinguishable from ordinary forwarding policy.
    #[must_use]
    pub const fn is_probe_resistant(self) -> bool {
        !self.rate_limited && !self.early_close_on_garbage
    }
}

impl Default for FallbackRelayPolicy {
    fn default() -> Self {
        Self::ordinary()
    }
}
