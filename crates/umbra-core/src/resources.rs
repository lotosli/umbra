//! Resource policy shared by authenticated connections and credential groups.

use crate::CoreError;
use serde::Deserialize;
use umbra_inner::budget::{BudgetLease, BudgetPool};
use umbra_proto::flow::FlowSettings;

pub use crate::work::WorkGroupSnapshot;

/// Local QUIC sender congestion policy, independent of Linux TCP settings.
#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum QuicCongestion {
    /// Experimental bundled Quinn BBR, selected for the 0.0.9 throughput trial.
    #[default]
    Bbr,
    /// Cubic congestion control.
    Cubic,
    /// NewReno congestion control.
    NewReno,
}

impl QuicCongestion {
    pub(crate) fn apply(self, transport: &mut quinn::TransportConfig) {
        use std::sync::Arc;
        match self {
            Self::Bbr => transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())),
            Self::Cubic => transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
            Self::NewReno => transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            )),
        };
    }
}

/// Memory ceilings and automatic mux window policy; rates need not be configured.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PerformanceCfg {
    /// Algorithm used by this endpoint when sending QUIC packets.
    pub quic_congestion: QuicCongestion,
    /// Process-level application buffer commitment ceiling, in MiB.
    pub memory_mib: usize,
    /// Ceiling shared by all connections using one canonical credential group.
    pub group_memory_mib: usize,
    /// Largest adaptive mux or native QUIC aggregate receive window, in MiB.
    pub max_window_mib: u32,
    /// Native QUIC per-stream receive window, in MiB (1–64).
    pub quic_stream_window_mib: u32,
    /// Maximum native QUIC retained send storage, in MiB (1–64).
    pub quic_send_window_mib: u32,
    /// Enable client opt-in to adaptive flow control for new TCP CONNECT mux sessions.
    pub adaptive_mux: bool,
    /// Anonymous pipeline diagnostic reporting interval; zero disables collection.
    pub diagnostics_interval_secs: u64,
}

impl Default for PerformanceCfg {
    fn default() -> Self {
        Self {
            quic_congestion: QuicCongestion::Bbr,
            memory_mib: 512,
            group_memory_mib: 256,
            max_window_mib: 64,
            quic_stream_window_mib: 6,
            quic_send_window_mib: 32,
            adaptive_mux: true,
            diagnostics_interval_secs: 0,
        }
    }
}

impl PerformanceCfg {
    /// Validate memory limits and supported protocol windows.
    pub fn validate(self) -> Result<Self, CoreError> {
        if !(16..=16_384).contains(&self.memory_mib)
            || self.group_memory_mib < 16
            || self.group_memory_mib > self.memory_mib
            || !(1..=64).contains(&self.max_window_mib)
            || !(1..=64).contains(&self.quic_stream_window_mib)
            || !(1..=64).contains(&self.quic_send_window_mib)
            || self.diagnostics_interval_secs > 3600
        {
            return Err(CoreError::InvalidConfig(
                "invalid performance memory or window limits",
            ));
        }
        Ok(self)
    }

    pub(crate) fn flow(self) -> FlowSettings {
        let maximum = self.max_window_mib * 1024 * 1024;
        FlowSettings {
            stream: maximum.min(1024 * 1024),
            connection: maximum.min(4 * 1024 * 1024),
            max_connection: maximum,
            max_stream: maximum.min(32 * 1024 * 1024),
        }
    }

    pub(crate) fn quic_windows(self) -> QuicWindows {
        let maximum = self.max_window_mib * 1024 * 1024;
        // The public defaults match the captured Chrome 153 flow-control fields.
        // Smaller group budgets clip commitments, rather than over-admit owners.
        let group_bytes = self.group_memory_mib * 1024 * 1024;
        QuicWindows {
            stream: (self.quic_stream_window_mib * 1024 * 1024).min(maximum),
            receive: maximum
                .min(15 * 1024 * 1024)
                .min(u32::try_from(group_bytes / 8).unwrap_or(u32::MAX)),
            send: (u64::from(self.quic_send_window_mib) * 1024 * 1024)
                .min(u64::try_from(group_bytes / 4).unwrap_or(u64::MAX)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QuicWindows {
    pub(crate) stream: u32,
    pub(crate) receive: u32,
    pub(crate) send: u64,
}

impl QuicWindows {
    pub(crate) fn configure(self, transport: &mut quinn::TransportConfig) {
        transport
            .stream_receive_window(self.stream.into())
            .receive_window(self.receive.into())
            .send_window(self.send);
    }
}

/// Shared policy owner. All connection leases retain the underlying pool.
#[derive(Clone)]
pub(crate) struct Resources {
    pub(crate) pool: BudgetPool,
    pub(crate) config: PerformanceCfg,
    pub(crate) scheduler: crate::work::Scheduler,
    pub(crate) diagnostics: crate::diagnostics::Diagnostics,
}

impl Resources {
    pub(crate) fn new(config: PerformanceCfg) -> Result<Self, CoreError> {
        let config = config.validate()?;
        Ok(Self {
            pool: BudgetPool::new(
                config.memory_mib * 1024 * 1024,
                config.group_memory_mib * 1024 * 1024,
            )?,
            config,
            scheduler: crate::work::Scheduler::new(),
            diagnostics: crate::diagnostics::Diagnostics::new(config.diagnostics_interval_secs > 0),
        })
    }

    pub(crate) fn reserve(&self, group: usize, bytes: usize) -> Result<BudgetLease, CoreError> {
        self.pool.reserve(group, bytes).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "authenticated resource budget exhausted",
            )
            .into()
        })
    }

    pub(crate) fn receive(&self, group: usize) -> Result<BudgetLease, CoreError> {
        self.reserve(group, self.config.flow().connection as usize)
    }

    pub(crate) fn group(&self, id: usize, mode: crate::diagnostics::Mode) -> ResourceGroup {
        ResourceGroup {
            resources: self.clone(),
            id,
            observation: self.diagnostics.register(id, mode),
        }
    }
}

/// Carry a storage reservation with the transport that owns its buffers.
pub(crate) struct ResourceIo<IO> {
    inner: IO,
    _lease: BudgetLease,
}

impl<IO> ResourceIo<IO> {
    pub(crate) fn new(inner: IO, lease: BudgetLease) -> Self {
        Self {
            inner,
            _lease: lease,
        }
    }
}

impl<IO: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for ResourceIo<IO> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<IO: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for ResourceIo<IO> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
/// Authenticated grouping context for independent target tasks and messages.
#[derive(Clone)]
pub(crate) struct ResourceGroup {
    pub(crate) resources: Resources,
    pub(crate) id: usize,
    pub(crate) observation: Option<crate::diagnostics::Observation>,
}

impl ResourceGroup {
    pub(crate) fn work(&self) -> crate::work::WorkGroup {
        self.resources.scheduler.group(self.id)
    }

    pub(crate) fn reserve(&self, bytes: usize) -> Result<BudgetLease, CoreError> {
        self.resources.reserve(self.id, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quic_policy_configuration_rejects_unknown_names() {
        for (name, policy) in [
            ("bbr", QuicCongestion::Bbr),
            ("cubic", QuicCongestion::Cubic),
            ("new-reno", QuicCongestion::NewReno),
        ] {
            let cfg: PerformanceCfg =
                toml::from_str(&format!("quic_congestion = \"{name}\"")).unwrap();
            assert_eq!(cfg.quic_congestion, policy);
        }
        assert!(toml::from_str::<PerformanceCfg>("quic_congestion = \"unknown\"").is_err());
    }

    #[test]
    fn performance_limits_and_shared_connection_owners_are_bounded() {
        assert!(PerformanceCfg {
            diagnostics_interval_secs: 3601,
            ..PerformanceCfg::default()
        }
        .validate()
        .is_err());
        assert!(PerformanceCfg {
            memory_mib: 0,
            ..PerformanceCfg::default()
        }
        .validate()
        .is_err());
        assert!(PerformanceCfg {
            group_memory_mib: 1024,
            ..PerformanceCfg::default()
        }
        .validate()
        .is_err());
        assert!(PerformanceCfg {
            max_window_mib: 65,
            ..PerformanceCfg::default()
        }
        .validate()
        .is_err());
        let resources = Resources::new(PerformanceCfg {
            quic_congestion: QuicCongestion::Bbr,
            memory_mib: 32,
            group_memory_mib: 16,
            max_window_mib: 1,
            adaptive_mux: true,
            diagnostics_interval_secs: 0,
            ..PerformanceCfg::default()
        })
        .unwrap();
        assert_eq!(resources.config.flow().max_connection, 1024 * 1024);
        let lease = resources.reserve(0, 16 * 1024 * 1024).unwrap();
        assert!(resources.receive(0).is_err());
        let other = resources.receive(1).unwrap();
        assert_eq!(resources.pool.committed(), 17 * 1024 * 1024);
        drop(lease);
        drop(other);
        assert_eq!(resources.pool.committed(), 0);
    }

    #[test]
    fn native_window_settings_are_explicit_and_budget_bounded() {
        let defaults = PerformanceCfg::default();
        let policy = defaults.quic_windows();
        assert_eq!(policy.stream, 6 * 1024 * 1024);
        assert_eq!(policy.receive, 15 * 1024 * 1024);
        assert_eq!(policy.send, 32 * 1024 * 1024);
        let custom: PerformanceCfg =
            toml::from_str("quic_stream_window_mib=32\nquic_send_window_mib=64\nmax_window_mib=32")
                .unwrap();
        assert_eq!(
            custom.validate().unwrap().quic_windows().stream,
            32 * 1024 * 1024
        );
        assert_eq!(custom.quic_windows().send, 64 * 1024 * 1024);
        for bad in [
            "quic_stream_window_mib=0",
            "quic_stream_window_mib=65",
            "quic_send_window_mib=0",
            "quic_send_window_mib=65",
        ] {
            assert!(toml::from_str::<PerformanceCfg>(bad)
                .unwrap()
                .validate()
                .is_err());
        }
        let small = PerformanceCfg {
            group_memory_mib: 16,
            max_window_mib: 1,
            ..defaults
        }
        .quic_windows();
        assert_eq!(small.stream, 1024 * 1024);
        assert_eq!(small.receive, 1024 * 1024);
        assert_eq!(small.send, 4 * 1024 * 1024);
    }
}
