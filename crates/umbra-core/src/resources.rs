//! Resource policy shared by authenticated connections and credential groups.

use crate::CoreError;
use serde::Deserialize;
use umbra_inner::budget::{BudgetLease, BudgetPool};
use umbra_proto::flow::FlowSettings;

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
    /// Enable client opt-in to adaptive flow control for new TCP CONNECT mux sessions.
    pub adaptive_mux: bool,
}

impl Default for PerformanceCfg {
    fn default() -> Self {
        Self {
            quic_congestion: QuicCongestion::Bbr,
            memory_mib: 512,
            group_memory_mib: 256,
            max_window_mib: 64,
            adaptive_mux: true,
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
            max_connection: maximum,
            max_stream: maximum.min(32 * 1024 * 1024),
            ..FlowSettings::default()
        }
    }
}

/// Shared policy owner. All connection leases retain the underlying pool.
#[derive(Clone)]
pub(crate) struct Resources {
    pub(crate) pool: BudgetPool,
    pub(crate) config: PerformanceCfg,
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
}

impl ResourceGroup {
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
}
