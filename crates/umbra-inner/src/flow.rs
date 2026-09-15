//! Adaptive mux credit state. Wire I/O and cancellation remain owned by mux.

use crate::{budget::BudgetLease, InnerError};
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};
use umbra_proto::{
    flow::{CreditUpdate, FlowSettings},
    frame::{MuxCommand, MuxFrame},
};

#[derive(Default)]
struct Send {
    sent: u64,
    limit: u64,
    consumed: u64,
}

impl Send {
    fn credit(&self) -> usize {
        usize::try_from(self.limit.saturating_sub(self.sent)).unwrap_or(0)
    }
    fn update(&mut self, update: CreditUpdate, maximum: u32) -> Result<(), InnerError> {
        if update.consumed > self.sent
            || update.consumed < self.consumed
            || update.limit < self.limit
            || update.limit - update.consumed > u64::from(maximum)
        {
            return Err(InnerError::WindowOverflow);
        }
        self.limit = update.limit;
        self.consumed = update.consumed;
        Ok(())
    }
}

struct Receive {
    received: u64,
    consumed: u64,
    limit: u64,
    window: u32,
    epoch: Instant,
    epoch_consumed: u64,
    reported_consumed: u64,
    finished: bool,
}

impl Receive {
    fn new(window: u32) -> Self {
        Self {
            received: 0,
            consumed: 0,
            limit: u64::from(window),
            window,
            epoch: Instant::now(),
            epoch_consumed: 0,
            reported_consumed: 0,
            finished: false,
        }
    }
    fn receive(&mut self, len: u64) -> Result<(), InnerError> {
        let next = self
            .received
            .checked_add(len)
            .ok_or(InnerError::WindowOverflow)?;
        if next > self.limit {
            return Err(InnerError::WindowOverflow);
        }
        self.received = next;
        Ok(())
    }
    fn consume(&mut self, len: u64) -> Result<(), InnerError> {
        let next = self
            .consumed
            .checked_add(len)
            .ok_or(InnerError::WindowOverflow)?;
        if next > self.received {
            return Err(InnerError::WindowOverflow);
        }
        if len != 0 && self.consumed == self.epoch_consumed {
            self.epoch = Instant::now();
        }
        self.consumed = next;
        Ok(())
    }
    fn desired(&mut self, maximum: u32, rtt: Duration) -> u32 {
        if self.consumed - self.epoch_consumed < u64::from(self.window / 2) {
            return self.window;
        }
        let elapsed = self.epoch.elapsed();
        self.epoch = Instant::now();
        self.epoch_consumed = self.consumed;
        if elapsed <= rtt.saturating_mul(2) {
            self.window.saturating_mul(2).min(maximum)
        } else {
            self.window
        }
    }
    fn update(&mut self) -> Result<CreditUpdate, InnerError> {
        self.limit = self.limit.max(
            self.consumed
                .checked_add(u64::from(self.window))
                .ok_or(InnerError::WindowOverflow)?,
        );
        self.reported_consumed = self.consumed;
        Ok(CreditUpdate {
            limit: self.limit,
            consumed: self.consumed,
        })
    }

    fn update_due(&self, force: bool) -> bool {
        force
            || self.finished
            || self.consumed - self.reported_consumed >= u64::from((self.window / 8).max(1))
            || self.limit.saturating_sub(self.received) <= u64::from(self.window / 4)
    }
}

struct Stream {
    send: Send,
    receive: Receive,
}

/// Non-secret counters for validation and throughput diagnostics.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FlowSnapshot {
    /// Current funded connection receive window.
    pub receive_window: u32,
    /// Cumulative DATA bytes sent.
    pub sent: u64,
    /// Cumulative DATA bytes received.
    pub received: u64,
    /// DATA consumed by the local application.
    pub consumed: u64,
    /// Received DATA not yet consumed, including retained events.
    pub buffered_receive: u64,
    /// Remaining peer-granted aggregate send credit.
    pub send_credit: u64,
    /// Number of connection-window expansions.
    pub expansions: u64,
    /// Smoothed round-trip sample, or bootstrap estimate before the first reply.
    pub rtt: Duration,
}

pub(crate) struct AdaptiveFlow {
    local: FlowSettings,
    peer: Option<FlowSettings>,
    streams: BTreeMap<u32, Stream>,
    send: Send,
    receive: Receive,
    lease: BudgetLease,
    settings_pending: bool,
    controls: VecDeque<(MuxCommand, Vec<u8>)>,
    updates: BTreeMap<u32, CreditUpdate>,
    rtt: Duration,
    probe: Option<(u64, Instant)>,
    nonce: u64,
    last_probe: Instant,
    expansions: u64,
}

impl AdaptiveFlow {
    pub(crate) fn new(local: FlowSettings, lease: BudgetLease) -> Result<Self, InnerError> {
        local.validate()?;
        if lease.bytes() < local.connection as usize {
            return Err(InnerError::WindowOverflow);
        }
        Ok(Self {
            local,
            peer: None,
            streams: BTreeMap::new(),
            send: Send::default(),
            receive: Receive::new(local.connection),
            lease,
            settings_pending: true,
            controls: VecDeque::new(),
            updates: BTreeMap::new(),
            rtt: Duration::from_millis(100),
            probe: None,
            nonce: 0,
            last_probe: Instant::now(),
            expansions: 0,
        })
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.peer.is_some()
    }

    pub(crate) fn lease(&self) -> BudgetLease {
        self.lease.clone()
    }

    pub(crate) fn snapshot(&self) -> FlowSnapshot {
        FlowSnapshot {
            receive_window: self.receive.window,
            sent: self.send.sent,
            received: self.receive.received,
            consumed: self.receive.consumed,
            buffered_receive: self.receive.received - self.receive.consumed,
            send_credit: self.send.limit - self.send.sent,
            expansions: self.expansions,
            rtt: self.rtt,
        }
    }

    pub(crate) fn register(&mut self, id: u32) {
        self.streams.insert(
            id,
            Stream {
                send: Send {
                    limit: self.peer.map_or(0, |peer| u64::from(peer.stream)),
                    ..Send::default()
                },
                receive: Receive::new(self.local.stream),
            },
        );
    }

    pub(crate) fn connection_credit(&self) -> usize {
        self.send.credit()
    }

    pub(crate) fn send_credit(&self, id: u32) -> usize {
        self.streams
            .get(&id)
            .map_or(0, |stream| stream.send.credit().min(self.send.credit()))
    }

    pub(crate) fn sent(&mut self, id: u32, len: usize) -> Result<(), InnerError> {
        if len > self.send_credit(id) {
            return Err(InnerError::WindowOverflow);
        }
        let stream = self.streams.get_mut(&id).ok_or(InnerError::StreamReset)?;
        let len = u64::try_from(len).map_err(|_| InnerError::WindowOverflow)?;
        stream.send.sent = stream
            .send
            .sent
            .checked_add(len)
            .ok_or(InnerError::WindowOverflow)?;
        self.send.sent = self
            .send
            .sent
            .checked_add(len)
            .ok_or(InnerError::WindowOverflow)?;
        Ok(())
    }

    pub(crate) fn received(&mut self, id: u32, len: usize) -> Result<(), InnerError> {
        if self.peer.is_none() {
            return Err(InnerError::WindowOverflow);
        }
        let len = u64::try_from(len).map_err(|_| InnerError::WindowOverflow)?;
        self.receive.receive(len)?;
        if let Some(stream) = self.streams.get_mut(&id) {
            stream.receive.receive(len)?;
        } else {
            // A valid retired id can have DATA in flight before its RST.
            self.receive.consume(len)?;
            self.refresh_connection(true)?;
        }
        Ok(())
    }

    pub(crate) fn consume(&mut self, id: u32, len: usize) -> Result<(), InnerError> {
        self.consume_with_policy(id, len, true).map(|_| ())
    }

    pub(crate) fn consume_coalesced(&mut self, id: u32, len: usize) -> Result<bool, InnerError> {
        self.consume_with_policy(id, len, false)
    }

    fn consume_with_policy(
        &mut self,
        id: u32,
        len: usize,
        force: bool,
    ) -> Result<bool, InnerError> {
        let len = u64::try_from(len).map_err(|_| InnerError::WindowOverflow)?;
        let stream = self.streams.get_mut(&id).ok_or(InnerError::StreamReset)?;
        stream.receive.consume(len)?;
        let previous = stream.receive.window;
        stream.receive.window = stream.receive.desired(self.local.max_stream, self.rtt);
        let stream_update = stream
            .receive
            .update_due(force || previous != stream.receive.window);
        if stream_update {
            self.updates.insert(id, stream.receive.update()?);
        }
        self.receive.consume(len)?;
        Ok(self.refresh_connection(force)? || stream_update)
    }

    pub(crate) fn finish_received(&mut self, id: u32) -> Result<(), InnerError> {
        let stream = self.streams.get_mut(&id).ok_or(InnerError::StreamReset)?;
        stream.receive.finished = true;
        self.updates.insert(id, stream.receive.update()?);
        self.refresh_connection(true).map(|_| ())
    }

    fn refresh_connection(&mut self, force: bool) -> Result<bool, InnerError> {
        let previous = self.receive.window;
        let desired = self.receive.desired(self.local.max_connection, self.rtt);
        if desired > self.receive.window && self.lease.grow_to(desired as usize) {
            self.receive.window = desired;
            self.expansions += 1;
        }
        let update = self
            .receive
            .update_due(force || previous != self.receive.window);
        if update {
            self.updates.insert(0, self.receive.update()?);
        }
        Ok(update)
    }

    pub(crate) fn retire(&mut self, id: u32) -> Result<(), InnerError> {
        if let Some(stream) = self.streams.remove(&id) {
            self.receive
                .consume(stream.receive.received - stream.receive.consumed)?;
            self.refresh_connection(true)?;
        }
        Ok(())
    }

    pub(crate) fn settled(&self, id: u32) -> bool {
        self.streams.get(&id).is_some_and(|stream| {
            stream.send.sent == stream.send.consumed
                && stream.receive.received == stream.receive.consumed
        })
    }

    pub(crate) fn handle(&mut self, frame: &MuxFrame) -> Result<(), InnerError> {
        match frame.command {
            MuxCommand::Settings => {
                if frame.stream_id != 0 || self.peer.is_some() {
                    return Err(InnerError::WindowOverflow);
                }
                let settings = FlowSettings::decode(&frame.payload)?;
                self.send.limit = u64::from(settings.connection);
                for stream in self.streams.values_mut() {
                    stream.send.limit = u64::from(settings.stream);
                }
                self.peer = Some(settings);
            }
            MuxCommand::Credit => {
                let peer = self.peer.ok_or(InnerError::WindowOverflow)?;
                let update = CreditUpdate::decode(&frame.payload)?;
                if frame.stream_id == 0 {
                    self.send.update(update, peer.max_connection)?;
                } else if let Some(stream) = self.streams.get_mut(&frame.stream_id) {
                    stream.send.update(update, peer.max_stream)?;
                }
            }
            MuxCommand::Probe | MuxCommand::ProbeAck => {
                if frame.stream_id != 0 || self.peer.is_none() {
                    return Err(InnerError::WindowOverflow);
                }
                let nonce = u64::from_be_bytes(
                    frame
                        .payload
                        .as_slice()
                        .try_into()
                        .map_err(|_| InnerError::WindowOverflow)?,
                );
                if frame.command == MuxCommand::Probe {
                    if self.controls.len() >= 4 {
                        return Err(InnerError::WindowOverflow);
                    }
                    self.controls
                        .push_back((MuxCommand::ProbeAck, frame.payload.clone()));
                } else if let Some((expected, started)) = self.probe {
                    if nonce != expected {
                        return Err(InnerError::WindowOverflow);
                    }
                    let sample = started.elapsed().max(Duration::from_millis(1));
                    self.rtt = if self.nonce == 1 {
                        sample
                    } else {
                        (self.rtt.saturating_mul(3) + sample) / 4
                    };
                    self.probe = None;
                } else {
                    return Err(InnerError::WindowOverflow);
                }
            }
            _ => return Err(InnerError::WindowOverflow),
        }
        Ok(())
    }

    pub(crate) fn next_control(&mut self) -> Result<Option<MuxFrame>, InnerError> {
        if self.settings_pending {
            self.settings_pending = false;
            return Ok(Some(MuxFrame::new(
                MuxCommand::Settings,
                0,
                self.local.encode()?,
            )?));
        }
        if let Some((command, payload)) = self.controls.pop_front() {
            return Ok(Some(MuxFrame::new(command, 0, payload)?));
        }
        if let Some((id, update)) = self.updates.pop_first() {
            return Ok(Some(MuxFrame::new(
                MuxCommand::Credit,
                id,
                update.encode()?,
            )?));
        }
        if self.peer.is_some()
            && self.probe.is_none()
            && (self.nonce == 0 || self.last_probe.elapsed() >= Duration::from_millis(500))
        {
            self.nonce = self
                .nonce
                .checked_add(1)
                .ok_or(InnerError::WindowOverflow)?;
            self.last_probe = Instant::now();
            self.probe = Some((self.nonce, self.last_probe));
            return Ok(Some(MuxFrame::new(
                MuxCommand::Probe,
                0,
                self.nonce.to_be_bytes().to_vec(),
            )?));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesced_consumption_preserves_low_credit_fin_and_reset_settlement() {
        let limits = FlowSettings {
            stream: 1024,
            connection: 4096,
            max_stream: 1024,
            max_connection: 4096,
        };
        let pool = crate::budget::BudgetPool::new(8192, 8192).unwrap();
        let mut flow = AdaptiveFlow::new(limits, pool.reserve(0, 4096).unwrap()).unwrap();
        flow.handle(&MuxFrame::new(MuxCommand::Settings, 0, limits.encode().unwrap()).unwrap())
            .unwrap();
        flow.register(1);
        flow.received(1, 64).unwrap();
        assert!(!flow.consume_coalesced(1, 64).unwrap());
        assert!(flow.updates.is_empty());
        flow.received(1, 64).unwrap();
        assert!(flow.consume_coalesced(1, 64).unwrap());
        assert_eq!(flow.updates[&1].consumed, 128);
        assert!(!flow.updates.contains_key(&0));
        flow.updates.clear();
        flow.finish_received(1).unwrap();
        assert_eq!(
            flow.updates[&1].consumed, 128,
            "FIN forces final consumption even with spare credit"
        );
        assert_eq!(flow.updates[&0].consumed, 128);
        flow.updates.clear();
        flow.register(3);
        flow.received(3, 960).unwrap();
        assert!(
            flow.consume_coalesced(3, 16).unwrap(),
            "nearly exhausted credit is replenished immediately"
        );
        assert_eq!(flow.updates[&3].consumed, 16);
        flow.retire(3).unwrap();
        assert_eq!(flow.updates[&0].consumed, 1088);
        assert_eq!(flow.snapshot().buffered_receive, 0);
        assert!(flow.finish_received(99).is_err());
        drop(flow);
        assert_eq!(pool.committed(), 0);
    }
    use crate::budget::BudgetPool;

    fn flow() -> (AdaptiveFlow, BudgetPool) {
        let settings = FlowSettings {
            stream: 16_384,
            connection: 32_768,
            max_stream: 131_072,
            max_connection: 262_144,
        };
        let pool = BudgetPool::new(524_288, 262_144).unwrap();
        let lease = pool.reserve(0, 32_768).unwrap();
        (AdaptiveFlow::new(settings, lease).unwrap(), pool)
    }
    fn ready(flow: &mut AdaptiveFlow) {
        flow.handle(&MuxFrame::new(MuxCommand::Settings, 0, flow.local.encode().unwrap()).unwrap())
            .unwrap();
        flow.register(1);
    }

    #[test]
    fn growth_dual_credit_reset_and_last_owner_release() {
        let (mut flow, pool) = flow();
        ready(&mut flow);
        assert_eq!(flow.send_credit(1), 16_384);
        flow.sent(1, 16_384).unwrap();
        assert_eq!(flow.send_credit(1), 0);
        assert!(flow.sent(1, 1).is_err());
        flow.received(1, 16_384).unwrap();
        flow.consume(1, 16_384).unwrap();
        assert_eq!(flow.snapshot().receive_window, 65_536);
        assert_eq!(pool.committed(), 65_536);
        let update = CreditUpdate {
            limit: 32_768,
            consumed: 16_384,
        }
        .encode()
        .unwrap();
        flow.handle(&MuxFrame::new(MuxCommand::Credit, 1, update).unwrap())
            .unwrap();
        assert!(flow.settled(1));
        flow.received(1, 32).unwrap();
        flow.retire(1).unwrap();
        flow.received(1, 8).unwrap();
        assert_eq!(flow.receive.received, flow.receive.consumed);
        assert_eq!(flow.send_credit(1), 0);
        let retained = flow.lease();
        drop(flow);
        assert_eq!(pool.committed(), 65_536);
        drop(retained);
        assert_eq!(pool.committed(), 0);
    }

    #[test]
    fn malformed_or_impossible_controls_fail_without_allocating_streams() {
        let (mut flow, _) = flow();
        let credit = MuxFrame::new(
            MuxCommand::Credit,
            0,
            CreditUpdate {
                limit: 1,
                consumed: 0,
            }
            .encode()
            .unwrap(),
        )
        .unwrap();
        assert!(flow.handle(&credit).is_err());
        ready(&mut flow);
        assert!(flow.handle(&credit).is_err());
        let consumed = MuxFrame::new(
            MuxCommand::Credit,
            1,
            CreditUpdate {
                limit: 16_384,
                consumed: 1,
            }
            .encode()
            .unwrap(),
        )
        .unwrap();
        assert!(flow.handle(&consumed).is_err());
        let settings =
            MuxFrame::new(MuxCommand::Settings, 0, flow.local.encode().unwrap()).unwrap();
        assert!(flow.handle(&settings).is_err());
        assert!(flow
            .handle(&MuxFrame::new(MuxCommand::Probe, 0, vec![0; 7]).unwrap())
            .is_err());
        assert!(flow
            .handle(&MuxFrame::new(MuxCommand::Probe, 1, vec![0; 8]).unwrap())
            .is_err());
        assert!(flow
            .handle(&MuxFrame::new(MuxCommand::ProbeAck, 0, vec![0; 8]).unwrap())
            .is_err());
        assert!(flow
            .handle(&MuxFrame::new(MuxCommand::Data, 1, Vec::new()).unwrap())
            .is_err());
        assert!(flow.consume(1, 1).is_err());
        assert_eq!(flow.streams.len(), 1);
    }

    #[test]
    fn probes_are_bounded_and_rtt_acknowledgements_match() {
        let (mut flow, _) = flow();
        ready(&mut flow);
        assert_eq!(
            flow.next_control().unwrap().unwrap().command,
            MuxCommand::Settings
        );
        let probe = flow.next_control().unwrap().unwrap();
        assert_eq!(probe.command, MuxCommand::Probe);
        assert!(flow.next_control().unwrap().is_none());
        flow.handle(&MuxFrame::new(MuxCommand::ProbeAck, 0, probe.payload).unwrap())
            .unwrap();
        assert!(flow.probe.is_none());
        for _ in 0..4 {
            flow.handle(&MuxFrame::new(MuxCommand::Probe, 0, vec![0; 8]).unwrap())
                .unwrap();
        }
        assert!(flow
            .handle(&MuxFrame::new(MuxCommand::Probe, 0, vec![0; 8]).unwrap())
            .is_err());
        assert_eq!(
            flow.next_control().unwrap().unwrap().command,
            MuxCommand::ProbeAck
        );
    }
}
