//! Bounded target setup and datagram sends, independently polled by associations.

use super::{
    connect_udp_target_with_activity, CoreError, TargetAddr, UdpRelayDatagram, UdpTargetState,
    DEFAULT_OUTER_CONNECT_TIMEOUT, MAX_UDP_TARGETS_PER_ASSOCIATION,
};
use crate::{
    diagnostics::{Point, Waiter},
    relay::ProgressClock,
    resources::ResourceGroup,
};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{sync::mpsc, task::JoinSet};

const MAX_SETUP: usize = 16;
const MAX_PACKETS: usize = 256;
const MAX_BYTES: usize = 1024 * 1024;

struct Queued {
    packet: UdpRelayDatagram,
    cost: usize,
}

struct Sending {
    queued: Queued,
    observation: Waiter,
}

type Setup = (TargetAddr, Result<UdpTargetState, CoreError>);

pub(super) struct UdpTargets {
    ready: HashMap<TargetAddr, UdpTargetState>,
    waiting: HashMap<TargetAddr, VecDeque<Queued>>,
    setup: JoinSet<Setup>,
    sends: VecDeque<Sending>,
    replies: mpsc::Sender<UdpRelayDatagram>,
    group: Option<ResourceGroup>,
    clock: Arc<ProgressClock>,
    bytes: usize,
    packets: usize,
}

impl UdpTargets {
    pub(super) fn new(
        replies: mpsc::Sender<UdpRelayDatagram>,
        group: Option<ResourceGroup>,
        clock: Arc<ProgressClock>,
    ) -> Self {
        Self {
            ready: HashMap::new(),
            waiting: HashMap::new(),
            setup: JoinSet::new(),
            sends: VecDeque::new(),
            replies,
            group,
            clock,
            bytes: 0,
            packets: 0,
        }
    }

    pub(super) fn queue(&mut self, packet: UdpRelayDatagram) -> bool {
        let clock = self.clock.clone();
        self.queue_with(packet, move |target, replies, group| {
            connect_udp_target_with_activity(target, replies, group, Some(clock))
        })
    }

    fn queue_with<Connect, Connecting>(
        &mut self,
        mut packet: UdpRelayDatagram,
        connect: Connect,
    ) -> bool
    where
        Connect:
            FnOnce(TargetAddr, mpsc::Sender<UdpRelayDatagram>, Option<ResourceGroup>) -> Connecting,
        Connecting: Future<Output = Result<UdpTargetState, CoreError>> + Send + 'static,
    {
        let cost = packet.payload.capacity().saturating_add(512);
        let known =
            self.ready.contains_key(&packet.target) || self.waiting.contains_key(&packet.target);
        if self.packets == MAX_PACKETS
            || cost > MAX_BYTES.saturating_sub(self.bytes)
            || (!known
                && (self.ready.len() + self.waiting.len() >= MAX_UDP_TARGETS_PER_ASSOCIATION
                    || self.setup.len() >= MAX_SETUP))
        {
            return false;
        }
        if packet.lease.is_none() {
            match self
                .group
                .as_ref()
                .map(|group| group.reserve(cost))
                .transpose()
            {
                Ok(lease) => packet.lease = lease,
                Err(_) => return false,
            }
        }
        self.bytes += cost;
        self.packets += 1;
        let target = packet.target.clone();
        let queued = Queued { packet, cost };
        if let Some(state) = self.ready.get(&target) {
            self.sends.push_back(Sending {
                queued,
                observation: Waiter::new(state.observation.clone(), Point::TargetWrite),
            });
        } else if let Some(waiting) = self.waiting.get_mut(&target) {
            waiting.push_back(queued);
        } else {
            self.waiting
                .insert(target.clone(), VecDeque::from([queued]));
            let connecting = connect(target.clone(), self.replies.clone(), self.group.clone());
            let task = async move {
                let result = tokio::time::timeout(DEFAULT_OUTER_CONNECT_TIMEOUT, connecting)
                    .await
                    .map_err(|_| CoreError::IdleTimeout("UDP target setup"))
                    .and_then(std::convert::identity);
                (target, result)
            };
            if let Some(group) = &self.group {
                self.setup.spawn(group.work().wrap(task));
            } else {
                self.setup.spawn(task);
            }
        }
        true
    }

    pub(super) async fn progress(&mut self) -> Result<(), CoreError> {
        std::future::poll_fn(|cx| self.poll_progress(cx)).await
    }

    fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        if let Poll::Ready(Some(result)) = self.setup.poll_join_next(cx) {
            let (target, result) =
                result.map_err(|_| std::io::Error::other("UDP target setup task failed"))?;
            if let Some(waiting) = self.waiting.remove(&target) {
                match result {
                    Ok(state) => {
                        for queued in waiting {
                            self.sends.push_back(Sending {
                                queued,
                                observation: Waiter::new(
                                    state.observation.clone(),
                                    Point::TargetWrite,
                                ),
                            });
                        }
                        self.ready.insert(target, state);
                    }
                    Err(_) => {
                        for queued in waiting {
                            self.release(queued);
                        }
                    }
                }
            }
            return Poll::Ready(Ok(()));
        }
        // Only queued sends are inspected, and a blocked socket rotates behind
        // its siblings so a single destination cannot stop their datagrams.
        for _ in 0..self.sends.len() {
            let Some(mut sending) = self.sends.pop_front() else {
                break;
            };
            let Some(state) = self.ready.get(&sending.queued.packet.target) else {
                self.release(sending.queued);
                return Poll::Ready(Ok(()));
            };
            let result = state.socket.poll_send(cx, &sending.queued.packet.payload);
            sending.observation.record(
                match &result {
                    Poll::Ready(Ok(n)) => *n,
                    _ => 0,
                },
                result.is_pending(),
            );
            match result {
                Poll::Pending => self.sends.push_back(sending),
                Poll::Ready(result) => {
                    if result.is_ok() {
                        self.clock.advance();
                    }
                    self.release(sending.queued);
                    // UDP target errors discard this datagram, not the other
                    // established targets or the reverse carrier direction.
                    return Poll::Ready(Ok(()));
                }
            }
        }
        Poll::Pending
    }

    fn release(&mut self, queued: Queued) {
        self.bytes -= queued.cost;
        self.packets -= 1;
        drop(queued);
    }

    pub(super) async fn shutdown(&mut self) {
        self.setup.shutdown().await;
        self.waiting.clear();
        self.sends.clear();
        for state in self.ready.values_mut() {
            state.shutdown().await;
        }
        self.ready.clear();
        self.bytes = 0;
        self.packets = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::super::connect_udp_target;
    use super::*;
    use std::{
        io,
        net::{Ipv4Addr, SocketAddr},
        time::Duration,
    };
    use tokio::net::UdpSocket;

    fn packet(target: TargetAddr) -> UdpRelayDatagram {
        UdpRelayDatagram {
            target,
            payload: b"payload".to_vec(),
            lease: None,
        }
    }

    #[tokio::test]
    async fn slow_setup_does_not_block_established_target_and_shutdown_cancels_it() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let target = TargetAddr::Ipv4(Ipv4Addr::LOCALHOST, addr.port());
        let (replies, mut rx) = mpsc::channel(8);
        let state = connect_udp_target(target.clone(), replies.clone(), None)
            .await
            .unwrap();
        let mut targets = UdpTargets::new(replies, None, Arc::new(ProgressClock::new()));
        targets.ready.insert(target.clone(), state);
        let slow = TargetAddr::Domain("slow.invalid".into(), 1);
        assert!(targets.queue_with(packet(slow), |_, _, _| std::future::pending()));
        assert!(targets.queue(packet(target)));
        tokio::time::timeout(Duration::from_secs(1), targets.progress())
            .await
            .unwrap()
            .unwrap();
        let mut bytes = [0; 7];
        let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..length], b"payload");
        socket.send_to(b"reverse", peer).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap()
                .payload,
            b"reverse"
        );
        assert_eq!(targets.setup.len(), 1);
        targets.shutdown().await;
        assert!(targets.setup.is_empty());
        assert_eq!(targets.bytes, 0);
    }

    #[tokio::test]
    async fn failed_setup_releases_packets_and_pending_setup_is_bounded() {
        let (tx, _rx) = mpsc::channel(1);
        let mut targets = UdpTargets::new(tx, None, Arc::new(ProgressClock::new()));
        let target = TargetAddr::Ipv4(Ipv4Addr::LOCALHOST, 1);
        assert!(targets.queue_with(packet(target.clone()), |_, _, _| async {
            Err(io::Error::from(io::ErrorKind::NotFound).into())
        }));
        assert!(targets.queue(packet(target)));
        targets.progress().await.unwrap();
        assert_eq!(targets.bytes, 0);
        assert_eq!(targets.packets, 0);
        for port in 1..=MAX_SETUP {
            let SocketAddr::V4(address) =
                SocketAddr::from(([127, 0, 0, 1], u16::try_from(port).unwrap()))
            else {
                unreachable!()
            };
            assert!(targets.queue_with(
                packet(TargetAddr::Ipv4(*address.ip(), address.port())),
                |_, _, _| std::future::pending()
            ));
        }
        assert!(!targets.queue(packet(TargetAddr::Ipv4(Ipv4Addr::LOCALHOST, 100))));
        targets.shutdown().await;
        assert_eq!(targets.packets, 0);
    }
}
