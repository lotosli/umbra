use std::{
    future::poll_fn,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use tokio::io::{DuplexStream, ReadBuf};
use umbra_crypto::{mlkem::mlkem_keygen, x25519};
use umbra_fingerprint::load_profile;
use umbra_tls::{
    clienthello::{ClientHelloParams, MlkemShare},
    handshake::{CertVerify, PeerKind, Tls13Client},
    server::{DestProfile, ForgedCert, Tls13Server},
};

use super::*;
use crate::tls_io::TlsAppEndpoint;

type Session = VisionSession<ReadHalf<DuplexStream>, WriteHalf<DuplexStream>>;

struct Fixture {
    client: Tls13Client,
    server: Tls13Server,
    observer: Tls13Observer,
}

fn fixture() -> Fixture {
    let profile = load_profile("chrome-latest").expect("fingerprint");
    let keypair = x25519::generate_keypair();
    let public = *keypair.public.as_bytes();
    let mlkem = mlkem_keygen();
    let mut key_exchange = mlkem.encapsulation_key;
    key_exchange.extend_from_slice(&public);
    let params = ClientHelloParams {
        sni: "server.example".to_owned(),
        session_id: vec![0x44; 32],
        x25519_priv: *keypair.private.expose_secret(),
        x25519_pub: public,
        mlkem: MlkemShare::x25519_mlkem768_with_decapsulation_key(
            key_exchange,
            mlkem.decapsulation_key,
        ),
        profile,
        random: [0x22; 32],
        quic_transport_parameters: Vec::new(),
    };
    let dest = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
    let (mut client, hello) = Tls13Client::start(params).expect("start client");
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(["server.example".to_owned()]).expect("certificate");
    let cert = ForgedCert {
        leaf_der: cert.der().as_ref().to_vec(),
        chain_der: Vec::new(),
        certificate_verify_key_der: key_pair.serialize_der(),
    };
    let (mut server, flight) = Tls13Server::accept(&hello, cert, &dest).expect("accept");
    let output = client.drive(&flight, &AcceptAll).expect("client finish");
    server.drive(&output.outbound).expect("server finish");
    let mut observer = Tls13Observer::new();
    observer
        .observe(VisionDirection::ClientToTarget, &hello)
        .expect("observe hello");
    observer
        .observe(VisionDirection::TargetToClient, &flight)
        .expect("observe flight");
    observer
        .observe(VisionDirection::ClientToTarget, &output.outbound)
        .expect("observe finish");
    assert!(
        observer.eligible(),
        "real completed TLS handshake establishes structural eligibility"
    );
    Fixture {
        client,
        server,
        observer,
    }
}

struct AcceptAll;

impl CertVerify for AcceptAll {
    fn verify(&self, _leaf_der: &[u8], _chain: &[Vec<u8>]) -> PeerKind {
        PeerKind::UmbraTrusted
    }
}

fn established_pair() -> (EstablishedTcp<DuplexStream>, EstablishedTcp<DuplexStream>) {
    let Fixture { client, server, .. } = fixture();
    let (client_io, server_io) = tokio::io::duplex(65_536);
    (
        EstablishedTcp::new(
            client_io,
            TlsAppEndpoint::Client(Box::new(client)),
            Vec::new(),
        )
        .expect("client owner"),
        EstablishedTcp::new(
            server_io,
            TlsAppEndpoint::Server(Box::new(server)),
            Vec::new(),
        )
        .expect("server owner"),
    )
}

fn sessions(raw_enabled: bool) -> (Session, Session) {
    let (client, server) = established_pair();
    let (reader, writer, stats) = client.split();
    let client = VisionSession::new(reader, writer, stats, Role::Client, raw_enabled);
    let (reader, writer, stats) = server.split();
    let server = VisionSession::new(reader, writer, stats, Role::Server, raw_enabled);
    (client, server)
}

fn set_eligible(session: &mut Session) -> Boundaries {
    session.observer = fixture().observer;
    session.tx_offset = session.observer.offset(session.tx_direction());
    session.rx_offset = session.observer.offset(session.rx_direction());
    Boundaries {
        switch_id: 1,
        c2s_boundary: session.observer.offset(VisionDirection::ClientToTarget),
        s2c_boundary: session.observer.offset(VisionDirection::TargetToClient),
    }
}

fn zero_bounds() -> Boundaries {
    Boundaries {
        switch_id: 1,
        c2s_boundary: 0,
        s2c_boundary: 0,
    }
}

#[test]
fn unexpected_controls_and_wrong_roles_never_advance_to_raw() {
    for control in [
        Message::Hello {
            min_raw_ver: 1,
            max_raw_ver: 1,
            features: 1,
        },
        Message::HelloAck {
            selected_raw_ver: 1,
            target_result: 0,
            features: 1,
        },
        Message::SwitchAck(zero_bounds()),
        Message::Commit(zero_bounds()),
        Message::CommitAck(zero_bounds()),
        Message::SwitchReject {
            boundaries: zero_bounds(),
            reason: 1,
        },
    ] {
        let (mut client, _server) = sessions(true);
        assert!(client
            .accept_message(control, &mut PendingBytes::default())
            .is_err());
        assert_eq!(client.stage, Stage::Wrapped);
        assert_eq!(client.stats.snapshot().sealed_records, 0);
    }
    let (mut client, _server) = sessions(true);
    assert!(client
        .accept_message(
            Message::SwitchReq {
                switch_id: 1,
                c2s_boundary: 0
            },
            &mut PendingBytes::default()
        )
        .is_err());
    assert!(!client.switch_attempted);
}

#[tokio::test]
async fn invalid_or_duplicate_requests_are_terminal_even_after_reject() {
    for (raw_enabled, request_id, offset) in [(false, 1, 0), (true, 0, 0), (true, 1, 1)] {
        let (_client, mut server) = sessions(raw_enabled);
        assert!(server
            .accept_message(
                Message::SwitchReq {
                    switch_id: request_id,
                    c2s_boundary: offset
                },
                &mut PendingBytes::default()
            )
            .is_err());
        assert!(!server.switch_attempted);
    }
    let (mut client, mut server) = sessions(true);
    server
        .accept_message(
            Message::SwitchReq {
                switch_id: 1,
                c2s_boundary: 0,
            },
            &mut PendingBytes::default(),
        )
        .expect("request before eligibility");
    assert!(server.switch_attempted);
    assert_eq!(server.stage, Stage::ServerPrepareReject { c: 0, reason: 1 });
    assert!(server
        .accept_message(
            Message::SwitchReq {
                switch_id: 1,
                c2s_boundary: 0
            },
            &mut PendingBytes::default()
        )
        .is_err());
    server.drive(true).expect("queue reject");
    server.writer.flush_pending().await.expect("flush reject");
    assert!(matches!(
        receive(&mut client.reader).await.expect("reject"),
        Message::SwitchReject { reason: 1, .. }
    ));
    assert_eq!(server.stage, Stage::WrappedOnly);
    assert!(server.switch_started.is_none());
    assert!(server
        .accept_message(
            Message::SwitchReq {
                switch_id: 1,
                c2s_boundary: 0
            },
            &mut PendingBytes::default()
        )
        .is_err());
}

#[test]
fn data_fin_and_padding_obey_exact_offsets_and_phase() {
    let (mut client, _server) = sessions(false);
    let mut pending = PendingBytes::default();
    client
        .accept_message(Message::Data(b"abc".to_vec()), &mut pending)
        .expect("data");
    assert_eq!(client.rx_offset, 3);
    assert_eq!(pending.bytes, 3);
    assert!(client
        .accept_message(Message::Fin { final_offset: 2 }, &mut pending)
        .is_err());
    assert!(!client.rx_fin);
    client
        .accept_message(Message::Fin { final_offset: 3 }, &mut pending)
        .expect("exact FIN");
    assert!(client
        .accept_message(Message::Fin { final_offset: 3 }, &mut pending)
        .is_err());
    assert!(client
        .accept_message(Message::Data(b"after fin".to_vec()), &mut pending)
        .is_err());
    for phase in [
        Stage::ClientWaitFinal(zero_bounds()),
        Stage::ServerWaitCommit(zero_bounds()),
        Stage::Raw,
    ] {
        client.stage = phase;
        assert!(client
            .accept_message(Message::Data(vec![1]), &mut pending)
            .is_err());
        assert!(client
            .accept_message(Message::Padding, &mut pending)
            .is_err());
        assert!(client
            .accept_message(Message::Fin { final_offset: 3 }, &mut pending)
            .is_err());
    }
    assert_eq!(pending.bytes, 3);
}

#[tokio::test]
async fn crossing_server_fin_and_client_request_rejects_then_relays_reverse_bytes() {
    let (mut client, mut server) = sessions(true);
    let mut server_pending = PendingBytes::default();
    let mut client_pending = PendingBytes::default();
    server.tx_state = SendState::Eof;
    server.drive(true).expect("queue local FIN");
    assert_eq!(server.tx_state, SendState::Fin);
    server.writer.flush_pending().await.expect("flush FIN");
    client.stage = Stage::ClientWaitAck { c: 0 };
    client.switch_started = Some(Instant::now());
    client.switch_attempted = true;
    let fin = receive(&mut client.reader).await.expect("receive FIN");
    client
        .accept_message(fin, &mut client_pending)
        .expect("crossing FIN allowed");
    assert!(client.rx_fin);
    server
        .accept_message(
            Message::SwitchReq {
                switch_id: 1,
                c2s_boundary: 0,
            },
            &mut server_pending,
        )
        .expect("crossing request");
    server.drive(true).expect("queue reject after FIN");
    server.writer.flush_pending().await.expect("flush reject");
    let reject = receive(&mut client.reader).await.expect("receive reject");
    assert!(matches!(&reject, Message::SwitchReject { reason: 2, .. }));
    client
        .accept_message(reject, &mut client_pending)
        .expect("finish rejection");
    assert_eq!(client.stage, Stage::WrappedOnly);
    assert_eq!(server.stage, Stage::WrappedOnly);
    client
        .queue_data(b"request body after server half-close")
        .expect("reverse data remains open");
    client
        .writer
        .flush_pending()
        .await
        .expect("flush reverse data");
    let data = receive(&mut server.reader).await.expect("reverse record");
    server
        .accept_message(data, &mut server_pending)
        .expect("accept reverse data");
    let mut output = StepWriter::unlimited();
    while !server_pending.is_idle() {
        server_pending
            .flush_or_shutdown(&mut output, false)
            .await
            .expect("drain data");
    }
    assert_eq!(output.output(), b"request body after server half-close");
}

#[tokio::test]
async fn acknowledgement_and_commit_require_exact_verified_boundaries() {
    let (mut client, mut server) = sessions(true);
    let bounds = set_eligible(&mut client);
    client.stage = Stage::ClientWaitAck {
        c: bounds.c2s_boundary,
    };
    for wrong in [
        Boundaries {
            switch_id: 2,
            ..bounds
        },
        Boundaries {
            c2s_boundary: bounds.c2s_boundary + 1,
            ..bounds
        },
        Boundaries {
            s2c_boundary: bounds.s2c_boundary + 1,
            ..bounds
        },
    ] {
        assert!(client
            .accept_message(Message::SwitchAck(wrong), &mut PendingBytes::default())
            .is_err());
    }
    client
        .accept_message(Message::SwitchAck(bounds), &mut PendingBytes::default())
        .expect("verified ACK");
    client.drive(false).expect("wait for target delivery");
    assert!(client.writer.is_idle());
    client.drive(true).expect("queue COMMIT");
    assert_eq!(client.stage, Stage::ClientCommitDraining(bounds));
    assert!(!client.can_read_peer());
    client.writer.flush_pending().await.expect("commit flush");
    assert!(
        matches!(receive(&mut server.reader).await.expect("commit"), Message::Commit(value) if value == bounds)
    );
    client.drive(true).expect("advance after flush");
    assert_eq!(client.stage, Stage::ClientWaitFinal(bounds));
    assert!(client
        .accept_message(
            Message::CommitAck(Boundaries {
                s2c_boundary: bounds.s2c_boundary + 1,
                ..bounds
            }),
            &mut PendingBytes::default()
        )
        .is_err());
    client
        .accept_message(Message::CommitAck(bounds), &mut PendingBytes::default())
        .expect("final authenticated ACK");
    assert_eq!(client.stage, Stage::Raw);

    server.stage = Stage::ServerWaitCommit(bounds);
    assert!(server
        .accept_message(
            Message::Commit(Boundaries {
                c2s_boundary: 0,
                ..bounds
            }),
            &mut PendingBytes::default()
        )
        .is_err());
    server
        .accept_message(Message::Commit(bounds), &mut PendingBytes::default())
        .expect("exact commit");
    assert_eq!(server.stage, Stage::ServerPrepareFinal(bounds));
}

#[test]
fn reject_reasons_match_crossing_fin_and_exact_counters() {
    for (fin, reason, valid) in [
        (false, 1, true),
        (false, 2, false),
        (true, 1, false),
        (true, 2, true),
    ] {
        let (mut client, _server) = sessions(true);
        client.stage = Stage::ClientWaitAck { c: 0 };
        client.rx_fin = fin;
        let result = client.accept_message(
            Message::SwitchReject {
                boundaries: zero_bounds(),
                reason,
            },
            &mut PendingBytes::default(),
        );
        assert_eq!(result.is_ok(), valid);
    }
    let (mut client, _server) = sessions(true);
    client.stage = Stage::ClientWaitAck { c: 3 };
    assert!(client
        .accept_message(
            Message::SwitchReject {
                boundaries: zero_bounds(),
                reason: 1
            },
            &mut PendingBytes::default()
        )
        .is_err());
}

#[tokio::test]
async fn partial_server_record_that_loses_eligibility_queues_reject_without_another_event() {
    let (mut client, mut server) = sessions(true);
    let bounds = set_eligible(&mut server);
    server
        .observer
        .observe(server.tx_direction(), &[0x17, 3])
        .expect("partial next header");
    assert!(!server.observer.is_boundary(server.tx_direction()));
    server.stage = Stage::ServerPrepareAck {
        c: bounds.c2s_boundary,
    };
    server.switch_started = Some(Instant::now());
    server.switch_attempted = true;
    assert!(server.can_read_local());
    server
        .observer
        .observe(server.tx_direction(), &[1, 0, 17])
        .expect("unsupported header disables");
    assert!(server.observer.disabled());
    server.drive(true).expect("immediate reject");
    assert_eq!(server.stage, Stage::WrappedOnly);
    assert_eq!(server.writer.pending_records(), 1);
    server.writer.flush_pending().await.expect("flush reject");
    assert!(matches!(
        receive(&mut client.reader).await.expect("reject"),
        Message::SwitchReject { reason: 1, .. }
    ));
}

#[tokio::test]
async fn switch_deadline_is_absolute_and_barrier_preserves_existing_evidence() {
    let (mut client, _server) = sessions(true);
    let bounds = set_eligible(&mut client);
    client.observation_started = Some(Instant::now() - OBSERVE_TIMEOUT - Duration::from_secs(1));
    client.switch_started = Some(Instant::now() - SWITCH_TIMEOUT - Duration::from_millis(1));
    client.switch_attempted = true;
    client.stage = Stage::ClientWaitAck {
        c: bounds.c2s_boundary,
    };
    client
        .drive(true)
        .expect("barrier retains previously checked evidence");
    assert!(client.observer.eligible());
    let (mut local, _application) = tokio::io::duplex(128);
    let result = client.relay(&mut local, Duration::from_mins(1)).await;
    assert_eq!(
        result.expect_err("expired barrier").kind(),
        io::ErrorKind::TimedOut
    );

    let (mut client, _server) = sessions(true);
    set_eligible(&mut client);
    client.observation_started = Some(Instant::now() - OBSERVE_TIMEOUT - Duration::from_secs(1));
    client
        .drive(true)
        .expect("observation expires before attempt");
    assert!(client.observer.disabled());
    assert!(!client.switch_attempted);
    assert!(client.writer.is_idle());
}

#[tokio::test]
async fn client_setup_rejects_bad_acknowledgements_before_business_data() {
    for failure in ["wrong_kind", "raw_version", "target_result", "refused"] {
        let (client, server) = established_pair();
        let target = TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST, 443);
        let peer = async {
            let (mut reader, mut writer, _) = server.split();
            assert_eq!(
                TargetAddr::decode(
                    &reader
                        .next_record()
                        .await
                        .expect("target record")
                        .expect("target bytes")
                )
                .expect("target"),
                target
            );
            assert!(matches!(
                receive(&mut reader).await.expect("HELLO"),
                Message::Hello { .. }
            ));
            let mut ack = encode(
                Message::HelloAck {
                    selected_raw_ver: 1,
                    target_result: 0,
                    features: 1,
                },
                Vec::new(),
            )
            .expect("ACK");
            match failure {
                "wrong_kind" => ack = encode(Message::Data(vec![1]), Vec::new()).expect("DATA"),
                "raw_version" => ack[8] = 2,
                "target_result" => ack[9] = 2,
                _ => ack[9] = 1,
            }
            writer
                .queue_record(&ack)
                .expect("malformed plaintext still authenticates");
            writer.flush_pending().await.expect("write ACK");
            reader
                .next_record()
                .await
                .expect("client closes without business")
        };
        let (result, extra) = tokio::join!(client_open(client, &target), peer);
        assert!(result.is_err());
        assert!(extra.is_none());
    }
}

#[tokio::test]
async fn server_declines_unoffered_raw_capability_but_accepts_wrapped_session() {
    let (client, server) = established_pair();
    let target = TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST, 443);
    let peer = async {
        let (mut reader, mut writer, _) = client.split();
        writer
            .queue_record(&target.encode().expect("target"))
            .expect("queue target");
        writer.flush_pending().await.expect("target flush");
        send(
            &mut writer,
            Message::Hello {
                min_raw_ver: 2,
                max_raw_ver: 3,
                features: 1,
            },
        )
        .await
        .expect("HELLO future raw version");
        receive(&mut reader).await.expect("wrapped-only ACK")
    };
    let (accepted, ack) = tokio::join!(server_open(server, |_target| async { Ok(()) }), peer);
    let (session, ()) = accepted.expect("accepted wrapped v2");
    assert!(!session.raw_enabled);
    assert_eq!(session.stage, Stage::WrappedOnly);
    assert!(matches!(
        ack,
        Message::HelloAck {
            selected_raw_ver: 0,
            target_result: 0,
            features: 0
        }
    ));
}

#[tokio::test]
async fn target_failure_and_preface_trailing_bytes_fail_before_relay() {
    let (client, server) = established_pair();
    let target = TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST, 443);
    let (client_result, server_result) = tokio::join!(
        client_open(client, &target),
        server_open(server, |_target| async {
            Err::<(), _>(io::Error::from(io::ErrorKind::ConnectionRefused))
        }),
    );
    assert_eq!(
        client_result.err().expect("client failure").kind(),
        io::ErrorKind::ConnectionRefused
    );
    assert_eq!(
        server_result.err().expect("server failure").kind(),
        io::ErrorKind::ConnectionRefused
    );

    let (client, server) = established_pair();
    let (_reader, mut writer, _) = client.split();
    let mut preface = target.encode().expect("target");
    preface.push(0);
    writer
        .queue_record(&preface)
        .expect("trailing target bytes");
    writer.flush_pending().await.expect("flush target");
    let mut connected = false;
    let result = server_open(server, |_target| {
        connected = true;
        async { Ok(()) }
    })
    .await;
    assert!(!connected, "invalid target must not reach the connector");
    assert_eq!(
        result.err().expect("reject trailing bytes").kind(),
        io::ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn wrapped_fin_then_outer_eof_drains_queued_target_bytes_before_shutdown() {
    let (client, mut server) = sessions(false);
    let (mut local, mut application) = tokio::io::duplex(8);
    let payload = vec![0x4a; 8192];
    let expected = payload.clone();
    let peer = async move {
        assert!(matches!(
            receive(&mut server.reader).await.expect("client FIN"),
            Message::Fin { final_offset: 0 }
        ));
        server.queue_data(&payload).expect("response DATA");
        server.writer.flush_pending().await.expect("response flush");
        server.tx_state = SendState::Eof;
        server.drive(true).expect("server FIN");
        server.writer.flush_pending().await.expect("FIN flush");
        // Both logical FINs are now known to the peer. Dropping its owners can
        // expose TCP EOF before the client's small local buffer has drained.
    };
    let application = async move {
        application
            .shutdown()
            .await
            .expect("application request EOF");
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut observed = Vec::new();
        application
            .read_to_end(&mut observed)
            .await
            .expect("response half-close");
        observed
    };
    let (outcome, (), observed) = tokio::join!(
        client.relay(&mut local, Duration::from_secs(2)),
        peer,
        application
    );
    assert!(!outcome.expect("ordinary wrapped half-close").spliced);
    assert_eq!(observed, expected);
}

#[tokio::test]
async fn barrier_eof_after_crossing_fin_still_requires_reject() {
    let (mut client, server) = sessions(true);
    client.stage = Stage::ClientWaitAck { c: 0 };
    client.switch_started = Some(Instant::now());
    client.switch_attempted = true;
    client.rx_fin = true;
    drop(server);
    let (mut local, _application) = tokio::io::duplex(32);
    assert_eq!(
        client
            .relay(&mut local, Duration::from_secs(2))
            .await
            .expect_err("FIN cannot replace REJECT during barrier")
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[derive(Default)]
struct WriteState {
    bytes: Vec<u8>,
    budget: usize,
    zero: bool,
    shutdowns: usize,
}

#[derive(Clone, Default)]
struct StepWriter(Arc<Mutex<WriteState>>);

impl StepWriter {
    fn unlimited() -> Self {
        Self(Arc::new(Mutex::new(WriteState {
            budget: usize::MAX,
            ..WriteState::default()
        })))
    }

    fn output(&self) -> Vec<u8> {
        self.0.lock().expect("writer state").bytes.clone()
    }
}

impl AsyncWrite for StepWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut output = self.0.lock().expect("writer state");
        if output.zero {
            return Poll::Ready(Ok(0));
        }
        if output.budget == 0 {
            return Poll::Pending;
        }
        let count = bytes.len().min(output.budget);
        output.bytes.extend_from_slice(&bytes[..count]);
        output.budget -= count;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.lock().expect("writer state").shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}

async fn cancel_pending<F: Future>(future: F) {
    tokio::pin!(future);
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn pending_delivery_bounds_zero_writes_and_cancellation_preserve_bytes() {
    let mut pending = PendingBytes::default();
    pending
        .push(vec![7; QUEUE_LIMIT])
        .expect("exact queue bound");
    assert!(pending.push(vec![8]).is_err());
    assert_eq!(pending.bytes, QUEUE_LIMIT);
    let mut zero = StepWriter::default();
    zero.0.lock().expect("state").zero = true;
    assert_eq!(
        pending
            .flush_or_shutdown(&mut zero, false)
            .await
            .expect_err("zero write")
            .kind(),
        io::ErrorKind::WriteZero
    );
    assert_eq!(pending.bytes, QUEUE_LIMIT);

    let mut pending = PendingBytes::default();
    pending.push(b"abcdef".to_vec()).expect("first chunk");
    pending.push(b"ghi".to_vec()).expect("second chunk");
    let mut writer = StepWriter::default();
    writer.0.lock().expect("state").budget = 2;
    assert!(!pending
        .flush_or_shutdown(&mut writer, true)
        .await
        .expect("partial step"));
    assert_eq!(pending.offset, 2);
    assert_eq!(pending.bytes, 7);
    cancel_pending(pending.flush_or_shutdown(&mut writer, true)).await;
    assert_eq!(writer.output(), b"ab");
    assert_eq!(pending.offset, 2);
    writer.0.lock().expect("state").budget = usize::MAX;
    while !pending
        .flush_or_shutdown(&mut writer, true)
        .await
        .expect("resume")
    {}
    assert!(pending.is_idle());
    assert_eq!(writer.output(), b"abcdefghi");
    assert_eq!(writer.0.lock().expect("state").shutdowns, 1);
}

fn protected_record(fill: u8) -> Vec<u8> {
    [&[0x17, 3, 3, 0, 17][..], &[fill; 17][..]].concat()
}

#[tokio::test]
async fn raw_guard_rejects_bad_headers_and_every_partial_record_without_forwarding() {
    let record = protected_record(0x51);
    let mut bad = vec![
        vec![0x16, 3, 3, 0, 17],
        vec![0x17, 3, 1, 0, 17],
        vec![0x17, 3, 3, 0, 16],
        vec![0x17, 3, 3, 0x41, 1],
    ];
    bad.extend((1..record.len()).map(|cut| record[..cut].to_vec()));
    for input in bad {
        let mut reader = input.as_slice();
        let mut writer = StepWriter::unlimited();
        let (progress, _changes) = watch::channel(Instant::now());
        assert!(forward_records(&mut reader, &mut writer, false, &progress)
            .await
            .is_err());
        assert!(writer.output().is_empty());
        assert_eq!(writer.0.lock().expect("state").shutdowns, 0);
    }
    let input = [record.clone(), vec![0x16, 3, 3, 0, 17]].concat();
    let mut reader = input.as_slice();
    let mut writer = StepWriter::unlimited();
    let (progress, _changes) = watch::channel(Instant::now());
    assert!(forward_records(&mut reader, &mut writer, false, &progress)
        .await
        .is_err());
    assert_eq!(
        writer.output(),
        record,
        "only the preceding valid protected record is forwarded"
    );
}

#[tokio::test]
async fn raw_eof_half_closes_and_preserves_the_opposite_direction() {
    let record = protected_record(0x62);
    let mut local_read = tokio::io::empty();
    let mut local_write = StepWriter::unlimited();
    let peer_write = StepWriter::unlimited();
    let peer_observed = peer_write.clone();
    let result = raw_relay(
        &mut local_read,
        &mut local_write,
        record.as_slice(),
        peer_write,
        true,
        Duration::from_secs(1),
    )
    .await
    .expect("raw half close");
    assert_eq!(
        result,
        (0, u64::try_from(record.len()).expect("record count"))
    );
    assert_eq!(local_write.output(), record);
    assert!(peer_observed.output().is_empty());
    assert_eq!(local_write.0.lock().expect("state").shutdowns, 1);
    assert_eq!(peer_observed.0.lock().expect("state").shutdowns, 1);
}

#[tokio::test]
async fn raw_idle_and_write_zero_terminate_owned_work() {
    let (mut local_read, _local_peer) = tokio::io::duplex(32);
    let (peer_read, _remote_peer) = tokio::io::duplex(32);
    let mut local_write = StepWriter::unlimited();
    let peer_write = StepWriter::unlimited();
    assert_eq!(
        raw_relay(
            &mut local_read,
            &mut local_write,
            peer_read,
            peer_write,
            false,
            Duration::from_millis(5)
        )
        .await
        .expect_err("idle raw connection")
        .kind(),
        io::ErrorKind::TimedOut
    );

    let record = protected_record(0x63);
    let mut reader = record.as_slice();
    let mut writer = StepWriter::default();
    writer.0.lock().expect("state").zero = true;
    let (progress, _changes) = watch::channel(Instant::now());
    assert_eq!(
        forward_records(&mut reader, &mut writer, false, &progress)
            .await
            .expect_err("raw write zero")
            .kind(),
        io::ErrorKind::WriteZero
    );
    assert!(writer.output().is_empty());
}

struct PacedReader {
    bytes: VecDeque<u8>,
    next: Pin<Box<tokio::time::Sleep>>,
}

impl AsyncRead for PacedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.bytes.is_empty() || output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.next.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        output.put_slice(&[self.bytes.pop_front().expect("nonempty checked")]);
        self.next
            .as_mut()
            .reset(Instant::now() + Duration::from_millis(10));
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn raw_partial_record_activity_refreshes_idle_deadline() {
    let record = [&[0x17, 3, 3, 0, 64][..], &[0x54; 64][..]].concat();
    let peer_read = PacedReader {
        bytes: record.clone().into(),
        next: Box::pin(tokio::time::sleep(Duration::from_millis(10))),
    };
    let mut local_read = tokio::io::empty();
    let mut local_write = StepWriter::unlimited();
    let result = raw_relay(
        &mut local_read,
        &mut local_write,
        peer_read,
        StepWriter::unlimited(),
        true,
        Duration::from_millis(200),
    )
    .await
    .expect("individual bytes refresh idle despite a record taking over 200 ms");
    assert_eq!(
        result,
        (0, u64::try_from(record.len()).expect("record length"))
    );
    assert_eq!(local_write.output(), record);
}

#[test]
fn byte_counters_check_overflow() {
    assert_eq!(add_bytes(u64::MAX - 2, 2).expect("exact maximum"), u64::MAX);
    assert!(add_bytes(u64::MAX, 1).is_err());
}

#[tokio::test]
#[ignore = "explicit release-mode raw-record throughput diagnostic"]
async fn measure_raw_record_throughput() {
    let mut record = vec![0x5a; 16_406];
    record[..5].copy_from_slice(&[0x17, 3, 3, 0x40, 0x11]);
    let input = record.repeat(8192);
    for sample in 0..5 {
        let (progress, _) = watch::channel(Instant::now());
        let mut reader = input.as_slice();
        let mut sink = tokio::io::sink();
        let start = Instant::now();
        let count = forward_records(&mut reader, &mut sink, false, &progress)
            .await
            .expect("valid complete records");
        assert_eq!(count, u64::try_from(input.len()).expect("bounded input"));
        assert!(reader.is_empty());
        println!(
            "mode=raw-records sample={sample} records=8192 bytes={count} elapsed_ns={}",
            start.elapsed().as_nanos()
        );
    }
}
