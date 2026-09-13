//! Deterministic cancellation, dispatch, credit and lifecycle tests for mux.

use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::{pin, Pin},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use umbra_inner::{
    mux::{
        MuxEvent, MuxRole, MuxSession, MuxSettings, MuxStream, MAX_DATA_CHUNK_LEN,
        MAX_PENDING_EVENTS, MAX_PENDING_EVENT_BYTES, MAX_PENDING_WRITE_BYTES,
        MAX_PENDING_WRITE_FRAMES, MAX_RECEIVE_BUFFER_BYTES, MAX_STREAMS,
    },
    padding::PadScheme,
    InnerError,
};
use umbra_proto::{
    addr::TargetAddr,
    frame::{MuxCommand, MuxFrame, MAX_FRAME_PAYLOAD_LEN},
    udp::UdpEnvelope,
};

#[derive(Clone)]
struct Control(Arc<Mutex<Script>>);

#[test]
fn effective_stream_capacity_accounts_for_reserved_receive_credit() {
    for (window, expected) in [
        (0, MAX_STREAMS),
        (1, MAX_STREAMS),
        (64 * 1024, MAX_STREAMS),
        (256 * 1024, 32),
        (MAX_RECEIVE_BUFFER_BYTES, 1),
    ] {
        let (io, _control) = Control::new();
        let session = MuxSession::with_settings(
            io,
            MuxRole::Client,
            &PadScheme::none(),
            MuxSettings {
                initial_window: window,
                ..MuxSettings::default()
            },
        )
        .expect("bounded settings accepted");
        assert_eq!(session.stream_capacity(), expected);
        assert_eq!(session.active_stream_count(), 0);
    }
}

enum FlushMode {
    Ready,
    Blocked,
    Failed,
}

struct Script {
    input: VecDeque<u8>,
    output: Vec<u8>,
    read_allowance: usize,
    write_allowance: usize,
    flush: FlushMode,
    eof: bool,
    write_error: Option<io::ErrorKind>,
    write_zero: bool,
    dropped: bool,
}

impl Control {
    fn new() -> (ScriptIo, Self) {
        let control = Self(Arc::new(Mutex::new(Script {
            input: VecDeque::new(),
            output: Vec::new(),
            read_allowance: usize::MAX,
            write_allowance: usize::MAX,
            flush: FlushMode::Ready,
            eof: false,
            write_error: None,
            write_zero: false,
            dropped: false,
        })));
        (ScriptIo(control.clone()), control)
    }

    fn feed(&self, bytes: &[u8]) {
        self.0.lock().expect("script").input.extend(bytes);
    }

    fn output(&self) -> Vec<u8> {
        self.0.lock().expect("script").output.clone()
    }

    fn clear_output(&self) {
        self.0.lock().expect("script").output.clear();
    }

    fn read_allowance(&self, bytes: usize) {
        self.0.lock().expect("script").read_allowance = bytes;
    }

    fn write_allowance(&self, bytes: usize) {
        self.0.lock().expect("script").write_allowance = bytes;
    }
}

struct ScriptIo(Control);

impl Drop for ScriptIo {
    fn drop(&mut self) {
        self.0 .0.lock().expect("script").dropped = true;
    }
}

impl AsyncRead for ScriptIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut script = self.0 .0.lock().expect("script");
        if script.input.is_empty() && script.eof {
            return Poll::Ready(Ok(()));
        }
        let len = buf
            .remaining()
            .min(script.input.len())
            .min(script.read_allowance);
        if len == 0 {
            return Poll::Pending;
        }
        let bytes: Vec<u8> = script.input.drain(..len).collect();
        script.read_allowance -= len;
        buf.put_slice(&bytes);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut script = self.0 .0.lock().expect("script");
        if let Some(error) = script.write_error {
            return Poll::Ready(Err(error.into()));
        }
        if script.write_zero {
            return Poll::Ready(Ok(0));
        }
        let len = bytes.len().min(script.write_allowance);
        if len == 0 {
            return Poll::Pending;
        }
        script.write_allowance -= len;
        script.output.extend_from_slice(&bytes[..len]);
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let script = self.0 .0.lock().expect("script");
        match script.flush {
            FlushMode::Failed => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            FlushMode::Blocked => Poll::Pending,
            FlushMode::Ready => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

fn complete<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("scripted operation unexpectedly blocked"),
    }
}

fn cancel_pending<F: Future>(future: F) {
    let mut future = pin!(future);
    assert!(future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
}

fn target() -> TargetAddr {
    TargetAddr::domain("mux.example", 443).expect("target")
}

fn wire(command: MuxCommand, id: u32, payload: &[u8]) -> Vec<u8> {
    MuxFrame::new(command, id, payload.to_vec())
        .expect("frame")
        .encode()
        .expect("encode")
}

fn data_event(id: u32, bytes: &[u8]) -> MuxEvent {
    MuxEvent::Data {
        stream_id: id,
        payload: bytes.to_vec(),
    }
}

fn session(role: MuxRole, window: usize, pad: &PadScheme) -> (MuxSession<ScriptIo>, Control) {
    let (io, control) = Control::new();
    let settings = MuxSettings {
        initial_window: window,
        ..MuxSettings::default()
    };
    (
        MuxSession::with_settings(io, role, pad, settings).expect("session"),
        control,
    )
}

fn client(window: usize) -> (MuxSession<ScriptIo>, MuxStream, Control) {
    let (mut session, control) = session(MuxRole::Client, window, &PadScheme::none());
    let stream = establish_client(&mut session, &control);
    (session, stream, control)
}

fn establish_client(session: &mut MuxSession<ScriptIo>, control: &Control) -> MuxStream {
    let stream = session.begin_open(&target()).expect("begin open");
    assert_eq!(
        session
            .send_credit(stream.stream_id)
            .expect("opening credit"),
        0
    );
    assert_eq!(
        session
            .try_send_data(stream.stream_id, b"not-yet")
            .expect("opening send"),
        0
    );
    control.feed(&wire(MuxCommand::SynAck, stream.stream_id, &[]));
    assert_eq!(
        complete(session.receive_next()).expect("ack"),
        MuxEvent::SynAck {
            stream_id: stream.stream_id
        }
    );
    control.clear_output();
    stream
}

fn server(window: usize) -> (MuxSession<ScriptIo>, MuxStream, Control) {
    let (mut session, control) = session(MuxRole::Server, window, &PadScheme::none());
    let stream = establish_server(&mut session, &control, 1);
    (session, stream, control)
}

fn establish_server(session: &mut MuxSession<ScriptIo>, control: &Control, id: u32) -> MuxStream {
    control.feed(&wire(
        MuxCommand::Syn,
        id,
        &target().encode().expect("target"),
    ));
    let (stream, accepted) = complete(session.accept()).expect("accept");
    assert_eq!(stream.stream_id, id);
    assert_eq!(accepted, target());
    control.clear_output();
    stream
}

fn trailing_frames(id: u32) -> [Vec<u8>; 5] {
    [
        wire(MuxCommand::SynAck, id, &[]),
        wire(MuxCommand::Data, id, b"late"),
        wire(MuxCommand::WindowUpdate, id, &1_u32.to_be_bytes()),
        wire(MuxCommand::Fin, id, &[]),
        wire(MuxCommand::Rst, id, &[]),
    ]
}

fn assert_retired(session: &mut MuxSession<ScriptIo>, id: u32) {
    assert!(matches!(
        session.send_credit(id),
        Err(InnerError::StreamReset)
    ));
    assert!(matches!(
        session.try_send_data(id, b"x"),
        Err(InnerError::StreamReset)
    ));
    assert!(matches!(
        session.queue_accept(id),
        Err(InnerError::StreamReset)
    ));
    assert!(matches!(
        session.queue_window_update(id, 1),
        Err(InnerError::StreamReset)
    ));
    assert!(matches!(
        session.queue_finish(id),
        Err(InnerError::StreamReset)
    ));
    assert!(matches!(
        session.queue_reset(id),
        Err(InnerError::StreamReset)
    ));
}

fn assert_would_block<T: std::fmt::Debug>(result: Result<T, InnerError>) {
    match result {
        Err(InnerError::Io(error)) => assert_eq!(error.kind(), io::ErrorKind::WouldBlock),
        other => panic!("expected WouldBlock, got {other:?}"),
    }
}

#[test]
fn receive_cancelled_at_every_header_and_body_split_preserves_following_frame() {
    let frame = wire(MuxCommand::Data, 1, b"payload");
    let next = wire(MuxCommand::Ping, 0, b"next");
    for split in 0..frame.len() {
        let (mut session, _, control) = client(32);
        control.feed(&frame);
        control.feed(&next);
        control.read_allowance(split);
        cancel_pending(session.receive_next());
        control.read_allowance(usize::MAX);
        assert_eq!(
            complete(session.receive_next()).expect("DATA"),
            data_event(1, b"payload"),
            "split {split}"
        );
        assert_eq!(
            complete(session.receive_next()).expect("next event"),
            MuxEvent::Ping {
                stream_id: 0,
                payload: b"next".to_vec()
            }
        );
        cancel_pending(session.receive_next());
    }
}

#[test]
fn repeated_one_byte_cancellations_and_empty_body_are_lossless() {
    for frame in [
        wire(MuxCommand::Data, 1, b"fragmented"),
        wire(MuxCommand::Fin, 1, &[]),
    ] {
        let (mut session, _, control) = client(32);
        control.feed(&frame);
        for _ in 0..frame.len() - 1 {
            control.read_allowance(1);
            cancel_pending(session.receive_next());
        }
        control.read_allowance(1);
        let expected = if frame[1] == u8::from(MuxCommand::Fin) {
            MuxEvent::Fin { stream_id: 1 }
        } else {
            data_event(1, b"fragmented")
        };
        assert_eq!(
            complete(session.receive_next()).expect("resumed frame"),
            expected
        );
        cancel_pending(session.receive_next());
    }
}

#[test]
fn cancelled_sender_finishes_owned_frame_and_padding_before_next_frame() {
    let pad = PadScheme {
        early_records: 20,
        min_len: 2,
        max_len: 2,
        later_every: 0,
    };
    // PADDING(10) + DATA(14) + PADDING(10), including boundaries between frames.
    for split in 0..34 {
        let (mut session, control) = session(MuxRole::Client, 32, &pad);
        let mut stream = establish_client(&mut session, &control);
        control.write_allowance(split);
        cancel_pending(session.send_data_wait_window(&mut stream, b"abcdef"));
        assert_eq!(session.send_credit(1).expect("debited credit"), 26);
        session
            .queue_finish(1)
            .expect("queue FIN behind accepted data");
        control.write_allowance(usize::MAX);
        complete(session.flush_pending()).expect("resume writer");
        let bytes = control.output();
        let mut offset = 0;
        let mut frames = Vec::new();
        while offset < bytes.len() {
            let (frame, len) = MuxFrame::decode_from(&bytes[offset..], MAX_FRAME_PAYLOAD_LEN)
                .expect("serialized frame");
            frames.push(frame);
            offset += len;
        }
        assert_eq!(frames.len(), 4, "split {split}");
        assert_eq!(frames[0].command, MuxCommand::Padding);
        assert_eq!(
            frames[1],
            MuxFrame::new(MuxCommand::Data, 1, b"abcdef".to_vec()).expect("DATA")
        );
        assert_eq!(frames[2].command, MuxCommand::Padding);
        assert_eq!(
            frames[3],
            MuxFrame::new(MuxCommand::Fin, 1, Vec::new()).expect("FIN")
        );
    }
}

#[test]
fn cancellation_during_flush_does_not_replay_encoded_bytes() {
    let (mut session, _, control) = client(8);
    assert_eq!(session.try_send_data(1, b"one").expect("queue"), 3);
    control.0.lock().expect("script").flush = FlushMode::Blocked;
    cancel_pending(session.flush_pending());
    assert_eq!(control.output(), wire(MuxCommand::Data, 1, b"one"));
    assert_eq!(session.try_send_data(1, b"two").expect("queue"), 3);
    control.0.lock().expect("script").flush = FlushMode::Ready;
    complete(session.flush_pending()).expect("resume flush");
    assert_eq!(
        control.output(),
        [
            wire(MuxCommand::Data, 1, b"one"),
            wire(MuxCommand::Data, 1, b"two")
        ]
        .concat()
    );
}

#[test]
fn reading_control_remains_possible_while_writer_is_blocked() {
    let (mut session, _, control) = client(4);
    assert_eq!(session.try_send_data(1, b"full").expect("queue"), 4);
    control.write_allowance(0);
    control.feed(&wire(MuxCommand::Rst, 1, &[]));
    assert_eq!(
        complete(session.receive_next()).expect("RST despite blocked writer"),
        MuxEvent::Rst { stream_id: 1 }
    );
    assert_eq!(session.active_stream_count(), 0);
    assert!(control.output().is_empty());
}

#[test]
fn terminal_write_errors_drop_transport_instead_of_continuing_partial_frame() {
    for mode in 0..3 {
        let (mut session, _, control) = client(16);
        session.try_send_data(1, b"partial").expect("queue");
        control.write_allowance(3);
        cancel_pending(session.flush_pending());
        assert_eq!(control.output().len(), 3);
        {
            let mut script = control.0.lock().expect("script");
            script.write_allowance = usize::MAX;
            match mode {
                0 => script.write_error = Some(io::ErrorKind::BrokenPipe),
                1 => script.write_zero = true,
                _ => script.flush = FlushMode::Failed,
            }
        }
        assert!(matches!(
            complete(session.flush_pending()),
            Err(InnerError::Io(_))
        ));
        assert!(control.0.lock().expect("script").dropped);
        assert!(matches!(
            session.begin_open(&target()),
            Err(InnerError::StreamClosed)
        ));
        assert_eq!(session.active_stream_count(), 0);
        assert!(matches!(
            complete(session.receive_next()),
            Err(InnerError::StreamClosed)
        ));
    }
}

#[test]
fn data_udp_fin_before_window_update_are_retained_exactly_once() {
    let (mut session, mut stream, control) = client(4);
    complete(session.send_data_wait_window(&mut stream, b"full")).expect("exhaust credit");
    control.clear_output();
    let udp = UdpEnvelope::new(target(), b"udp".to_vec()).expect("envelope");
    control.feed(&wire(MuxCommand::Data, 1, b"recv"));
    control.feed(&wire(
        MuxCommand::UdpDatagram,
        0,
        &udp.encode().expect("UDP"),
    ));
    control.feed(&wire(MuxCommand::Fin, 1, &[]));
    control.feed(&wire(MuxCommand::WindowUpdate, 1, &4_u32.to_be_bytes()));
    complete(session.send_data_wait_window(&mut stream, b"next")).expect("credit wait completes");
    assert_eq!(control.output(), wire(MuxCommand::Data, 1, b"next"));
    assert_eq!(session.send_credit(1).expect("credit spent once"), 0);
    assert!(
        matches!(
            session.queue_window_update(1, 4),
            Err(InnerError::WindowOverflow)
        ),
        "queued DATA is not consumed"
    );
    assert_eq!(
        complete(session.receive_next()).expect("queued DATA"),
        data_event(1, b"recv")
    );
    session
        .queue_window_update(1, 4)
        .expect("consume returned data after peer FIN");
    assert_eq!(
        complete(session.receive_next()).expect("queued UDP"),
        MuxEvent::UdpDatagram {
            target: target(),
            payload: b"udp".to_vec()
        }
    );
    assert_eq!(
        complete(session.receive_next()).expect("queued FIN"),
        MuxEvent::Fin { stream_id: 1 }
    );
    assert_eq!(
        complete(session.receive_next()).expect("queued credit event"),
        MuxEvent::WindowUpdate {
            stream_id: 1,
            increment: 4
        }
    );
    assert_eq!(
        session
            .send_credit(1)
            .expect("dequeue never reapplies update"),
        0
    );
    cancel_pending(session.receive_next());
}

#[test]
fn reset_terminates_zero_credit_wait_and_preserves_unrelated_stream() {
    let (mut session, mut stream, control) = client(4);
    let second = establish_client(&mut session, &control);
    complete(session.send_data_wait_window(&mut stream, b"full")).expect("full window");
    control.feed(&wire(MuxCommand::Rst, 1, &[]));
    assert!(matches!(
        complete(session.send_data_wait_window(&mut stream, b"blocked")),
        Err(InnerError::StreamReset)
    ));
    assert!(stream.is_reset());
    assert_eq!(session.active_stream_count(), 1);
    assert_eq!(
        complete(session.receive_next()).expect("RST retained"),
        MuxEvent::Rst { stream_id: 1 }
    );
    assert_eq!(
        session
            .try_send_data(second.stream_id, b"live")
            .expect("other stream"),
        4
    );
}

#[test]
fn pending_open_preserves_established_data_and_handles_rejection() {
    let (mut session, _, control) = client(8);
    control.feed(&wire(MuxCommand::Data, 1, b"old"));
    control.feed(&wire(MuxCommand::SynAck, 3, &[]));
    let stream = complete(session.open(&target())).expect("second open");
    assert_eq!(stream.stream_id, 3);
    assert!(matches!(
        session.queue_window_update(1, 3),
        Err(InnerError::WindowOverflow)
    ));
    assert_eq!(
        complete(session.receive_next()).expect("established data preserved"),
        data_event(1, b"old")
    );
    session
        .queue_window_update(1, 3)
        .expect("consumption credit");
    control.feed(&wire(MuxCommand::Rst, 5, &[]));
    assert!(matches!(
        complete(session.open(&target())),
        Err(InnerError::StreamReset)
    ));
    assert_eq!(
        complete(session.receive_next()).expect("rejected open event"),
        MuxEvent::Rst { stream_id: 5 }
    );
    assert_eq!(session.active_stream_count(), 2);
    cancel_pending(session.receive_next());
}

#[test]
fn accept_preserves_established_traffic_and_never_requeues_it_forever() {
    let (mut session, _, control) = server(16);
    control.feed(&wire(MuxCommand::Data, 1, b"first"));
    control.feed(&wire(
        MuxCommand::Syn,
        3,
        &target().encode().expect("target"),
    ));
    let (third, _) = complete(session.accept()).expect("second accept");
    assert_eq!(third.stream_id, 3);
    control.feed(&wire(
        MuxCommand::Syn,
        5,
        &target().encode().expect("target"),
    ));
    let (fifth, _) = complete(session.accept()).expect("accept ignores earlier queued DATA");
    assert_eq!(fifth.stream_id, 5);
    assert_eq!(
        complete(session.receive_next()).expect("first data exactly once"),
        data_event(1, b"first")
    );
    cancel_pending(session.receive_next());
}

#[test]
fn accept_can_find_a_syn_already_queued_by_a_credit_wait() {
    let (mut session, mut stream, control) = server(1);
    complete(session.send_data_wait_window(&mut stream, b"x")).expect("exhaust");
    control.feed(&wire(
        MuxCommand::Syn,
        3,
        &target().encode().expect("target"),
    ));
    control.feed(&wire(MuxCommand::WindowUpdate, 1, &1_u32.to_be_bytes()));
    complete(session.send_data_wait_window(&mut stream, b"y")).expect("wait retains SYN");
    let (accepted, _) = complete(session.accept()).expect("accept queued SYN without socket input");
    assert_eq!(accepted.stream_id, 3);
    assert_eq!(
        complete(session.receive_next()).expect("queued window event"),
        MuxEvent::WindowUpdate {
            stream_id: 1,
            increment: 1
        }
    );
}

#[test]
fn half_close_allows_delayed_response_and_reclaims_after_consumption() {
    let (mut server, mut stream, control) = server(8);
    control.feed(&wire(MuxCommand::Data, 1, b"request"));
    control.feed(&wire(MuxCommand::Fin, 1, &[]));
    assert_eq!(
        complete(server.receive_next()).expect("request"),
        data_event(1, b"request")
    );
    assert_eq!(
        complete(server.receive_next()).expect("request FIN"),
        MuxEvent::Fin { stream_id: 1 }
    );
    complete(server.send_data_wait_window(&mut stream, b"response"))
        .expect("response after peer FIN");
    server.queue_finish(1).expect("response FIN");
    server
        .queue_finish(1)
        .expect("idempotent while awaiting consumption");
    assert_eq!(
        server.active_stream_count(),
        1,
        "received data still reserves capacity"
    );
    assert!(matches!(
        server.try_send_data(1, b"late"),
        Err(InnerError::StreamClosed)
    ));
    assert!(matches!(
        complete(server.send_data_wait_window(&mut stream, b"late")),
        Err(InnerError::StreamClosed)
    ));
    server
        .queue_window_update(1, 7)
        .expect("application consumes request after both FINs");
    assert_eq!(
        server.active_stream_count(),
        1,
        "final response credit is still in flight"
    );
    control.feed(&wire(MuxCommand::WindowUpdate, 1, &8_u32.to_be_bytes()));
    assert_eq!(
        complete(server.receive_next()).expect("late final response acknowledgement"),
        MuxEvent::WindowUpdate {
            stream_id: 1,
            increment: 8
        }
    );
    assert_eq!(server.active_stream_count(), 0);
    complete(server.flush_pending()).expect("flush final FIN");
    assert_eq!(
        control.output(),
        [
            wire(MuxCommand::Data, 1, b"response"),
            wire(MuxCommand::Fin, 1, &[]),
            wire(MuxCommand::WindowUpdate, 1, &7_u32.to_be_bytes())
        ]
        .concat()
    );

    let (mut client, _, control) = client(16);
    client.queue_finish(1).expect("request half closed");
    control.feed(&wire(MuxCommand::Data, 1, b"delayed"));
    control.feed(&wire(MuxCommand::Fin, 1, &[]));
    assert_eq!(
        complete(client.receive_next()).expect("response"),
        data_event(1, b"delayed")
    );
    client.queue_window_update(1, 7).expect("consume response");
    assert_eq!(
        complete(client.receive_next()).expect("peer FIN"),
        MuxEvent::Fin { stream_id: 1 }
    );
    assert_eq!(client.active_stream_count(), 0);
}

#[test]
fn stale_handle_windows_cannot_oversend_or_wait_after_credit_was_applied() {
    let (mut session, mut stream, control) = client(4);
    let mut stale = stream.clone();
    complete(session.send_data_wait_window(&mut stream, b"full")).expect("exhaust window");
    control.clear_output();
    cancel_pending(session.send_data_wait_window(&mut stale, b"x"));
    assert_eq!(stale.send_window(), 0);
    assert!(
        control.output().is_empty(),
        "stale positive handle cannot send"
    );
    control.feed(&wire(MuxCommand::WindowUpdate, 1, &4_u32.to_be_bytes()));
    assert_eq!(
        complete(session.receive_next()).expect("external update"),
        MuxEvent::WindowUpdate {
            stream_id: 1,
            increment: 4
        }
    );
    complete(session.send_data_wait_window(&mut stream, b"more"))
        .expect("stale zero handle refreshes before wait");
    assert_eq!(control.output(), wire(MuxCommand::Data, 1, b"more"));
}

#[test]
fn receive_credit_requires_delivered_and_consumed_data_and_rejects_over_ack() {
    let (mut session, _, control) = client(4);
    assert!(matches!(
        session.queue_window_update(1, 1),
        Err(InnerError::WindowOverflow)
    ));
    control.feed(&wire(MuxCommand::Data, 1, b"four"));
    assert_eq!(
        complete(session.receive_next()).expect("receive"),
        data_event(1, b"four")
    );
    for increment in [0, 5, u32::MAX] {
        assert!(matches!(
            session.queue_window_update(1, increment),
            Err(InnerError::WindowOverflow)
        ));
    }
    session
        .queue_window_update(1, 2)
        .expect("partial consumption");
    session
        .queue_window_update(1, 2)
        .expect("remaining consumption");
    assert!(matches!(
        session.queue_window_update(1, 1),
        Err(InnerError::WindowOverflow)
    ));
    control.feed(&wire(MuxCommand::Data, 1, b"next"));
    assert_eq!(
        complete(session.receive_next()).expect("restored receive credit"),
        data_event(1, b"next")
    );
    assert_eq!(
        control.output(),
        [
            wire(MuxCommand::WindowUpdate, 1, &2_u32.to_be_bytes()),
            wire(MuxCommand::WindowUpdate, 1, &2_u32.to_be_bytes())
        ]
        .concat()
    );
}

#[test]
fn slow_stream_withheld_credit_does_not_block_other_stream_or_control() {
    let (mut session, _, control) = client(4);
    establish_client(&mut session, &control);
    for id in [1, 3] {
        control.feed(&wire(MuxCommand::Data, id, b"full"));
        assert_eq!(
            complete(session.receive_next()).expect("data"),
            data_event(id, b"full")
        );
    }
    session
        .queue_window_update(3, 4)
        .expect("only fast stream consumed");
    control.feed(&wire(MuxCommand::Data, 3, b"fast"));
    control.feed(&wire(MuxCommand::Ping, 0, b"control"));
    assert_eq!(
        complete(session.receive_next()).expect("fast stream continues"),
        data_event(3, b"fast")
    );
    assert_eq!(
        complete(session.receive_next()).expect("control remains available"),
        MuxEvent::Ping {
            stream_id: 0,
            payload: b"control".to_vec()
        }
    );
    control.feed(&wire(MuxCommand::Data, 1, b"x"));
    assert!(
        matches!(
            complete(session.receive_next()),
            Err(InnerError::WindowOverflow)
        ),
        "slow stream cannot exceed unconsumed credit"
    );
    assert!(control.0.lock().expect("script").dropped);
}

#[test]
fn invalid_window_updates_are_terminal_and_do_not_wrap() {
    for payload in [
        vec![],
        vec![0; 3],
        vec![0; 5],
        0_u32.to_be_bytes().to_vec(),
        1_u32.to_be_bytes().to_vec(),
        u32::MAX.to_be_bytes().to_vec(),
    ] {
        let (mut session, _, control) = client(4);
        control.feed(&wire(MuxCommand::WindowUpdate, 1, &payload));
        assert!(
            complete(session.receive_next()).is_err(),
            "reject {payload:?}"
        );
        assert_eq!(session.active_stream_count(), 0);
        assert!(control.0.lock().expect("script").dropped);
    }
}

#[test]
fn unknown_stream_controls_and_data_never_allocate_state() {
    for command in [
        MuxCommand::WindowUpdate,
        MuxCommand::Fin,
        MuxCommand::Rst,
        MuxCommand::SynAck,
        MuxCommand::Data,
    ] {
        for id in [0, 1, u32::MAX] {
            let (mut session, control) = session(MuxRole::Server, 4, &PadScheme::none());
            let payload = if command == MuxCommand::WindowUpdate {
                1_u32.to_be_bytes().to_vec()
            } else {
                Vec::new()
            };
            control.feed(&wire(command, id, &payload));
            assert!(
                matches!(complete(session.receive_next()), Err(InnerError::Io(ref error)) if error.kind() == io::ErrorKind::InvalidData)
            );
            assert_eq!(session.active_stream_count(), 0);
            assert!(control.0.lock().expect("script").dropped);
        }
    }
    let (mut session, _, control) = client(4);
    session.queue_reset(1).expect("reset and reclaim");
    control.feed(&wire(MuxCommand::WindowUpdate, 3, &1_u32.to_be_bytes()));
    assert!(complete(session.receive_next()).is_err());
    assert_eq!(session.active_stream_count(), 0);
}

#[test]
fn reclaimed_ids_ignore_trailing_frames_without_restoring_state_or_credit() {
    for role in [MuxRole::Client, MuxRole::Server] {
        for reclamation in 0..3 {
            let (mut session, _, control) = match role {
                MuxRole::Client => client(4),
                MuxRole::Server => server(4),
            };
            match reclamation {
                0 => session.queue_reset(1).expect("local reset"),
                1 => {
                    control.feed(&wire(MuxCommand::Rst, 1, &[]));
                    assert_eq!(
                        complete(session.receive_next()).expect("peer reset"),
                        MuxEvent::Rst { stream_id: 1 }
                    );
                }
                _ => {
                    session.queue_finish(1).expect("local FIN");
                    control.feed(&wire(MuxCommand::Fin, 1, &[]));
                    assert_eq!(
                        complete(session.receive_next()).expect("peer FIN"),
                        MuxEvent::Fin { stream_id: 1 }
                    );
                }
            }
            assert_eq!(session.active_stream_count(), 0);
            complete(session.flush_pending()).expect("flush reclamation");
            control.clear_output();
            // More ignored events than the convenience queue limit must not be retained.
            for _ in 0..MAX_PENDING_EVENTS {
                for frame in trailing_frames(1) {
                    control.feed(&frame);
                }
            }
            control.feed(&wire(MuxCommand::Ping, 0, b"alive"));
            assert_eq!(
                complete(session.receive_next()).expect("skip retired traffic"),
                MuxEvent::Ping {
                    stream_id: 0,
                    payload: b"alive".to_vec()
                }
            );
            assert_retired(&mut session, 1);
            assert_eq!(session.active_stream_count(), 0);
            assert!(
                control.output().is_empty(),
                "retired DATA must not generate credit"
            );
            cancel_pending(session.receive_next());
            let next = match role {
                MuxRole::Client => establish_client(&mut session, &control),
                MuxRole::Server => establish_server(&mut session, &control, 3),
            };
            assert_eq!(next.stream_id, 3);
            assert_eq!(session.send_credit(3).expect("fresh credit"), 4);
            assert_eq!(session.active_stream_count(), 1);
        }
    }
}

#[test]
fn reset_crosses_partial_data_and_controls_without_harming_siblings() {
    for role in [MuxRole::Client, MuxRole::Server] {
        for frame in trailing_frames(1).into_iter().skip(1) {
            for split in 0..frame.len() {
                let (mut session, _, control) = match role {
                    MuxRole::Client => client(4),
                    MuxRole::Server => server(4),
                };
                match role {
                    MuxRole::Client => establish_client(&mut session, &control),
                    MuxRole::Server => establish_server(&mut session, &control, 3),
                };
                assert_eq!(
                    session
                        .try_send_data(1, b"sent")
                        .expect("send before reset"),
                    4
                );
                control.feed(&frame);
                control.read_allowance(split);
                cancel_pending(session.receive_next());
                session.queue_reset(1).expect("reset during partial frame");
                control.feed(&wire(MuxCommand::Data, 3, b"live"));
                control.read_allowance(usize::MAX);
                assert_eq!(
                    complete(session.receive_next()).expect("sibling DATA"),
                    data_event(3, b"live")
                );
                assert_retired(&mut session, 1);
                assert_eq!(session.active_stream_count(), 1);
                session
                    .queue_window_update(3, 4)
                    .expect("sibling consumption");
                assert_eq!(session.try_send_data(3, b"back").expect("sibling reply"), 4);
                complete(session.flush_pending()).expect("flush sibling output");
                assert_eq!(
                    control.output(),
                    [
                        wire(MuxCommand::Data, 1, b"sent"),
                        wire(MuxCommand::Rst, 1, &[]),
                        wire(MuxCommand::WindowUpdate, 3, &4_u32.to_be_bytes()),
                        wire(MuxCommand::Data, 3, b"back"),
                    ]
                    .concat()
                );
                cancel_pending(session.receive_next());
            }
        }
    }
}

#[test]
fn reset_before_establishment_crosses_syn_ack_without_resurrection() {
    for role in [MuxRole::Client, MuxRole::Server] {
        for split in 0..8 {
            let (mut session, control) = session(role, 4, &PadScheme::none());
            match role {
                MuxRole::Client => {
                    session.begin_open(&target()).expect("opening");
                }
                MuxRole::Server => {
                    control.feed(&wire(
                        MuxCommand::Syn,
                        1,
                        &target().encode().expect("target"),
                    ));
                    assert_eq!(
                        complete(session.receive_next()).expect("accepting"),
                        MuxEvent::Syn {
                            stream_id: 1,
                            target: target()
                        }
                    );
                }
            }
            for frame in trailing_frames(1) {
                control.feed(&frame);
            }
            control.read_allowance(split);
            cancel_pending(session.receive_next());
            session.queue_reset(1).expect("cancel unestablished stream");
            control.read_allowance(usize::MAX);
            let next = match role {
                MuxRole::Client => {
                    control.feed(&wire(MuxCommand::SynAck, 3, &[]));
                    complete(session.open(&target())).expect("open ignores retired traffic")
                }
                MuxRole::Server => establish_server(&mut session, &control, 3),
            };
            assert_eq!(next.stream_id, 3);
            assert_retired(&mut session, 1);
            assert_eq!(session.active_stream_count(), 1);
            assert_eq!(session.send_credit(3).expect("sibling credit"), 4);
            cancel_pending(session.receive_next());
        }
    }
}

#[test]
fn both_endpoints_can_reset_concurrently_and_keep_sibling_progress() {
    let (mut client, _, client_io) = client(4);
    let (mut server, _, server_io) = server(4);
    establish_client(&mut client, &client_io);
    establish_server(&mut server, &server_io, 3);
    // Neither endpoint can observe the peer RST until both have reclaimed stream 1.
    client.queue_reset(1).expect("client reset");
    server.queue_reset(1).expect("server reset");
    assert_eq!(client.try_send_data(3, b"ping").expect("client sibling"), 4);
    assert_eq!(server.try_send_data(3, b"pong").expect("server sibling"), 4);
    complete(client.flush_pending()).expect("client flush");
    complete(server.flush_pending()).expect("server flush");
    client_io.feed(&server_io.output());
    server_io.feed(&client_io.output());
    assert_eq!(
        complete(client.receive_next()).expect("client receives sibling"),
        data_event(3, b"pong")
    );
    assert_eq!(
        complete(server.receive_next()).expect("server receives sibling"),
        data_event(3, b"ping")
    );
    client_io.clear_output();
    server_io.clear_output();
    client
        .queue_window_update(3, 4)
        .expect("client consumption");
    server
        .queue_window_update(3, 4)
        .expect("server consumption");
    complete(client.flush_pending()).expect("client credit flush");
    complete(server.flush_pending()).expect("server credit flush");
    client_io.feed(&server_io.output());
    server_io.feed(&client_io.output());
    for session in [&mut client, &mut server] {
        assert_eq!(
            complete(session.receive_next()).expect("sibling credit"),
            MuxEvent::WindowUpdate {
                stream_id: 3,
                increment: 4
            }
        );
        assert_eq!(session.send_credit(3).expect("restored sibling credit"), 4);
        assert_retired(session, 1);
        assert_eq!(session.active_stream_count(), 1);
        cancel_pending(session.receive_next());
    }
}

#[test]
fn high_water_mark_retires_skipped_ids_without_allocating_tombstones() {
    let (mut session, control) = session(MuxRole::Server, 4, &PadScheme::none());
    establish_server(&mut session, &control, u32::MAX - 2);
    session
        .queue_reset(u32::MAX - 2)
        .expect("reclaim admitted stream");
    for id in [1, 3, u32::MAX - 4, u32::MAX - 2] {
        for frame in trailing_frames(id) {
            control.feed(&frame);
        }
    }
    // A huge admission gap is classified using the high-water mark, not entries.
    assert_eq!(session.active_stream_count(), 0);
    establish_server(&mut session, &control, u32::MAX);
    for id in [1, 3, u32::MAX - 4, u32::MAX - 2] {
        assert_retired(&mut session, id);
    }
    assert_eq!(session.active_stream_count(), 1);
    assert_eq!(
        session.send_credit(u32::MAX).expect("last stream credit"),
        4
    );
    cancel_pending(session.receive_next());
}

#[test]
fn retired_or_skipped_ids_cannot_be_reopened_with_syn() {
    for id in [1, 3, 5] {
        let (mut session, control) = session(MuxRole::Server, 4, &PadScheme::none());
        establish_server(&mut session, &control, 5);
        session.queue_reset(5).expect("retire high-water stream");
        control.feed(&wire(
            MuxCommand::Syn,
            id,
            &target().encode().expect("target"),
        ));
        assert!(
            matches!(complete(session.receive_next()), Err(InnerError::Io(ref error)) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert_eq!(session.active_stream_count(), 0);
        assert!(control.0.lock().expect("script").dropped);
    }
}

#[test]
fn future_zero_and_even_ids_remain_terminal_after_retirement() {
    for role in [MuxRole::Client, MuxRole::Server] {
        for id in [0, 2, 3, 4, u32::MAX] {
            for frame in trailing_frames(id) {
                let (mut session, _, control) = match role {
                    MuxRole::Client => client(4),
                    MuxRole::Server => server(4),
                };
                session.queue_reset(1).expect("retire first stream");
                control.feed(&frame);
                assert!(
                    matches!(complete(session.receive_next()), Err(InnerError::Io(ref error)) if error.kind() == io::ErrorKind::InvalidData)
                );
                assert_eq!(session.active_stream_count(), 0);
                assert!(control.0.lock().expect("script").dropped);
            }
        }
    }
}

#[test]
fn retired_frames_still_require_valid_command_payload_syntax_and_sizes() {
    let mut bad_command = wire(MuxCommand::Rst, 1, &[]);
    bad_command[1] = 255;
    let mut bad_version = wire(MuxCommand::Rst, 1, &[]);
    bad_version[0] = 2;
    for frame in [
        wire(MuxCommand::SynAck, 1, &[1]),
        wire(MuxCommand::Fin, 1, &[1]),
        wire(MuxCommand::Rst, 1, &[1]),
        wire(MuxCommand::WindowUpdate, 1, &[]),
        wire(MuxCommand::WindowUpdate, 1, &[1; 3]),
        wire(MuxCommand::WindowUpdate, 1, &[1; 5]),
        wire(MuxCommand::WindowUpdate, 1, &0_u32.to_be_bytes()),
        wire(MuxCommand::Data, 1, &vec![0; MAX_DATA_CHUNK_LEN + 1]),
        wire(
            MuxCommand::UdpDatagram,
            1,
            &UdpEnvelope::new(target(), vec![1])
                .expect("UDP")
                .encode()
                .expect("envelope"),
        ),
        bad_command,
        bad_version,
    ] {
        let (mut session, _, control) = client(4);
        session.queue_reset(1).expect("retire");
        control.feed(&frame);
        assert!(complete(session.receive_next()).is_err());
        assert_eq!(session.active_stream_count(), 0);
        assert!(control.0.lock().expect("script").dropped);
    }
    let (io, control) = Control::new();
    let mut session = MuxSession::with_settings(
        io,
        MuxRole::Client,
        &PadScheme::none(),
        MuxSettings {
            initial_window: 4,
            max_payload_len: 2,
        },
    )
    .expect("settings");
    session.begin_open(&target()).expect("open");
    session.queue_reset(1).expect("retire");
    control.feed(&wire(MuxCommand::Data, 1, b"big"));
    assert!(matches!(
        complete(session.receive_next()),
        Err(InnerError::Protocol(_))
    ));
    assert!(control.0.lock().expect("script").dropped);
}

#[test]
fn streams_and_reserved_receive_capacity_are_bounded_and_released() {
    let (mut tiny, _) = session(MuxRole::Client, 0, &PadScheme::none());
    for _ in 0..MAX_STREAMS {
        tiny.begin_open(&target()).expect("available stream slot");
    }
    assert_would_block(tiny.begin_open(&target()));
    assert_eq!(tiny.active_stream_count(), MAX_STREAMS);
    tiny.queue_reset(1).expect("release one slot");
    tiny.begin_open(&target())
        .expect("slot is reusable with new id");
    assert_eq!(tiny.active_stream_count(), MAX_STREAMS);

    let (mut large, _) = session(
        MuxRole::Client,
        MAX_RECEIVE_BUFFER_BYTES,
        &PadScheme::none(),
    );
    large
        .begin_open(&target())
        .expect("all receive capacity reserved");
    assert_would_block(large.begin_open(&target()));
    large.queue_reset(1).expect("release receive reservation");
    assert_eq!(
        large
            .begin_open(&target())
            .expect("reservation reused")
            .stream_id,
        3
    );

    let (mut server, control) = session(
        MuxRole::Server,
        MAX_RECEIVE_BUFFER_BYTES,
        &PadScheme::none(),
    );
    control.feed(&wire(
        MuxCommand::Syn,
        1,
        &target().encode().expect("target"),
    ));
    assert!(matches!(
        complete(server.receive_next()).expect("first SYN"),
        MuxEvent::Syn { stream_id: 1, .. }
    ));
    control.feed(&wire(
        MuxCommand::Syn,
        3,
        &target().encode().expect("target"),
    ));
    assert!(
        complete(server.receive_next()).is_err(),
        "peer stream capacity is enforced too"
    );
}

#[test]
fn writer_frame_and_byte_bounds_leave_rejected_work_unaccepted() {
    for chunk in [vec![1], vec![2; MAX_DATA_CHUNK_LEN]] {
        let (mut session, _, control) = client(MAX_RECEIVE_BUFFER_BYTES);
        let mut accepted = 0;
        let mut frames = 0;
        loop {
            let count = session.try_send_data(1, &chunk).expect("attempt queue");
            if count == 0 {
                break;
            }
            accepted += count;
            frames += 1;
            assert!(frames <= MAX_PENDING_WRITE_FRAMES);
            assert!(accepted + frames * 8 <= MAX_PENDING_WRITE_BYTES);
        }
        assert_eq!(
            session
                .send_credit(1)
                .expect("credit only for admitted frames"),
            MAX_RECEIVE_BUFFER_BYTES - accepted
        );
        if chunk.len() == 1 {
            assert_would_block(session.queue_finish(1));
            assert!(
                session.send_credit(1).is_ok(),
                "rejected FIN did not close direction"
            );
        }
        complete(session.flush_pending()).expect("drain writer");
        assert_eq!(control.output().len(), accepted + frames * 8);
        assert_eq!(
            session
                .try_send_data(1, &chunk)
                .expect("writer capacity restored"),
            chunk.len()
        );
    }
}

#[test]
fn event_count_and_byte_bounds_close_instead_of_dropping_traffic() {
    for payload_len in [0, MAX_FRAME_PAYLOAD_LEN] {
        let (mut session, mut stream, control) = client(0);
        let count = MAX_PENDING_EVENT_BYTES
            .checked_div(payload_len)
            .unwrap_or(MAX_PENDING_EVENTS)
            + 1;
        let frame = wire(MuxCommand::Ping, 0, &vec![0; payload_len]);
        for _ in 0..count {
            control.feed(&frame);
        }
        assert!(
            matches!(complete(session.send_data_wait_window(&mut stream, b"blocked")), Err(InnerError::Io(ref error)) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert!(control.0.lock().expect("script").dropped);
        assert_eq!(session.active_stream_count(), 0);
    }
}

#[test]
fn malformed_frame_headers_and_truncated_input_fail_closed() {
    let mut bad_version = wire(MuxCommand::Ping, 0, &[]);
    bad_version[0] = 2;
    let mut bad_command = wire(MuxCommand::Ping, 0, &[]);
    bad_command[1] = 255;
    for bytes in [
        bad_version,
        bad_command,
        wire(MuxCommand::Ping, 0, b"payload")[..10].to_vec(),
        vec![1, 2],
    ] {
        let (mut session, control) = session(MuxRole::Client, 4, &PadScheme::none());
        control.feed(&bytes);
        control.0.lock().expect("script").eof = true;
        assert!(complete(session.receive_next()).is_err());
        assert!(control.0.lock().expect("script").dropped);
    }
    let (io, control) = Control::new();
    let mut session = MuxSession::with_settings(
        io,
        MuxRole::Client,
        &PadScheme::none(),
        MuxSettings {
            initial_window: 4,
            max_payload_len: 2,
        },
    )
    .expect("settings");
    control.feed(&wire(MuxCommand::Ping, 0, b"big"));
    assert!(matches!(
        complete(session.receive_next()),
        Err(InnerError::Protocol(_))
    ));
}

#[test]
fn control_shapes_stream_phases_and_data_chunk_limits_are_checked() {
    for command in [MuxCommand::Fin, MuxCommand::Rst, MuxCommand::SynAck] {
        let (mut session, _, control) = client(4);
        control.feed(&wire(command, 1, &[1]));
        assert!(matches!(
            complete(session.receive_next()),
            Err(InnerError::Protocol(_))
        ));
    }
    for command in [MuxCommand::Fin, MuxCommand::Data, MuxCommand::WindowUpdate] {
        let (mut session, control) = session(MuxRole::Client, 4, &PadScheme::none());
        session.begin_open(&target()).expect("pending open");
        assert!(session.queue_finish(1).is_err());
        assert!(session.queue_accept(1).is_err());
        let payload = if command == MuxCommand::WindowUpdate {
            1_u32.to_be_bytes().to_vec()
        } else {
            Vec::new()
        };
        control.feed(&wire(command, 1, &payload));
        assert!(complete(session.receive_next()).is_err());
    }
    let (mut session, _, control) = client(MAX_DATA_CHUNK_LEN * 2);
    control.feed(&wire(MuxCommand::Data, 1, &vec![0; MAX_DATA_CHUNK_LEN + 1]));
    assert!(matches!(
        complete(session.receive_next()),
        Err(InnerError::Protocol(_))
    ));
    let (mut session, _, control) = client(4);
    control.feed(&wire(MuxCommand::Fin, 1, &[]));
    assert_eq!(
        complete(session.receive_next()).expect("FIN"),
        MuxEvent::Fin { stream_id: 1 }
    );
    control.feed(&wire(MuxCommand::Data, 1, b"late"));
    assert!(complete(session.receive_next()).is_err());
}

#[test]
fn syn_roles_ids_duplicate_ack_and_invalid_settings_are_rejected() {
    for id in [0, 2] {
        let (mut session, control) = session(MuxRole::Server, 4, &PadScheme::none());
        assert!(session.begin_open(&target()).is_err());
        control.feed(&wire(
            MuxCommand::Syn,
            id,
            &target().encode().expect("target"),
        ));
        assert!(complete(session.receive_next()).is_err());
    }
    let (mut server, _, control) = server(4);
    assert!(server.queue_accept(1).is_err());
    server.queue_reset(1).expect("reclaim");
    control.feed(&wire(
        MuxCommand::Syn,
        1,
        &target().encode().expect("target"),
    ));
    assert!(
        complete(server.receive_next()).is_err(),
        "stream ids cannot be reused"
    );
    for command in [MuxCommand::Syn, MuxCommand::SynAck] {
        let (mut client, _, control) = client(4);
        let payload = if command == MuxCommand::Syn {
            target().encode().expect("target")
        } else {
            Vec::new()
        };
        control.feed(&wire(command, 1, &payload));
        assert!(complete(client.receive_next()).is_err());
    }
    for settings in [
        MuxSettings {
            initial_window: MAX_RECEIVE_BUFFER_BYTES + 1,
            ..MuxSettings::default()
        },
        MuxSettings {
            max_payload_len: MAX_FRAME_PAYLOAD_LEN + 1,
            ..MuxSettings::default()
        },
    ] {
        let (io, _) = Control::new();
        assert!(matches!(
            MuxSession::with_settings(io, MuxRole::Client, &PadScheme::none(), settings),
            Err(InnerError::WindowOverflow)
        ));
    }
}

#[test]
fn padding_skips_before_cancelled_data_and_udp_remains_stream_zero() {
    let (mut session, _, control) = client(16);
    control.feed(&wire(MuxCommand::Padding, 0, b"noise"));
    control.feed(&wire(MuxCommand::Data, 1, b"data"));
    control.read_allowance(16);
    cancel_pending(session.receive_next());
    control.read_allowance(usize::MAX);
    assert_eq!(
        complete(session.receive_next()).expect("DATA after padding"),
        data_event(1, b"data")
    );
    complete(session.send_udp_datagram(&target(), b"udp")).expect("UDP send");
    let encoded = UdpEnvelope::new(target(), b"udp".to_vec())
        .expect("UDP")
        .encode()
        .expect("encode");
    assert_eq!(control.output(), wire(MuxCommand::UdpDatagram, 0, &encoded));
    control.feed(&wire(MuxCommand::UdpDatagram, 1, &encoded));
    assert!(complete(session.receive_next()).is_err());
}
