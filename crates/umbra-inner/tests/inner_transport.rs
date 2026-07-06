//! Integration tests for inner mux, adaptive padding, and Vision solo mode.

use std::time::Duration;

use rand::RngCore;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use umbra_inner::{
    address::{decode_target_addr, decode_target_addr_from, encode_target_addr},
    mux::{MuxEvent, MuxSession, MuxSettings},
    padding::{is_padding, parse_pad_scheme, PaddingPlanner},
    spider::{spider, spider_request},
    vision::{
        is_tls_handshake_start, read_solo_preface, send_solo_preface, shape_handshake_bytes,
        vision_relay, VisionDirection, VisionPhase, VisionTracker,
    },
};
use umbra_proto::{
    addr::TargetAddr,
    frame::{MuxCommand, MuxFrame},
};

#[test]
fn scenario_address_helpers_round_trip_and_report_consumed_bytes() {
    let target = TargetAddr::domain("wrapped.example", 8443).expect("target");
    let encoded = encode_target_addr(&target).expect("encode target");

    assert_eq!(decode_target_addr(&encoded).expect("decode target"), target);
    let mut with_trailing = encoded.clone();
    with_trailing.push(0xff);
    let (decoded, consumed) =
        decode_target_addr_from(&with_trailing).expect("decode target prefix");
    assert_eq!(decoded, target);
    assert_eq!(consumed, encoded.len());
    assert!(decode_target_addr(&with_trailing).is_err());
}

#[test]
fn scenario_default_padding_scheme_parses() {
    let scheme = parse_pad_scheme("default").expect("default scheme parses");

    assert_eq!(scheme.early_records, 16);
    assert_eq!(scheme.min_len, 100);
    assert_eq!(scheme.max_len, 1400);
    assert!(scheme.later_every > 0);

    let explicit =
        parse_pad_scheme("early=2,min=4,max=8,later=10").expect("explicit scheme parses");
    assert_eq!(explicit.early_records, 2);
    assert_eq!(explicit.min_len, 4);
    assert_eq!(explicit.max_len, 8);
    assert_eq!(explicit.later_every, 10);
}

#[test]
fn scenario_later_padding_and_disabled_scheme_are_deterministic() {
    let scheme = parse_pad_scheme("early=0,min=2,max=2,later=2").expect("scheme");
    let mut planner = PaddingPlanner::new(scheme).expect("planner");
    let mut rng = FixedRng::default();
    let first = MuxFrame::new(MuxCommand::Data, 1, b"one".to_vec()).expect("first");
    let second = MuxFrame::new(MuxCommand::Data, 1, b"two".to_vec()).expect("second");

    assert_eq!(
        planner
            .schedule_with_rng(first.clone(), &mut rng)
            .expect("first schedule"),
        vec![first]
    );
    let frames = planner
        .schedule_with_rng(second.clone(), &mut rng)
        .expect("second schedule");
    assert_eq!(frames.len(), 2);
    assert!(is_padding(&frames[0]));
    assert_eq!(frames[0].payload.len(), 2);
    assert_eq!(frames[1], second);

    let none = parse_pad_scheme("none").expect("none scheme");
    let mut disabled = PaddingPlanner::new(none).expect("disabled planner");
    let padding = MuxFrame::new(MuxCommand::Padding, 0, b"pad".to_vec()).expect("padding");
    assert_eq!(
        disabled
            .schedule(padding.clone())
            .expect("schedule padding"),
        vec![padding]
    );
}

#[test]
fn scenario_invalid_padding_scheme_is_rejected() {
    assert!(parse_pad_scheme("").is_err());
    assert!(parse_pad_scheme("early=1,min=9,max=2,later=0").is_err());
    assert!(parse_pad_scheme("early=abc,min=1,max=2,later=0").is_err());
    assert!(parse_pad_scheme("unknown=1").is_err());
}

#[test]
fn scenario_early_business_frame_is_padded() {
    let scheme = parse_pad_scheme("early=1,min=3,max=3,later=0").expect("scheme");
    let mut planner = PaddingPlanner::new(scheme).expect("planner");
    let frame = MuxFrame::new(MuxCommand::Data, 7, b"hello".to_vec()).expect("data frame");
    let mut rng = FixedRng::default();

    let frames = planner
        .schedule_with_rng(frame.clone(), &mut rng)
        .expect("schedule padded frames");

    assert_eq!(frames.len(), 3);
    assert!(is_padding(&frames[0]));
    assert_eq!(frames[0].payload.len(), 3);
    assert_eq!(frames[1], frame);
    assert!(is_padding(&frames[2]));
    assert_eq!(frames[2].payload.len(), 3);
}

#[tokio::test]
async fn scenario_padding_payload_is_not_delivered() {
    let (mut writer, reader) = io::duplex(1024);
    let padding = MuxFrame::new(MuxCommand::Padding, 0, b"noise".to_vec())
        .expect("padding frame")
        .encode()
        .expect("encode padding");
    let data = MuxFrame::new(MuxCommand::Data, 9, b"payload".to_vec())
        .expect("data frame")
        .encode()
        .expect("encode data");
    writer.write_all(&padding).await.expect("write padding");
    writer.write_all(&data).await.expect("write data");

    let scheme = parse_pad_scheme("none").expect("none scheme");
    let mut session = MuxSession::server(reader, &scheme).expect("server session");
    let event = session.receive_next().await.expect("receive event");

    assert_eq!(
        event,
        MuxEvent::Data {
            stream_id: 9,
            payload: b"payload".to_vec(),
        }
    );
}

#[tokio::test]
async fn scenario_client_opens_stream() {
    let (client_io, server_io) = io::duplex(4096);
    let scheme = parse_pad_scheme("none").expect("none scheme");
    let mut client = MuxSession::client(client_io, &scheme).expect("client session");
    let mut server = MuxSession::server(server_io, &scheme).expect("server session");
    let target = TargetAddr::domain("example.com", 443).expect("target");

    let (client_stream, accepted) = tokio::join!(client.open(&target), server.accept());
    let client_stream = client_stream.expect("client opens stream");
    let (server_stream, accepted_target) = accepted.expect("server accepts stream");

    assert_eq!(client_stream.stream_id, 1);
    assert_eq!(server_stream.stream_id, 1);
    assert_eq!(accepted_target, target);
}

#[tokio::test]
async fn scenario_data_waits_for_window_update() {
    let (client_io, server_io) = io::duplex(4096);
    let scheme = parse_pad_scheme("none").expect("none scheme");
    let settings = MuxSettings {
        initial_window: 0,
        ..MuxSettings::default()
    };
    let mut client = MuxSession::with_settings(
        client_io,
        umbra_inner::mux::MuxRole::Client,
        &scheme,
        settings,
    )
    .expect("client session");
    let mut server = MuxSession::with_settings(
        server_io,
        umbra_inner::mux::MuxRole::Server,
        &scheme,
        settings,
    )
    .expect("server session");
    let target = TargetAddr::domain("example.com", 443).expect("target");
    let (stream, accepted) = tokio::join!(client.open(&target), server.accept());
    let mut stream = stream.expect("client stream");
    accepted.expect("server stream");
    let stream_id = stream.stream_id;

    let mut send = Box::pin(client.send_data_wait_window(&mut stream, b"hello"));
    assert!(
        timeout(Duration::from_millis(50), &mut send).await.is_err(),
        "DATA must wait while the stream window is exhausted"
    );

    server
        .send_window_update(stream_id, 5)
        .await
        .expect("send WINDOW_UPDATE");
    timeout(Duration::from_secs(1), &mut send)
        .await
        .expect("send completes after WINDOW_UPDATE")
        .expect("send data succeeds");

    let event = server.receive_next().await.expect("server receives DATA");
    assert_eq!(
        event,
        MuxEvent::Data {
            stream_id,
            payload: b"hello".to_vec(),
        }
    );
}

#[tokio::test]
async fn scenario_one_stream_reset_leaves_others_open() {
    let (client_io, server_io) = io::duplex(4096);
    let scheme = parse_pad_scheme("none").expect("none scheme");
    let mut client = MuxSession::client(client_io, &scheme).expect("client session");
    let mut server = MuxSession::server(server_io, &scheme).expect("server session");
    let target_one = TargetAddr::domain("one.example", 443).expect("target one");
    let target_two = TargetAddr::domain("two.example", 443).expect("target two");

    let (stream_one, accepted_one) = tokio::join!(client.open(&target_one), server.accept());
    let stream_one = stream_one.expect("stream one");
    accepted_one.expect("accept one");
    let (stream_two, accepted_two) = tokio::join!(client.open(&target_two), server.accept());
    let mut stream_two = stream_two.expect("stream two");
    accepted_two.expect("accept two");

    server
        .reset_stream(stream_one.stream_id)
        .await
        .expect("reset stream one");
    let event = client.receive_next().await.expect("client sees reset");
    assert_eq!(
        event,
        MuxEvent::Rst {
            stream_id: stream_one.stream_id,
        }
    );

    client
        .send_data_wait_window(&mut stream_two, b"still-open")
        .await
        .expect("stream two remains usable");
    let event = server
        .receive_next()
        .await
        .expect("server receives stream two data");
    assert_eq!(
        event,
        MuxEvent::Data {
            stream_id: stream_two.stream_id,
            payload: b"still-open".to_vec(),
        }
    );
}

#[tokio::test]
async fn scenario_fin_and_ping_do_not_close_unrelated_streams() {
    let (client_io, server_io) = io::duplex(4096);
    let scheme = parse_pad_scheme("none").expect("none scheme");
    let mut client = MuxSession::client(client_io, &scheme).expect("client session");
    let mut server = MuxSession::server(server_io, &scheme).expect("server session");
    let target_one = TargetAddr::domain("fin-one.example", 443).expect("target one");
    let target_two = TargetAddr::domain("fin-two.example", 443).expect("target two");
    assert_eq!(client.role(), umbra_inner::mux::MuxRole::Client);
    assert_eq!(server.role(), umbra_inner::mux::MuxRole::Server);

    let (stream_one, accepted_one) = tokio::join!(client.open(&target_one), server.accept());
    let stream_one = stream_one.expect("client stream one");
    accepted_one.expect("accepted stream one");
    let (stream_two, accepted_two) = tokio::join!(client.open(&target_two), server.accept());
    let mut stream_two = stream_two.expect("client stream two");
    accepted_two.expect("accepted stream two");

    server
        .finish_stream(stream_one.stream_id)
        .await
        .expect("send FIN");
    assert_eq!(
        client.receive_next().await.expect("client receives FIN"),
        MuxEvent::Fin {
            stream_id: stream_one.stream_id,
        }
    );

    client
        .send_data_wait_window(&mut stream_two, b"still-sendable")
        .await
        .expect("other stream remains sendable after peer FIN");
    assert_eq!(
        server.receive_next().await.expect("server receives DATA"),
        MuxEvent::Data {
            stream_id: stream_two.stream_id,
            payload: b"still-sendable".to_vec(),
        }
    );

    let ping = MuxFrame::new(MuxCommand::Ping, stream_two.stream_id, b"rt".to_vec())
        .expect("ping")
        .encode()
        .expect("encode ping");
    let (mut writer, reader) = io::duplex(128);
    writer.write_all(&ping).await.expect("write ping");
    let mut ping_session = MuxSession::server(reader, &scheme).expect("ping session");
    assert_eq!(
        ping_session.receive_next().await.expect("receive ping"),
        MuxEvent::Ping {
            stream_id: stream_two.stream_id,
            payload: b"rt".to_vec(),
        }
    );
}

#[tokio::test]
async fn scenario_server_receives_solo_target_address_first() {
    let target = TargetAddr::domain("solo.example", 443).expect("target");
    let (mut client, mut server) = io::duplex(128);

    send_solo_preface(&mut client, &target)
        .await
        .expect("send solo preface");
    let decoded = read_solo_preface(&mut server)
        .await
        .expect("read solo preface");

    assert_eq!(decoded, target);
}

#[test]
fn scenario_tls_handshake_enters_shaping_phase() {
    let handshake = [0x16, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4];
    assert!(is_tls_handshake_start(&handshake));

    let mut tracker = VisionTracker::new();
    tracker.observe(VisionDirection::ClientToTarget, &handshake);
    assert_eq!(tracker.phase(), VisionPhase::Shaping);

    let chunks = shape_handshake_bytes(&handshake, 3).expect("shape bytes");
    assert_eq!(chunks.len(), 3);
    assert!(chunks.iter().all(|chunk| chunk.len() <= 3));
    assert!(shape_handshake_bytes(&handshake, 0).is_err());
}

#[test]
fn scenario_splice_after_bidirectional_application_data() {
    let mut tracker = VisionTracker::new();
    tracker.observe(
        VisionDirection::ClientToTarget,
        &[0x16, 0x03, 0x03, 0x00, 0x00],
    );
    tracker.observe(
        VisionDirection::ClientToTarget,
        &[0x17, 0x03, 0x03, 0x00, 0x00],
    );
    assert_eq!(tracker.phase(), VisionPhase::Shaping);

    tracker.observe(
        VisionDirection::TargetToClient,
        &[0x17, 0x03, 0x03, 0x00, 0x00],
    );
    assert_eq!(tracker.phase(), VisionPhase::Splice);
}

#[tokio::test]
async fn scenario_non_tls_stream_bypasses_tls_shaping() {
    let (mut client, relay_client) = io::duplex(64);
    let (relay_target, mut target) = io::duplex(64);
    let mut relay = Box::pin(vision_relay(relay_client, relay_target));

    client.write_all(b"GET").await.expect("write non-TLS bytes");
    client.shutdown().await.expect("shutdown client write half");

    let mut target_received = vec![0_u8; 3];
    {
        let mut read_target = Box::pin(target.read_exact(&mut target_received));
        timeout(Duration::from_secs(1), async {
            tokio::select! {
                read = &mut read_target => read.expect("target reads client bytes"),
                outcome = &mut relay => panic!("relay finished before target read: {outcome:?}"),
            }
        })
        .await
        .expect("target receives non-TLS bytes");
    }
    assert_eq!(target_received, b"GET");

    target
        .write_all(b"HTTP")
        .await
        .expect("write target response");
    target.shutdown().await.expect("shutdown target");

    let outcome = timeout(Duration::from_secs(1), &mut relay)
        .await
        .expect("relay finishes")
        .expect("vision relay succeeds");
    assert_eq!(outcome.phase, VisionPhase::NonTls);
    assert_eq!(outcome.client_to_target, 3);
    assert_eq!(outcome.target_to_client, 4);

    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read response");
    assert_eq!(response, b"HTTP");
}

#[tokio::test]
async fn scenario_vision_relay_splices_after_bidirectional_application_data() {
    let (mut client, relay_client) = io::duplex(128);
    let (relay_target, mut target) = io::duplex(128);
    let mut relay = Box::pin(vision_relay(relay_client, relay_target));
    let client_records = [tls_record(0x16), tls_record(0x17)].concat();

    client
        .write_all(&client_records)
        .await
        .expect("write TLS records");

    let mut forwarded = vec![0_u8; client_records.len()];
    {
        let mut read_target = Box::pin(target.read_exact(&mut forwarded));
        timeout(Duration::from_secs(1), async {
            tokio::select! {
                read = &mut read_target => read.expect("target receives TLS records"),
                outcome = &mut relay => panic!("relay finished before target read: {outcome:?}"),
            }
        })
        .await
        .expect("target receives shaped TLS bytes");
    }
    assert_eq!(forwarded, client_records);

    let target_records = [tls_record(0x17), b"raw".to_vec()].concat();
    target
        .write_all(&target_records)
        .await
        .expect("write target app data");
    target.shutdown().await.expect("shutdown target");
    client.shutdown().await.expect("shutdown client");

    let outcome = timeout(Duration::from_secs(1), &mut relay)
        .await
        .expect("relay finishes")
        .expect("vision relay succeeds");
    assert_eq!(outcome.phase, VisionPhase::Splice);
    assert_eq!(
        outcome.client_to_target,
        u64::try_from(client_records.len()).expect("len fits")
    );
    assert_eq!(
        outcome.target_to_client,
        u64::try_from(target_records.len()).expect("len fits")
    );

    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read target records");
    assert_eq!(response, target_records);
}

#[tokio::test]
async fn scenario_realsite_spider_sends_normal_request_and_closes() {
    let (client_io, mut server_io) = io::duplex(4096);
    let mut spider = Box::pin(spider(client_io, "/probe"));

    let mut request = Vec::new();
    let mut buf = [0_u8; 256];
    loop {
        let read = timeout(Duration::from_secs(1), async {
            tokio::select! {
                read = server_io.read(&mut buf) => read.expect("read request bytes"),
                outcome = &mut spider => panic!("spider finished before request was read: {outcome:?}"),
            }
        })
            .await
            .expect("server reads request");
        assert!(read > 0);
        request.extend_from_slice(&buf[..read]);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let request_text = String::from_utf8(request).expect("request is UTF-8");
    assert!(request_text.starts_with("GET /probe HTTP/1.1\r\n"));
    assert!(request_text.contains("User-Agent: Mozilla/5.0"));
    assert!(request_text.contains("Connection: close\r\n"));

    server_io
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        .await
        .expect("write response");
    server_io.shutdown().await.expect("shutdown server");

    timeout(Duration::from_secs(1), &mut spider)
        .await
        .expect("spider finishes")
        .expect("spider succeeds");

    let mut eof = [0_u8; 1];
    let read = server_io.read(&mut eof).await.expect("read EOF");
    assert_eq!(read, 0);
}

#[test]
fn scenario_realsite_spider_rejects_malformed_path() {
    assert!(spider_request("relative").is_err());
    assert!(spider_request("/bad\r\nX: y").is_err());
}

#[derive(Default)]
struct FixedRng(u64);

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let bytes = self.0.to_be_bytes();
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn next_u64(&mut self) -> u64 {
        let hi = u64::from(self.next_u32());
        let lo = u64::from(self.next_u32());
        (hi << 32) | lo
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0_usize;
        while offset < dest.len() {
            let bytes = self.next_u32().to_le_bytes();
            let remaining = dest.len() - offset;
            let to_copy = remaining.min(bytes.len());
            dest[offset..offset + to_copy].copy_from_slice(&bytes[..to_copy]);
            offset += to_copy;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

fn tls_record(content_type: u8) -> Vec<u8> {
    vec![content_type, 0x03, 0x03, 0x00, 0x00]
}
