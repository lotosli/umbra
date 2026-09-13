use super::*;
use proptest::prelude::*;

const C: VisionDirection = VisionDirection::ClientToTarget;
const S: VisionDirection = VisionDirection::TargetToClient;

fn vec16(bytes: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(bytes.len())
        .expect("fixture bound")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(bytes);
    out
}

fn ext(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&vec16(data));
    out
}

fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len())
        .expect("fixture bound")
        .to_be_bytes();
    let mut out = vec![kind, len[1], len[2], len[3]];
    out.extend_from_slice(body);
    out
}

fn record(kind: u8, version: u16, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&vec16(body));
    out
}

fn key(group: u16, server: bool) -> Vec<u8> {
    let mut bytes = vec![9; key_len(group, server).unwrap_or(32)];
    if matches!(group, 0x17..=0x19) {
        bytes[0] = 4;
    }
    bytes
}

fn share(group: u16, server: bool) -> Vec<u8> {
    let mut out = group.to_be_bytes().to_vec();
    out.extend_from_slice(&vec16(&key(group, server)));
    out
}

fn client_extensions(group: u16) -> Vec<u8> {
    [
        ext(43, &[2, 3, 4]),
        ext(10, &vec16(&group.to_be_bytes())),
        ext(13, &[0, 2, 8, 7]),
        ext(51, &vec16(&share(group, false))),
    ]
    .concat()
}

fn client_body_with_exts(exts: &[u8], sid: &[u8], ciphers: &[u8]) -> Vec<u8> {
    let mut out = vec![3, 3];
    out.extend_from_slice(&[0x11; 32]);
    out.push(u8::try_from(sid.len()).expect("fixture session id"));
    out.extend_from_slice(sid);
    out.extend_from_slice(&vec16(ciphers));
    out.extend_from_slice(&[1, 0]);
    out.extend_from_slice(&vec16(exts));
    out
}

fn client_body(group: u16) -> Vec<u8> {
    client_body_with_exts(
        &client_extensions(group),
        &[0x33; 4],
        &[0x13, 1, 0x13, 2, 0x13, 3],
    )
}

fn server_body_with_exts(exts: &[u8], sid: &[u8], cipher: u16) -> Vec<u8> {
    let mut out = vec![3, 3];
    out.extend_from_slice(&[0x22; 32]);
    out.push(u8::try_from(sid.len()).expect("fixture session id"));
    out.extend_from_slice(sid);
    out.extend_from_slice(&cipher.to_be_bytes());
    out.push(0);
    out.extend_from_slice(&vec16(exts));
    out
}

fn server_extensions(group: u16) -> Vec<u8> {
    [ext(43, &[3, 4]), ext(51, &share(group, true))].concat()
}

fn server_body(group: u16) -> Vec<u8> {
    server_body_with_exts(&server_extensions(group), &[0x33; 4], 0x1301)
}

fn client_record() -> Vec<u8> {
    record(0x16, 0x0301, &handshake(1, &client_body(0x1d)))
}
fn server_record() -> Vec<u8> {
    record(0x16, 0x0303, &handshake(2, &server_body(0x1d)))
}
fn protected() -> Vec<u8> {
    record(0x17, 0x0303, &[0x55; 17])
}

fn feed(observer: &mut Tls13Observer, direction: VisionDirection, bytes: &[u8], chunk: usize) {
    for piece in bytes.chunks(chunk) {
        observer.observe(direction, piece).expect("counter");
    }
}

fn negotiated() -> Tls13Observer {
    let mut observer = Tls13Observer::new();
    observer.observe(C, &client_record()).expect("CH");
    observer.observe(S, &server_record()).expect("SH");
    assert!(!observer.disabled());
    observer
}

#[test]
fn complete_protected_bodies_required_after_real_hello_structure() {
    let mut observer = Tls13Observer::default();
    assert_eq!(observer.offset(C), 0);
    assert!(!observer.eligible());
    assert!(!observer.is_boundary(C));
    feed(&mut observer, C, &client_record(), 1);
    feed(&mut observer, C, &[0x14, 3, 3, 0, 1, 1], 1);
    feed(&mut observer, S, &server_record(), 1);
    feed(&mut observer, S, &[0x14, 3, 3, 0, 1, 1], 1);
    let protected = protected();
    feed(&mut observer, S, &protected, 1);
    assert!(!observer.eligible());
    assert!(observer.is_boundary(S));
    observer
        .observe(C, &protected[..protected.len() - 1])
        .expect("partial");
    assert!(!observer.eligible());
    assert!(!observer.is_boundary(C));
    observer
        .observe(C, &protected[protected.len() - 1..])
        .expect("body complete");
    assert!(observer.eligible());
    assert!(observer.is_boundary(C));
    observer.observe(C, &protected[..1]).expect("next prefix");
    assert!(observer.eligible());
    assert!(!observer.is_boundary(C));
    assert_eq!(observer.read_limit(C, 8192), 4);
    observer.observe(C, &protected[1..5]).expect("next header");
    assert_eq!(observer.read_limit(C, 8192), 17);
    assert_eq!(observer.read_limit(C, 2), 2);
    observer.observe(C, &protected[5..]).expect("next body");
    assert!(observer.is_boundary(C));
    assert_eq!(observer.read_limit(C, 8192), 5);
    assert_eq!(observer.read_limit(C, 0), 0);
    assert!(!format!("{observer:?}").contains("session_id"));
}

#[test]
fn handshake_messages_span_records_and_arbitrary_reads() {
    for split in 1..handshake(1, &client_body(0x1d)).len() {
        let mut observer = Tls13Observer::new();
        let ch = handshake(1, &client_body(0x1d));
        let sh = handshake(2, &server_body(0x1d));
        let split_server = split.min(sh.len() - 1);
        let c = [
            record(0x16, 0x0301, &ch[..split]),
            record(0x16, 0x0303, &ch[split..]),
        ]
        .concat();
        let s = [
            record(0x16, 0x0303, &sh[..split_server]),
            record(0x16, 0x0303, &sh[split_server..]),
            protected(),
        ]
        .concat();
        feed(&mut observer, C, &c, 3);
        feed(&mut observer, S, &s, 7);
        feed(&mut observer, C, &protected(), 2);
        assert!(observer.eligible(), "split {split}");
    }
}

#[test]
fn offset_zero_only_and_lone_or_embedded_application_markers_do_not_qualify() {
    for prefix in [
        b"GET / HTTP/1.1\r\n".to_vec(),
        protected(),
        vec![0x17, 3, 3, 0, 17],
        vec![0, 0x16, 3, 3, 0, 1],
    ] {
        let mut observer = Tls13Observer::new();
        observer.observe(C, &prefix).expect("prefix");
        observer.observe(C, &client_record()).expect("later CH");
        observer.observe(S, &server_record()).expect("later SH");
        observer.observe(C, &protected()).expect("later protected");
        observer.observe(S, &protected()).expect("later protected");
        assert!(observer.disabled());
        assert!(!observer.eligible());
    }
    let mut observer = Tls13Observer::new();
    let mut body = client_body(0x1d);
    body[2..7].copy_from_slice(&[0x17, 3, 3, 0, 17]);
    observer
        .observe(C, &record(0x16, 0x0303, &handshake(1, &body)))
        .expect("embedded marker");
    observer.observe(S, &server_record()).expect("SH");
    observer.observe(S, &protected()).expect("server protected");
    assert!(!observer.eligible());
    assert!(!observer.disabled());
}

#[test]
fn tls12_hrr_early_data_psk_wrong_cipher_and_invalid_ccs_stay_wrapped() {
    let mut tls12_exts = client_extensions(0x1d);
    tls12_exts[6] = 3;
    let mut cases = vec![client_body_with_exts(&tls12_exts, &[0x33; 4], &[0x13, 1])];
    for forbidden in [41, 42] {
        let exts = [client_extensions(0x1d), ext(forbidden, &[])].concat();
        cases.push(client_body_with_exts(&exts, &[0x33; 4], &[0x13, 1]));
    }
    for body in cases {
        let mut observer = Tls13Observer::new();
        observer
            .observe(C, &record(0x16, 0x0303, &handshake(1, &body)))
            .expect("unsupported CH");
        assert!(observer.disabled());
    }
    let mut hrr = server_body(0x1d);
    hrr[2..34].copy_from_slice(&HRR_RANDOM);
    let mut wrong_cipher = server_body(0x1d);
    wrong_cipher[39..41].copy_from_slice(&[0xc0, 0x2f]);
    for body in [hrr, wrong_cipher] {
        let mut observer = Tls13Observer::new();
        observer.observe(C, &client_record()).expect("CH");
        observer
            .observe(S, &record(0x16, 0x0303, &handshake(2, &body)))
            .expect("unsupported SH");
        assert!(observer.disabled());
    }
    let mut before_sh = Tls13Observer::new();
    before_sh.observe(C, &client_record()).expect("CH");
    before_sh.observe(C, &protected()).expect("early protected");
    assert!(before_sh.disabled());
    for ccs in [
        [0x14, 3, 3, 0, 1, 0],
        [0x14, 3, 1, 0, 1, 1],
        [0x14, 3, 3, 0, 0, 1],
    ] {
        let mut observer = negotiated();
        observer.observe(C, &ccs).expect("invalid CCS");
        assert!(observer.disabled());
    }
    let mut observer = Tls13Observer::new();
    observer
        .observe(C, &[0x14, 3, 3, 0, 1, 1])
        .expect("CCS before CH");
    assert!(observer.disabled());
    let mut observer = negotiated();
    observer.observe(C, &protected()).expect("protected");
    observer
        .observe(C, &[0x14, 3, 3, 0, 1, 1])
        .expect("CCS after protected");
    assert!(observer.disabled());
}

#[test]
fn malformed_record_and_handshake_sequences_disable_without_discarding_accounting() {
    for header in [
        [0x16, 3, 3, 0, 0],
        [0x16, 3, 3, 0x40, 1],
        [0x16, 2, 3, 0, 1],
        [0x15, 3, 3, 0, 2],
    ] {
        let mut observer = Tls13Observer::new();
        observer.observe(C, &header).expect("bad record");
        assert!(observer.disabled());
        assert_eq!(observer.offset(C), 5);
    }
    for message in [
        vec![2, 0, 0, 0],
        vec![1, 0xff, 0xff, 0xff],
        [handshake(1, &client_body(0x1d)), vec![0]].concat(),
    ] {
        let mut observer = Tls13Observer::new();
        observer
            .observe(C, &record(0x16, 0x0303, &message))
            .expect("bad message");
        assert!(observer.disabled());
    }
    let mut observer = negotiated();
    observer
        .observe(C, &client_record())
        .expect("unexpected second CH");
    assert!(observer.disabled());
    let mut observer = Tls13Observer::new();
    observer.observe(S, &server_record()).expect("SH before CH");
    assert!(observer.disabled());
    let mut observer = Tls13Observer::new();
    observer
        .observe(C, &record(0x16, 0x0303, &[1, 0, 1, 0, 0]))
        .expect("partial handshake");
    observer
        .observe(C, &[0x14, 3, 3, 0, 1, 1])
        .expect("CCS interrupts handshake");
    assert!(observer.disabled());
}

#[test]
fn record_limits_and_observation_deadline_disable_are_permanent() {
    let mut observer = negotiated();
    observer
        .observe(C, &record(0x17, 0x0303, &vec![0; 16_640]))
        .expect("max record");
    assert!(observer.is_boundary(C));
    observer.observe(S, &protected()).expect("server protected");
    assert!(observer.eligible());
    observer.disable();
    observer.observe(C, &[]).expect("empty after disable");
    assert!(observer.disabled());
    assert!(!observer.is_boundary(C));
    assert_eq!(observer.read_limit(C, 8192), 8192);
    assert!(observer.offer.is_none());
    let mut observer = negotiated();
    observer
        .observe(C, &vec![0; 262_145])
        .expect("over byte budget");
    assert!(observer.disabled());
    assert_eq!(
        observer.offset(C),
        u64::try_from(client_record().len()).expect("len") + 262_145
    );
    observer.observe(C, b"abc").expect("wrapped accounting");
    assert_eq!(
        observer.offset(C),
        u64::try_from(client_record().len()).expect("len") + 262_148
    );
    observer.directions[0].offset = u64::MAX;
    assert_eq!(
        observer.observe(C, &[0]),
        Err(ObserverError::CounterOverflow)
    );
    assert_eq!(observer.offset(C), u64::MAX);
}

#[test]
fn raw_record_helper_accepts_only_bounded_protected_records() {
    assert_eq!(protected_record_len(&[0x17, 3, 3, 0, 17]), Ok(22));
    assert_eq!(protected_record_len(&[0x17, 3, 3, 0x41, 0]), Ok(16_645));
    for h in [
        [0x17, 3, 3, 0, 16],
        [0x17, 3, 3, 0x41, 1],
        [0x16, 3, 3, 0, 17],
        [0x17, 3, 1, 0, 17],
        [0x17, 3, 3, 0, 0],
    ] {
        assert_eq!(
            protected_record_len(&h),
            Err(ObserverError::InvalidProtectedHeader)
        );
        let mut observer = negotiated();
        observer.observe(C, &h).expect("bad protected header");
        assert!(observer.disabled());
    }
}

#[test]
fn maximum_handshake_reassembly_is_bounded_and_preserves_negotiation() {
    let mut extensions = client_extensions(0x1d);
    let base = 4 + client_body_with_exts(&extensions, &[0x33; 4], &[0x13, 1]).len();
    let cover = MAX_HANDSHAKE_LEN - base - 4;
    extensions.extend_from_slice(&ext(0xfafa, &vec![0; cover]));
    let hello = handshake(
        1,
        &client_body_with_exts(&extensions, &[0x33; 4], &[0x13, 1]),
    );
    assert_eq!(hello.len(), MAX_HANDSHAKE_LEN);
    let mut observer = Tls13Observer::new();
    for fragment in hello.chunks(16_384) {
        let input = record(0x16, 0x0303, fragment);
        for part in input.chunks(17) {
            observer.observe(C, part).expect("bounded handshake count");
            assert!(observer.directions[0].handshake.capacity() <= MAX_HANDSHAKE_LEN);
        }
    }
    assert!(!observer.disabled());
    observer
        .observe(S, &[server_record(), protected()].concat())
        .expect("server flight");
    observer.observe(C, &protected()).expect("client protected");
    assert!(observer.eligible());
    let mut excessive = Tls13Observer::new();
    excessive
        .observe(C, &record(0x16, 0x0303, &[1, 1, 0, 1]))
        .expect("excessive declaration");
    assert!(excessive.disabled());
    assert!(excessive.directions[0].handshake.is_empty());
}

#[test]
fn nested_extension_lengths_key_shares_and_missing_prerequisites_are_checked() {
    let base = || {
        [
            ext(43, &[2, 3, 4]),
            ext(10, &[0, 2, 0, 0x1d]),
            ext(13, &[0, 2, 8, 7]),
        ]
        .concat()
    };
    let complete =
        |extra: Vec<u8>| client_body_with_exts(&[base(), extra].concat(), &[0x33; 4], &[0x13, 1]);
    for shares in [
        [vec16(&share(0x1d, false)), vec![0]].concat(),
        vec16(&[share(0x1d, false), share(0x1d, false)].concat()),
        vec16(&[0, 0x1d, 0, 0]),
        vec16(&[0, 0x1d, 0, 1, 9]),
        vec16(&share(0x17, false)),
        vec16(&[]),
    ] {
        assert!(parse_client_hello(&complete(ext(51, &shares))).is_none());
    }
    let mut ec_key = key(0x17, false);
    ec_key[0] = 3;
    let ec_share = [vec![0, 0x17], vec16(&ec_key)].concat();
    let exts = [
        ext(43, &[2, 3, 4]),
        ext(10, &[0, 2, 0, 0x17]),
        ext(13, &[0, 2, 8, 7]),
        ext(51, &vec16(&ec_share)),
    ]
    .concat();
    assert!(parse_client_hello(&client_body_with_exts(&exts, &[], &[0x13, 1])).is_none());
    let valid = [
        ext(43, &[2, 3, 4]),
        ext(10, &[0, 2, 0, 0x1d]),
        ext(13, &[0, 2, 8, 7]),
        ext(51, &vec16(&share(0x1d, false))),
    ];
    for remove in 0..valid.len() {
        let exts: Vec<u8> = valid
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != remove)
            .flat_map(|(_, e)| e.iter().copied())
            .collect();
        assert!(parse_client_hello(&client_body_with_exts(&exts, &[], &[0x13, 1])).is_none());
    }
    for (kind, bad) in [
        (43, vec![3, 3, 4, 0]),
        (43, vec![2, 3, 4, 0]),
        (10, vec![0, 2, 0, 0x1d, 0]),
        (10, vec![0, 4, 0, 0x1d, 0, 0x1d]),
        (13, vec![0, 2, 8, 7, 0]),
    ] {
        let exts: Vec<u8> = valid
            .iter()
            .filter(|e| u16::from_be_bytes([e[0], e[1]]) != kind)
            .flat_map(|e| e.iter().copied())
            .chain(ext(kind, &bad))
            .collect();
        assert!(parse_client_hello(&client_body_with_exts(&exts, &[], &[0x13, 1])).is_none());
    }
    let offer = parse_client_hello(&client_body(0x1d)).expect("offer");
    for exts in [
        ext(51, &share(0x1d, true)),
        ext(43, &[3, 4]),
        [ext(43, &[3, 3]), ext(51, &share(0x1d, true))].concat(),
        [
            ext(43, &[3, 4]),
            ext(51, &[share(0x1d, true), vec![0]].concat()),
        ]
        .concat(),
    ] {
        assert!(!parse_server_hello(
            &server_body_with_exts(&exts, &[0x33; 4], 0x1301),
            &offer
        ));
    }
}

#[test]
fn every_truncated_hello_body_and_duplicate_extensions_are_rejected() {
    let ch = client_body(0x1d);
    let offer = parse_client_hello(&ch).expect("valid CH");
    let sh = server_body(0x1d);
    for len in 0..ch.len() {
        assert!(parse_client_hello(&ch[..len]).is_none(), "CH len={len}");
    }
    for len in 0..sh.len() {
        assert!(!parse_server_hello(&sh[..len], &offer), "SH len={len}");
    }
    for group in [0x17, 0x18, 0x19, 0x1d, 0x1e, 0x11ec] {
        let offer = parse_client_hello(&client_body(group)).expect("known CH group");
        assert!(parse_server_hello(&server_body(group), &offer));
    }
    let duplicate = [client_extensions(0x1d), ext(43, &[2, 3, 4])].concat();
    assert!(
        parse_client_hello(&client_body_with_exts(&duplicate, &[0x33; 4], &[0x13, 1])).is_none()
    );
    let duplicate = [server_extensions(0x1d), ext(43, &[3, 4])].concat();
    assert!(!parse_server_hello(
        &server_body_with_exts(&duplicate, &[0x33; 4], 0x1301),
        &offer
    ));
}

#[test]
fn invalid_vector_semantics_and_selection_remain_wrapped() {
    let exts = client_extensions(0x1d);
    let ch = client_body(0x1d);
    let offer = parse_client_hello(&ch).expect("CH");
    for ciphers in [vec![], vec![0x13], vec![0xc0, 0x2f]] {
        assert!(parse_client_hello(&client_body_with_exts(&exts, &[], &ciphers)).is_none());
    }
    assert!(parse_client_hello(&client_body_with_exts(&exts, &[0; 33], &[0x13, 1])).is_none());
    for offset in [0, 1, 47, 48] {
        let mut changed = ch.clone();
        changed[offset] ^= 0xff;
        assert!(
            parse_client_hello(&changed).is_none(),
            "base offset {offset}"
        );
    }
    let mut changed = ch.clone();
    changed.push(0);
    assert!(parse_client_hello(&changed).is_none());
    assert!(parse_client_hello(&client_body(0x1234)).is_none());
    assert!(!parse_server_hello(&server_body(0x17), &offer));
    assert!(!parse_server_hello(
        &server_body_with_exts(&server_extensions(0x1d), &[], 0x1301),
        &offer
    ));
    for offset in [0, 1, 39, 40, 41] {
        let mut changed = server_body(0x1d);
        changed[offset] ^= 0xff;
        assert!(!parse_server_hello(&changed, &offer), "SH offset {offset}");
    }
    for forbidden in [41, 42] {
        let changed = [server_extensions(0x1d), ext(forbidden, &[])].concat();
        assert!(!parse_server_hello(
            &server_body_with_exts(&changed, &[0x33; 4], 0x1301),
            &offer
        ));
    }
    let mut changed = server_body(0x1d);
    changed.push(0);
    assert!(!parse_server_hello(&changed, &offer));
}

proptest! {
    #[test]
    fn valid_observation_is_independent_of_read_fragments(c_chunk in 1_usize..80, s_chunk in 1_usize..80, payload in 17_usize..4000) {
        let mut observer = Tls13Observer::new();
        feed(&mut observer, C, &client_record(), c_chunk);
        let server = [server_record(), record(0x17, 0x0303, &vec![0x55; payload]), protected()].concat();
        feed(&mut observer, S, &server, s_chunk);
        feed(&mut observer, C, &protected(), c_chunk);
        prop_assert!(observer.eligible());
        prop_assert!(observer.is_boundary(C));
        prop_assert!(observer.is_boundary(S));
    }

    #[test]
    fn arbitrary_input_never_panics_or_exceeds_observer_storage(bytes in prop::collection::vec(any::<u8>(), 0..20_000), chunk in 1_usize..100) {
        let mut observer = Tls13Observer::new();
        for (i, data) in bytes.chunks(chunk).enumerate() {
            observer.observe(if i % 2 == 0 { C } else { S }, data).expect("bounded count");
            prop_assert!(observer.directions.iter().all(|d| d.handshake.len() <= MAX_HANDSHAKE_LEN));
        }
        prop_assert!(!observer.eligible());
    }
}
