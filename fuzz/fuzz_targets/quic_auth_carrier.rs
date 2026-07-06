#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use umbra_fingerprint::load_profile;
use umbra_transport::quic::{
    build_quic_client_hello_surface, quic_fingerprint_from_profile, recover_quic_auth_token,
    QuicClientHelloSurface, QuicFingerprint, QuicTransportParameter,
};

fn default_fingerprint() -> &'static QuicFingerprint {
    static FP: OnceLock<QuicFingerprint> = OnceLock::new();
    FP.get_or_init(|| {
        let profile = load_profile("chrome-latest").expect("bundled profile loads");
        quic_fingerprint_from_profile(&profile)
    })
}

// 不变量：任意 SCID/transport parameter 组合不得 panic；非法 carrier 返回结构化错误。
// 运行：cargo +nightly fuzz run quic_auth_carrier
fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 {
        let mut token = [0_u8; 32];
        token.copy_from_slice(&data[..32]);
        let _ = build_quic_client_hello_surface(&token, default_fingerprint());
    }

    let mut offset = 0_usize;
    let scid_len = data.get(offset).map_or(0_usize, |len| {
        usize::from(*len).min(data.len().saturating_sub(1))
    });
    offset = offset.saturating_add(1);
    let scid_end = offset.saturating_add(scid_len).min(data.len());
    let scid = data[offset..scid_end].to_vec();
    offset = scid_end;

    let mut params = Vec::new();
    while offset < data.len() {
        let id = u64::from(data[offset]);
        offset += 1;
        if offset >= data.len() {
            break;
        }
        let len = usize::from(data[offset]).min(data.len().saturating_sub(offset + 1));
        offset += 1;
        let end = offset + len;
        params.push(QuicTransportParameter {
            id,
            value: data[offset..end].to_vec(),
        });
        offset = end;
    }

    let surface = QuicClientHelloSurface {
        alpn: "h3".to_owned(),
        scid,
        transport_parameters: params,
    };
    let _ = recover_quic_auth_token(&surface, default_fingerprint());
});
