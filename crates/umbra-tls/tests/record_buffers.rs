//! Reusable TLS records agree with independent AEAD and retain sequence state.

use umbra_tls::{
    clienthello::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
    records::{RecordLayer, CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_HANDSHAKE},
    TlsError,
};

#[test]
fn reusable_record_parts_and_open_match_independent_aead() {
    for (suite, algorithm, key_len) in [
        (TLS_AES_128_GCM_SHA256, &ring::aead::AES_128_GCM, 16),
        (TLS_AES_256_GCM_SHA384, &ring::aead::AES_256_GCM, 32),
        (
            TLS_CHACHA20_POLY1305_SHA256,
            &ring::aead::CHACHA20_POLY1305,
            32,
        ),
    ] {
        let key = vec![0x42; key_len];
        let iv = [0x24; 12];
        let reference =
            ring::aead::LessSafeKey::new(ring::aead::UnboundKey::new(algorithm, &key).unwrap());
        let mut writer = RecordLayer::new(suite, key.clone(), iv);
        let mut reader = RecordLayer::new(suite, key, iv);
        let mut output = Vec::with_capacity(16_645);
        let pointer = output.as_ptr();
        for (sequence, length) in [0, 1, 16, 1024, 16_384].into_iter().enumerate() {
            let payload = vec![0xa5; length];
            writer
                .seal_parts_into(
                    CONTENT_TYPE_APPLICATION_DATA,
                    &[&payload[..length / 2], &payload[length / 2..]],
                    &mut output,
                )
                .unwrap();
            assert_eq!(pointer, output.as_ptr());
            let mut nonce = iv;
            for (dst, src) in nonce[4..]
                .iter_mut()
                .zip(u64::try_from(sequence).unwrap().to_be_bytes())
            {
                *dst ^= src;
            }
            let size = u16::try_from(length + 17).unwrap().to_be_bytes();
            let header = [0x17, 3, 3, size[0], size[1]];
            let mut expected = payload.clone();
            expected.push(CONTENT_TYPE_APPLICATION_DATA);
            reference
                .seal_in_place_append_tag(
                    ring::aead::Nonce::assume_unique_for_key(nonce),
                    ring::aead::Aad::from(header),
                    &mut expected,
                )
                .unwrap();
            assert_eq!(output, [header.as_slice(), expected.as_slice()].concat());
            let mut tampered = output.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            assert_eq!(
                reader.open_in_place(&mut tampered),
                Err(TlsError::AuthenticationFailed)
            );
            assert!(tampered.is_empty());
            assert_eq!(reader.sequence(), u64::try_from(sequence).unwrap());
            reader.open_application_in_place(&mut output).unwrap();
            assert_eq!(&output[5..], payload);
            assert_eq!(reader.sequence(), writer.sequence());
        }
        writer
            .seal_into(CONTENT_TYPE_HANDSHAKE, b"control", &mut output)
            .unwrap();
        assert!(reader.open_application_in_place(&mut output).is_err());
        assert!(output.is_empty());
        output.extend_from_slice(b"stale");
        assert_eq!(
            writer.seal_into(CONTENT_TYPE_APPLICATION_DATA, &vec![0; 16_385], &mut output),
            Err(TlsError::LengthOutOfRange)
        );
        assert!(output.is_empty());
    }
}
