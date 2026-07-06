//! Minimal TLS 1.3 client handshake state machine.

use ring::signature::{self, UnparsedPublicKey};
use subtle::ConstantTimeEq;
use umbra_crypto::{secret::Secret, x25519};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{
    clienthello::{
        build_client_hello, ClientHelloParams, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    },
    keyschedule::{
        derive_tls13_secrets, derive_traffic_keys, finished_verify_data, transcript_hash,
    },
    records::{OpenRecord, RecordLayer, CONTENT_TYPE_HANDSHAKE},
    TlsError,
};

const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 0x08;
const HANDSHAKE_CERTIFICATE: u8 = 0x0b;
const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 0x0f;
const HANDSHAKE_FINISHED: u8 = 0x14;
const RECORD_HANDSHAKE: u8 = 0x16;
const TLS_RECORD_HEADER_LEN: usize = 5;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const GROUP_X25519: u16 = 0x001d;
pub(crate) const SIGNATURE_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const SERVER_CERTIFICATE_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

/// Peer classification returned by certificate verification callbacks.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PeerKind {
    /// Umbra-forged certificate authenticated by component E.
    UmbraTrusted,
    /// Real destination certificate accepted for direct-site behavior.
    RealSite,
    /// Invalid peer certificate.
    Invalid,
}

/// Certificate verification callback used by the minimal TLS client.
pub trait CertVerify {
    /// Classify the peer certificate chain.
    fn verify(&self, leaf_der: &[u8], chain: &[Vec<u8>]) -> PeerKind;
}

/// Output from advancing a handshake state machine.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DriveOut {
    /// Bytes that must be sent to the peer.
    pub outbound: Vec<u8>,
    /// True when application-data record layers are ready.
    pub complete: bool,
    /// Peer classification observed by client handshakes.
    pub peer_kind: Option<PeerKind>,
}

/// Minimal TLS 1.3 client.
pub struct Tls13Client {
    cipher_suite: u16,
    client_private: [u8; 32],
    client_hello_record: Vec<u8>,
    client_hello_handshake: Vec<u8>,
    state: ClientState,
    app_write: Option<RecordLayer>,
    app_read: Option<RecordLayer>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ClientState {
    ExpectServerFlight,
    Connected,
}

/// Parsed minimal ServerHello data.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServerHelloData {
    /// Raw ServerHello handshake message.
    pub handshake: Vec<u8>,
    /// TLS 1.3 compatibility session id echo.
    pub session_id: Vec<u8>,
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Server X25519 key share.
    pub x25519_key_share: [u8; 32],
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ParsedServerFlight {
    pub(crate) encrypted_extensions: Vec<u8>,
    pub(crate) certificate: Vec<u8>,
    pub(crate) certificate_chain: Vec<Vec<u8>>,
    pub(crate) certificate_verify_scheme: u16,
    pub(crate) certificate_verify_signature: Vec<u8>,
    pub(crate) finished: [u8; 32],
    pub(crate) transcript_before_certificate_verify: Vec<u8>,
    pub(crate) transcript_before_finished: Vec<u8>,
    pub(crate) transcript_after_finished: Vec<u8>,
}

impl Tls13Client {
    /// Start a TLS 1.3 client handshake.
    ///
    /// The returned bytes are the exact ClientHello record produced by the
    /// profile-driven builder.
    pub fn start(params: ClientHelloParams) -> Result<(Self, Vec<u8>), TlsError> {
        let client_hello_record = build_client_hello(&params)?;
        let client_hello_handshake = first_record_payload(&client_hello_record)?;
        let client_private = params.x25519_priv;
        drop(params);
        Ok((
            Self {
                cipher_suite: TLS_AES_128_GCM_SHA256,
                client_private,
                client_hello_record: client_hello_record.clone(),
                client_hello_handshake,
                state: ClientState::ExpectServerFlight,
                app_write: None,
                app_read: None,
            },
            client_hello_record,
        ))
    }

    /// Chrome-compatible dummy ChangeCipherSpec record.
    #[must_use]
    pub fn dummy_change_cipher_spec() -> [u8; 6] {
        [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
    }

    /// Advance the client handshake with server bytes.
    pub fn drive(&mut self, inbound: &[u8], verify: &dyn CertVerify) -> Result<DriveOut, TlsError> {
        if self.state != ClientState::ExpectServerFlight {
            return Err(TlsError::InvalidInput("client handshake already complete"));
        }

        let (server_hello_record, rest) = split_first_record(inbound)?;
        let server_hello = parse_server_hello_record(server_hello_record)?;
        self.cipher_suite = server_hello.cipher_suite;

        let client_secret = Secret::new(self.client_private);
        let shared = x25519::agree(&client_secret, &server_hello.x25519_key_share)
            .map_err(|_| TlsError::InvalidInput("bad server key_share"))?;
        let mut handshake_transcript = self.client_hello_handshake.clone();
        handshake_transcript.extend_from_slice(&server_hello.handshake);

        let hs_secrets = derive_tls13_secrets(shared.expose_secret(), &handshake_transcript, &[])?;
        let server_hs_keys = derive_traffic_keys(
            server_hello.cipher_suite,
            &hs_secrets.server_handshake_traffic_secret,
        )?;
        let mut server_hs_read = RecordLayer::new(
            server_hello.cipher_suite,
            server_hs_keys.key,
            server_hs_keys.iv,
        );
        let OpenRecord {
            content_type,
            plaintext,
        } = server_hs_read.open(rest)?;
        if content_type != CONTENT_TYPE_HANDSHAKE {
            return Err(TlsError::InvalidInput(
                "server flight is not handshake data",
            ));
        }

        let flight = parse_server_flight(&plaintext, &handshake_transcript)?;
        verify_certificate_verify(
            &flight.certificate,
            flight.certificate_verify_scheme,
            &flight.certificate_verify_signature,
            &flight.transcript_before_certificate_verify,
        )?;
        let peer_kind = verify.verify(&flight.certificate, &flight.certificate_chain);
        if matches!(peer_kind, PeerKind::Invalid) {
            return Err(TlsError::PeerRejected);
        }

        let expected = finished_verify_data(
            &hs_secrets.server_handshake_traffic_secret,
            &transcript_hash(&flight.transcript_before_finished),
        )?;
        if !bool::from(expected.as_slice().ct_eq(flight.finished.as_slice())) {
            return Err(TlsError::AuthenticationFailed);
        }

        let client_verify = finished_verify_data(
            &hs_secrets.client_handshake_traffic_secret,
            &transcript_hash(&flight.transcript_after_finished),
        )?;
        let client_finished = handshake_message(HANDSHAKE_FINISHED, &client_verify)?;
        let mut transcript_after_client_finished = flight.transcript_after_finished.clone();
        transcript_after_client_finished.extend_from_slice(&client_finished);

        let client_hs_keys = derive_traffic_keys(
            server_hello.cipher_suite,
            &hs_secrets.client_handshake_traffic_secret,
        )?;
        let mut client_hs_write = RecordLayer::new(
            server_hello.cipher_suite,
            client_hs_keys.key,
            client_hs_keys.iv,
        );
        let outbound = client_hs_write.seal(CONTENT_TYPE_HANDSHAKE, &client_finished)?;

        let app_secrets = derive_tls13_secrets(
            shared.expose_secret(),
            &handshake_transcript,
            &transcript_after_client_finished,
        )?;
        let client_app = derive_traffic_keys(
            server_hello.cipher_suite,
            &app_secrets.client_application_traffic_secret,
        )?;
        let server_app = derive_traffic_keys(
            server_hello.cipher_suite,
            &app_secrets.server_application_traffic_secret,
        )?;
        self.app_write = Some(RecordLayer::new(
            server_hello.cipher_suite,
            client_app.key,
            client_app.iv,
        ));
        self.app_read = Some(RecordLayer::new(
            server_hello.cipher_suite,
            server_app.key,
            server_app.iv,
        ));
        self.state = ClientState::Connected;

        Ok(DriveOut {
            outbound,
            complete: true,
            peer_kind: Some(peer_kind),
        })
    }

    /// Seal application data after the handshake completes.
    pub fn app_seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        self.app_write
            .as_mut()
            .ok_or(TlsError::InvalidInput("client is not connected"))?
            .seal(crate::records::CONTENT_TYPE_APPLICATION_DATA, plaintext)
    }

    /// Open application data after the handshake completes.
    pub fn app_open(&mut self, record: &[u8]) -> Result<Vec<u8>, TlsError> {
        let opened = self
            .app_read
            .as_mut()
            .ok_or(TlsError::InvalidInput("client is not connected"))?
            .open(record)?;
        if opened.content_type != crate::records::CONTENT_TYPE_APPLICATION_DATA {
            return Err(TlsError::InvalidInput("not application data"));
        }
        Ok(opened.plaintext)
    }

    /// Return the original ClientHello record.
    #[must_use]
    pub fn client_hello_record(&self) -> &[u8] {
        &self.client_hello_record
    }
}

pub(crate) fn build_server_hello(
    session_id: &[u8],
    cipher_suite: u16,
    server_random: &[u8; 32],
    server_x25519_pub: &[u8; 32],
) -> Result<Vec<u8>, TlsError> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303_u16.to_be_bytes());
    body.extend_from_slice(server_random);
    let session_len = u8::try_from(session_id.len()).map_err(|_| TlsError::LengthOutOfRange)?;
    body.push(session_len);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&cipher_suite.to_be_bytes());
    body.push(0);

    let mut extensions = Vec::new();
    let mut key_share = Vec::new();
    key_share.extend_from_slice(&GROUP_X25519.to_be_bytes());
    push_u16_len(server_x25519_pub.len(), &mut key_share)?;
    key_share.extend_from_slice(server_x25519_pub);
    push_extension(EXT_KEY_SHARE, &key_share, &mut extensions)?;
    push_extension(
        EXT_SUPPORTED_VERSIONS,
        &0x0304_u16.to_be_bytes(),
        &mut extensions,
    )?;
    push_u16_len(extensions.len(), &mut body)?;
    body.extend_from_slice(&extensions);

    handshake_record(&handshake_message(HANDSHAKE_SERVER_HELLO, &body)?)
}

pub(crate) fn handshake_message(handshake_type: u8, body: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut out = Vec::new();
    out.push(handshake_type);
    push_u24_len(body.len(), &mut out)?;
    out.extend_from_slice(body);
    Ok(out)
}

pub(crate) fn certificate_message(leaf: &[u8], chain: &[Vec<u8>]) -> Result<Vec<u8>, TlsError> {
    let mut entries = Vec::new();
    push_cert_entry(leaf, &mut entries)?;
    for cert in chain {
        push_cert_entry(cert, &mut entries)?;
    }

    let mut body = Vec::new();
    body.push(0);
    push_u24_len(entries.len(), &mut body)?;
    body.extend_from_slice(&entries);
    handshake_message(HANDSHAKE_CERTIFICATE, &body)
}

pub(crate) fn encrypted_extensions_message() -> Result<Vec<u8>, TlsError> {
    handshake_message(HANDSHAKE_ENCRYPTED_EXTENSIONS, &[0, 0])
}

pub(crate) fn certificate_verify_message(
    signature_scheme: u16,
    signature: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let mut body = Vec::new();
    body.extend_from_slice(&signature_scheme.to_be_bytes());
    push_u16_len(signature.len(), &mut body)?;
    body.extend_from_slice(signature);
    handshake_message(HANDSHAKE_CERTIFICATE_VERIFY, &body)
}

pub(crate) fn first_record_payload(record: &[u8]) -> Result<Vec<u8>, TlsError> {
    if record.len() < TLS_RECORD_HEADER_LEN || record[0] != RECORD_HANDSHAKE {
        return Err(TlsError::InvalidInput("missing handshake record"));
    }
    let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    if record.len() < TLS_RECORD_HEADER_LEN + len {
        return Err(TlsError::InvalidInput("truncated handshake record"));
    }
    Ok(record[TLS_RECORD_HEADER_LEN..TLS_RECORD_HEADER_LEN + len].to_vec())
}

pub(crate) fn handshake_record(handshake: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut out = Vec::new();
    out.push(RECORD_HANDSHAKE);
    out.extend_from_slice(&0x0303_u16.to_be_bytes());
    push_u16_len(handshake.len(), &mut out)?;
    out.extend_from_slice(handshake);
    Ok(out)
}

pub(crate) fn split_first_record(input: &[u8]) -> Result<(&[u8], &[u8]), TlsError> {
    if input.len() < TLS_RECORD_HEADER_LEN {
        return Err(TlsError::InvalidInput("short TLS record"));
    }
    let len = usize::from(u16::from_be_bytes([input[3], input[4]]));
    let end = TLS_RECORD_HEADER_LEN
        .checked_add(len)
        .ok_or(TlsError::InvalidInput("record length overflow"))?;
    if input.len() < end {
        return Err(TlsError::InvalidInput("truncated TLS record"));
    }
    Ok(input.split_at(end))
}

/// Parse a plaintext ServerHello handshake record.
pub fn parse_server_hello_record(record: &[u8]) -> Result<ServerHelloData, TlsError> {
    let handshake = first_record_payload(record)?;
    parse_server_hello_handshake(&handshake)
}

/// Parse a plaintext ServerHello handshake message.
pub fn parse_server_hello_handshake(handshake: &[u8]) -> Result<ServerHelloData, TlsError> {
    if handshake.len() < 4 || handshake[0] != HANDSHAKE_SERVER_HELLO {
        return Err(TlsError::InvalidInput("not a ServerHello"));
    }
    let declared = read_u24(&handshake[1..4])?;
    if handshake.len() < 4 + declared {
        return Err(TlsError::InvalidInput("truncated ServerHello"));
    }
    let body = &handshake[4..4 + declared];
    let mut offset = 0;
    let _legacy_version = read_u16_at(body, &mut offset)?;
    skip(body, &mut offset, 32)?;
    let session_len = usize::from(read_u8_at(body, &mut offset)?);
    let session_id = take(body, &mut offset, session_len)?.to_vec();
    let cipher_suite = read_u16_at(body, &mut offset)?;
    match cipher_suite {
        TLS_AES_128_GCM_SHA256 | TLS_AES_256_GCM_SHA384 | TLS_CHACHA20_POLY1305_SHA256 => {}
        other => return Err(TlsError::UnsupportedCipherSuite(other)),
    }
    let _compression = read_u8_at(body, &mut offset)?;
    let ext_len = usize::from(read_u16_at(body, &mut offset)?);
    let ext_end = offset
        .checked_add(ext_len)
        .ok_or(TlsError::InvalidInput("extension offset overflow"))?;
    if ext_end > body.len() {
        return Err(TlsError::InvalidInput("ServerHello extensions overflow"));
    }

    let mut x25519_key_share = None;
    while offset < ext_end {
        let ext = read_u16_at(body, &mut offset)?;
        let data_len = usize::from(read_u16_at(body, &mut offset)?);
        let data = take(body, &mut offset, data_len)?;
        if ext == EXT_KEY_SHARE {
            let mut data_offset = 0;
            let group = read_u16_at(data, &mut data_offset)?;
            let key_len = usize::from(read_u16_at(data, &mut data_offset)?);
            let key = take(data, &mut data_offset, key_len)?;
            if group == GROUP_X25519 && key.len() == 32 {
                x25519_key_share = Some(
                    key.try_into()
                        .map_err(|_| TlsError::InvalidInput("bad X25519 share"))?,
                );
            }
        }
    }

    Ok(ServerHelloData {
        handshake: handshake.to_vec(),
        session_id,
        cipher_suite,
        x25519_key_share: x25519_key_share
            .ok_or(TlsError::InvalidInput("missing server X25519 key_share"))?,
    })
}

pub(crate) fn parse_server_flight(
    input: &[u8],
    transcript_prefix: &[u8],
) -> Result<ParsedServerFlight, TlsError> {
    let mut offset = 0;
    let mut transcript = transcript_prefix.to_vec();
    let mut encrypted_extensions = None;
    let mut certificate = None;
    let mut certificate_chain = Vec::new();
    let mut certificate_verify_scheme = None;
    let mut certificate_verify_signature = None;
    let mut finished = None;
    let mut transcript_before_certificate_verify = None;
    let mut transcript_before_finished = None;
    let mut transcript_after_finished = None;

    while offset < input.len() {
        let start = offset;
        let typ = read_u8_at(input, &mut offset)?;
        let len = read_u24(take(input, &mut offset, 3)?)?;
        let body = take(input, &mut offset, len)?;
        let message = &input[start..offset];
        match typ {
            HANDSHAKE_ENCRYPTED_EXTENSIONS => {
                encrypted_extensions = Some(message.to_vec());
                transcript.extend_from_slice(message);
            }
            HANDSHAKE_CERTIFICATE => {
                let (leaf, chain) = parse_certificate_body(body)?;
                certificate = Some(leaf);
                certificate_chain = chain;
                transcript.extend_from_slice(message);
            }
            HANDSHAKE_CERTIFICATE_VERIFY => {
                let (scheme, signature) = parse_certificate_verify_body(body)?;
                certificate_verify_scheme = Some(scheme);
                certificate_verify_signature = Some(signature);
                transcript_before_certificate_verify = Some(transcript.clone());
                transcript.extend_from_slice(message);
            }
            HANDSHAKE_FINISHED => {
                let verify_data: [u8; 32] = body
                    .try_into()
                    .map_err(|_| TlsError::InvalidInput("bad Finished length"))?;
                transcript_before_finished = Some(transcript.clone());
                transcript.extend_from_slice(message);
                transcript_after_finished = Some(transcript.clone());
                finished = Some(verify_data);
            }
            _ => return Err(TlsError::InvalidInput("unexpected handshake message")),
        }
    }

    Ok(ParsedServerFlight {
        encrypted_extensions: encrypted_extensions
            .ok_or(TlsError::InvalidInput("missing EncryptedExtensions"))?,
        certificate: certificate.ok_or(TlsError::InvalidInput("missing Certificate"))?,
        certificate_chain,
        certificate_verify_scheme: certificate_verify_scheme
            .ok_or(TlsError::InvalidInput("missing CertificateVerify"))?,
        certificate_verify_signature: certificate_verify_signature
            .ok_or(TlsError::InvalidInput("missing CertificateVerify"))?,
        finished: finished.ok_or(TlsError::InvalidInput("missing Finished"))?,
        transcript_before_certificate_verify: transcript_before_certificate_verify.ok_or(
            TlsError::InvalidInput("missing CertificateVerify transcript"),
        )?,
        transcript_before_finished: transcript_before_finished
            .ok_or(TlsError::InvalidInput("missing Finished transcript"))?,
        transcript_after_finished: transcript_after_finished
            .ok_or(TlsError::InvalidInput("missing Finished transcript"))?,
    })
}

fn parse_certificate_body(body: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), TlsError> {
    let mut offset = 0;
    let context_len = usize::from(read_u8_at(body, &mut offset)?);
    skip(body, &mut offset, context_len)?;
    let list_len = read_u24(take(body, &mut offset, 3)?)?;
    let list_end = offset
        .checked_add(list_len)
        .ok_or(TlsError::InvalidInput("certificate list overflow"))?;
    if list_end != body.len() {
        return Err(TlsError::InvalidInput("bad certificate list length"));
    }

    let mut certs = Vec::new();
    while offset < list_end {
        let cert_len = read_u24(take(body, &mut offset, 3)?)?;
        let cert = take(body, &mut offset, cert_len)?.to_vec();
        let ext_len = usize::from(read_u16_at(body, &mut offset)?);
        skip(body, &mut offset, ext_len)?;
        certs.push(cert);
    }
    let Some(leaf) = certs.first().cloned() else {
        return Err(TlsError::InvalidInput("empty certificate list"));
    };
    Ok((leaf, certs.into_iter().skip(1).collect()))
}

fn parse_certificate_verify_body(body: &[u8]) -> Result<(u16, Vec<u8>), TlsError> {
    let mut offset = 0;
    let scheme = read_u16_at(body, &mut offset)?;
    let signature_len = usize::from(read_u16_at(body, &mut offset)?);
    let signature = take(body, &mut offset, signature_len)?.to_vec();
    if offset != body.len() {
        return Err(TlsError::InvalidInput(
            "CertificateVerify has trailing bytes",
        ));
    }
    Ok((scheme, signature))
}

pub(crate) fn certificate_verify_input(transcript_hash: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        64 + SERVER_CERTIFICATE_VERIFY_CONTEXT.len() + 1 + transcript_hash.len(),
    );
    input.extend_from_slice(&[0x20; 64]);
    input.extend_from_slice(SERVER_CERTIFICATE_VERIFY_CONTEXT);
    input.push(0);
    input.extend_from_slice(transcript_hash);
    input
}

pub(crate) fn verify_certificate_verify(
    leaf_der: &[u8],
    scheme: u16,
    signature: &[u8],
    transcript_before_certificate_verify: &[u8],
) -> Result<(), TlsError> {
    if scheme != SIGNATURE_ECDSA_SECP256R1_SHA256 {
        return Err(TlsError::InvalidInput(
            "unsupported CertificateVerify scheme",
        ));
    }
    let (_, cert) = X509Certificate::from_der(leaf_der)
        .map_err(|_| TlsError::InvalidInput("bad certificate DER"))?;
    let signature_input =
        certificate_verify_input(&transcript_hash(transcript_before_certificate_verify));
    UnparsedPublicKey::new(
        &signature::ECDSA_P256_SHA256_ASN1,
        &cert.public_key().subject_public_key.data,
    )
    .verify(&signature_input, signature)
    .map_err(|_| TlsError::AuthenticationFailed)
}

fn push_cert_entry(cert: &[u8], out: &mut Vec<u8>) -> Result<(), TlsError> {
    push_u24_len(cert.len(), out)?;
    out.extend_from_slice(cert);
    out.extend_from_slice(&0_u16.to_be_bytes());
    Ok(())
}

fn push_extension(ext: u16, data: &[u8], out: &mut Vec<u8>) -> Result<(), TlsError> {
    out.extend_from_slice(&ext.to_be_bytes());
    push_u16_len(data.len(), out)?;
    out.extend_from_slice(data);
    Ok(())
}

fn read_u8_at(input: &[u8], offset: &mut usize) -> Result<u8, TlsError> {
    let byte = *input
        .get(*offset)
        .ok_or(TlsError::InvalidInput("unexpected end of input"))?;
    *offset += 1;
    Ok(byte)
}

fn read_u16_at(input: &[u8], offset: &mut usize) -> Result<u16, TlsError> {
    let bytes = take(input, offset, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u24(input: &[u8]) -> Result<usize, TlsError> {
    if input.len() != 3 {
        return Err(TlsError::InvalidInput("bad uint24"));
    }
    Ok((usize::from(input[0]) << 16) | (usize::from(input[1]) << 8) | usize::from(input[2]))
}

fn take<'a>(input: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], TlsError> {
    let end = offset
        .checked_add(len)
        .ok_or(TlsError::InvalidInput("offset overflow"))?;
    if end > input.len() {
        return Err(TlsError::InvalidInput("unexpected end of input"));
    }
    let out = &input[*offset..end];
    *offset = end;
    Ok(out)
}

fn skip(input: &[u8], offset: &mut usize, len: usize) -> Result<(), TlsError> {
    take(input, offset, len).map(|_| ())
}

fn push_u16_len(value: usize, out: &mut Vec<u8>) -> Result<(), TlsError> {
    let value = u16::try_from(value).map_err(|_| TlsError::LengthOutOfRange)?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn push_u24_len(value: usize, out: &mut Vec<u8>) -> Result<(), TlsError> {
    if value > 0x00ff_ffff {
        return Err(TlsError::LengthOutOfRange);
    }
    out.push(u8::try_from((value >> 16) & 0xff).map_err(|_| TlsError::LengthOutOfRange)?);
    out.push(u8::try_from((value >> 8) & 0xff).map_err(|_| TlsError::LengthOutOfRange)?);
    out.push(u8::try_from(value & 0xff).map_err(|_| TlsError::LengthOutOfRange)?);
    Ok(())
}
