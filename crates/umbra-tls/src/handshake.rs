//! Minimal TLS 1.3 client handshake state machine.

use subtle::ConstantTimeEq;
use umbra_crypto::{
    mlkem::mlkem_decapsulate,
    secret::{Secret, SecretBytes},
    x25519,
};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{
    clienthello::{
        build_client_hello, ClientHelloParams, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    },
    keyschedule::{
        derive_tls13_secrets_for_suite, derive_traffic_keys, finished_verify_data_for_suite,
        transcript_hash_for_suite, SuiteSecrets,
    },
    records::{RecordLayer, CONTENT_TYPE_HANDSHAKE},
    TlsError,
};

const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 0x08;
const HANDSHAKE_CERTIFICATE: u8 = 0x0b;
const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 0x0f;
const HANDSHAKE_FINISHED: u8 = 0x14;
const RECORD_HANDSHAKE: u8 = 0x16;
const TLS_RECORD_HEADER_LEN: usize = 5;
const EXT_ALPN: u16 = 0x0010;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const GROUP_X25519: u16 = 0x001d;
const GROUP_X25519_MLKEM768: u16 = 0x11ec;
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
    client_private: Secret<32>,
    mlkem_decapsulation_key: Option<SecretBytes>,
    client_hello_record: Vec<u8>,
    client_hello_handshake: Vec<u8>,
    offered: OfferedParameters,
    inbound: Vec<u8>,
    messages: Vec<u8>,
    received: usize,
    context: Option<ClientHandshakeContext>,
    server_hs_read: Option<RecordLayer>,
    state: ClientState,
    app_write: Option<RecordLayer>,
    app_read: Option<RecordLayer>,
    negotiated_alpn: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ClientState {
    ExpectServerFlight,
    Connected,
    Failed,
}

pub(crate) const MAX_HANDSHAKE_FLIGHT: usize = 1024 * 1024;
const MAX_CERTIFICATE: usize = 256 * 1024;

pub(crate) struct OfferedParameters {
    session_id: Vec<u8>,
    ciphers: Vec<u16>,
    key_shares: Vec<u16>,
    signatures: Vec<u16>,
    alpn: Vec<Vec<u8>>,
    tls13: bool,
    brotli: bool,
}

impl OfferedParameters {
    pub(crate) fn new(params: &ClientHelloParams, hello: &[u8]) -> Result<Self, TlsError> {
        let parsed = crate::parse::parse_client_hello(hello)?;
        Ok(Self {
            session_id: parsed.session_id,
            ciphers: params.profile.ciphers.clone(),
            key_shares: parsed.key_shares.iter().map(|share| share.group).collect(),
            signatures: if parsed.extensions.contains(&13) {
                params.profile.signature_algorithms.clone()
            } else {
                Vec::new()
            },
            // The builder serializes this list only when ALPN is in the wire extensions.
            alpn: if parsed.extensions.contains(&EXT_ALPN) {
                params
                    .profile
                    .alpn
                    .iter()
                    .map(|protocol| protocol.as_bytes().to_vec())
                    .collect()
            } else {
                Vec::new()
            },
            tls13: parsed.extensions.contains(&EXT_SUPPORTED_VERSIONS)
                && params.profile.supported_versions.contains(&0x0304),
            brotli: parsed.extensions.contains(&27),
        })
    }

    pub(crate) fn validate_server_hello(&self, hello: &ServerHelloData) -> Result<(), TlsError> {
        if !self.tls13
            || self.session_id != hello.session_id
            || !self.ciphers.contains(&hello.cipher_suite)
            || !self.key_shares.contains(&hello.key_share_group)
        {
            return Err(TlsError::InvalidInput(
                "ServerHello selected unoffered parameters",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_flight(&self, flight: &ParsedServerFlight) -> Result<(), TlsError> {
        if !self.signatures.contains(&flight.certificate_verify_scheme) {
            return Err(TlsError::InvalidInput("unoffered CertificateVerify scheme"));
        }
        if flight.compressed_certificate && !self.brotli {
            return Err(TlsError::InvalidInput("unoffered certificate compression"));
        }
        if let Some(protocol) = &flight.negotiated_alpn {
            if !self.alpn.contains(protocol) {
                return Err(TlsError::InvalidInput("unoffered ALPN protocol"));
            }
        }
        Ok(())
    }
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
    /// Selected key-share group.
    pub key_share_group: u16,
    /// Raw selected key-share bytes.
    pub key_share: Vec<u8>,
    /// Server X25519 key-share component.
    pub x25519_key_share: [u8; 32],
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ParsedServerFlight {
    pub(crate) encrypted_extensions: Vec<u8>,
    pub(crate) negotiated_alpn: Option<Vec<u8>>,
    pub(crate) certificate: Vec<u8>,
    pub(crate) compressed_certificate: bool,
    pub(crate) certificate_chain: Vec<Vec<u8>>,
    pub(crate) certificate_verify_scheme: u16,
    pub(crate) certificate_verify_signature: Vec<u8>,
    pub(crate) finished: Vec<u8>,
    pub(crate) transcript_before_certificate_verify: Vec<u8>,
    pub(crate) transcript_before_finished: Vec<u8>,
    pub(crate) transcript_after_finished: Vec<u8>,
}

struct ClientHandshakeContext {
    shared: SecretBytes,
    handshake_transcript: Vec<u8>,
    hs_secrets: SuiteSecrets,
}

struct VerifiedServerFlight {
    peer_kind: PeerKind,
    client_finished: Vec<u8>,
    transcript_after_client_finished: Vec<u8>,
}

impl Tls13Client {
    /// Start a TLS 1.3 client handshake.
    ///
    /// The returned bytes are the exact ClientHello record produced by the
    /// profile-driven builder.
    pub fn start(mut params: ClientHelloParams) -> Result<(Self, Vec<u8>), TlsError> {
        let client_hello_record = build_client_hello(&params)?;
        let client_hello_handshake = first_record_payload(&client_hello_record)?;
        let offered = OfferedParameters::new(&params, &client_hello_handshake)?;
        let client_private = Secret::new(params.x25519_priv);
        let mlkem_decapsulation_key = params.mlkem.decapsulation_key.take();
        Ok((
            Self {
                cipher_suite: TLS_AES_128_GCM_SHA256,
                client_private,
                mlkem_decapsulation_key,
                client_hello_record: client_hello_record.clone(),
                client_hello_handshake,
                offered,
                inbound: Vec::new(),
                messages: Vec::new(),
                received: 0,
                context: None,
                server_hs_read: None,
                state: ClientState::ExpectServerFlight,
                app_write: None,
                app_read: None,
                negotiated_alpn: None,
            },
            client_hello_record,
        ))
    }

    /// Chrome-compatible dummy ChangeCipherSpec record.
    #[must_use]
    pub fn dummy_change_cipher_spec() -> [u8; 6] {
        [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
    }

    /// Consume arbitrary chunks of the server flight, bounded to 1 MiB.
    /// Returns `complete: false` until Finished is verified. After completion,
    /// retrieve any coalesced post-handshake bytes with `take_pending_input`.
    /// Any error makes this handshake unusable.
    pub fn drive(&mut self, inbound: &[u8], verify: &dyn CertVerify) -> Result<DriveOut, TlsError> {
        if self.state != ClientState::ExpectServerFlight {
            return Err(TlsError::InvalidInput("client handshake already complete"));
        }
        let result = self.drive_inner(inbound, verify);
        if result.is_err() {
            self.state = ClientState::Failed;
            self.context = None;
            self.server_hs_read = None;
            self.client_private = Secret::new([0; 32]);
            self.mlkem_decapsulation_key = None;
            self.inbound.clear();
            self.messages.clear();
        }
        result
    }

    /// Take bytes received after server Finished for subsequent record processing.
    pub fn take_pending_input(&mut self) -> Vec<u8> {
        if self.state == ClientState::Connected {
            core::mem::take(&mut self.inbound)
        } else {
            Vec::new()
        }
    }

    fn drive_inner(
        &mut self,
        inbound: &[u8],
        verify: &dyn CertVerify,
    ) -> Result<DriveOut, TlsError> {
        self.received = self
            .received
            .checked_add(inbound.len())
            .ok_or(TlsError::LengthOutOfRange)?;
        if self.received > MAX_HANDSHAKE_FLIGHT {
            return Err(TlsError::LengthOutOfRange);
        }
        self.inbound.extend_from_slice(inbound);
        while self.inbound.len() >= TLS_RECORD_HEADER_LEN {
            let len = usize::from(u16::from_be_bytes([self.inbound[3], self.inbound[4]]));
            if len > 16384 + 256 {
                return Err(TlsError::LengthOutOfRange);
            }
            if self.inbound.len() < TLS_RECORD_HEADER_LEN + len {
                break;
            }
            let record: Vec<_> = self.inbound.drain(..TLS_RECORD_HEADER_LEN + len).collect();
            if record[1..3] != [3, 3] {
                return Err(TlsError::InvalidInput("invalid server record version"));
            }
            if record[0] == 0x14 {
                if record != Self::dummy_change_cipher_spec() {
                    return Err(TlsError::InvalidInput("invalid compatibility CCS"));
                }
                continue;
            }
            if let Some(reader) = self.server_hs_read.as_mut() {
                let opened = reader.open(&record)?;
                if opened.content_type != CONTENT_TYPE_HANDSHAKE {
                    return Err(TlsError::InvalidInput(
                        "server flight is not handshake data",
                    ));
                }
                self.messages.extend_from_slice(&opened.plaintext);
                if complete_server_flight(&self.messages)? {
                    return self.finish_server_flight(verify);
                }
            } else {
                if record[0] != RECORD_HANDSHAKE || len == 0 || len > 16384 {
                    return Err(TlsError::InvalidInput("invalid ServerHello record"));
                }
                self.messages.extend_from_slice(&record[5..]);
                if let Some(end) = complete_handshake_message(&self.messages)? {
                    if end != self.messages.len() {
                        return Err(TlsError::InvalidInput(
                            "trailing plaintext after ServerHello",
                        ));
                    }
                    let message = core::mem::take(&mut self.messages);
                    let context = self.prepare_handshake_context(&message)?;
                    let keys = derive_traffic_keys(
                        self.cipher_suite,
                        &context.hs_secrets.server_handshake_traffic_secret,
                    )?;
                    self.server_hs_read =
                        Some(RecordLayer::from_traffic_keys(self.cipher_suite, keys));
                    self.context = Some(context);
                }
            }
        }
        Ok(DriveOut {
            outbound: Vec::new(),
            complete: false,
            peer_kind: None,
        })
    }

    fn finish_server_flight(&mut self, verify: &dyn CertVerify) -> Result<DriveOut, TlsError> {
        let context = self
            .context
            .take()
            .ok_or(TlsError::InvalidInput("missing handshake context"))?;
        let flight = parse_server_flight(&self.messages, &context.handshake_transcript)?;
        self.offered.validate_flight(&flight)?;
        let verified =
            verify_server_flight(&flight, self.cipher_suite, &context.hs_secrets, verify)?;
        let outbound = seal_client_finished(
            self.cipher_suite,
            &context.hs_secrets,
            &verified.client_finished,
        )?;
        self.install_application_keys(
            self.cipher_suite,
            &context.shared,
            &context.handshake_transcript,
            &flight.transcript_after_finished,
            &verified.transcript_after_client_finished,
        )?;
        self.server_hs_read = None;
        self.messages.clear();
        self.negotiated_alpn = flight.negotiated_alpn;
        self.state = ClientState::Connected;
        Ok(DriveOut {
            outbound,
            complete: true,
            peer_kind: Some(verified.peer_kind),
        })
    }

    fn prepare_handshake_context(
        &mut self,
        server_hello_record: &[u8],
    ) -> Result<ClientHandshakeContext, TlsError> {
        let server_hello = parse_server_hello_handshake(server_hello_record)?;
        self.offered.validate_server_hello(&server_hello)?;
        self.cipher_suite = server_hello.cipher_suite;
        let classic_shared = x25519::agree(&self.client_private, &server_hello.x25519_key_share)
            .map_err(|_| TlsError::InvalidInput("bad server key_share"))?;
        let shared = client_negotiated_secret(
            &classic_shared,
            server_hello.key_share_group,
            &server_hello.key_share,
            self.mlkem_decapsulation_key.as_ref(),
        )?;
        self.client_private = Secret::new([0; 32]);
        self.mlkem_decapsulation_key = None;
        let mut handshake_transcript = self.client_hello_handshake.clone();
        handshake_transcript.extend_from_slice(&server_hello.handshake);

        let hs_secrets = derive_tls13_secrets_for_suite(
            server_hello.cipher_suite,
            shared.expose_secret(),
            &handshake_transcript,
            &[],
            &[],
        )?;
        Ok(ClientHandshakeContext {
            shared,
            handshake_transcript,
            hs_secrets,
        })
    }

    fn install_application_keys(
        &mut self,
        cipher_suite: u16,
        shared: &SecretBytes,
        handshake_transcript: &[u8],
        transcript_after_server_finished: &[u8],
        transcript_after_client_finished: &[u8],
    ) -> Result<(), TlsError> {
        let app_secrets = derive_tls13_secrets_for_suite(
            cipher_suite,
            shared.expose_secret(),
            handshake_transcript,
            transcript_after_server_finished,
            transcript_after_client_finished,
        )?;
        let client_app =
            derive_traffic_keys(cipher_suite, &app_secrets.client_application_traffic_secret)?;
        let server_app =
            derive_traffic_keys(cipher_suite, &app_secrets.server_application_traffic_secret)?;
        self.app_write = Some(RecordLayer::from_traffic_keys(cipher_suite, client_app));
        self.app_read = Some(RecordLayer::from_traffic_keys(cipher_suite, server_app));
        Ok(())
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

    /// Return the peer's selected ALPN bytes after a successfully verified handshake.
    ///
    /// Returns `None` before completion, after a failed handshake, or when the peer
    /// omitted ALPN. Callers must check handshake completion before using `None`
    /// as the no-ALPN fallback; selection does not imply application-protocol support.
    #[must_use]
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }
}

fn complete_handshake_message(input: &[u8]) -> Result<Option<usize>, TlsError> {
    if input.len() < 4 {
        return Ok(None);
    }
    let end = 4 + read_u24(&input[1..4])?;
    if end > MAX_HANDSHAKE_FLIGHT {
        return Err(TlsError::LengthOutOfRange);
    }
    Ok((input.len() >= end).then_some(end))
}

fn complete_server_flight(mut input: &[u8]) -> Result<bool, TlsError> {
    let mut index = 0;
    while !input.is_empty() {
        let Some(end) = complete_handshake_message(input)? else {
            return Ok(false);
        };
        if !matches!((index, input[0]), (0, 8) | (1, 11 | 25) | (2, 15) | (3, 20)) {
            return Err(TlsError::InvalidInput("unexpected handshake message order"));
        }
        if input[0] == HANDSHAKE_FINISHED {
            if end != input.len() {
                return Err(TlsError::InvalidInput("trailing handshake after Finished"));
            }
            return Ok(true);
        }
        input = &input[end..];
        index += 1;
    }
    Ok(false)
}

fn verify_server_flight(
    flight: &ParsedServerFlight,
    cipher_suite: u16,
    hs_secrets: &SuiteSecrets,
    verify: &dyn CertVerify,
) -> Result<VerifiedServerFlight, TlsError> {
    verify_certificate_verify(
        &flight.certificate,
        flight.certificate_verify_scheme,
        &flight.certificate_verify_signature,
        &flight.transcript_before_certificate_verify,
        cipher_suite,
    )?;
    let peer_kind = verify.verify(&flight.certificate, &flight.certificate_chain);
    if matches!(peer_kind, PeerKind::Invalid) {
        return Err(TlsError::PeerRejected);
    }

    let expected = finished_verify_data_for_suite(
        cipher_suite,
        &hs_secrets.server_handshake_traffic_secret,
        &transcript_hash_for_suite(cipher_suite, &flight.transcript_before_finished)?,
    )?;
    if !bool::from(expected.as_slice().ct_eq(flight.finished.as_slice())) {
        return Err(TlsError::AuthenticationFailed);
    }

    let client_verify = finished_verify_data_for_suite(
        cipher_suite,
        &hs_secrets.client_handshake_traffic_secret,
        &transcript_hash_for_suite(cipher_suite, &flight.transcript_after_finished)?,
    )?;
    let client_finished = handshake_message(HANDSHAKE_FINISHED, &client_verify)?;
    let mut transcript_after_client_finished = flight.transcript_after_finished.clone();
    transcript_after_client_finished.extend_from_slice(&client_finished);
    Ok(VerifiedServerFlight {
        peer_kind,
        client_finished,
        transcript_after_client_finished,
    })
}

fn seal_client_finished(
    cipher_suite: u16,
    hs_secrets: &SuiteSecrets,
    client_finished: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let client_hs_keys =
        derive_traffic_keys(cipher_suite, &hs_secrets.client_handshake_traffic_secret)?;
    let mut client_hs_write = RecordLayer::from_traffic_keys(cipher_suite, client_hs_keys);
    client_hs_write.seal(CONTENT_TYPE_HANDSHAKE, client_finished)
}

pub(crate) fn build_server_hello(
    session_id: &[u8],
    cipher_suite: u16,
    server_random: &[u8; 32],
    key_share_group: u16,
    key_exchange: &[u8],
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
    key_share.extend_from_slice(&key_share_group.to_be_bytes());
    push_u16_len(key_exchange.len(), &mut key_share)?;
    key_share.extend_from_slice(key_exchange);
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

pub(crate) fn encrypted_extensions_for_profile(
    alpn: Option<&str>,
    extension_ids: &[u16],
) -> Result<Vec<u8>, TlsError> {
    let mut extensions = Vec::new();
    let mut wrote_alpn = false;
    for ext in extension_ids {
        if *ext == EXT_ALPN {
            if let Some(protocol) = alpn {
                push_extension(
                    EXT_ALPN,
                    &selected_alpn_extension(protocol)?,
                    &mut extensions,
                )?;
                wrote_alpn = true;
            }
        } else if *ext != EXT_KEY_SHARE && *ext != EXT_SUPPORTED_VERSIONS {
            push_extension(*ext, &[], &mut extensions)?;
        }
    }
    if !wrote_alpn {
        if let Some(protocol) = alpn {
            push_extension(
                EXT_ALPN,
                &selected_alpn_extension(protocol)?,
                &mut extensions,
            )?;
        }
    }

    let mut body = Vec::new();
    push_u16_len(extensions.len(), &mut body)?;
    body.extend_from_slice(&extensions);
    handshake_message(HANDSHAKE_ENCRYPTED_EXTENSIONS, &body)
}

pub(crate) fn selected_alpn_extension(protocol: &str) -> Result<Vec<u8>, TlsError> {
    let protocol = protocol.as_bytes();
    let protocol_len = u8::try_from(protocol.len()).map_err(|_| TlsError::LengthOutOfRange)?;
    let mut list = Vec::new();
    list.push(protocol_len);
    list.extend_from_slice(protocol);
    let mut out = Vec::new();
    push_u16_len(list.len(), &mut out)?;
    out.extend_from_slice(&list);
    Ok(out)
}

pub(crate) fn client_negotiated_secret(
    classic_shared: &Secret<32>,
    key_share_group: u16,
    server_key_share: &[u8],
    mlkem_decapsulation_key: Option<&SecretBytes>,
) -> Result<SecretBytes, TlsError> {
    match key_share_group {
        GROUP_X25519 => Ok(SecretBytes::new(classic_shared.expose_secret().to_vec())),
        GROUP_X25519_MLKEM768 => {
            if server_key_share.len() <= 32 {
                return Err(TlsError::InvalidInput("truncated hybrid server key_share"));
            }
            let ciphertext = &server_key_share[32..];
            let decapsulation_key = mlkem_decapsulation_key
                .ok_or(TlsError::InvalidInput("missing ML-KEM decapsulation key"))?;
            let mlkem_shared = mlkem_decapsulate(decapsulation_key, ciphertext)
                .map_err(|_| TlsError::InvalidInput("bad ML-KEM ciphertext"))?;
            Ok(combine_shared_secrets(classic_shared, Some(&mlkem_shared)))
        }
        _ => Err(TlsError::InvalidInput("unsupported server key_share group")),
    }
}

pub(crate) fn combine_shared_secrets(
    classic_shared: &Secret<32>,
    mlkem_shared: Option<&Secret<32>>,
) -> SecretBytes {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(classic_shared.expose_secret());
    if let Some(mlkem_shared) = mlkem_shared {
        out.extend_from_slice(mlkem_shared.expose_secret());
    }
    SecretBytes::new(out)
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
    if record[1..3] != [3, 3]
        || handshake.len() > 16384
        || record.len() != TLS_RECORD_HEADER_LEN + handshake.len()
    {
        return Err(TlsError::InvalidInput(
            "invalid ServerHello record envelope",
        ));
    }
    parse_server_hello_handshake(&handshake)
}

/// Parse a plaintext ServerHello handshake message.
pub fn parse_server_hello_handshake(handshake: &[u8]) -> Result<ServerHelloData, TlsError> {
    const HRR_RANDOM: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ];
    if handshake.len() < 4 || handshake[0] != HANDSHAKE_SERVER_HELLO {
        return Err(TlsError::InvalidInput("not a ServerHello"));
    }
    let declared = read_u24(&handshake[1..4])?;
    if handshake.len() != 4 + declared {
        return Err(TlsError::InvalidInput("ServerHello length mismatch"));
    }
    let body = &handshake[4..];
    let mut offset = 0;
    if read_u16_at(body, &mut offset)? != 0x0303 {
        return Err(TlsError::InvalidInput("invalid ServerHello legacy version"));
    }
    let random = take(body, &mut offset, 32)?;
    if random == HRR_RANDOM {
        return Err(TlsError::InvalidInput("HelloRetryRequest is unsupported"));
    }
    let session_len = usize::from(read_u8_at(body, &mut offset)?);
    if session_len > 32 {
        return Err(TlsError::InvalidInput(
            "invalid ServerHello session id length",
        ));
    }
    let session_id = take(body, &mut offset, session_len)?.to_vec();
    let cipher_suite = read_u16_at(body, &mut offset)?;
    match cipher_suite {
        TLS_AES_128_GCM_SHA256 | TLS_AES_256_GCM_SHA384 | TLS_CHACHA20_POLY1305_SHA256 => {}
        other => return Err(TlsError::UnsupportedCipherSuite(other)),
    }
    if read_u8_at(body, &mut offset)? != 0 {
        return Err(TlsError::InvalidInput("invalid ServerHello compression"));
    }
    let ext_len = usize::from(read_u16_at(body, &mut offset)?);
    let ext_end = offset
        .checked_add(ext_len)
        .ok_or(TlsError::InvalidInput("extension offset overflow"))?;
    if ext_end != body.len() {
        return Err(TlsError::InvalidInput("ServerHello extensions overflow"));
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut selected_tls13 = false;
    let mut key_share_group = None;
    let mut key_share = None;
    let mut x25519_key_share = None;
    while offset < ext_end {
        let ext = read_u16_at(body, &mut offset)?;
        let data_len = usize::from(read_u16_at(body, &mut offset)?);
        let data = take(body, &mut offset, data_len)?;
        if !seen.insert(ext) {
            return Err(TlsError::InvalidInput("duplicate ServerHello extension"));
        }
        if ext == EXT_SUPPORTED_VERSIONS {
            if data != [3, 4] {
                return Err(TlsError::InvalidInput("ServerHello did not select TLS 1.3"));
            }
            selected_tls13 = true;
        } else if ext == EXT_KEY_SHARE {
            let mut data_offset = 0;
            let group = read_u16_at(data, &mut data_offset)?;
            let key_len = usize::from(read_u16_at(data, &mut data_offset)?);
            let key = take(data, &mut data_offset, key_len)?;
            if data_offset != data.len() {
                return Err(TlsError::InvalidInput("trailing server key_share bytes"));
            }
            key_share_group = Some(group);
            key_share = Some(key.to_vec());
            if group == GROUP_X25519 && key.len() == 32 {
                x25519_key_share = Some(array32(key, "bad X25519 share")?);
            } else if group == GROUP_X25519_MLKEM768 && key.len() == 32 + 1088 {
                x25519_key_share = Some(array32(&key[..32], "bad hybrid X25519 share")?);
            }
        } else {
            return Err(TlsError::InvalidInput("unexpected ServerHello extension"));
        }
    }
    if !selected_tls13 {
        return Err(TlsError::InvalidInput(
            "missing ServerHello supported_versions",
        ));
    }

    Ok(ServerHelloData {
        handshake: handshake.to_vec(),
        session_id,
        cipher_suite,
        key_share_group: key_share_group
            .ok_or(TlsError::InvalidInput("missing server key_share"))?,
        key_share: key_share.ok_or(TlsError::InvalidInput("missing server key_share"))?,
        x25519_key_share: x25519_key_share
            .ok_or(TlsError::InvalidInput("missing server X25519 key_share"))?,
    })
}

pub(crate) fn parse_server_flight(
    input: &[u8],
    transcript_prefix: &[u8],
) -> Result<ParsedServerFlight, TlsError> {
    if input.len() > MAX_HANDSHAKE_FLIGHT || !complete_server_flight(input)? {
        return Err(TlsError::InvalidInput(
            "incomplete or oversized server flight",
        ));
    }
    let mut offset = 0;
    let mut transcript = transcript_prefix.to_vec();
    let mut encrypted_extensions = None;
    let mut negotiated_alpn = None;
    let mut certificate = None;
    let mut compressed_certificate = false;
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
                negotiated_alpn = parse_encrypted_extensions_alpn(body)?;
                encrypted_extensions = Some(message.to_vec());
                transcript.extend_from_slice(message);
            }
            HANDSHAKE_CERTIFICATE | 25 => {
                let decoded;
                let certificate_body = if typ == 25 {
                    decoded = decompress_certificate(body)?;
                    compressed_certificate = true;
                    decoded.as_slice()
                } else {
                    body
                };
                let (leaf, chain) = parse_certificate_body(certificate_body)?;
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
                transcript_before_finished = Some(transcript.clone());
                transcript.extend_from_slice(message);
                transcript_after_finished = Some(transcript.clone());
                finished = Some(body.to_vec());
            }
            _ => return Err(TlsError::InvalidInput("unexpected handshake message")),
        }
    }

    Ok(ParsedServerFlight {
        encrypted_extensions: encrypted_extensions
            .ok_or(TlsError::InvalidInput("missing EncryptedExtensions"))?,
        negotiated_alpn,
        certificate: certificate.ok_or(TlsError::InvalidInput("missing Certificate"))?,
        compressed_certificate,
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

fn parse_encrypted_extensions_alpn(body: &[u8]) -> Result<Option<Vec<u8>>, TlsError> {
    let mut offset = 0;
    let extensions_len = usize::from(read_u16_at(body, &mut offset)?);
    if extensions_len != body.len() - offset {
        return Err(TlsError::InvalidInput("bad EncryptedExtensions length"));
    }
    // The uint16 vector bounds both parsing work and duplicate-tracking storage.
    let mut seen = std::collections::BTreeSet::new();
    let mut selected = None;
    while offset < body.len() {
        let ext = read_u16_at(body, &mut offset)?;
        let len = usize::from(read_u16_at(body, &mut offset)?);
        let data = take(body, &mut offset, len)?;
        if !seen.insert(ext) {
            return Err(TlsError::InvalidInput(
                "duplicate EncryptedExtensions extension",
            ));
        }
        if ext == EXT_ALPN {
            let mut protocol_offset = 0;
            let list_len = usize::from(read_u16_at(data, &mut protocol_offset)?);
            if list_len != data.len() - protocol_offset {
                return Err(TlsError::InvalidInput("bad ALPN list length"));
            }
            let protocol_len = usize::from(read_u8_at(data, &mut protocol_offset)?);
            if protocol_len == 0 || protocol_len != data.len() - protocol_offset {
                return Err(TlsError::InvalidInput(
                    "ALPN must select exactly one nonempty protocol",
                ));
            }
            selected = Some(take(data, &mut protocol_offset, protocol_len)?.to_vec());
        }
    }
    Ok(selected)
}

fn decompress_certificate(body: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut offset = 0;
    if read_u16_at(body, &mut offset)? != 2 {
        return Err(TlsError::InvalidInput(
            "unsupported certificate compression",
        ));
    }
    let uncompressed_len = read_u24(take(body, &mut offset, 3)?)?;
    let compressed_len = read_u24(take(body, &mut offset, 3)?)?;
    if uncompressed_len == 0
        || uncompressed_len > MAX_CERTIFICATE
        || compressed_len == 0
        || compressed_len > MAX_CERTIFICATE
    {
        return Err(TlsError::LengthOutOfRange);
    }
    let compressed = take(body, &mut offset, compressed_len)?;
    if offset != body.len() {
        return Err(TlsError::InvalidInput(
            "compressed certificate length mismatch",
        ));
    }
    let mut output = vec![0; uncompressed_len];
    rustls::compress::BROTLI_DECOMPRESSOR
        .decompress(compressed, &mut output)
        .map_err(|_| TlsError::InvalidInput("invalid Brotli certificate"))?;
    Ok(output)
}

fn parse_certificate_body(body: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), TlsError> {
    if body.len() > MAX_CERTIFICATE {
        return Err(TlsError::LengthOutOfRange);
    }
    let mut offset = 0;
    if read_u8_at(body, &mut offset)? != 0 {
        return Err(TlsError::InvalidInput(
            "server certificate context must be empty",
        ));
    }
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
    cipher_suite: u16,
) -> Result<(), TlsError> {
    use rustls::internal::msgs::codec::Codec;

    let transcript_hash =
        transcript_hash_for_suite(cipher_suite, transcript_before_certificate_verify)?;
    let signature_input = certificate_verify_input(&transcript_hash);
    if matches!(scheme, 0x0904..=0x0906) {
        return verify_mldsa_certificate_verify(leaf_der, scheme, &signature_input, signature);
    }
    let mut encoded = scheme.to_be_bytes().to_vec();
    push_u16_len(signature.len(), &mut encoded)?;
    encoded.extend_from_slice(signature);
    let signed = rustls::DigitallySignedStruct::read_bytes(&encoded)
        .map_err(|_| TlsError::InvalidInput("bad CertificateVerify signature"))?;
    rustls::crypto::verify_tls13_signature(
        &signature_input,
        &rustls::pki_types::CertificateDer::from(leaf_der),
        &signed,
        &rustls::crypto::ring::default_provider().signature_verification_algorithms,
    )
    .map(|_| ())
    .map_err(|_| TlsError::AuthenticationFailed)
}

fn verify_mldsa_certificate_verify(
    leaf: &[u8],
    scheme: u16,
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    let (rest, cert) = X509Certificate::from_der(leaf)
        .map_err(|_| TlsError::InvalidInput("bad certificate DER"))?;
    let spki = cert.public_key();
    let oid = match scheme {
        0x0904 => "2.16.840.1.101.3.4.3.17",
        0x0905 => "2.16.840.1.101.3.4.3.18",
        0x0906 => "2.16.840.1.101.3.4.3.19",
        _ => return Err(TlsError::AuthenticationFailed),
    };
    if !rest.is_empty()
        || spki.algorithm.algorithm.to_id_string() != oid
        || spki.algorithm.parameters.is_some()
        || spki.subject_public_key.unused_bits != 0
    {
        return Err(TlsError::AuthenticationFailed);
    }
    let key = &spki.subject_public_key.data;
    let valid = match scheme {
        0x0904 => verify_mldsa::<ml_dsa::MlDsa44>(key, message, signature),
        0x0905 => verify_mldsa::<ml_dsa::MlDsa65>(key, message, signature),
        0x0906 => verify_mldsa::<ml_dsa::MlDsa87>(key, message, signature),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(TlsError::AuthenticationFailed)
    }
}

fn verify_mldsa<P: ml_dsa::MlDsaParams>(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = ml_dsa::EncodedVerifyingKey::<P>::try_from(key) else {
        return false;
    };
    let Ok(signature) = ml_dsa::EncodedSignature::<P>::try_from(signature) else {
        return false;
    };
    let Some(signature) = ml_dsa::Signature::<P>::decode(&signature) else {
        return false;
    };
    ml_dsa::VerifyingKey::<P>::decode(&key).verify_with_context(message, &[], &signature)
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

fn array32(input: &[u8], error: &'static str) -> Result<[u8; 32], TlsError> {
    input.try_into().map_err(|_| TlsError::InvalidInput(error))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypted_extensions_body(extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut encoded = Vec::new();
        for (id, data) in extensions {
            push_extension(*id, data, &mut encoded).unwrap();
        }
        let mut body = Vec::new();
        push_u16_len(encoded.len(), &mut body).unwrap();
        body.extend_from_slice(&encoded);
        body
    }

    #[test]
    fn encrypted_extensions_alpn_is_optional_bounded_and_opaque() {
        assert_eq!(parse_encrypted_extensions_alpn(&[0, 0]), Ok(None));
        let unknown = encrypted_extensions_body(&[(0x39, &[4, 1, 64])]);
        assert_eq!(parse_encrypted_extensions_alpn(&unknown), Ok(None));
        for protocol in [b"h2".to_vec(), b"http/1.1".to_vec(), vec![0xff; 255]] {
            let mut data = Vec::new();
            push_u16_len(protocol.len() + 1, &mut data).unwrap();
            data.push(u8::try_from(protocol.len()).unwrap());
            data.extend_from_slice(&protocol);
            let body = encrypted_extensions_body(&[(0, &[]), (EXT_ALPN, &data), (0x39, &[1])]);
            assert_eq!(parse_encrypted_extensions_alpn(&body), Ok(Some(protocol)));
        }
        assert!(parse_encrypted_extensions_alpn(&vec![0; usize::from(u16::MAX) + 3]).is_err());
    }

    #[test]
    fn encrypted_extensions_alpn_rejects_empty_multiple_duplicate_and_truncated_values() {
        let alpn = selected_alpn_extension("h2").unwrap();
        let valid = encrypted_extensions_body(&[(EXT_ALPN, &alpn)]);
        for len in 0..valid.len() {
            assert!(parse_encrypted_extensions_alpn(&valid[..len]).is_err());
        }
        let mut trailing = valid;
        trailing.push(0);
        assert!(parse_encrypted_extensions_alpn(&trailing).is_err());
        for malformed in [
            vec![],
            vec![0],
            vec![0, 0],
            vec![0, 1, 0],
            vec![0, 2, 2, b'h', b'2'],
            vec![0, 3, 2, b'h'],
            vec![0, 2, 2, b'h'],
            vec![0, 6, 2, b'h', b'2', 2, b'h', b'3'],
            vec![0, 4, 2, b'h', b'2', 0],
        ] {
            let body = encrypted_extensions_body(&[(EXT_ALPN, &malformed)]);
            assert!(
                parse_encrypted_extensions_alpn(&body).is_err(),
                "{malformed:?}"
            );
        }
        // Correct outer vector length must not hide a truncated extension header or value.
        for encoded in [
            vec![0],
            vec![0, 16],
            vec![0, 16, 0],
            vec![0, 16, 0, 5, 0, 3],
        ] {
            let mut body = Vec::new();
            push_u16_len(encoded.len(), &mut body).unwrap();
            body.extend_from_slice(&encoded);
            assert!(parse_encrypted_extensions_alpn(&body).is_err());
        }
        for extensions in [
            vec![(EXT_ALPN, alpn.as_slice()), (EXT_ALPN, alpn.as_slice())],
            vec![(0x39, &[][..]), (0x39, &[][..])],
        ] {
            assert_eq!(
                parse_encrypted_extensions_alpn(&encrypted_extensions_body(&extensions)),
                Err(TlsError::InvalidInput(
                    "duplicate EncryptedExtensions extension"
                ))
            );
        }
    }

    fn server_hello() -> Vec<u8> {
        first_record_payload(
            &build_server_hello(
                &[7; 32],
                TLS_AES_128_GCM_SHA256,
                &[8; 32],
                GROUP_X25519,
                &[9; 32],
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn server_hello_rejects_invalid_negotiation_and_duplicate_extensions() {
        let original = server_hello();
        assert!(parse_server_hello_handshake(&original).is_ok());
        let record = handshake_record(&original).unwrap();
        assert!(parse_server_hello_record(&record).is_ok());
        for length in 0..record.len() {
            assert!(parse_server_hello_record(&record[..length]).is_err());
        }
        let mut trailing = record.clone();
        trailing.push(0);
        assert!(parse_server_hello_record(&trailing).is_err());
        let mut wrong_version = record;
        wrong_version[2] = 1;
        assert!(parse_server_hello_record(&wrong_version).is_err());
        for (index, value) in [(4, 2), (73, 1), (38, 33)] {
            let mut bad = original.clone();
            bad[index] = value;
            assert!(parse_server_hello_handshake(&bad).is_err());
        }
        for len in 0..original.len() {
            assert!(parse_server_hello_handshake(&original[..len]).is_err());
        }
        let mut missing_version = original.clone();
        let end = missing_version.len();
        missing_version[end - 6] = 1;
        assert!(parse_server_hello_handshake(&missing_version).is_err());
        let mut wrong_version = original.clone();
        wrong_version[end - 1] = 3;
        assert!(parse_server_hello_handshake(&wrong_version).is_err());
        let mut duplicate_body = original[4..].to_vec();
        duplicate_body.extend_from_slice(&original[end - 6..]);
        let extension_len = u16::from_be_bytes([duplicate_body[70], duplicate_body[71]]) + 6;
        duplicate_body[70..72].copy_from_slice(&extension_len.to_be_bytes());
        let duplicate = handshake_message(2, &duplicate_body).unwrap();
        assert_eq!(
            parse_server_hello_handshake(&duplicate),
            Err(TlsError::InvalidInput("duplicate ServerHello extension"))
        );
        let mut hrr = original.clone();
        hrr[6..38].copy_from_slice(&hex(
            "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c",
        ));
        assert_eq!(
            parse_server_hello_handshake(&hrr),
            Err(TlsError::InvalidInput("HelloRetryRequest is unsupported"))
        );
        let offered = OfferedParameters {
            session_id: vec![7; 32],
            ciphers: vec![TLS_AES_128_GCM_SHA256],
            key_shares: vec![GROUP_X25519],
            signatures: vec![0x0403],
            alpn: Vec::new(),
            tls13: true,
            brotli: true,
        };
        let valid = parse_server_hello_handshake(&original).unwrap();
        offered.validate_server_hello(&valid).unwrap();
        let mut wrong = valid.clone();
        wrong.session_id[0] ^= 1;
        assert!(offered.validate_server_hello(&wrong).is_err());
        wrong = valid.clone();
        wrong.cipher_suite = TLS_AES_256_GCM_SHA384;
        assert!(offered.validate_server_hello(&wrong).is_err());
        wrong = valid;
        wrong.key_share_group = GROUP_X25519_MLKEM768;
        assert!(offered.validate_server_hello(&wrong).is_err());
    }

    fn compressed_body(body: &[u8]) -> Vec<u8> {
        let compressed = rustls::compress::BROTLI_COMPRESSOR
            .compress(
                body.to_vec(),
                rustls::compress::CompressionLevel::Interactive,
            )
            .unwrap();
        let mut out = vec![0, 2];
        push_u24_len(body.len(), &mut out).unwrap();
        push_u24_len(compressed.len(), &mut out).unwrap();
        out.extend_from_slice(&compressed);
        out
    }

    #[test]
    fn compressed_certificate_is_bounded_and_uses_wire_transcript() {
        let certificate = certificate_message(b"leaf DER", &[]).unwrap();
        let body = compressed_body(&certificate[4..]);
        assert_eq!(decompress_certificate(&body).unwrap(), certificate[4..]);
        for len in 0..body.len() {
            assert!(decompress_certificate(&body[..len]).is_err());
        }
        for length in [0, 1, MAX_CERTIFICATE + 1, 0xff_ffff] {
            let mut bad = body.clone();
            let mut encoded = Vec::new();
            push_u24_len(length, &mut encoded).unwrap();
            bad[2..5].copy_from_slice(&encoded);
            assert!(decompress_certificate(&bad).is_err());
        }
        let mut bad = body.clone();
        bad[1] = 1;
        assert!(decompress_certificate(&bad).is_err());
        let mut bad = body.clone();
        bad.extend_from_slice(&[0]);
        assert!(decompress_certificate(&bad).is_err());
        let mut flight = handshake_message(8, &[0, 0]).unwrap();
        let compressed = handshake_message(25, &body).unwrap();
        flight.extend_from_slice(&compressed);
        let before_cv = flight.clone();
        flight.extend_from_slice(&certificate_verify_message(0x0403, &[1]).unwrap());
        flight.extend_from_slice(&handshake_message(20, &[2; 32]).unwrap());
        let parsed = parse_server_flight(&flight, &[]).unwrap();
        assert!(parsed.compressed_certificate);
        assert_eq!(parsed.certificate, b"leaf DER");
        assert_eq!(parsed.transcript_before_certificate_verify, before_cv);
        assert_eq!(parsed.transcript_after_finished, flight);
        let offered = OfferedParameters {
            session_id: vec![],
            ciphers: vec![],
            key_shares: vec![],
            signatures: vec![0x0403],
            alpn: Vec::new(),
            tls13: true,
            brotli: false,
        };
        assert!(offered.validate_flight(&parsed).is_err());
        flight.extend_from_slice(&handshake_message(20, &[3; 32]).unwrap());
        assert!(parse_server_flight(&flight, &[]).is_err());
        assert!(parse_certificate_body(&[1, 0, 0, 0, 0]).is_err());
        assert!(parse_certificate_body(&vec![0; MAX_CERTIFICATE + 1]).is_err());
    }

    #[test]
    fn certificate_verify_classical_algorithms_reject_tampering_and_tls12() {
        use ring::{
            rand::SystemRandom,
            signature::{EcdsaKeyPair, Ed25519KeyPair},
        };
        for (scheme, algorithm, signing) in [
            (
                0x0403,
                &rcgen::PKCS_ECDSA_P256_SHA256,
                &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            ),
            (
                0x0503,
                &rcgen::PKCS_ECDSA_P384_SHA384,
                &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            ),
        ] {
            let key = rcgen::KeyPair::generate_for(algorithm).unwrap();
            let cert = rcgen::CertificateParams::new(vec!["test.example".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            let rng = SystemRandom::new();
            let pair = EcdsaKeyPair::from_pkcs8(signing, &key.serialize_der(), &rng).unwrap();
            let input =
                certificate_verify_input(&crate::keyschedule::transcript_hash(b"transcript"));
            let signature = pair.sign(&rng, &input).unwrap();
            assert_signature(cert.der(), scheme, b"transcript", signature.as_ref());
            assert!(verify_certificate_verify(
                cert.der(),
                0x0401,
                signature.as_ref(),
                b"transcript",
                TLS_AES_128_GCM_SHA256
            )
            .is_err());
        }
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["test.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(&key.serialize_der()).unwrap();
        let signature = pair.sign(&certificate_verify_input(
            &crate::keyschedule::transcript_hash(b"transcript"),
        ));
        assert_signature(cert.der(), 0x0807, b"transcript", signature.as_ref());
    }

    #[test]
    fn rsa_pss_certificate_verify_matches_openssl_reference() {
        // OpenSSL dgst with RSA-PSS, MGF1 digest and digest-length salt, over the TLS
        // CV input for b"rsa reference transcript". Public key from ring 0.17.14's
        // rsa_test_private_key_2048.p8 test fixture; no private key is stored here.
        let spki = hex("30820122300d06092a864886f70d01010105000382010f003082010a0282010100c8a78500a5a250db8ed36c85b8dcf83c4be1953114faaac7616e0ea24922fa6b7ab01f85582c815cc3bdeb5ed46762bc536accaa8b72705b00cef316b2ec508fb9697241b9e34238419cccf7339eeb8b062147af4f5932f613d9bc0ae70bf6d56d4432e83e13767587531bfa9dd56531741244be75e8bc9226b9fa44b4b8a101358d7e8bb75d0c724a4f11ece77776263faefe79612eb1d71646e77e8982866be1400eafc3580d3139b41aaa7380187372f22e35bd55b288496165c881ed154d5811245c52d56cc09d4916d4f2a50bcf5ae0a2637f4cfa6bf9daafc113dba8383b6dd7da6dd8db22d8510a8d3115983308909a1a0332517aa55e896e154249b30203010001");
        let cert = certificate_with_spki(&spki);
        for (scheme, signature) in [
            (0x0804, "07330b71009394ecd053eeaf6810fa4cfca4a3739c1f0441a5fbf59be34f7f607bd338b18acfa0a39b2e4c6c1689b3561afe5b6b9cea4adbbbefc85086f4976ab1cb212a4408d7b8d618accb840083e2e15e4d552dd8dd118945d619d3b988efe3bf73041046ff23463ff3565482daef8f0f614be2d54b6a6c13f318c2afaceee12b9be0bcf27af1dce49c6a587df9ed20fec95b30cf243974467403dff6341d824fa390861b7f3f98f7b9da6d5da84cdddbc3121745248562140319f7d907908ec108568969ed549d140f979ee8e8b3f9fa3e5889ad116799033bff417483603502ecbbc1681f72b20e2ca89bb79e5ef6220ddf8d8a53ef00f444bc73c60f1a"),
            (0x0805, "24339234fbc5dccdc94401284b3701c9a25d20435991729b700d2bdafe0ebb8ca2686800bba5c387d537cbbcb4e23857ae97e07e232810ae8babb7fe6d199535372967b9a975a618127451dd966186b33b799e5b8927eb482d71859fa03aeea129f3e20b67c7678b48161ce153fdd2ea033a923f5c7e63f29f057c16e2cc17be0bfbb89f79be54a5a717a73014efcf501483aa0efbccdd18a17ab35ddbb92842f22673b89482c15ea1678d7dc9b25ce05a95f716e14f31185b17d63795208e0d26647c469c711061716dfcca66e2970ca40d684fa6da10d867da4891f171eb2e69f2655aab208ae32c3084220f9d10ef33e8b904a78f0ce89e8e335341d7758d"),
            (0x0806, "17625ab79d901004d2273e16cada83f874903dc09d258643498fd3cd95b6748c2de5c69f3ce935ac30f8af29b27a4e9a5ce656ccf580fe752ffdf55ad012c7e2a41d889776c6f1dcbc2fd41a31bdbed5a002e54ac09f628f0c750209230300c5a2d88089cab3b749f3cad089b664311d923e91b947ea0dedc171ca6aa7e7cf3c20ac6b72f7809414d6bb8a49dec21899cf395f3ebf53dad0ed885bb3d31794f6ab670bd819e4754c7b74edf853aea2421c0b21dc517c6a2e9a12d73057a7437431a012c6b3e13ea0555631aa7f7605e3ba7b11c778412c6d17f029872f7a9d4f8188ac6b9ce0209adbbb7036784783c9936f466c33a8ed5af104febf739a1b53"),
        ] {
            assert_signature(&cert, scheme, b"rsa reference transcript", &hex(signature));
        }
    }

    fn assert_signature(cert: &[u8], scheme: u16, transcript: &[u8], signature: &[u8]) {
        verify_certificate_verify(cert, scheme, signature, transcript, TLS_AES_128_GCM_SHA256)
            .unwrap();
        let mut bad = signature.to_vec();
        bad[0] ^= 1;
        assert!(
            verify_certificate_verify(cert, scheme, &bad, transcript, TLS_AES_128_GCM_SHA256)
                .is_err()
        );
        assert!(verify_certificate_verify(
            cert,
            scheme,
            signature,
            b"changed transcript",
            TLS_AES_128_GCM_SHA256
        )
        .is_err());
    }

    #[test]
    fn mldsa_tls_schemes_verify_and_bind_certificate_algorithm() {
        mldsa_case::<ml_dsa::MlDsa44>(0x0904, 17);
        mldsa_case::<ml_dsa::MlDsa65>(0x0905, 18);
        mldsa_case::<ml_dsa::MlDsa87>(0x0906, 19);
    }

    fn mldsa_case<P: ml_dsa::MlDsaParams>(scheme: u16, oid: u8) {
        use ml_dsa::signature::{Keypair, Signer};
        let key = ml_dsa::SigningKey::<P>::from_seed(&[42; 32].into());
        let public = key.verifying_key().encode();
        let mut algorithm = hex("300b06096086480165030403");
        algorithm.push(oid);
        let mut bits = vec![0];
        bits.extend_from_slice(&public);
        let spki = der(0x30, &[algorithm, der(3, &bits)].concat());
        let cert = certificate_with_spki(&spki);
        let input = certificate_verify_input(&crate::keyschedule::transcript_hash(b"transcript"));
        let signature: ml_dsa::Signature<P> = key.sign(&input);
        let signature = signature.encode();
        assert_signature(&cert, scheme, b"transcript", &signature);
        assert!(verify_certificate_verify(
            &cert,
            0x0403,
            &signature,
            b"transcript",
            TLS_AES_128_GCM_SHA256
        )
        .is_err());
        assert!(!verify_mldsa::<P>(
            &public[..public.len() - 1],
            &input,
            &signature
        ));
        assert!(!verify_mldsa::<P>(
            &public,
            &input,
            &signature[..signature.len() - 1]
        ));
    }

    fn certificate_with_spki(spki: &[u8]) -> Vec<u8> {
        // Certificate-chain validation is a separate callback; only its SPKI is used here.
        let generated = rcgen::generate_simple_self_signed(["test.example".into()]).unwrap();
        let raw = generated.cert.der().as_ref();
        let (_, parsed) = X509Certificate::from_der(raw).unwrap();
        let tbs = parsed.tbs_certificate.as_ref();
        let old_spki = parsed.public_key().raw;
        let position = tbs
            .windows(old_spki.len())
            .position(|bytes| bytes == old_spki)
            .unwrap();
        let new_tbs = der(
            0x30,
            &[
                &tbs[der_header_len(tbs)..position],
                spki,
                &tbs[position + old_spki.len()..],
            ]
            .concat(),
        );
        der(
            0x30,
            &[new_tbs.as_slice(), &raw[der_header_len(raw) + tbs.len()..]].concat(),
        )
    }

    fn der_header_len(input: &[u8]) -> usize {
        if input[1] < 128 {
            2
        } else {
            2 + usize::from(input[1] & 0x7f)
        }
    }

    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 128 {
            out.push(u8::try_from(body.len()).unwrap());
        } else if body.len() < 256 {
            out.extend_from_slice(&[0x81, u8::try_from(body.len()).unwrap()]);
        } else {
            out.push(0x82);
            out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }

    fn hex(input: &str) -> Vec<u8> {
        (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
            .collect()
    }
}
