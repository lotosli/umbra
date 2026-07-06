//! QUIC-facing TLS 1.3 handshake state.
//!
//! QUIC carries TLS handshake messages directly in CRYPTO frames instead of
//! wrapping them in TLS records. This module keeps the same ClientHello,
//! transcript, certificate verification, and key schedule logic as the TCP TLS
//! state machines, but exposes raw handshake bytes and traffic secrets for the
//! QUIC packet layer.

use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;
use umbra_crypto::{
    secret::{Secret, SecretBytes},
    x25519,
};

use crate::{
    clienthello::ClientHelloParams,
    clienthello::{build_client_hello_handshake, EXT_QUIC_TRANSPORT_PARAMETERS},
    handshake::{
        build_server_hello, certificate_message, certificate_verify_message,
        client_negotiated_secret, encrypted_extensions_for_profile, handshake_message,
        parse_server_flight, parse_server_hello_handshake, selected_alpn_extension,
        verify_certificate_verify, CertVerify, PeerKind, SIGNATURE_ECDSA_SECP256R1_SHA256,
    },
    keyschedule::{
        derive_tls13_secrets_for_suite, finished_verify_data_for_suite, transcript_hash_for_suite,
        SuiteSecrets,
    },
    parse::parse_client_hello,
    server::{
        parse_client_finished, server_negotiated_key_share, sign_certificate_verify, DestProfile,
        ForgedCert,
    },
    TlsError,
};

const HANDSHAKE_FINISHED: u8 = 0x14;
const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 0x08;

/// QUIC traffic secrets for one encryption level.
pub struct QuicTrafficSecrets {
    /// Negotiated TLS 1.3 cipher suite.
    pub cipher_suite: u16,
    /// Traffic secret used for client-to-server packets.
    pub client: Vec<u8>,
    /// Traffic secret used for server-to-client packets.
    pub server: Vec<u8>,
}

/// Output from completing the client side of a QUIC TLS handshake.
pub struct QuicClientFinished {
    /// Raw TLS Finished handshake message to send in the QUIC Handshake packet space.
    pub finished: Vec<u8>,
    /// Application traffic secrets to install as QUIC 1-RTT packet keys.
    pub application_secrets: QuicTrafficSecrets,
    /// Classification returned by the certificate verifier.
    pub peer_kind: PeerKind,
    /// Raw QUIC transport parameters advertised by the server.
    pub peer_transport_parameters: Vec<u8>,
}

/// QUIC-facing TLS 1.3 client state.
pub struct QuicTlsClient {
    cipher_suite: u16,
    client_private: [u8; 32],
    mlkem_decapsulation_key: Option<SecretBytes>,
    client_hello: Vec<u8>,
    shared_secret: Option<SecretBytes>,
    handshake_transcript: Vec<u8>,
    state: QuicClientState,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum QuicClientState {
    ExpectServerHello,
    ExpectServerFlight,
    Connected,
}

impl QuicTlsClient {
    /// Start a QUIC TLS client and return the raw ClientHello handshake bytes.
    pub fn start(params: &ClientHelloParams) -> Result<(Self, Vec<u8>), TlsError> {
        if !params.session_id.is_empty() {
            return Err(TlsError::InvalidInput(
                "QUIC ClientHello legacy_session_id must be empty",
            ));
        }
        let client_private = params.x25519_priv;
        let mlkem_decapsulation_key = params
            .mlkem
            .decapsulation_key
            .as_ref()
            .map(|secret| SecretBytes::new(secret.expose_secret().to_vec()));
        let client_hello = build_client_hello_handshake(params)?;
        Ok((
            Self {
                cipher_suite: crate::clienthello::TLS_AES_128_GCM_SHA256,
                client_private,
                mlkem_decapsulation_key,
                client_hello: client_hello.clone(),
                shared_secret: None,
                handshake_transcript: Vec::new(),
                state: QuicClientState::ExpectServerHello,
            },
            client_hello,
        ))
    }

    /// Read raw ServerHello bytes and return QUIC handshake traffic secrets.
    pub fn read_server_hello(
        &mut self,
        server_hello: &[u8],
    ) -> Result<QuicTrafficSecrets, TlsError> {
        if self.state != QuicClientState::ExpectServerHello {
            return Err(TlsError::InvalidInput("unexpected QUIC ServerHello"));
        }
        let parsed = parse_server_hello_handshake(server_hello)?;
        self.cipher_suite = parsed.cipher_suite;
        let client_secret = Secret::new(self.client_private);
        let classic_shared = x25519::agree(&client_secret, &parsed.x25519_key_share)
            .map_err(|_| TlsError::InvalidInput("bad server key_share"))?;
        let shared = client_negotiated_secret(
            &classic_shared,
            parsed.key_share_group,
            &parsed.key_share,
            self.mlkem_decapsulation_key.as_ref(),
        )?;

        let mut transcript = self.client_hello.clone();
        transcript.extend_from_slice(&parsed.handshake);
        let secrets = derive_tls13_secrets_for_suite(
            parsed.cipher_suite,
            shared.expose_secret(),
            &transcript,
            &[],
        )?;
        self.shared_secret = Some(shared);
        self.handshake_transcript = transcript;
        self.state = QuicClientState::ExpectServerFlight;
        Ok(handshake_secrets(parsed.cipher_suite, &secrets))
    }

    /// Read the server's raw handshake flight and produce a raw client Finished message.
    pub fn read_server_flight(
        &mut self,
        server_flight: &[u8],
        verify: &dyn CertVerify,
    ) -> Result<QuicClientFinished, TlsError> {
        if self.state != QuicClientState::ExpectServerFlight {
            return Err(TlsError::InvalidInput("unexpected QUIC server flight"));
        }
        let flight = parse_server_flight(server_flight, &self.handshake_transcript)?;
        verify_certificate_verify(
            &flight.certificate,
            flight.certificate_verify_scheme,
            &flight.certificate_verify_signature,
            &flight.transcript_before_certificate_verify,
            self.cipher_suite,
        )?;
        let peer_kind = verify.verify(&flight.certificate, &flight.certificate_chain);
        if matches!(peer_kind, PeerKind::Invalid) {
            return Err(TlsError::PeerRejected);
        }
        let shared = self
            .shared_secret
            .as_ref()
            .ok_or(TlsError::InvalidInput("missing QUIC shared secret"))?;
        let handshake_secrets = derive_tls13_secrets_for_suite(
            self.cipher_suite,
            shared.expose_secret(),
            &self.handshake_transcript,
            &[],
        )?;
        let expected = finished_verify_data_for_suite(
            self.cipher_suite,
            &handshake_secrets.server_handshake_traffic_secret,
            &transcript_hash_for_suite(self.cipher_suite, &flight.transcript_before_finished)?,
        )?;
        if !bool::from(expected.as_slice().ct_eq(flight.finished.as_slice())) {
            return Err(TlsError::AuthenticationFailed);
        }

        let client_verify = finished_verify_data_for_suite(
            self.cipher_suite,
            &handshake_secrets.client_handshake_traffic_secret,
            &transcript_hash_for_suite(self.cipher_suite, &flight.transcript_after_finished)?,
        )?;
        let finished = handshake_message(HANDSHAKE_FINISHED, &client_verify)?;
        let mut transcript_after_client_finished = flight.transcript_after_finished;
        transcript_after_client_finished.extend_from_slice(&finished);
        let app_secrets = derive_tls13_secrets_for_suite(
            self.cipher_suite,
            shared.expose_secret(),
            &self.handshake_transcript,
            &transcript_after_client_finished,
        )?;
        self.state = QuicClientState::Connected;
        Ok(QuicClientFinished {
            finished,
            application_secrets: application_secrets(self.cipher_suite, &app_secrets),
            peer_kind,
            peer_transport_parameters: encrypted_extensions_quic_transport_parameters(
                &flight.encrypted_extensions,
            )?,
        })
    }
}

/// Output from accepting a QUIC ClientHello on the server side.
pub struct QuicServerAccepted {
    /// Server state waiting for the client Finished message.
    pub server: QuicTlsServer,
    /// Raw ServerHello handshake bytes to send in Initial packet space.
    pub server_hello: Vec<u8>,
    /// Raw EncryptedExtensions, Certificate, CertificateVerify, and Finished bytes.
    pub server_flight: Vec<u8>,
    /// Handshake traffic secrets to install as QUIC Handshake packet keys.
    pub handshake_secrets: QuicTrafficSecrets,
    /// Raw QUIC transport parameters advertised by the client.
    pub peer_transport_parameters: Vec<u8>,
}

/// QUIC-facing TLS 1.3 server state.
pub struct QuicTlsServer {
    cipher_suite: u16,
    shared_secret: SecretBytes,
    handshake_transcript: Vec<u8>,
    transcript_before_client_finished: Vec<u8>,
    state: QuicServerState,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum QuicServerState {
    ExpectClientFinished,
    Connected,
}

impl QuicTlsServer {
    /// Accept raw QUIC ClientHello bytes and build raw server handshake flights.
    pub fn accept(
        client_hello_raw: &[u8],
        leaf: ForgedCert,
        profile: &DestProfile,
    ) -> Result<QuicServerAccepted, TlsError> {
        Self::accept_with_transport_parameters(client_hello_raw, leaf, profile, &[])
    }

    /// Accept raw QUIC ClientHello bytes and include raw QUIC transport parameters.
    pub fn accept_with_transport_parameters(
        client_hello_raw: &[u8],
        leaf: ForgedCert,
        profile: &DestProfile,
        transport_parameters: &[u8],
    ) -> Result<QuicServerAccepted, TlsError> {
        let ForgedCert {
            leaf_der,
            chain_der,
            certificate_verify_key_der,
        } = leaf;
        let client_hello = parse_client_hello(client_hello_raw)?;
        if !client_hello.session_id.is_empty() {
            return Err(TlsError::InvalidInput(
                "QUIC ClientHello legacy_session_id must be empty",
            ));
        }
        let client_public = client_hello
            .x25519_key_share
            .ok_or(TlsError::InvalidInput("missing client X25519 key_share"))?;
        let server_keypair = x25519::generate_keypair();
        let classic_shared = x25519::agree(&server_keypair.private, &client_public)
            .map_err(|_| TlsError::InvalidInput("bad client key_share"))?;
        let negotiated = server_negotiated_key_share(
            &client_hello,
            profile.key_share_group,
            server_keypair.public.as_bytes(),
            &classic_shared,
        )?;
        let mut server_random = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut server_random)
            .map_err(|_| TlsError::InvalidInput("server random generation failed"))?;
        let server_hello_record = build_server_hello(
            &[],
            profile.cipher_suite,
            &server_random,
            negotiated.group,
            &negotiated.key_exchange,
        )?;
        let server_hello = crate::handshake::first_record_payload(&server_hello_record)?;
        let mut handshake_transcript = client_hello_raw.to_vec();
        handshake_transcript.extend_from_slice(&server_hello);
        let hs_secrets = derive_tls13_secrets_for_suite(
            profile.cipher_suite,
            negotiated.shared_secret.expose_secret(),
            &handshake_transcript,
            &[],
        )?;

        let encrypted_extensions = if transport_parameters.is_empty() {
            encrypted_extensions_for_profile(
                profile.alpn.as_deref(),
                &profile.encrypted_extensions,
            )?
        } else {
            encrypted_extensions_with_quic_transport_parameters(profile, transport_parameters)?
        };
        let certificate = certificate_message(&leaf_der, &chain_der)?;
        let mut transcript_before_certificate_verify = handshake_transcript.clone();
        transcript_before_certificate_verify.extend_from_slice(&encrypted_extensions);
        transcript_before_certificate_verify.extend_from_slice(&certificate);
        let certificate_verify_signature = sign_certificate_verify(
            &certificate_verify_key_der,
            &transcript_hash_for_suite(
                profile.cipher_suite,
                &transcript_before_certificate_verify,
            )?,
        )?;
        let certificate_verify = certificate_verify_message(
            SIGNATURE_ECDSA_SECP256R1_SHA256,
            &certificate_verify_signature,
        )?;
        let mut transcript_before_server_finished = transcript_before_certificate_verify;
        transcript_before_server_finished.extend_from_slice(&certificate_verify);
        let verify_data = finished_verify_data_for_suite(
            profile.cipher_suite,
            &hs_secrets.server_handshake_traffic_secret,
            &transcript_hash_for_suite(profile.cipher_suite, &transcript_before_server_finished)?,
        )?;
        let server_finished = handshake_message(HANDSHAKE_FINISHED, &verify_data)?;

        let mut server_flight = Vec::new();
        server_flight.extend_from_slice(&encrypted_extensions);
        server_flight.extend_from_slice(&certificate);
        server_flight.extend_from_slice(&certificate_verify);
        server_flight.extend_from_slice(&server_finished);

        let mut transcript_before_client_finished = transcript_before_server_finished;
        transcript_before_client_finished.extend_from_slice(&server_finished);
        Ok(QuicServerAccepted {
            server: QuicTlsServer {
                cipher_suite: profile.cipher_suite,
                shared_secret: negotiated.shared_secret,
                handshake_transcript,
                transcript_before_client_finished,
                state: QuicServerState::ExpectClientFinished,
            },
            server_hello,
            server_flight,
            handshake_secrets: handshake_secrets(profile.cipher_suite, &hs_secrets),
            peer_transport_parameters: encode_quic_transport_parameters(
                &client_hello.quic_transport_parameters,
            )?,
        })
    }

    /// Read raw client Finished bytes and return QUIC 1-RTT application traffic secrets.
    pub fn read_client_finished(
        &mut self,
        client_finished: &[u8],
    ) -> Result<QuicTrafficSecrets, TlsError> {
        if self.state != QuicServerState::ExpectClientFinished {
            return Err(TlsError::InvalidInput(
                "server QUIC handshake already complete",
            ));
        }
        let verify_data = parse_client_finished(client_finished)?;
        let handshake_secrets = derive_tls13_secrets_for_suite(
            self.cipher_suite,
            self.shared_secret.expose_secret(),
            &self.handshake_transcript,
            &[],
        )?;
        let expected = finished_verify_data_for_suite(
            self.cipher_suite,
            &handshake_secrets.client_handshake_traffic_secret,
            &transcript_hash_for_suite(self.cipher_suite, &self.transcript_before_client_finished)?,
        )?;
        if !bool::from(expected.as_slice().ct_eq(verify_data.as_slice())) {
            return Err(TlsError::AuthenticationFailed);
        }
        let mut transcript_after_client_finished = self.transcript_before_client_finished.clone();
        transcript_after_client_finished.extend_from_slice(client_finished);
        let app_secrets = derive_tls13_secrets_for_suite(
            self.cipher_suite,
            self.shared_secret.expose_secret(),
            &self.handshake_transcript,
            &transcript_after_client_finished,
        )?;
        self.state = QuicServerState::Connected;
        Ok(application_secrets(self.cipher_suite, &app_secrets))
    }
}

fn handshake_secrets(cipher_suite: u16, secrets: &SuiteSecrets) -> QuicTrafficSecrets {
    QuicTrafficSecrets {
        cipher_suite,
        client: secrets.client_handshake_traffic_secret.clone(),
        server: secrets.server_handshake_traffic_secret.clone(),
    }
}

fn application_secrets(cipher_suite: u16, secrets: &SuiteSecrets) -> QuicTrafficSecrets {
    QuicTrafficSecrets {
        cipher_suite,
        client: secrets.client_application_traffic_secret.clone(),
        server: secrets.server_application_traffic_secret.clone(),
    }
}

fn encrypted_extensions_with_quic_transport_parameters(
    profile: &DestProfile,
    transport_parameters: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let mut extensions = Vec::new();
    let mut wrote_alpn = false;
    for ext in &profile.encrypted_extensions {
        if *ext == EXT_QUIC_TRANSPORT_PARAMETERS {
            push_extension(*ext, transport_parameters, &mut extensions)?;
        } else if *ext == 0x0010 {
            if let Some(alpn) = &profile.alpn {
                push_extension(*ext, &selected_alpn_extension(alpn)?, &mut extensions)?;
                wrote_alpn = true;
            }
        } else {
            push_extension(*ext, &[], &mut extensions)?;
        }
    }
    if !profile
        .encrypted_extensions
        .contains(&EXT_QUIC_TRANSPORT_PARAMETERS)
    {
        push_extension(
            EXT_QUIC_TRANSPORT_PARAMETERS,
            transport_parameters,
            &mut extensions,
        )?;
    }
    if !wrote_alpn {
        if let Some(alpn) = &profile.alpn {
            push_extension(0x0010, &selected_alpn_extension(alpn)?, &mut extensions)?;
        }
    }

    let mut body = Vec::new();
    push_u16_len(extensions.len(), &mut body)?;
    body.extend_from_slice(&extensions);
    handshake_message(HANDSHAKE_ENCRYPTED_EXTENSIONS, &body)
}

fn push_extension(ext: u16, data: &[u8], out: &mut Vec<u8>) -> Result<(), TlsError> {
    out.extend_from_slice(&ext.to_be_bytes());
    push_u16_len(data.len(), out)?;
    out.extend_from_slice(data);
    Ok(())
}

fn encrypted_extensions_quic_transport_parameters(
    encrypted_extensions: &[u8],
) -> Result<Vec<u8>, TlsError> {
    if encrypted_extensions.len() < 6 || encrypted_extensions[0] != HANDSHAKE_ENCRYPTED_EXTENSIONS {
        return Err(TlsError::InvalidInput("not EncryptedExtensions"));
    }
    let declared = read_u24(&encrypted_extensions[1..4])?;
    if encrypted_extensions.len() < 4 + declared {
        return Err(TlsError::InvalidInput("truncated EncryptedExtensions"));
    }
    let body = &encrypted_extensions[4..4 + declared];
    let mut offset = 0_usize;
    let extensions_len = usize::from(read_u16_at(body, &mut offset)?);
    let extensions_end = offset
        .checked_add(extensions_len)
        .ok_or(TlsError::InvalidInput(
            "EncryptedExtensions length overflow",
        ))?;
    if extensions_end > body.len() {
        return Err(TlsError::InvalidInput("EncryptedExtensions overflow"));
    }
    while offset < extensions_end {
        let ext = read_u16_at(body, &mut offset)?;
        let len = usize::from(read_u16_at(body, &mut offset)?);
        let value = take(body, &mut offset, len)?;
        if ext == EXT_QUIC_TRANSPORT_PARAMETERS {
            return Ok(value.to_vec());
        }
    }
    Ok(Vec::new())
}

fn encode_quic_transport_parameters(
    parameters: &[crate::parse::QuicTransportParameter],
) -> Result<Vec<u8>, TlsError> {
    let mut out = Vec::new();
    for parameter in parameters {
        write_quic_varint(parameter.id, &mut out)?;
        write_quic_varint(
            u64::try_from(parameter.value.len()).map_err(|_| TlsError::LengthOutOfRange)?,
            &mut out,
        )?;
        out.extend_from_slice(&parameter.value);
    }
    Ok(out)
}

fn push_u16_len(len: usize, out: &mut Vec<u8>) -> Result<(), TlsError> {
    let len = u16::try_from(len).map_err(|_| TlsError::LengthOutOfRange)?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
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

fn write_quic_varint(value: u64, out: &mut Vec<u8>) -> Result<(), TlsError> {
    if value < 64 {
        out.push(u8::try_from(value).map_err(|_| TlsError::LengthOutOfRange)?);
    } else if value < 16_384 {
        let encoded = 0x4000_u16 | u16::try_from(value).map_err(|_| TlsError::LengthOutOfRange)?;
        out.extend_from_slice(&encoded.to_be_bytes());
    } else if value < 1_073_741_824 {
        let encoded =
            0x8000_0000_u32 | u32::try_from(value).map_err(|_| TlsError::LengthOutOfRange)?;
        out.extend_from_slice(&encoded.to_be_bytes());
    } else if value < 4_611_686_018_427_387_904 {
        out.extend_from_slice(&(0xc000_0000_0000_0000_u64 | value).to_be_bytes());
    } else {
        return Err(TlsError::LengthOutOfRange);
    }
    Ok(())
}
