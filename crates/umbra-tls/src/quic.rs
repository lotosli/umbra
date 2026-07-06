//! QUIC-facing TLS 1.3 handshake state.
//!
//! QUIC carries TLS handshake messages directly in CRYPTO frames instead of
//! wrapping them in TLS records. This module keeps the same ClientHello,
//! transcript, certificate verification, and key schedule logic as the TCP TLS
//! state machines, but exposes raw handshake bytes and traffic secrets for the
//! QUIC packet layer.

use subtle::ConstantTimeEq;
use umbra_crypto::{secret::Secret, x25519};

use crate::{
    clienthello::build_client_hello_handshake,
    clienthello::ClientHelloParams,
    handshake::{
        build_server_hello, certificate_message, certificate_verify_message,
        encrypted_extensions_message, handshake_message, parse_server_flight,
        parse_server_hello_handshake, verify_certificate_verify, CertVerify, PeerKind,
        SIGNATURE_ECDSA_SECP256R1_SHA256,
    },
    keyschedule::{derive_tls13_secrets, finished_verify_data, transcript_hash, Tls13Secrets},
    parse::parse_client_hello,
    server::{parse_client_finished, sign_certificate_verify, DestProfile, ForgedCert},
    TlsError,
};

const HANDSHAKE_FINISHED: u8 = 0x14;

/// QUIC traffic secrets for one encryption level.
pub struct QuicTrafficSecrets {
    /// Negotiated TLS 1.3 cipher suite.
    pub cipher_suite: u16,
    /// Traffic secret used for client-to-server packets.
    pub client: [u8; 32],
    /// Traffic secret used for server-to-client packets.
    pub server: [u8; 32],
}

/// Output from completing the client side of a QUIC TLS handshake.
pub struct QuicClientFinished {
    /// Raw TLS Finished handshake message to send in the QUIC Handshake packet space.
    pub finished: Vec<u8>,
    /// Application traffic secrets to install as QUIC 1-RTT packet keys.
    pub application_secrets: QuicTrafficSecrets,
    /// Classification returned by the certificate verifier.
    pub peer_kind: PeerKind,
}

/// QUIC-facing TLS 1.3 client state.
pub struct QuicTlsClient {
    cipher_suite: u16,
    client_private: [u8; 32],
    client_hello: Vec<u8>,
    shared_secret: Option<[u8; 32]>,
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
        let client_hello = build_client_hello_handshake(params)?;
        Ok((
            Self {
                cipher_suite: crate::clienthello::TLS_AES_128_GCM_SHA256,
                client_private,
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
        let shared = x25519::agree(&client_secret, &parsed.x25519_key_share)
            .map_err(|_| TlsError::InvalidInput("bad server key_share"))?;

        let mut transcript = self.client_hello.clone();
        transcript.extend_from_slice(&parsed.handshake);
        let secrets = derive_tls13_secrets(shared.expose_secret(), &transcript, &[])?;
        self.shared_secret = Some(shared.into_inner());
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
        )?;
        let peer_kind = verify.verify(&flight.certificate, &flight.certificate_chain);
        if matches!(peer_kind, PeerKind::Invalid) {
            return Err(TlsError::PeerRejected);
        }
        let shared = self
            .shared_secret
            .ok_or(TlsError::InvalidInput("missing QUIC shared secret"))?;
        let handshake_secrets = derive_tls13_secrets(&shared, &self.handshake_transcript, &[])?;
        let expected = finished_verify_data(
            &handshake_secrets.server_handshake_traffic_secret,
            &transcript_hash(&flight.transcript_before_finished),
        )?;
        if !bool::from(expected.as_slice().ct_eq(flight.finished.as_slice())) {
            return Err(TlsError::AuthenticationFailed);
        }

        let client_verify = finished_verify_data(
            &handshake_secrets.client_handshake_traffic_secret,
            &transcript_hash(&flight.transcript_after_finished),
        )?;
        let finished = handshake_message(HANDSHAKE_FINISHED, &client_verify)?;
        let mut transcript_after_client_finished = flight.transcript_after_finished;
        transcript_after_client_finished.extend_from_slice(&finished);
        let app_secrets = derive_tls13_secrets(
            &shared,
            &self.handshake_transcript,
            &transcript_after_client_finished,
        )?;
        self.state = QuicClientState::Connected;
        Ok(QuicClientFinished {
            finished,
            application_secrets: application_secrets(self.cipher_suite, &app_secrets),
            peer_kind,
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
}

/// QUIC-facing TLS 1.3 server state.
pub struct QuicTlsServer {
    cipher_suite: u16,
    shared_secret: [u8; 32],
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
        let shared = x25519::agree(&server_keypair.private, &client_public)
            .map_err(|_| TlsError::InvalidInput("bad client key_share"))?;
        let server_random = [0x5a_u8; 32];
        let server_hello_record = build_server_hello(
            &[],
            profile.cipher_suite,
            &server_random,
            server_keypair.public.as_bytes(),
        )?;
        let server_hello = crate::handshake::first_record_payload(&server_hello_record)?;
        let mut handshake_transcript = client_hello_raw.to_vec();
        handshake_transcript.extend_from_slice(&server_hello);
        let hs_secrets = derive_tls13_secrets(shared.expose_secret(), &handshake_transcript, &[])?;

        let encrypted_extensions = encrypted_extensions_message()?;
        let certificate = certificate_message(&leaf_der, &chain_der)?;
        let mut transcript_before_certificate_verify = handshake_transcript.clone();
        transcript_before_certificate_verify.extend_from_slice(&encrypted_extensions);
        transcript_before_certificate_verify.extend_from_slice(&certificate);
        let certificate_verify_signature = sign_certificate_verify(
            &certificate_verify_key_der,
            &transcript_hash(&transcript_before_certificate_verify),
        )?;
        let certificate_verify = certificate_verify_message(
            SIGNATURE_ECDSA_SECP256R1_SHA256,
            &certificate_verify_signature,
        )?;
        let mut transcript_before_server_finished = transcript_before_certificate_verify;
        transcript_before_server_finished.extend_from_slice(&certificate_verify);
        let verify_data = finished_verify_data(
            &hs_secrets.server_handshake_traffic_secret,
            &transcript_hash(&transcript_before_server_finished),
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
                shared_secret: shared.into_inner(),
                handshake_transcript,
                transcript_before_client_finished,
                state: QuicServerState::ExpectClientFinished,
            },
            server_hello,
            server_flight,
            handshake_secrets: handshake_secrets(profile.cipher_suite, &hs_secrets),
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
        let handshake_secrets =
            derive_tls13_secrets(&self.shared_secret, &self.handshake_transcript, &[])?;
        let expected = finished_verify_data(
            &handshake_secrets.client_handshake_traffic_secret,
            &transcript_hash(&self.transcript_before_client_finished),
        )?;
        if !bool::from(expected.as_slice().ct_eq(verify_data.as_slice())) {
            return Err(TlsError::AuthenticationFailed);
        }
        let mut transcript_after_client_finished = self.transcript_before_client_finished.clone();
        transcript_after_client_finished.extend_from_slice(client_finished);
        let app_secrets = derive_tls13_secrets(
            &self.shared_secret,
            &self.handshake_transcript,
            &transcript_after_client_finished,
        )?;
        self.state = QuicServerState::Connected;
        Ok(application_secrets(self.cipher_suite, &app_secrets))
    }
}

fn handshake_secrets(cipher_suite: u16, secrets: &Tls13Secrets) -> QuicTrafficSecrets {
    QuicTrafficSecrets {
        cipher_suite,
        client: secrets.client_handshake_traffic_secret,
        server: secrets.server_handshake_traffic_secret,
    }
}

fn application_secrets(cipher_suite: u16, secrets: &Tls13Secrets) -> QuicTrafficSecrets {
    QuicTrafficSecrets {
        cipher_suite,
        client: secrets.client_application_traffic_secret,
        server: secrets.server_application_traffic_secret,
    }
}
