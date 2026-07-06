//! Minimal TLS 1.3 server handshake state machine.

use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use subtle::ConstantTimeEq;
use umbra_crypto::x25519;
use umbra_fingerprint::profile::FingerprintProfile;

use crate::{
    handshake::{
        build_server_hello, certificate_message, certificate_verify_input,
        certificate_verify_message, encrypted_extensions_message, first_record_payload,
        handshake_message, split_first_record, DriveOut, SIGNATURE_ECDSA_SECP256R1_SHA256,
    },
    keyschedule::{
        derive_tls13_secrets, derive_traffic_keys, finished_verify_data, transcript_hash,
    },
    parse::parse_client_hello,
    records::{OpenRecord, RecordLayer, CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_HANDSHAKE},
    TlsError,
};

const HANDSHAKE_FINISHED: u8 = 0x14;

/// Certificate material supplied by component E.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ForgedCert {
    /// Leaf certificate DER.
    pub leaf_der: Vec<u8>,
    /// Intermediate chain DER values.
    pub chain_der: Vec<Vec<u8>>,
    /// Ephemeral leaf private key DER used for TLS `CertificateVerify`.
    pub certificate_verify_key_der: Vec<u8>,
}

/// Parameters that influence the visible server flight.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DestProfile {
    /// Destination host name this profile was collected from.
    pub server_name: String,
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Selected ALPN, if any.
    pub alpn: Option<String>,
    /// Measured RTT to first byte in milliseconds.
    pub rtt_millis: u64,
}

impl DestProfile {
    /// Build a minimal destination profile from a fingerprint profile.
    #[must_use]
    pub fn from_fingerprint(server_name: String, profile: &FingerprintProfile) -> Self {
        let cipher_suite = profile.ciphers.iter().copied().find(|cipher| {
            matches!(
                *cipher,
                crate::clienthello::TLS_AES_128_GCM_SHA256
                    | crate::clienthello::TLS_AES_256_GCM_SHA384
                    | crate::clienthello::TLS_CHACHA20_POLY1305_SHA256
            )
        });
        Self {
            server_name,
            cipher_suite: cipher_suite.unwrap_or(crate::clienthello::TLS_AES_128_GCM_SHA256),
            alpn: profile.alpn.first().cloned(),
            rtt_millis: 0,
        }
    }
}

/// Minimal TLS 1.3 server.
pub struct Tls13Server {
    cipher_suite: u16,
    shared_secret: [u8; 32],
    handshake_transcript: Vec<u8>,
    transcript_before_client_finished: Vec<u8>,
    client_hs_read: RecordLayer,
    state: ServerState,
    app_write: Option<RecordLayer>,
    app_read: Option<RecordLayer>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ServerState {
    ExpectClientFinished,
    Connected,
}

impl Tls13Server {
    /// Accept a prefetched ClientHello and return initial server handshake bytes.
    pub fn accept(
        chello_raw: &[u8],
        leaf: ForgedCert,
        profile: &DestProfile,
    ) -> Result<(Self, Vec<u8>), TlsError> {
        let ForgedCert {
            leaf_der,
            chain_der,
            certificate_verify_key_der,
        } = leaf;
        let client_hello = parse_client_hello(chello_raw)?;
        let client_public = client_hello
            .x25519_key_share
            .ok_or(TlsError::InvalidInput("missing client X25519 key_share"))?;
        let server_keypair = x25519::generate_keypair();
        let shared = x25519::agree(&server_keypair.private, &client_public)
            .map_err(|_| TlsError::InvalidInput("bad client key_share"))?;
        let server_random = [0x5a_u8; 32];
        let server_hello_record = build_server_hello(
            &client_hello.session_id,
            profile.cipher_suite,
            &server_random,
            server_keypair.public.as_bytes(),
        )?;
        let client_hello_handshake = first_record_payload(chello_raw)?;
        let server_hello_handshake = first_record_payload(&server_hello_record)?;
        let mut handshake_transcript = client_hello_handshake;
        handshake_transcript.extend_from_slice(&server_hello_handshake);

        let hs_secrets = derive_tls13_secrets(shared.expose_secret(), &handshake_transcript, &[])?;
        let server_hs_keys = derive_traffic_keys(
            profile.cipher_suite,
            &hs_secrets.server_handshake_traffic_secret,
        )?;
        let client_hs_keys = derive_traffic_keys(
            profile.cipher_suite,
            &hs_secrets.client_handshake_traffic_secret,
        )?;

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

        let mut encrypted_flight = Vec::new();
        encrypted_flight.extend_from_slice(&encrypted_extensions);
        encrypted_flight.extend_from_slice(&certificate);
        encrypted_flight.extend_from_slice(&certificate_verify);
        encrypted_flight.extend_from_slice(&server_finished);

        let mut server_hs_write =
            RecordLayer::new(profile.cipher_suite, server_hs_keys.key, server_hs_keys.iv);
        let encrypted_record = server_hs_write.seal(CONTENT_TYPE_HANDSHAKE, &encrypted_flight)?;

        let mut outbound = server_hello_record;
        outbound.extend_from_slice(&encrypted_record);

        let mut transcript_before_client_finished = transcript_before_server_finished;
        transcript_before_client_finished.extend_from_slice(&server_finished);

        Ok((
            Self {
                cipher_suite: profile.cipher_suite,
                shared_secret: shared.into_inner(),
                handshake_transcript,
                transcript_before_client_finished,
                client_hs_read: RecordLayer::new(
                    profile.cipher_suite,
                    client_hs_keys.key,
                    client_hs_keys.iv,
                ),
                state: ServerState::ExpectClientFinished,
                app_write: None,
                app_read: None,
            },
            outbound,
        ))
    }

    /// Advance the server with client handshake bytes.
    pub fn drive(&mut self, inbound: &[u8]) -> Result<DriveOut, TlsError> {
        if self.state != ServerState::ExpectClientFinished {
            return Err(TlsError::InvalidInput("server handshake already complete"));
        }
        let (record, trailing) = split_first_record(inbound)?;
        if !trailing.is_empty() {
            return Err(TlsError::InvalidInput(
                "unexpected trailing handshake bytes",
            ));
        }
        let OpenRecord {
            content_type,
            plaintext,
        } = self.client_hs_read.open(record)?;
        if content_type != CONTENT_TYPE_HANDSHAKE {
            return Err(TlsError::InvalidInput(
                "client flight is not handshake data",
            ));
        }
        let verify_data = parse_client_finished(&plaintext)?;
        let expected = finished_verify_data(
            &derive_tls13_secrets(&self.shared_secret, &self.handshake_transcript, &[])?
                .client_handshake_traffic_secret,
            &transcript_hash(&self.transcript_before_client_finished),
        )?;
        if !bool::from(expected.as_slice().ct_eq(verify_data.as_slice())) {
            return Err(TlsError::AuthenticationFailed);
        }

        let mut transcript_after_client_finished = self.transcript_before_client_finished.clone();
        transcript_after_client_finished.extend_from_slice(&plaintext);
        let app_secrets = derive_tls13_secrets(
            &self.shared_secret,
            &self.handshake_transcript,
            &transcript_after_client_finished,
        )?;
        let server_app = derive_traffic_keys(
            self.cipher_suite,
            &app_secrets.server_application_traffic_secret,
        )?;
        let client_app = derive_traffic_keys(
            self.cipher_suite,
            &app_secrets.client_application_traffic_secret,
        )?;
        self.app_write = Some(RecordLayer::new(
            self.cipher_suite,
            server_app.key,
            server_app.iv,
        ));
        self.app_read = Some(RecordLayer::new(
            self.cipher_suite,
            client_app.key,
            client_app.iv,
        ));
        self.state = ServerState::Connected;
        Ok(DriveOut {
            outbound: Vec::new(),
            complete: true,
            peer_kind: None,
        })
    }

    /// Seal application data after the handshake completes.
    pub fn app_seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        self.app_write
            .as_mut()
            .ok_or(TlsError::InvalidInput("server is not connected"))?
            .seal(CONTENT_TYPE_APPLICATION_DATA, plaintext)
    }

    /// Open application data after the handshake completes.
    pub fn app_open(&mut self, record: &[u8]) -> Result<Vec<u8>, TlsError> {
        let opened = self
            .app_read
            .as_mut()
            .ok_or(TlsError::InvalidInput("server is not connected"))?
            .open(record)?;
        if opened.content_type != CONTENT_TYPE_APPLICATION_DATA {
            return Err(TlsError::InvalidInput("not application data"));
        }
        Ok(opened.plaintext)
    }
}

pub(crate) fn sign_certificate_verify(
    leaf_private_key_der: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let rng = SystemRandom::new();
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, leaf_private_key_der, &rng)
            .map_err(|_| TlsError::InvalidInput("bad CertificateVerify key"))?;
    let signature_input = certificate_verify_input(transcript_hash);
    let signature = key_pair
        .sign(&rng, &signature_input)
        .map_err(|_| TlsError::AuthenticationFailed)?;
    Ok(signature.as_ref().to_vec())
}

pub(crate) fn parse_client_finished(input: &[u8]) -> Result<[u8; 32], TlsError> {
    if input.len() != 36 || input[0] != HANDSHAKE_FINISHED {
        return Err(TlsError::InvalidInput("bad client Finished"));
    }
    let len = (usize::from(input[1]) << 16) | (usize::from(input[2]) << 8) | usize::from(input[3]);
    if len != 32 {
        return Err(TlsError::InvalidInput("bad client Finished length"));
    }
    input[4..]
        .try_into()
        .map_err(|_| TlsError::InvalidInput("bad client Finished"))
}
