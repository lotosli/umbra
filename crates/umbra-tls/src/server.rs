//! Minimal TLS 1.3 server handshake state machine.

use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use subtle::ConstantTimeEq;
use umbra_crypto::{mlkem::mlkem_encapsulate, secret::SecretBytes, x25519};
use umbra_fingerprint::profile::FingerprintProfile;

use crate::{
    clienthello::{GROUP_X25519, GROUP_X25519_MLKEM768, MLKEM768_PUBLIC_KEY_LEN, X25519_SHARE_LEN},
    handshake::{
        build_server_hello, certificate_message, certificate_verify_input,
        certificate_verify_message, combine_shared_secrets, encrypted_extensions_for_profile,
        first_record_payload, handshake_message, split_first_record, DriveOut,
        SIGNATURE_ECDSA_SECP256R1_SHA256,
    },
    keyschedule::{
        derive_tls13_secrets_for_suite, derive_traffic_keys, finished_verify_data_for_suite,
        transcript_hash_for_suite, SuiteSecrets, TrafficKeys,
    },
    parse::{parse_client_hello, ParsedClientHello},
    records::{OpenRecord, RecordLayer, CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_HANDSHAKE},
    TlsError,
};

const HANDSHAKE_FINISHED: u8 = 0x14;

/// Certificate material supplied by component E.
pub struct ForgedCert {
    /// Leaf certificate DER.
    pub leaf_der: Vec<u8>,
    /// Intermediate chain DER values.
    pub chain_der: Vec<Vec<u8>>,
    /// Ephemeral leaf private key DER used for TLS `CertificateVerify`.
    pub certificate_verify_key_der: Vec<u8>,
}

impl core::fmt::Debug for ForgedCert {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ForgedCert")
            .field("certificate_verify_key_der", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl zeroize::Zeroize for ForgedCert {
    fn zeroize(&mut self) {
        self.certificate_verify_key_der.zeroize();
    }
}

impl Drop for ForgedCert {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl zeroize::ZeroizeOnDrop for ForgedCert {}

/// Parameters that influence the visible server flight.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DestProfile {
    /// Destination host name this profile was collected from.
    pub server_name: String,
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Selected key-share group mirrored from destination.
    pub key_share_group: u16,
    /// Selected ALPN, if any.
    pub alpn: Option<String>,
    /// EncryptedExtensions identifiers mirrored from destination.
    pub encrypted_extensions: Vec<u16>,
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
            key_share_group: crate::clienthello::GROUP_X25519_MLKEM768,
            alpn: profile.alpn.first().cloned(),
            encrypted_extensions: vec![0x0010],
            rtt_millis: 0,
        }
    }
}

/// Minimal TLS 1.3 server.
pub struct Tls13Server {
    cipher_suite: u16,
    shared_secret: SecretBytes,
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

struct ServerHandshakeStart {
    negotiated: NegotiatedKeyShare,
    server_hello_record: Vec<u8>,
    handshake_transcript: Vec<u8>,
    hs_secrets: SuiteSecrets,
    server_hs_keys: TrafficKeys,
    client_hs_keys: TrafficKeys,
}

struct ServerFlightParts {
    encrypted_record: Vec<u8>,
    transcript_before_client_finished: Vec<u8>,
}

impl Tls13Server {
    /// Accept a prefetched ClientHello and return initial server handshake bytes.
    pub fn accept(
        chello_raw: &[u8],
        leaf: ForgedCert,
        profile: &DestProfile,
    ) -> Result<(Self, Vec<u8>), TlsError> {
        let ServerHandshakeStart {
            negotiated,
            server_hello_record,
            handshake_transcript,
            hs_secrets,
            server_hs_keys,
            client_hs_keys,
        } = prepare_server_handshake(chello_raw, profile)?;
        let flight = build_server_flight(
            profile,
            &leaf.leaf_der,
            &leaf.chain_der,
            &leaf.certificate_verify_key_der,
            &handshake_transcript,
            &hs_secrets,
            server_hs_keys,
        )?;
        drop(leaf);

        let mut outbound = server_hello_record;
        outbound.extend_from_slice(&flight.encrypted_record);

        Ok((
            Self {
                cipher_suite: profile.cipher_suite,
                shared_secret: negotiated.shared_secret,
                handshake_transcript,
                transcript_before_client_finished: flight.transcript_before_client_finished,
                client_hs_read: RecordLayer::from_traffic_keys(
                    profile.cipher_suite,
                    client_hs_keys,
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
        let expected = finished_verify_data_for_suite(
            self.cipher_suite,
            &derive_tls13_secrets_for_suite(
                self.cipher_suite,
                self.shared_secret.expose_secret(),
                &self.handshake_transcript,
                &[],
                &[],
            )?
            .client_handshake_traffic_secret,
            &transcript_hash_for_suite(self.cipher_suite, &self.transcript_before_client_finished)?,
        )?;
        if !bool::from(expected.as_slice().ct_eq(verify_data.as_slice())) {
            return Err(TlsError::AuthenticationFailed);
        }

        let mut transcript_after_client_finished = self.transcript_before_client_finished.clone();
        transcript_after_client_finished.extend_from_slice(&plaintext);
        let app_secrets = derive_tls13_secrets_for_suite(
            self.cipher_suite,
            self.shared_secret.expose_secret(),
            &self.handshake_transcript,
            &self.transcript_before_client_finished,
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
        self.app_write = Some(RecordLayer::from_traffic_keys(
            self.cipher_suite,
            server_app,
        ));
        self.app_read = Some(RecordLayer::from_traffic_keys(
            self.cipher_suite,
            client_app,
        ));
        self.state = ServerState::Connected;
        Ok(DriveOut {
            outbound: Vec::new(),
            complete: true,
            peer_kind: None,
        })
    }

    /// Transfer established application keys and release the handshake context.
    pub fn into_application_records(
        mut self,
    ) -> Result<crate::records::ApplicationRecords, TlsError> {
        if self.state != ServerState::Connected {
            return Err(TlsError::InvalidInput("server is not connected"));
        }
        let read = self
            .app_read
            .take()
            .ok_or(TlsError::InvalidInput("server is not connected"))?;
        let write = self
            .app_write
            .take()
            .ok_or(TlsError::InvalidInput("server is not connected"))?;
        Ok(crate::records::ApplicationRecords { read, write })
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

fn prepare_server_handshake(
    chello_raw: &[u8],
    profile: &DestProfile,
) -> Result<ServerHandshakeStart, TlsError> {
    let client_hello = parse_client_hello(chello_raw)?;
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
        &client_hello.session_id,
        profile.cipher_suite,
        &server_random,
        negotiated.group,
        &negotiated.key_exchange,
    )?;
    let client_hello_handshake = first_record_payload(chello_raw)?;
    let server_hello_handshake = first_record_payload(&server_hello_record)?;
    let mut handshake_transcript = client_hello_handshake;
    handshake_transcript.extend_from_slice(&server_hello_handshake);

    let hs_secrets = derive_tls13_secrets_for_suite(
        profile.cipher_suite,
        negotiated.shared_secret.expose_secret(),
        &handshake_transcript,
        &[],
        &[],
    )?;
    let server_hs_keys = derive_traffic_keys(
        profile.cipher_suite,
        &hs_secrets.server_handshake_traffic_secret,
    )?;
    let client_hs_keys = derive_traffic_keys(
        profile.cipher_suite,
        &hs_secrets.client_handshake_traffic_secret,
    )?;
    Ok(ServerHandshakeStart {
        negotiated,
        server_hello_record,
        handshake_transcript,
        hs_secrets,
        server_hs_keys,
        client_hs_keys,
    })
}

fn build_server_flight(
    profile: &DestProfile,
    leaf_der: &[u8],
    chain_der: &[Vec<u8>],
    certificate_verify_key_der: &[u8],
    handshake_transcript: &[u8],
    hs_secrets: &SuiteSecrets,
    server_hs_keys: TrafficKeys,
) -> Result<ServerFlightParts, TlsError> {
    let encrypted_extensions =
        encrypted_extensions_for_profile(profile.alpn.as_deref(), &profile.encrypted_extensions)?;
    let certificate = certificate_message(leaf_der, chain_der)?;
    let mut transcript_before_certificate_verify = handshake_transcript.to_vec();
    transcript_before_certificate_verify.extend_from_slice(&encrypted_extensions);
    transcript_before_certificate_verify.extend_from_slice(&certificate);
    let certificate_verify_signature = sign_certificate_verify(
        certificate_verify_key_der,
        &transcript_hash_for_suite(profile.cipher_suite, &transcript_before_certificate_verify)?,
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

    let mut encrypted_flight = Vec::new();
    encrypted_flight.extend_from_slice(&encrypted_extensions);
    encrypted_flight.extend_from_slice(&certificate);
    encrypted_flight.extend_from_slice(&certificate_verify);
    encrypted_flight.extend_from_slice(&server_finished);

    let mut server_hs_write = RecordLayer::from_traffic_keys(profile.cipher_suite, server_hs_keys);
    let mut encrypted_record = Vec::new();
    for fragment in encrypted_flight.chunks(16384) {
        encrypted_record
            .extend_from_slice(&server_hs_write.seal(CONTENT_TYPE_HANDSHAKE, fragment)?);
    }

    let mut transcript_before_client_finished = transcript_before_server_finished;
    transcript_before_client_finished.extend_from_slice(&server_finished);

    Ok(ServerFlightParts {
        encrypted_record,
        transcript_before_client_finished,
    })
}

pub(crate) struct NegotiatedKeyShare {
    pub(crate) group: u16,
    pub(crate) key_exchange: Vec<u8>,
    pub(crate) shared_secret: SecretBytes,
}

pub(crate) fn server_negotiated_key_share(
    client_hello: &ParsedClientHello,
    preferred_group: u16,
    server_x25519_public: &[u8; 32],
    classic_shared: &umbra_crypto::secret::Secret<32>,
) -> Result<NegotiatedKeyShare, TlsError> {
    match preferred_group {
        GROUP_X25519_MLKEM768 => {
            let hybrid = client_hello
                .key_shares
                .iter()
                .find(|share| share.group == GROUP_X25519_MLKEM768)
                .ok_or(TlsError::InvalidInput("missing client hybrid key_share"))?;
            if hybrid.key_exchange.len() != MLKEM768_PUBLIC_KEY_LEN + X25519_SHARE_LEN {
                return Err(TlsError::InvalidInput(
                    "invalid client hybrid key_share length",
                ));
            }
            let client_x25519 = client_hello
                .x25519_key_share
                .ok_or(TlsError::InvalidInput("missing client X25519 key_share"))?;
            if hybrid.key_exchange[MLKEM768_PUBLIC_KEY_LEN..] != client_x25519[..] {
                return Err(TlsError::InvalidInput(
                    "hybrid and classic X25519 key_shares differ",
                ));
            }
            let encapsulation = mlkem_encapsulate(&hybrid.key_exchange[..MLKEM768_PUBLIC_KEY_LEN])
                .map_err(|_| TlsError::InvalidInput("bad client ML-KEM key_share"))?;
            let shared_secret =
                combine_shared_secrets(classic_shared, Some(&encapsulation.shared_secret));
            let mut key_exchange =
                Vec::with_capacity(server_x25519_public.len() + encapsulation.ciphertext.len());
            key_exchange.extend_from_slice(&encapsulation.ciphertext);
            key_exchange.extend_from_slice(server_x25519_public);
            Ok(NegotiatedKeyShare {
                group: GROUP_X25519_MLKEM768,
                key_exchange,
                shared_secret,
            })
        }
        GROUP_X25519 => Ok(NegotiatedKeyShare {
            group: GROUP_X25519,
            key_exchange: server_x25519_public.to_vec(),
            shared_secret: combine_shared_secrets(classic_shared, None),
        }),
        _ => Err(TlsError::InvalidInput(
            "unsupported destination key_share group",
        )),
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

pub(crate) fn parse_client_finished(input: &[u8]) -> Result<Vec<u8>, TlsError> {
    if input.len() < 4 || input[0] != HANDSHAKE_FINISHED {
        return Err(TlsError::InvalidInput("bad client Finished"));
    }
    let len = (usize::from(input[1]) << 16) | (usize::from(input[2]) << 8) | usize::from(input[3]);
    if input.len() != 4 + len {
        return Err(TlsError::InvalidInput("bad client Finished length"));
    }
    Ok(input[4..].to_vec())
}
