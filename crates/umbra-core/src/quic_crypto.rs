//! Internal quinn crypto adapter backed by Umbra's QUIC-facing TLS stack.

use std::{
    any::Any,
    collections::VecDeque,
    io,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use rand::{rngs::OsRng, RngCore};
use umbra_crypto::{
    mlkem::mlkem_keygen,
    secret::{Secret, SecretBytes},
    x25519,
};
use umbra_fingerprint::{load_profile, FingerprintProfile};
use umbra_reality::{
    auth::try_seal_session_id,
    cert::{classify_peer_certificate, forge_leaf_certificate, PeerKind as RealityPeerKind},
    prebuild::DestProfile,
};
use umbra_tls::{
    clienthello::{
        build_client_hello_handshake, quic_hello0, ClientHelloParams, ClientQuicTransportParameter,
        MlkemShare, EXT_QUIC_TRANSPORT_PARAMETERS,
    },
    handshake::{CertVerify, PeerKind as TlsPeerKind},
    keyschedule::hkdf_expand_label_for_suite,
    quic::{QuicTlsClient, QuicTlsServer, QuicTrafficSecrets},
};
use umbra_transport::quic::{
    derive_initial_quinn_packet_keys, derive_quinn_packet_keys, quic_retry_integrity_tag,
    quic_retry_integrity_valid,
};

use crate::{config::ClientCfg, CoreError};

const EXT_PADDING: u16 = 0x0015;
const TLS_HANDSHAKE_FINISHED: u8 = 0x14;

pub(crate) fn client_config(cfg: &ClientCfg) -> Result<quinn::ClientConfig, CoreError> {
    let profile = load_profile(&cfg.fingerprint)?;
    let (profile, grease_parameter, cid_len) = quic_profile(profile)?;
    let crypto = UmbraQuicClientConfig {
        public_key: *cfg.public_key.as_bytes(),
        short_id: cfg.short_id.clone(),
        profile,
        grease_parameter,
        mldsa_verify: cfg.mldsa_verify.clone(),
    };
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.initial_dst_cid_provider(Arc::new(move || random_connection_id(cid_len)));
    config.transport_config(quic_transport_config());
    Ok(config)
}

/// Authenticated server-side material recovered before handing a flow to quinn.
pub(crate) struct AuthenticatedServerCrypto {
    pub(crate) sni: String,
    pub(crate) session_id: [u8; 32],
    pub(crate) shared_secret: Secret<32>,
    pub(crate) client_hello: Vec<u8>,
    pub(crate) profile: DestProfile,
    pub(crate) mldsa_seed: Secret<32>,
}

pub(crate) fn server_config(authenticated: AuthenticatedServerCrypto) -> quinn::ServerConfig {
    let mut config =
        quinn::ServerConfig::with_crypto(Arc::new(UmbraQuicServerConfig { authenticated }));
    config.transport_config(quic_transport_config());
    config
}

/// Quinn client crypto config that creates one Umbra-backed TLS session.
struct UmbraQuicClientConfig {
    public_key: [u8; 32],
    short_id: Vec<u8>,
    profile: FingerprintProfile,
    grease_parameter: u64,
    mldsa_verify: Vec<u8>,
}

impl quinn_proto::crypto::ClientConfig for UmbraQuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &quinn_proto::transport_parameters::TransportParameters,
    ) -> Result<Box<dyn quinn_proto::crypto::Session>, quinn_proto::ConnectError> {
        if version != 1 {
            return Err(quinn_proto::ConnectError::UnsupportedVersion);
        }
        if server_name.is_empty() {
            return Err(quinn_proto::ConnectError::InvalidServerName(
                server_name.to_owned(),
            ));
        }
        let session = build_client_session(&self, server_name, params)
            .map_err(|_| quinn_proto::ConnectError::InvalidServerName(server_name.to_owned()))?;
        Ok(Box::new(session))
    }
}

/// Quinn server crypto config seeded with an already-authenticated Initial.
struct UmbraQuicServerConfig {
    authenticated: AuthenticatedServerCrypto,
}

impl quinn_proto::crypto::ServerConfig for UmbraQuicServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &quinn_proto::ConnectionId,
    ) -> Result<quinn_proto::crypto::Keys, quinn_proto::crypto::UnsupportedVersion> {
        derive_initial_quinn_packet_keys(version, dst_cid, quinn_proto::Side::Server)
            .map_err(|_| quinn_proto::crypto::UnsupportedVersion)
    }

    fn retry_tag(
        &self,
        version: u32,
        orig_dst_cid: &quinn_proto::ConnectionId,
        packet: &[u8],
    ) -> [u8; 16] {
        quic_retry_integrity_tag(version, orig_dst_cid, packet).unwrap_or([0_u8; 16])
    }

    fn start_session(
        self: Arc<Self>,
        _version: u32,
        params: &quinn_proto::transport_parameters::TransportParameters,
    ) -> Box<dyn quinn_proto::crypto::Session> {
        let local_transport_parameters = encode_transport_parameters(params);
        Box::new(UmbraQuicSession {
            side: quinn_proto::Side::Server,
            server_name: Some(self.authenticated.sni.clone()),
            state: SessionState::ServerExpectClientHello {
                authenticated: Box::new(ServerExpected {
                    sni: self.authenticated.sni.clone(),
                    session_id: self.authenticated.session_id,
                    shared_secret: Secret::new(*self.authenticated.shared_secret.expose_secret()),
                    client_hello: self.authenticated.client_hello.clone(),
                    profile: self.authenticated.profile.clone(),
                    mldsa_seed: Secret::new(*self.authenticated.mldsa_seed.expose_secret()),
                    local_transport_parameters,
                }),
            },
            inbound: Vec::new(),
            outgoing: VecDeque::new(),
            pending_keys: VecDeque::new(),
            next_1rtt: None,
            peer_transport_parameters: None,
            handshake_data_ready: false,
            handshake_data_reported: false,
        })
    }
}

/// Stateful quinn crypto session backed by `umbra-tls` handshake transitions.
struct UmbraQuicSession {
    side: quinn_proto::Side,
    server_name: Option<String>,
    state: SessionState,
    inbound: Vec<u8>,
    outgoing: VecDeque<Vec<u8>>,
    pending_keys: VecDeque<PendingKeys>,
    next_1rtt: Option<QuicTrafficSecrets>,
    peer_transport_parameters: Option<Vec<u8>>,
    handshake_data_ready: bool,
    handshake_data_reported: bool,
}

/// Minimal handshake state machine required by quinn's crypto trait.
enum SessionState {
    ClientExpectServerHello {
        client: QuicTlsClient,
        verifier: QuicRealityCertVerifier,
    },
    ClientExpectServerFlight {
        client: QuicTlsClient,
        verifier: QuicRealityCertVerifier,
    },
    ServerExpectClientHello {
        authenticated: Box<ServerExpected>,
    },
    ServerExpectClientFinished {
        server: QuicTlsServer,
    },
    Connected,
    Failed,
}

/// Server-side values expected to match the prefetched authenticated ClientHello.
struct ServerExpected {
    sni: String,
    session_id: [u8; 32],
    shared_secret: Secret<32>,
    client_hello: Vec<u8>,
    profile: DestProfile,
    mldsa_seed: Secret<32>,
    local_transport_parameters: Vec<u8>,
}

/// Certificate verifier that accepts only Umbra-forged REALITY certificates.
struct QuicRealityCertVerifier {
    shared: Secret<32>,
    session_id: [u8; 32],
    mldsa_verify: Vec<u8>,
    server_name: String,
}

impl CertVerify for QuicRealityCertVerifier {
    fn verify(&self, leaf_der: &[u8], chain: &[Vec<u8>]) -> TlsPeerKind {
        match classify_peer_certificate(
            leaf_der,
            self.shared.expose_secret(),
            &self.session_id,
            &self.mldsa_verify,
            true,
        ) {
            RealityPeerKind::UmbraTrusted => TlsPeerKind::UmbraTrusted,
            RealityPeerKind::RealSite
                if umbra_reality::cert::verify_site_certificate(
                    leaf_der,
                    chain,
                    &self.server_name,
                ) =>
            {
                TlsPeerKind::RealSite
            }
            RealityPeerKind::RealSite | RealityPeerKind::Invalid => TlsPeerKind::Invalid,
        }
    }
}

/// Traffic secrets waiting to be installed into quinn packet keys.
enum PendingKeys {
    Handshake(QuicTrafficSecrets),
    Application(QuicTrafficSecrets),
}

/// Handshake metadata returned to quinn once authentication is complete.
struct UmbraQuicHandshakeData {
    _protocol: Option<Vec<u8>>,
    _server_name: Option<String>,
}

impl quinn_proto::crypto::Session for UmbraQuicSession {
    fn initial_keys(
        &self,
        dst_cid: &quinn_proto::ConnectionId,
        side: quinn_proto::Side,
    ) -> quinn_proto::crypto::Keys {
        derive_initial_quinn_packet_keys(1, dst_cid, side).unwrap_or_else(|_| empty_keys())
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.handshake_data_ready {
            return None;
        }
        let server_name = match &self.state {
            SessionState::ServerExpectClientFinished { .. } | SessionState::Connected => {
                self.server_name()
            }
            _ => None,
        };
        Some(Box::new(UmbraQuicHandshakeData {
            _protocol: Some(b"h3".to_vec()),
            _server_name: server_name,
        }))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        None
    }

    fn early_crypto(
        &self,
    ) -> Option<(
        Box<dyn quinn_proto::crypto::HeaderKey>,
        Box<dyn quinn_proto::crypto::PacketKey>,
    )> {
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        !matches!(self.state, SessionState::Connected | SessionState::Failed)
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, quinn_proto::TransportError> {
        self.inbound.extend_from_slice(buf);
        let result = if matches!(&self.state, SessionState::ClientExpectServerHello { .. }) {
            self.client_read_server_hello()
        } else if matches!(&self.state, SessionState::ClientExpectServerFlight { .. }) {
            self.client_read_server_flight()
        } else if matches!(&self.state, SessionState::ServerExpectClientHello { .. }) {
            self.server_read_client_hello()
        } else if matches!(&self.state, SessionState::ServerExpectClientFinished { .. }) {
            self.server_read_client_finished()
        } else if matches!(&self.state, SessionState::Connected) {
            Ok(false)
        } else {
            Err(proto_error("QUIC TLS session failed"))
        };
        if result.is_err() {
            self.state = SessionState::Failed;
        }
        result
    }

    fn transport_parameters(
        &self,
    ) -> Result<
        Option<quinn_proto::transport_parameters::TransportParameters>,
        quinn_proto::TransportError,
    > {
        let Some(parameters) = &self.peer_transport_parameters else {
            return Ok(None);
        };
        let filtered;
        let parameters = if self.side.is_server() {
            filtered = filter_tls_grease_transport_parameters(parameters)
                .map_err(|err| proto_error(err.to_string()))?;
            filtered.as_slice()
        } else {
            parameters.as_slice()
        };
        quinn_proto::transport_parameters::TransportParameters::read(
            self.side,
            &mut io::Cursor::new(parameters),
        )
        .map(Some)
        .map_err(|err| proto_error(err.to_string()))
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<quinn_proto::crypto::Keys> {
        if let Some(outgoing) = self.outgoing.pop_front() {
            buf.extend_from_slice(&outgoing);
        }
        let pending = self.pending_keys.pop_front()?;
        match pending {
            PendingKeys::Handshake(secrets) => derive_quinn_packet_keys(&secrets, self.side).ok(),
            PendingKeys::Application(secrets) => {
                self.next_1rtt = next_application_secrets(&secrets).ok();
                derive_quinn_packet_keys(&secrets, self.side).ok()
            }
        }
    }

    fn next_1rtt_keys(
        &mut self,
    ) -> Option<quinn_proto::crypto::KeyPair<Box<dyn quinn_proto::crypto::PacketKey>>> {
        let secrets = self.next_1rtt.take()?;
        self.next_1rtt = next_application_secrets(&secrets).ok();
        let keys = derive_quinn_packet_keys(&secrets, self.side).ok()?;
        Some(keys.packet)
    }

    fn is_valid_retry(
        &self,
        orig_dst_cid: &quinn_proto::ConnectionId,
        header: &[u8],
        payload: &[u8],
    ) -> bool {
        quic_retry_integrity_valid(1, orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: &[u8],
    ) -> Result<(), quinn_proto::crypto::ExportKeyingMaterialError> {
        Err(quinn_proto::crypto::ExportKeyingMaterialError)
    }
}

impl UmbraQuicSession {
    fn client_read_server_hello(&mut self) -> Result<bool, quinn_proto::TransportError> {
        let Some(server_hello) = take_first_handshake_message(&mut self.inbound)? else {
            return Ok(false);
        };
        let state = std::mem::replace(&mut self.state, SessionState::Failed);
        let SessionState::ClientExpectServerHello {
            mut client,
            verifier,
        } = state
        else {
            self.state = state;
            return Err(proto_error("unexpected client QUIC state"));
        };
        let handshake_secrets = client
            .read_server_hello(&server_hello)
            .map_err(|err| proto_error(err.to_string()))?;
        self.pending_keys
            .push_back(PendingKeys::Handshake(handshake_secrets));
        self.state = SessionState::ClientExpectServerFlight { client, verifier };
        self.client_read_server_flight()
    }

    fn client_read_server_flight(&mut self) -> Result<bool, quinn_proto::TransportError> {
        let Some(server_flight) = take_finished_flight(&mut self.inbound)? else {
            return Ok(false);
        };
        let state = std::mem::replace(&mut self.state, SessionState::Failed);
        let SessionState::ClientExpectServerFlight {
            mut client,
            verifier,
        } = state
        else {
            self.state = state;
            return Err(proto_error("unexpected client QUIC state"));
        };
        let finished = client
            .read_server_flight(&server_flight, &verifier)
            .map_err(|err| proto_error(err.to_string()))?;
        self.complete_client_handshake(finished)
    }

    fn complete_client_handshake(
        &mut self,
        finished: umbra_tls::quic::QuicClientFinished,
    ) -> Result<bool, quinn_proto::TransportError> {
        if finished.peer_kind != TlsPeerKind::UmbraTrusted {
            self.state = SessionState::Failed;
            return Err(proto_error("peer certificate was not Umbra trusted"));
        }
        self.peer_transport_parameters = Some(finished.peer_transport_parameters);
        self.outgoing.push_back(finished.finished);
        self.pending_keys
            .push_back(PendingKeys::Application(finished.application_secrets));
        self.handshake_data_ready = true;
        self.state = SessionState::Connected;
        Ok(self.report_handshake_data_once())
    }

    fn server_read_client_hello(&mut self) -> Result<bool, quinn_proto::TransportError> {
        let Some(client_hello) = take_first_handshake_message(&mut self.inbound)? else {
            return Ok(false);
        };
        let state = std::mem::replace(&mut self.state, SessionState::Failed);
        let SessionState::ServerExpectClientHello { authenticated } = state else {
            self.state = state;
            return Err(proto_error("unexpected server QUIC state"));
        };
        if client_hello != authenticated.client_hello {
            return Err(proto_error("authenticated QUIC ClientHello changed"));
        }
        let forged = forge_leaf_certificate(
            &authenticated.profile,
            &authenticated.sni,
            authenticated.shared_secret.expose_secret(),
            &authenticated.session_id,
            &authenticated.mldsa_seed,
        )
        .map_err(|err| proto_error(err.to_string()))?;
        let mut profile = authenticated.profile.to_tls_server_profile();
        profile.alpn = Some("h3".to_owned());
        let accepted = QuicTlsServer::accept_with_transport_parameters(
            &client_hello,
            forged.tls_cert,
            &profile,
            &authenticated.local_transport_parameters,
        )
        .map_err(|err| proto_error(err.to_string()))?;
        self.peer_transport_parameters = Some(accepted.peer_transport_parameters);
        self.outgoing.push_back(accepted.server_hello);
        self.outgoing.push_back(accepted.server_flight);
        self.pending_keys
            .push_back(PendingKeys::Handshake(accepted.handshake_secrets));
        self.handshake_data_ready = true;
        self.state = SessionState::ServerExpectClientFinished {
            server: accepted.server,
        };
        Ok(self.report_handshake_data_once())
    }

    fn server_read_client_finished(&mut self) -> Result<bool, quinn_proto::TransportError> {
        let Some(client_finished) = take_first_handshake_message(&mut self.inbound)? else {
            return Ok(false);
        };
        let state = std::mem::replace(&mut self.state, SessionState::Failed);
        let SessionState::ServerExpectClientFinished { mut server } = state else {
            self.state = state;
            return Err(proto_error("unexpected server QUIC state"));
        };
        let application_secrets = server
            .read_client_finished(&client_finished)
            .map_err(|err| proto_error(err.to_string()))?;
        self.pending_keys
            .push_back(PendingKeys::Application(application_secrets));
        self.state = SessionState::Connected;
        Ok(false)
    }

    fn report_handshake_data_once(&mut self) -> bool {
        if self.handshake_data_reported {
            false
        } else {
            self.handshake_data_reported = true;
            true
        }
    }

    fn server_name(&self) -> Option<String> {
        self.server_name.clone()
    }
}

fn build_client_session(
    cfg: &UmbraQuicClientConfig,
    server_name: &str,
    params: &quinn_proto::transport_parameters::TransportParameters,
) -> Result<UmbraQuicSession, CoreError> {
    let transport_parameters = encode_transport_parameters(params);
    let mut parsed_parameters = parse_transport_parameters(&transport_parameters)?;
    parsed_parameters.retain(|parameter| parameter.id != cfg.grease_parameter);

    let keypair = x25519::generate_keypair();
    let shared = x25519::agree(&keypair.private, &cfg.public_key)?;
    let mut random = [0_u8; 32];
    OsRng.fill_bytes(&mut random);
    let mlkem = hybrid_mlkem_key_exchange(keypair.public.as_bytes());

    let mut zero_parameters = parsed_parameters.clone();
    zero_parameters.push(ClientQuicTransportParameter {
        id: cfg.grease_parameter,
        value: vec![0_u8; 32],
    });
    let zero_hello = build_client_hello_handshake(&client_hello_params(
        server_name,
        &keypair,
        cfg.profile.clone(),
        random,
        MlkemShare::x25519_mlkem768(mlkem.key_exchange.clone()),
        zero_parameters,
    ))?;
    let aad = quic_hello0(&zero_hello, cfg.grease_parameter)?;
    let auth_token = try_seal_session_id(
        shared.expose_secret(),
        &cfg.short_id,
        &aad,
        current_unix_time()?,
    )?;

    parsed_parameters.push(ClientQuicTransportParameter {
        id: cfg.grease_parameter,
        value: auth_token.to_vec(),
    });
    let params = client_hello_params(
        server_name,
        &keypair,
        cfg.profile.clone(),
        random,
        MlkemShare::x25519_mlkem768_with_decapsulation_key(
            mlkem.key_exchange,
            mlkem.decapsulation_key,
        ),
        parsed_parameters,
    );
    let (client, client_hello) = QuicTlsClient::start(&params)?;
    let verifier = QuicRealityCertVerifier {
        shared,
        session_id: auth_token,
        mldsa_verify: cfg.mldsa_verify.clone(),
        server_name: server_name.to_owned(),
    };
    let mut outgoing = VecDeque::new();
    outgoing.push_back(client_hello);
    Ok(UmbraQuicSession {
        side: quinn_proto::Side::Client,
        server_name: None,
        state: SessionState::ClientExpectServerHello { client, verifier },
        inbound: Vec::new(),
        outgoing,
        pending_keys: VecDeque::new(),
        next_1rtt: None,
        peer_transport_parameters: None,
        handshake_data_ready: false,
        handshake_data_reported: false,
    })
}

fn client_hello_params(
    server_name: &str,
    keypair: &x25519::Keypair,
    profile: FingerprintProfile,
    random: [u8; 32],
    mlkem: MlkemShare,
    quic_transport_parameters: Vec<ClientQuicTransportParameter>,
) -> ClientHelloParams {
    ClientHelloParams {
        sni: server_name.to_owned(),
        session_id: Vec::new(),
        x25519_priv: *keypair.private.expose_secret(),
        x25519_pub: *keypair.public.as_bytes(),
        mlkem,
        profile,
        random,
        quic_transport_parameters,
    }
}

fn quic_profile(
    mut profile: FingerprintProfile,
) -> Result<(FingerprintProfile, u64, usize), CoreError> {
    if profile.quic.alpn != "h3" {
        return Err(CoreError::InvalidConfig("QUIC ALPN must be h3"));
    }
    if !(8..=20).contains(&profile.quic.scid_len) {
        return Err(CoreError::InvalidConfig(
            "QUIC connection id length must be between 8 and 20 bytes",
        ));
    }
    let grease_parameter = profile.quic.grease_parameter;
    let cid_len = profile.quic.scid_len;
    if !profile.supported_versions.contains(&0x0304) {
        return Err(CoreError::InvalidConfig("QUIC profile must offer TLS 1.3"));
    }
    // Normalize before HELLO0/authentication binds the serialized ClientHello.
    profile
        .supported_versions
        .retain(|version| *version == 0x0304 || umbra_fingerprint::grease::is_grease(*version));
    profile.alpn = vec![profile.quic.alpn.clone()];
    if !profile
        .extension_order
        .contains(&EXT_QUIC_TRANSPORT_PARAMETERS)
    {
        let insert_at = profile
            .extension_order
            .iter()
            .position(|ext| *ext == EXT_PADDING)
            .unwrap_or(profile.extension_order.len());
        profile
            .extension_order
            .insert(insert_at, EXT_QUIC_TRANSPORT_PARAMETERS);
    }
    Ok((profile, grease_parameter, cid_len))
}

fn quic_transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    Arc::new(transport)
}

fn encode_transport_parameters(
    params: &quinn_proto::transport_parameters::TransportParameters,
) -> Vec<u8> {
    let mut out = Vec::new();
    params.write(&mut out);
    out
}

fn parse_transport_parameters(raw: &[u8]) -> Result<Vec<ClientQuicTransportParameter>, CoreError> {
    let mut offset = 0_usize;
    let mut out = Vec::new();
    while offset < raw.len() {
        let id = read_quic_varint(raw, &mut offset)?;
        let len = usize::try_from(read_quic_varint(raw, &mut offset)?)
            .map_err(|_| CoreError::InvalidConfig("QUIC transport parameter length too large"))?;
        let value = take(raw, &mut offset, len)?.to_vec();
        out.push(ClientQuicTransportParameter { id, value });
    }
    Ok(out)
}

fn filter_tls_grease_transport_parameters(raw: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut offset = 0_usize;
    let mut out = Vec::new();
    while offset < raw.len() {
        let id = read_quic_varint(raw, &mut offset)?;
        let len = usize::try_from(read_quic_varint(raw, &mut offset)?)
            .map_err(|_| CoreError::InvalidConfig("QUIC transport parameter length too large"))?;
        let value = take(raw, &mut offset, len)?;
        if is_tls_grease_u64(id) {
            continue;
        }
        write_quic_varint(id, &mut out)?;
        write_quic_varint(
            u64::try_from(value.len())
                .map_err(|_| CoreError::InvalidConfig("QUIC transport parameter too large"))?,
            &mut out,
        )?;
        out.extend_from_slice(value);
    }
    Ok(out)
}

fn is_tls_grease_u64(value: u64) -> bool {
    u16::try_from(value).is_ok_and(|value| value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff)
}

fn write_quic_varint(value: u64, out: &mut Vec<u8>) -> Result<(), CoreError> {
    if value < 64 {
        out.push(
            u8::try_from(value)
                .map_err(|_| CoreError::InvalidConfig("QUIC varint is too large"))?,
        );
    } else if value < 16_384 {
        let encoded = u16::try_from(value | 0x4000)
            .map_err(|_| CoreError::InvalidConfig("QUIC varint is too large"))?;
        out.extend_from_slice(&encoded.to_be_bytes());
    } else if value < 1_073_741_824 {
        let encoded = u32::try_from(value | 0x8000_0000)
            .map_err(|_| CoreError::InvalidConfig("QUIC varint is too large"))?;
        out.extend_from_slice(&encoded.to_be_bytes());
    } else if value < 4_611_686_018_427_387_904 {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    } else {
        return Err(CoreError::InvalidConfig("QUIC varint is too large"));
    }
    Ok(())
}

fn next_application_secrets(secrets: &QuicTrafficSecrets) -> Result<QuicTrafficSecrets, CoreError> {
    let client = next_traffic_secret(secrets.cipher_suite, &secrets.client)?;
    let server = next_traffic_secret(secrets.cipher_suite, &secrets.server)?;
    Ok(QuicTrafficSecrets {
        cipher_suite: secrets.cipher_suite,
        client,
        server,
    })
}

fn next_traffic_secret(cipher_suite: u16, secret: &[u8]) -> Result<Vec<u8>, CoreError> {
    hkdf_expand_label_for_suite(cipher_suite, secret, "traffic upd", &[], secret.len())
        .map_err(CoreError::from)
}

fn take_first_handshake_message(
    buf: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, quinn_proto::TransportError> {
    let Some(len) = first_handshake_len(buf)? else {
        return Ok(None);
    };
    Ok(Some(buf.drain(..len).collect()))
}

fn take_finished_flight(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>, quinn_proto::TransportError> {
    let Some(len) = complete_finished_flight_len(buf)? else {
        return Ok(None);
    };
    Ok(Some(buf.drain(..len).collect()))
}

fn first_handshake_len(buf: &[u8]) -> Result<Option<usize>, quinn_proto::TransportError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = read_u24(&buf[1..4])?;
    let needed = len
        .checked_add(4)
        .ok_or_else(|| proto_error("TLS handshake length overflows"))?;
    if buf.len() < needed {
        return Ok(None);
    }
    Ok(Some(needed))
}

fn complete_finished_flight_len(buf: &[u8]) -> Result<Option<usize>, quinn_proto::TransportError> {
    let mut offset = 0_usize;
    while offset < buf.len() {
        if buf.len() - offset < 4 {
            return Ok(None);
        }
        let handshake_type = buf[offset];
        let len = read_u24(&buf[offset + 1..offset + 4])?;
        let next = offset
            .checked_add(4)
            .and_then(|value| value.checked_add(len))
            .ok_or_else(|| proto_error("TLS handshake flight length overflows"))?;
        if buf.len() < next {
            return Ok(None);
        }
        offset = next;
        if handshake_type == TLS_HANDSHAKE_FINISHED {
            return Ok(Some(offset));
        }
    }
    Ok(None)
}

fn read_u24(input: &[u8]) -> Result<usize, quinn_proto::TransportError> {
    if input.len() != 3 {
        return Err(proto_error("bad TLS uint24"));
    }
    Ok((usize::from(input[0]) << 16) | (usize::from(input[1]) << 8) | usize::from(input[2]))
}

fn read_quic_varint(input: &[u8], offset: &mut usize) -> Result<u64, CoreError> {
    let first = *input
        .get(*offset)
        .ok_or(CoreError::InvalidConfig("missing QUIC varint"))?;
    let len = 1_usize << usize::from(first >> 6);
    let bytes = take(input, offset, len)?;
    let mut value = u64::from(bytes[0] & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(value)
}

fn take<'a>(input: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], CoreError> {
    let end = offset
        .checked_add(len)
        .ok_or(CoreError::InvalidConfig("QUIC offset overflows"))?;
    if end > input.len() {
        return Err(CoreError::InvalidConfig(
            "truncated QUIC transport parameter",
        ));
    }
    let out = &input[*offset..end];
    *offset = end;
    Ok(out)
}

fn random_connection_id(len: usize) -> quinn_proto::ConnectionId {
    let mut bytes = vec![0_u8; len];
    OsRng.fill_bytes(&mut bytes);
    quinn_proto::ConnectionId::new(&bytes)
}

struct HybridMlkemMaterial {
    key_exchange: Vec<u8>,
    decapsulation_key: SecretBytes,
}

fn hybrid_mlkem_key_exchange(x25519_public: &[u8; 32]) -> HybridMlkemMaterial {
    let mlkem = mlkem_keygen();
    let mut key_exchange = Vec::with_capacity(x25519_public.len() + mlkem.encapsulation_key.len());
    key_exchange.extend_from_slice(&mlkem.encapsulation_key);
    key_exchange.extend_from_slice(x25519_public);
    HybridMlkemMaterial {
        key_exchange,
        decapsulation_key: mlkem.decapsulation_key,
    }
}

fn current_unix_time() -> Result<u64, CoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoreError::InvalidConfig("system clock is before Unix epoch"))
        .map(|duration| duration.as_secs())
}

fn proto_error(reason: impl Into<String>) -> quinn_proto::TransportError {
    quinn_proto::TransportError {
        code: quinn_proto::TransportErrorCode::PROTOCOL_VIOLATION,
        frame: None,
        reason: reason.into(),
    }
}

fn empty_keys() -> quinn_proto::crypto::Keys {
    let secrets = QuicTrafficSecrets {
        cipher_suite: umbra_tls::clienthello::TLS_AES_128_GCM_SHA256,
        client: vec![0_u8; 32],
        server: vec![0_u8; 32],
    };
    derive_quinn_packet_keys(&secrets, quinn_proto::Side::Client)
        .unwrap_or_else(|_| panic_free_empty_keys())
}

fn panic_free_empty_keys() -> quinn_proto::crypto::Keys {
    derive_initial_quinn_packet_keys(1, &[0_u8; 8], quinn_proto::Side::Client)
        .unwrap_or_else(|_| unreachable_keys())
}

fn unreachable_keys() -> quinn_proto::crypto::Keys {
    struct NullHeaderKey;
    struct NullPacketKey;

    impl quinn_proto::crypto::HeaderKey for NullHeaderKey {
        fn decrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}
        fn encrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}
        fn sample_size(&self) -> usize {
            16
        }
    }

    impl quinn_proto::crypto::PacketKey for NullPacketKey {
        fn encrypt(&self, _packet: u64, _buf: &mut [u8], _header_len: usize) {}
        fn decrypt(
            &self,
            _packet: u64,
            _header: &[u8],
            _payload: &mut bytes::BytesMut,
        ) -> Result<(), quinn_proto::crypto::CryptoError> {
            Err(quinn_proto::crypto::CryptoError)
        }
        fn tag_len(&self) -> usize {
            16
        }
        fn confidentiality_limit(&self) -> u64 {
            0
        }
        fn integrity_limit(&self) -> u64 {
            0
        }
    }

    quinn_proto::crypto::Keys {
        header: quinn_proto::crypto::KeyPair {
            local: Box::new(NullHeaderKey),
            remote: Box::new(NullHeaderKey),
        },
        packet: quinn_proto::crypto::KeyPair {
            local: Box::new(NullPacketKey),
            remote: Box::new(NullPacketKey),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn_proto::crypto::Session as _;
    use umbra_tls::clienthello::TLS_AES_128_GCM_SHA256;

    #[test]
    fn scenario_quic_profile_validates_alpn_and_cid() {
        let profile = load_profile("chrome-latest").expect("profile loads");
        let (_, grease, cid_len) = quic_profile(profile.clone()).expect("valid QUIC profile");
        assert_eq!(grease, profile.quic.grease_parameter);
        assert_eq!(cid_len, profile.quic.scid_len);

        let mut bad_alpn = profile.clone();
        bad_alpn.quic.alpn = "h2".to_owned();
        assert!(quic_profile(bad_alpn).is_err());

        let mut bad_cid = profile.clone();
        bad_cid.quic.scid_len = 7;
        assert!(quic_profile(bad_cid).is_err());

        let mut missing_tls13 = profile.clone();
        missing_tls13.supported_versions = vec![0x0a0a, 0x0303];
        assert!(quic_profile(missing_tls13).is_err());

        let mut missing_extension = profile;
        missing_extension
            .extension_order
            .retain(|ext| *ext != EXT_QUIC_TRANSPORT_PARAMETERS);
        let (patched, _, _) = quic_profile(missing_extension).expect("extension inserted");
        assert!(patched
            .extension_order
            .contains(&EXT_QUIC_TRANSPORT_PARAMETERS));
    }

    #[test]
    fn scenario_quinn_serialized_versions_are_normalized_before_authentication() {
        use umbra_reality::{auth::open_session_id, replay::ReplayCache};
        use umbra_tls::{clienthello::GROUP_X25519_MLKEM768, parse::parse_client_hello};

        let mut source = load_profile("chrome-latest").expect("profile loads");
        source.supported_versions = vec![0x0a0a, 0x0304, 0x0303, 0x1a1a, 0x0302, 0x2a0a];
        let (profile, grease_parameter, _) = quic_profile(source.clone()).expect("QUIC profile");
        let server_key = x25519::generate_keypair();
        let config = UmbraQuicClientConfig {
            public_key: *server_key.public.as_bytes(),
            short_id: vec![1, 2],
            profile,
            grease_parameter,
            mldsa_verify: Vec::new(),
        };
        let params = quinn_proto::transport_parameters::TransportParameters::read(
            quinn_proto::Side::Server,
            &mut io::Cursor::new([]),
        )
        .expect("default transport parameters");
        let mut session =
            build_client_session(&config, "server.example", &params).expect("client session");
        let hello = session
            .outgoing
            .pop_front()
            .expect("serialized ClientHello");
        let fingerprint = umbra_fingerprint::ja3::parse_client_hello(&hello).expect("fingerprint");
        assert_eq!(fingerprint.supported_versions, vec![0x0a0a, 0x0304, 0x1a1a]);
        assert_eq!(
            source.supported_versions,
            vec![0x0a0a, 0x0304, 0x0303, 0x1a1a, 0x0302, 0x2a0a]
        );

        let parsed = parse_client_hello(&hello).expect("ClientHello parses");
        let classic = parsed
            .x25519_key_share
            .expect("classic authentication share");
        let hybrid = parsed
            .key_shares
            .iter()
            .find(|share| share.group == GROUP_X25519_MLKEM768)
            .expect("hybrid key share");
        assert_eq!(hybrid.key_exchange.len(), 1184 + 32);
        assert_eq!(&hybrid.key_exchange[1184..], &classic);

        let shared = x25519::agree(&server_key.private, &classic).expect("server auth secret");
        let carrier = parsed
            .quic_transport_parameters
            .iter()
            .find(|parameter| parameter.id == grease_parameter)
            .expect("authentication carrier");
        let token: [u8; 32] = carrier.value.as_slice().try_into().expect("token length");
        let aad = quic_hello0(&hello, grease_parameter).expect("authenticated HELLO0");
        let now = current_unix_time().expect("current time");
        let replay = ReplayCache::new(64, 120).expect("replay cache");
        let authenticated = open_session_id(
            shared.expose_secret(),
            &token,
            &aad,
            &[config.short_id],
            now,
            120,
            &replay,
        )
        .expect("normalized serialized ClientHello authenticates");
        assert_eq!(authenticated.short_id.as_bytes(), &[1, 2, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn scenario_quic_transport_parameter_codec_filters_tls_grease() {
        let mut raw = Vec::new();
        write_quic_varint(0x0a0a, &mut raw).expect("write grease id");
        write_quic_varint(1, &mut raw).expect("write grease len");
        raw.push(0xaa);
        write_quic_varint(0x1f, &mut raw).expect("write normal id");
        write_quic_varint(2, &mut raw).expect("write normal len");
        raw.extend_from_slice(&[0xbb, 0xcc]);

        let parsed = parse_transport_parameters(&raw).expect("parse params");
        assert_eq!(parsed.len(), 2);
        assert!(is_tls_grease_u64(parsed[0].id));

        let filtered = filter_tls_grease_transport_parameters(&raw).expect("filter grease");
        let parsed_filtered = parse_transport_parameters(&filtered).expect("parse filtered");
        assert_eq!(parsed_filtered.len(), 1);
        assert_eq!(parsed_filtered[0].id, 0x1f);
        assert_eq!(parsed_filtered[0].value, vec![0xbb, 0xcc]);

        assert!(write_quic_varint(4_611_686_018_427_387_904, &mut Vec::new()).is_err());
        let mut empty_offset = 0;
        assert!(read_quic_varint(&[], &mut empty_offset).is_err());
        let mut truncated_offset = 0;
        assert!(read_quic_varint(&[0x40], &mut truncated_offset).is_err());
    }

    #[test]
    fn scenario_quic_udp_carrier_preserves_fingerprint_by_disabling_datagrams() {
        let config = quic_transport_config();
        let config_debug = format!("{config:?}");

        assert!(config_debug.contains("datagram_receive_buffer_size: None"));
        assert!(config_debug.contains("datagram_send_buffer_size: 0"));
    }

    #[test]
    fn scenario_quic_handshake_extractors_handle_partial_and_finished() {
        let mut first = b"\x01\x00\x00\x03abc\x14\x00\x00\x00".to_vec();
        assert_eq!(
            take_first_handshake_message(&mut first).expect("first message"),
            Some(b"\x01\x00\x00\x03abc".to_vec())
        );
        assert_eq!(first, b"\x14\x00\x00\x00");

        assert_eq!(
            first_handshake_len(b"\x01\x00\x00").expect("partial len"),
            None
        );
        assert!(read_u24(&[0, 1]).is_err());

        assert_eq!(
            complete_finished_flight_len(b"\x08\x00\x00\x01x\x14\x00\x00\x00")
                .expect("finished flight"),
            Some(9)
        );
        assert_eq!(
            complete_finished_flight_len(b"\x08\x00\x00\x03x").expect("partial flight"),
            None
        );
    }

    #[test]
    fn scenario_quic_session_trait_defaults_are_fail_closed() {
        let mut session = test_session(SessionState::Connected);

        assert!(session.handshake_data().is_none());
        session.handshake_data_ready = true;
        assert!(session.handshake_data().is_some());
        assert!(session.peer_identity().is_none());
        assert!(session.early_crypto().is_none());
        assert_eq!(session.early_data_accepted(), None);
        assert!(!session.is_handshaking());
        assert!(session.next_1rtt_keys().is_none());
        assert!(session
            .export_keying_material(&mut [0_u8; 8], b"label", b"context")
            .is_err());

        let mut out = Vec::new();
        assert!(session.write_handshake(&mut out).is_none());
        session.outgoing.push_back(b"hello".to_vec());
        session
            .pending_keys
            .push_back(PendingKeys::Handshake(test_traffic_secrets()));
        assert!(session.write_handshake(&mut out).is_some());
        assert_eq!(out, b"hello");
    }

    #[test]
    fn scenario_quic_session_failed_state_rejects_handshake_bytes() {
        let mut failed = test_session(SessionState::Failed);

        assert!(failed.read_handshake(b"\x01\x00\x00\x00").is_err());
    }

    #[test]
    fn scenario_quic_verifier_rejects_untrusted_ordinary_certificate() {
        let cert = rcgen::generate_simple_self_signed(vec!["site.example".to_owned()])
            .expect("synthetic certificate");
        let verifier = QuicRealityCertVerifier {
            shared: Secret::new([1; 32]),
            session_id: [2; 32],
            mldsa_verify: Vec::new(),
            server_name: "site.example".to_owned(),
        };
        assert_eq!(verifier.verify(cert.cert.der(), &[]), TlsPeerKind::Invalid);
        assert_eq!(verifier.verify(b"bad DER", &[]), TlsPeerKind::Invalid);
    }

    #[test]
    fn scenario_quic_untrusted_peer_cannot_publish_application_keys() {
        for peer_kind in [TlsPeerKind::RealSite, TlsPeerKind::Invalid] {
            let mut session = test_session(SessionState::Failed);
            let finished = test_client_finished(peer_kind);
            assert!(session.complete_client_handshake(finished).is_err());
            assert!(matches!(session.state, SessionState::Failed));
            assert!(!session.handshake_data_ready);
            assert!(!session.handshake_data_reported);
            assert!(session.handshake_data().is_none());
            assert!(session.pending_keys.is_empty());
            assert!(session.outgoing.is_empty());
            assert!(session.peer_transport_parameters.is_none());
            assert!(session.next_1rtt_keys().is_none());
        }
    }

    #[test]
    fn scenario_quic_trusted_peer_publishes_readiness_once() {
        let mut session = test_session(SessionState::Failed);
        assert!(session
            .complete_client_handshake(test_client_finished(TlsPeerKind::UmbraTrusted))
            .expect("trusted handshake"));
        assert!(matches!(session.state, SessionState::Connected));
        assert!(session.handshake_data_ready);
        assert!(session.handshake_data().is_some());
        assert!(!session.report_handshake_data_once());
        assert_eq!(session.peer_transport_parameters, Some(vec![1, 2]));
        assert_eq!(session.outgoing.pop_front(), Some(vec![0x14, 0, 0, 0]));
        assert!(matches!(
            session.pending_keys.pop_front(),
            Some(PendingKeys::Application(_))
        ));
    }

    fn test_client_finished(peer_kind: TlsPeerKind) -> umbra_tls::quic::QuicClientFinished {
        umbra_tls::quic::QuicClientFinished {
            finished: vec![0x14, 0, 0, 0],
            application_secrets: test_traffic_secrets(),
            peer_kind,
            peer_transport_parameters: vec![1, 2],
        }
    }

    fn test_session(state: SessionState) -> UmbraQuicSession {
        UmbraQuicSession {
            side: quinn_proto::Side::Server,
            server_name: Some("server.example".to_owned()),
            state,
            inbound: Vec::new(),
            outgoing: VecDeque::new(),
            pending_keys: VecDeque::new(),
            next_1rtt: None,
            peer_transport_parameters: None,
            handshake_data_ready: false,
            handshake_data_reported: false,
        }
    }

    fn test_traffic_secrets() -> QuicTrafficSecrets {
        QuicTrafficSecrets {
            cipher_suite: TLS_AES_128_GCM_SHA256,
            client: vec![1_u8; 32],
            server: vec![2_u8; 32],
        }
    }
}
