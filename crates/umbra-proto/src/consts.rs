//! Protocol constants shared across components.

/// Mux frame version used by `docs/protocol-design.md`.
pub const MUX_VERSION: u8 = 0x01;

/// IPv4 address type marker.
pub const ATYP_IPV4: u8 = 0x01;
/// Domain address type marker.
pub const ATYP_DOMAIN: u8 = 0x03;
/// IPv6 address type marker.
pub const ATYP_IPV6: u8 = 0x04;

/// Private extension OID for Umbra certificate MAC.
pub const OID_CERT_MAC: &str = "1.3.6.1.4.1.62397.1";
/// Private extension OID for Umbra ML-DSA certificate signature.
pub const OID_MLDSA_SIG: &str = "1.3.6.1.4.1.62397.2";
