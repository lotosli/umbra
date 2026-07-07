//! Target address encoding used by SYN and Vision solo prefaces.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{
    consts::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6},
    ProtocolError,
};

/// Target address carried by Umbra inner transports.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum TargetAddr {
    /// IPv4 target and TCP port.
    Ipv4(Ipv4Addr, u16),
    /// Domain target and TCP port.
    Domain(String, u16),
    /// IPv6 target and TCP port.
    Ipv6(Ipv6Addr, u16),
}

impl TargetAddr {
    /// Create a domain address after validating the wire length.
    pub fn domain(domain: impl Into<String>, port: u16) -> Result<Self, ProtocolError> {
        let domain = domain.into();
        validate_domain(&domain)?;
        Ok(Self::Domain(domain, port))
    }

    /// Return the target port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        match self {
            Self::Ipv4(_, port) | Self::Domain(_, port) | Self::Ipv6(_, port) => *port,
        }
    }

    /// Encode the target address into protocol bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut out = Vec::new();
        match self {
            Self::Ipv4(addr, port) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&addr.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::Domain(domain, port) => {
                validate_domain(domain)?;
                out.push(ATYP_DOMAIN);
                out.push(u8::try_from(domain.len()).map_err(|_| ProtocolError::LengthViolation)?);
                out.extend_from_slice(domain.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::Ipv6(addr, port) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&addr.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(out)
    }

    /// Decode one target address and require the full input to be consumed.
    pub fn decode(input: &[u8]) -> Result<Self, ProtocolError> {
        let (addr, consumed) = Self::decode_from(input)?;
        if consumed == input.len() {
            Ok(addr)
        } else {
            Err(ProtocolError::TrailingBytes)
        }
    }

    /// Decode one target address and return the number of bytes consumed.
    pub fn decode_from(input: &[u8]) -> Result<(Self, usize), ProtocolError> {
        let Some((&atyp, rest)) = input.split_first() else {
            return Err(ProtocolError::TruncatedInput);
        };
        match atyp {
            ATYP_IPV4 => decode_ipv4(rest),
            ATYP_DOMAIN => decode_domain(rest),
            ATYP_IPV6 => decode_ipv6(rest),
            _ => Err(ProtocolError::InvalidAddress),
        }
    }
}

fn decode_ipv4(input: &[u8]) -> Result<(TargetAddr, usize), ProtocolError> {
    if input.len() < 6 {
        return Err(ProtocolError::TruncatedInput);
    }
    let addr = Ipv4Addr::new(input[0], input[1], input[2], input[3]);
    let port = u16::from_be_bytes([input[4], input[5]]);
    Ok((TargetAddr::Ipv4(addr, port), 7))
}

fn decode_domain(input: &[u8]) -> Result<(TargetAddr, usize), ProtocolError> {
    let Some((&len, rest)) = input.split_first() else {
        return Err(ProtocolError::TruncatedInput);
    };
    let len = usize::from(len);
    if len == 0 {
        return Err(ProtocolError::InvalidAddress);
    }
    if rest.len() < len + 2 {
        return Err(ProtocolError::TruncatedInput);
    }
    let domain_bytes = &rest[..len];
    let domain = std::str::from_utf8(domain_bytes)
        .map_err(|_| ProtocolError::InvalidAddress)?
        .to_owned();
    validate_domain(&domain)?;
    let port_offset = len;
    let port = u16::from_be_bytes([rest[port_offset], rest[port_offset + 1]]);
    Ok((TargetAddr::Domain(domain, port), 1 + 1 + len + 2))
}

fn decode_ipv6(input: &[u8]) -> Result<(TargetAddr, usize), ProtocolError> {
    if input.len() < 18 {
        return Err(ProtocolError::TruncatedInput);
    }
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&input[..16]);
    let port = u16::from_be_bytes([input[16], input[17]]);
    Ok((TargetAddr::Ipv6(Ipv6Addr::from(octets), port), 19))
}

fn validate_domain(domain: &str) -> Result<(), ProtocolError> {
    if domain.is_empty() || domain.len() > usize::from(u8::MAX) || !domain.is_ascii() {
        return Err(ProtocolError::InvalidAddress);
    }
    Ok(())
}
