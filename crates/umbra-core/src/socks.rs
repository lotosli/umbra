//! SOCKS5 no-auth negotiation and CONNECT request parsing.

use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use umbra_proto::addr::TargetAddr;

use crate::CoreError;

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const REP_SUCCEEDED: u8 = 0x00;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Parsed SOCKS5 CONNECT request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SocksConnect {
    /// Requested destination.
    pub target: TargetAddr,
}

/// Complete SOCKS5 no-auth negotiation and CONNECT parsing.
pub async fn accept_connect<IO>(io: &mut IO) -> Result<SocksConnect, CoreError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_no_auth(io).await?;
    let request = read_connect_request(io).await;
    match request {
        Ok(connect) => {
            write_reply(io, REP_SUCCEEDED).await?;
            Ok(connect)
        }
        Err(CoreError::Socks("unsupported SOCKS command")) => {
            write_reply(io, REP_COMMAND_NOT_SUPPORTED).await?;
            Err(CoreError::Socks("unsupported SOCKS command"))
        }
        Err(err) => Err(err),
    }
}

/// Select the SOCKS5 no-auth method when the client offers it.
pub async fn negotiate_no_auth<IO>(io: &mut IO) -> Result<(), CoreError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0_u8; 2];
    io.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION {
        return Err(CoreError::Socks("unsupported SOCKS version"));
    }
    let method_count = usize::from(header[1]);
    if method_count == 0 {
        io.write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE]).await?;
        io.flush().await?;
        return Err(CoreError::Socks("no SOCKS auth methods offered"));
    }
    let mut methods = vec![0_u8; method_count];
    io.read_exact(&mut methods).await?;
    if methods.contains(&METHOD_NO_AUTH) {
        io.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
        io.flush().await?;
        Ok(())
    } else {
        io.write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE]).await?;
        io.flush().await?;
        Err(CoreError::Socks("SOCKS no-auth method missing"))
    }
}

/// Read a SOCKS5 CONNECT request and convert it to a target address.
pub async fn read_connect_request<R>(reader: &mut R) -> Result<SocksConnect, CoreError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION {
        return Err(CoreError::Socks("unsupported SOCKS version"));
    }
    if header[2] != 0 {
        return Err(CoreError::Socks("SOCKS reserved byte is invalid"));
    }
    let target = read_target(reader, header[3]).await?;
    if header[1] != CMD_CONNECT {
        return Err(CoreError::Socks("unsupported SOCKS command"));
    }
    Ok(SocksConnect { target })
}

/// Write a SOCKS5 success reply with an unspecified bound address.
pub async fn write_success_reply<W>(writer: &mut W) -> Result<(), CoreError>
where
    W: AsyncWrite + Unpin,
{
    write_reply(writer, REP_SUCCEEDED).await
}

/// Write a SOCKS5 unsupported-command reply.
pub async fn write_unsupported_command_reply<W>(writer: &mut W) -> Result<(), CoreError>
where
    W: AsyncWrite + Unpin,
{
    write_reply(writer, REP_COMMAND_NOT_SUPPORTED).await
}

async fn read_target<R>(reader: &mut R, atyp: u8) -> Result<TargetAddr, CoreError>
where
    R: AsyncRead + Unpin,
{
    match atyp {
        ATYP_IPV4 => {
            let mut bytes = [0_u8; 6];
            reader.read_exact(&mut bytes).await?;
            let addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            let port = u16::from_be_bytes([bytes[4], bytes[5]]);
            Ok(TargetAddr::Ipv4(addr, port))
        }
        ATYP_DOMAIN => {
            let mut len = [0_u8; 1];
            reader.read_exact(&mut len).await?;
            let len = usize::from(len[0]);
            if len == 0 {
                return Err(CoreError::Socks("SOCKS domain is empty"));
            }
            let mut domain = vec![0_u8; len];
            reader.read_exact(&mut domain).await?;
            let mut port = [0_u8; 2];
            reader.read_exact(&mut port).await?;
            let domain = String::from_utf8(domain)
                .map_err(|_| CoreError::Socks("SOCKS domain is not UTF-8"))?;
            TargetAddr::domain(domain, u16::from_be_bytes(port)).map_err(CoreError::from)
        }
        ATYP_IPV6 => {
            let mut bytes = [0_u8; 18];
            reader.read_exact(&mut bytes).await?;
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[..16]);
            let port = u16::from_be_bytes([bytes[16], bytes[17]]);
            Ok(TargetAddr::Ipv6(Ipv6Addr::from(octets), port))
        }
        _ => Err(CoreError::Socks("unsupported SOCKS address type")),
    }
}

async fn write_reply<W>(writer: &mut W, reply: u8) -> Result<(), CoreError>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&[SOCKS_VERSION, reply, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    writer.flush().await?;
    Ok(())
}
