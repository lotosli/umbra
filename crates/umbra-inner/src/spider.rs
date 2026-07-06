//! RealSite spider-mode helper.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::InnerError;

const MAX_SPIDER_RESPONSE_BYTES: usize = 64 * 1024;
const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36";

/// Build the browser-like HTTP request used for RealSite spider mode.
pub fn spider_request(spider_path: &str) -> Result<Vec<u8>, InnerError> {
    validate_spider_path(spider_path)?;
    Ok(format!(
        "GET {spider_path} HTTP/1.1\r\n\
         User-Agent: {USER_AGENT}\r\n\
         Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
         Accept-Language: en-US,en;q=0.9\r\n\
         Connection: close\r\n\
         \r\n"
    )
    .into_bytes())
}

/// Run RealSite spider mode against a TLS-like I/O object and close normally.
pub async fn spider<IO>(mut tls: IO, spider_path: &str) -> Result<(), InnerError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let request = spider_request(spider_path)?;
    tls.write_all(&request).await?;
    tls.flush().await?;

    let mut total = 0_usize;
    let mut buf = [0_u8; 1024];
    while total < MAX_SPIDER_RESPONSE_BYTES {
        let read = tls.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read).ok_or(InnerError::WindowOverflow)?;
    }
    tls.shutdown().await?;
    Ok(())
}

fn validate_spider_path(path: &str) -> Result<(), InnerError> {
    if !path.starts_with('/') {
        return Err(InnerError::InvalidSpiderPath("path must start with '/'"));
    }
    if path
        .as_bytes()
        .iter()
        .any(|byte| matches!(*byte, b'\r' | b'\n'))
    {
        return Err(InnerError::InvalidSpiderPath(
            "path must not contain CR or LF",
        ));
    }
    if path.len() > 2048 {
        return Err(InnerError::InvalidSpiderPath("path is too long"));
    }
    Ok(())
}
