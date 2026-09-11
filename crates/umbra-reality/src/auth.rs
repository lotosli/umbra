//! REALITY `legacy_session_id` authentication token.

use subtle::ConstantTimeEq;
use umbra_crypto::{
    aead,
    aead::AeadAlgorithm,
    kdf,
    secret::{Secret, SecretBytes},
};

use crate::{replay::ReplayCache, RealityError};

const VERSION: u8 = 0x01;
const SALT: &[u8] = b"umbra-reality-v1";
const PLAINTEXT_LEN: usize = 16;
const SESSION_ID_LEN: usize = 32;

/// Zero-padded 8-byte REALITY short id.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ShortId([u8; 8]);

impl ShortId {
    /// Build a short id from 0 to 8 raw bytes.
    pub fn from_slice(input: &[u8]) -> Result<Self, RealityError> {
        if input.len() > 8 {
            return Err(RealityError::InvalidShortIdLength);
        }
        let mut out = [0_u8; 8];
        out[..input.len()].copy_from_slice(input);
        Ok(Self(out))
    }

    /// Return the padded wire bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Constant-time equality.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl core::fmt::Debug for ShortId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ShortId(<redacted>)")
    }
}

/// Opened REALITY authentication token.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthOk {
    /// Token flags byte.
    pub flags: u8,
    /// Token timestamp in seconds.
    pub timestamp: u32,
    /// Accepted padded short id.
    pub short_id: ShortId,
}

/// Seal a REALITY token into a 32-byte TLS `legacy_session_id`.
///
/// This fail-fast API validates `short_id` and timestamp range before sealing.
pub fn try_seal_session_id(
    shared: &[u8; 32],
    short_id: &[u8],
    hello0: &[u8],
    now: u64,
) -> Result<[u8; SESSION_ID_LEN], RealityError> {
    seal_session_id_with_flags(shared, short_id, hello0, now, 0)
}

/// Seal a REALITY token with a caller-provided flags byte.
pub fn seal_session_id_with_flags(
    shared: &[u8; 32],
    short_id: &[u8],
    hello0: &[u8],
    now: u64,
    flags: u8,
) -> Result<[u8; SESSION_ID_LEN], RealityError> {
    let timestamp = u32::try_from(now).map_err(|_| RealityError::TimestampOutOfRange)?;
    let short_id = ShortId::from_slice(short_id)?;
    let (auth_key, nonce) = auth_key_nonce(shared)?;
    let plaintext = Secret::new(plaintext(flags, timestamp, short_id));
    let sealed = aead::seal(
        AeadAlgorithm::Aes128Gcm,
        auth_key.expose_secret(),
        nonce.expose_secret(),
        plaintext.expose_secret(),
        hello0,
    )
    .map_err(|_| RealityError::AuthenticationFailed)?;
    sealed
        .try_into()
        .map_err(|_| RealityError::AuthenticationFailed)
}

/// Open and validate a REALITY session id.
///
/// Accepted tokens are replay-protected through `timestamp + max_diff` inclusive,
/// independently of the cache's default TTL. Expiry overflow and cache capacity
/// exhaustion reject local authentication just like other validation failures.
pub fn open_session_id(
    shared: &[u8; 32],
    session_id: &[u8; SESSION_ID_LEN],
    hello0: &[u8],
    allowed: &[Vec<u8>],
    now: u64,
    max_diff: u64,
    replay: &ReplayCache,
) -> Result<AuthOk, RealityError> {
    if max_diff == 0 {
        return Err(RealityError::InvalidTimeWindow);
    }
    let (auth_key, nonce) = auth_key_nonce(shared)?;
    let plaintext = SecretBytes::new(
        aead::open(
            AeadAlgorithm::Aes128Gcm,
            auth_key.expose_secret(),
            nonce.expose_secret(),
            session_id,
            hello0,
        )
        .map_err(|_| RealityError::AuthenticationFailed)?,
    );
    let opened = parse_plaintext(plaintext.expose_secret())?;
    let expires_at = validate_time(opened.timestamp, now, max_diff)?;
    validate_short_id(opened.short_id, allowed)?;
    replay.insert_or_reject_until(*session_id, now, expires_at)?;
    Ok(opened)
}

/// Validate a ClientHello SNI against configured REALITY server names.
pub fn validate_server_name(sni: &str, allowed: &[String]) -> Result<(), RealityError> {
    if allowed.iter().any(|name| name == sni) {
        Ok(())
    } else {
        Err(RealityError::ServerNameRejected)
    }
}

/// Seal using the protocol signature from `docs/protocol-design.md`.
///
/// Callers that need explicit validation errors should use
/// [`try_seal_session_id`]. This function is intentionally infallible to keep
/// the documented protocol surface available; invalid inputs produce the
/// all-zero sentinel, which fails server authentication.
#[must_use]
pub fn seal_session_id(
    shared: &[u8; 32],
    short_id: &[u8],
    hello0: &[u8],
    now: u64,
) -> [u8; SESSION_ID_LEN] {
    try_seal_session_id(shared, short_id, hello0, now).unwrap_or([0_u8; SESSION_ID_LEN])
}

fn auth_key_nonce(shared: &[u8; 32]) -> Result<(SecretBytes, SecretBytes), RealityError> {
    let key = SecretBytes::new(
        kdf::hkdf_sha256(SALT, shared, b"key", 16)
            .map_err(|_| RealityError::AuthenticationFailed)?,
    );
    let nonce = SecretBytes::new(
        kdf::hkdf_sha256(SALT, shared, b"nonce", 12)
            .map_err(|_| RealityError::AuthenticationFailed)?,
    );
    Ok((key, nonce))
}

fn plaintext(flags: u8, timestamp: u32, short_id: ShortId) -> [u8; PLAINTEXT_LEN] {
    let mut out = [0_u8; PLAINTEXT_LEN];
    out[0] = VERSION;
    out[1] = flags;
    out[2..6].copy_from_slice(&timestamp.to_be_bytes());
    out[6..14].copy_from_slice(short_id.as_bytes());
    out
}

fn parse_plaintext(input: &[u8]) -> Result<AuthOk, RealityError> {
    if input.len() != PLAINTEXT_LEN {
        return Err(RealityError::AuthenticationFailed);
    }
    let version = input[0];
    if version != VERSION {
        return Err(RealityError::InvalidVersion(version));
    }
    if input[14..16] != [0, 0] {
        return Err(RealityError::AuthenticationFailed);
    }
    let timestamp = u32::from_be_bytes(
        input[2..6]
            .try_into()
            .map_err(|_| RealityError::AuthenticationFailed)?,
    );
    let short_id = ShortId(
        input[6..14]
            .try_into()
            .map_err(|_| RealityError::AuthenticationFailed)?,
    );
    Ok(AuthOk {
        flags: input[1],
        timestamp,
        short_id,
    })
}

fn validate_time(timestamp: u32, now: u64, max_diff: u64) -> Result<u64, RealityError> {
    let timestamp = u64::from(timestamp);
    let diff = now.abs_diff(timestamp);
    if diff > max_diff {
        return Err(RealityError::Expired);
    }
    timestamp
        .checked_add(max_diff)
        .ok_or(RealityError::ReplayExpiryOverflow)
}

fn validate_short_id(short_id: ShortId, allowed: &[Vec<u8>]) -> Result<(), RealityError> {
    let mut accepted = false;
    for item in allowed {
        let candidate = ShortId::from_slice(item)?;
        accepted |= short_id.ct_eq(&candidate);
    }
    if accepted {
        Ok(())
    } else {
        Err(RealityError::ShortIdRejected)
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_plaintext, plaintext, ShortId};
    use crate::RealityError;

    #[test]
    fn plaintext_parser_rejects_nonzero_reserved_bytes() {
        let short_id = ShortId::from_slice(b"sid").expect("short id");
        let mut token = plaintext(7, 100, short_id);

        let parsed = parse_plaintext(&token).expect("reserved zeros parse");
        assert_eq!(parsed.flags, 7);
        assert_eq!(parsed.timestamp, 100);

        token[14] = 1;
        assert_eq!(
            parse_plaintext(&token).expect_err("reserved byte must fail"),
            RealityError::AuthenticationFailed
        );
    }
}
