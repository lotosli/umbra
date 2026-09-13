//! Bounded, passive TLS 1.3 structure observation for authenticated Vision solo.
//!
//! Eligibility does not authenticate inner peers or encrypted Finished messages.
//! Malformed, unsupported, or excessive input permanently disables observation;
//! callers must continue forwarding its original bytes inside outer TLS.

use thiserror::Error;

/// Direction of bytes in the original end-to-end target connection.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VisionDirection {
    /// Client application to target server.
    ClientToTarget,
    /// Target server to client application.
    TargetToClient,
}

/// Maximum inspected target bytes in either direction.
pub const MAX_INSPECTED_BYTES: u64 = 262_144;
/// Maximum reassembled handshake, including its four-byte header.
pub const MAX_HANDSHAKE_LEN: usize = 65_536;
/// Maximum complete protected record, including its five-byte header.
pub const MAX_PROTECTED_RECORD_LEN: usize = 16_645;

const RECORD_HEADER_LEN: usize = 5;
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Terminal bookkeeping or raw record validation error.
#[derive(Debug, Clone, Copy, Error, Eq, PartialEq)]
pub enum ObserverError {
    /// Target byte accounting overflowed its wire representation.
    #[error("Vision target byte counter overflow")]
    CounterOverflow,
    /// Raw input does not have a supported protected TLS record header.
    #[error("invalid Vision raw TLS record header")]
    InvalidProtectedHeader,
}

/// Validate a raw protected record header and return its complete record length.
///
/// This does not authenticate the record body. A caller must retain partial
/// records, reject partial-record EOF, and never forward an invalid header.
pub fn protected_record_len(header: &[u8; RECORD_HEADER_LEN]) -> Result<usize, ObserverError> {
    let payload_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if header[..3] != [0x17, 0x03, 0x03] || !(17..=16_640).contains(&payload_len) {
        return Err(ObserverError::InvalidProtectedHeader);
    }
    Ok(RECORD_HEADER_LEN + payload_len)
}

#[derive(Default)]
struct DirectionState {
    offset: u64,
    header: [u8; RECORD_HEADER_LEN],
    header_len: usize,
    remaining: usize,
    handshake: Vec<u8>,
    hello_done: bool,
    protected: bool,
    last_protected: bool,
}

struct ClientOffer {
    session_id: Vec<u8>,
    ciphers: u8,
    shares: Vec<u16>,
}

/// Incremental, bounded observer of the two original target byte streams.
pub struct Tls13Observer {
    directions: [DirectionState; 2],
    offer: Option<ClientOffer>,
    server_hello: bool,
    disabled: bool,
}

impl core::fmt::Debug for Tls13Observer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tls13Observer")
            .field("disabled", &self.disabled)
            .field("eligible", &self.eligible())
            .finish_non_exhaustive()
    }
}

impl Default for Tls13Observer {
    fn default() -> Self {
        Self::new()
    }
}

impl Tls13Observer {
    /// Start observing each stream from offset zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            directions: [DirectionState::default(), DirectionState::default()],
            offer: None,
            server_hello: false,
            disabled: false,
        }
    }

    /// Observe bytes without delaying or changing their wrapped delivery.
    ///
    /// Unsupported TLS only disables eligibility. Byte counter overflow is a
    /// terminal error, including when observation has already been disabled.
    pub fn observe(
        &mut self,
        direction: VisionDirection,
        mut bytes: &[u8],
    ) -> Result<(), ObserverError> {
        let idx = index(direction);
        let count = u64::try_from(bytes.len()).map_err(|_| ObserverError::CounterOverflow)?;
        self.directions[idx].offset = self.directions[idx]
            .offset
            .checked_add(count)
            .ok_or(ObserverError::CounterOverflow)?;
        if self.directions[idx].offset > MAX_INSPECTED_BYTES {
            self.disable();
        }
        while !bytes.is_empty() && !self.disabled {
            let state = &mut self.directions[idx];
            if state.header_len < RECORD_HEADER_LEN {
                let take = bytes.len().min(RECORD_HEADER_LEN - state.header_len);
                state.header[state.header_len..state.header_len + take]
                    .copy_from_slice(&bytes[..take]);
                state.header_len += take;
                bytes = &bytes[take..];
                if state.header_len == RECORD_HEADER_LEN && !self.start_record(idx) {
                    self.disable();
                }
            } else {
                let take = bytes.len().min(state.remaining);
                let piece = &bytes[..take];
                if !self.consume_body(idx, piece) {
                    self.disable();
                    break;
                }
                bytes = &bytes[take..];
                let state = &mut self.directions[idx];
                state.remaining -= take;
                if state.remaining == 0 {
                    state.last_protected = state.header[0] == 0x17;
                    state.protected |= state.last_protected;
                    state.header_len = 0;
                }
            }
        }
        Ok(())
    }

    /// True after a supported negotiation and complete protected records both ways.
    #[must_use]
    pub fn eligible(&self) -> bool {
        !self.disabled && self.server_hello && self.directions.iter().all(|d| d.protected)
    }

    /// True only immediately after a complete protected record in this direction.
    #[must_use]
    pub fn is_boundary(&self, direction: VisionDirection) -> bool {
        let state = &self.directions[index(direction)];
        !self.disabled && state.header_len == 0 && state.last_protected
    }

    /// Limit a read to the next record header/body boundary while observing.
    ///
    /// A nonzero `max` produces at least one; disabled observers return `max`.
    /// The caller may forward each partial read immediately as wrapped DATA.
    #[must_use]
    pub fn read_limit(&self, direction: VisionDirection, max: usize) -> usize {
        if self.disabled {
            return max;
        }
        let state = &self.directions[index(direction)];
        let remaining = if state.header_len < RECORD_HEADER_LEN {
            RECORD_HEADER_LEN - state.header_len
        } else {
            state.remaining
        };
        max.min(remaining.max(1))
    }

    /// Total bytes supplied in one direction, including after disabling.
    #[must_use]
    pub fn offset(&self, direction: VisionDirection) -> u64 {
        self.directions[index(direction)].offset
    }

    /// Whether this session must permanently retain its outer encryption.
    #[must_use]
    pub const fn disabled(&self) -> bool {
        self.disabled
    }

    /// Permanently disable observation, for example when its runtime deadline expires.
    pub fn disable(&mut self) {
        self.disabled = true;
        self.offer = None;
        for state in &mut self.directions {
            state.handshake = Vec::new();
            state.header_len = 0;
            state.remaining = 0;
        }
    }

    fn start_record(&mut self, idx: usize) -> bool {
        let state = &self.directions[idx];
        let header = state.header;
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let valid = match header[0] {
            0x16 => {
                !state.hello_done
                    && !state.protected
                    && len > 0
                    && len <= 16_384
                    && (header[1..3] == [3, 3] || (idx == 0 && header[1..3] == [3, 1]))
                    && (idx == 0 || self.offer.is_some())
            }
            0x14 => {
                self.offer.is_some()
                    && !state.protected
                    && state.handshake.is_empty()
                    && header[1..] == [3, 3, 0, 1]
            }
            0x17 => self.server_hello && state.hello_done && protected_record_len(&header).is_ok(),
            _ => false,
        };
        if valid {
            self.directions[idx].remaining = len;
        }
        valid
    }

    fn consume_body(&mut self, idx: usize, bytes: &[u8]) -> bool {
        match self.directions[idx].header[0] {
            0x16 => self.consume_handshake(idx, bytes),
            0x14 => bytes == [1],
            0x17 => true,
            _ => false,
        }
    }

    fn consume_handshake(&mut self, idx: usize, bytes: &[u8]) -> bool {
        let state = &mut self.directions[idx];
        if state.hello_done || state.handshake.len() + bytes.len() > MAX_HANDSHAKE_LEN {
            return false;
        }
        // Vec's default growth can exceed 64 KiB for awkward read sizes.
        // Reserve a bounded power of two explicitly before appending instead.
        let needed = state.handshake.len() + bytes.len();
        if needed > state.handshake.capacity()
            && state
                .handshake
                .try_reserve_exact(needed.next_power_of_two() - state.handshake.len())
                .is_err()
        {
            return false;
        }
        state.handshake.extend_from_slice(bytes);
        if state
            .handshake
            .first()
            .is_some_and(|kind| *kind != if idx == 0 { 1 } else { 2 })
        {
            return false;
        }
        if state.handshake.len() < 4 {
            return true;
        }
        let declared = 4
            + (usize::from(state.handshake[1]) << 16)
            + (usize::from(state.handshake[2]) << 8)
            + usize::from(state.handshake[3]);
        if declared > MAX_HANDSHAKE_LEN || state.handshake.len() > declared {
            return false;
        }
        if state.handshake.len() < declared {
            return true;
        }
        // Exactly one cleartext hello must end at the end of its final record.
        if state.remaining != bytes.len() {
            return false;
        }
        let handshake = core::mem::take(&mut state.handshake);
        let valid = if idx == 0 {
            self.offer = parse_client_hello(&handshake[4..]);
            self.offer.is_some()
        } else {
            self.server_hello = self
                .offer
                .as_ref()
                .is_some_and(|offer| parse_server_hello(&handshake[4..], offer));
            self.server_hello
        };
        self.directions[idx].hello_done = valid;
        valid
    }
}

const fn index(direction: VisionDirection) -> usize {
    match direction {
        VisionDirection::ClientToTarget => 0,
        VisionDirection::TargetToClient => 1,
    }
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }
    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn word(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.byte()?);
        self.take(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.word()?);
        self.take(n)
    }
}

struct Extensions<'a>(&'a [u8]);

impl<'a> Extensions<'a> {
    fn find(&self, wanted: u16) -> Option<&'a [u8]> {
        let mut cursor = Cursor(self.0);
        while !cursor.0.is_empty() {
            let kind = cursor.word()?;
            let data = cursor.vec16()?;
            if kind == wanted {
                return Some(data);
            }
        }
        None
    }
}

fn extensions(input: &[u8]) -> Option<Extensions<'_>> {
    let mut cursor = Cursor(input);
    let mut seen = [0_u64; 1024];
    while !cursor.0.is_empty() {
        let kind = cursor.word()?;
        let entry = &mut seen[usize::from(kind / 64)];
        let bit = 1_u64 << (kind % 64);
        if *entry & bit != 0 {
            return None;
        }
        *entry |= bit;
        cursor.vec16()?;
    }
    Some(Extensions(input))
}

fn words(input: &[u8]) -> Option<impl Iterator<Item = u16> + '_> {
    if input.is_empty() || !input.len().is_multiple_of(2) {
        return None;
    }
    Some(
        input
            .chunks_exact(2)
            .map(|b| u16::from_be_bytes([b[0], b[1]])),
    )
}

fn cipher_bit(cipher: u16) -> u8 {
    match cipher {
        0x1301 => 1,
        0x1302 => 2,
        0x1303 => 4,
        _ => 0,
    }
}

fn key_len(group: u16, server: bool) -> Option<usize> {
    match group {
        0x0017 => Some(65),
        0x0018 => Some(97),
        0x0019 => Some(133),
        0x001d => Some(32),
        0x001e => Some(56),
        0x11ec => Some(if server { 1120 } else { 1216 }),
        _ => None,
    }
}

fn valid_key(group: u16, key: &[u8], server: bool) -> bool {
    key_len(group, server) == Some(key.len())
        && (!matches!(group, 0x0017..=0x0019) || key.first() == Some(&4))
}

fn parse_shares(input: &[u8], groups: &[u64; 1024]) -> Option<Vec<u16>> {
    let mut outer = Cursor(input);
    let mut cursor = Cursor(outer.vec16()?);
    if !outer.0.is_empty() {
        return None;
    }
    let mut seen = [0_u64; 1024];
    let mut known = Vec::new();
    while !cursor.0.is_empty() {
        let group = cursor.word()?;
        let key = cursor.vec16()?;
        let entry = &mut seen[usize::from(group / 64)];
        let bit = 1_u64 << (group % 64);
        if *entry & bit != 0 || key.is_empty() || groups[usize::from(group / 64)] & bit == 0 {
            return None;
        }
        *entry |= bit;
        if key_len(group, false).is_some() {
            if !valid_key(group, key, false) {
                return None;
            }
            known.push(group);
        }
    }
    Some(known)
}

fn parse_client_hello(input: &[u8]) -> Option<ClientOffer> {
    let mut cursor = Cursor(input);
    if cursor.word()? != 0x0303 {
        return None;
    }
    cursor.take(32)?;
    let session_id = cursor.vec8()?;
    if session_id.len() > 32 {
        return None;
    }
    let ciphers = words(cursor.vec16()?)?.fold(0, |mask, cipher| mask | cipher_bit(cipher));
    if cursor.vec8()? != [0] {
        return None;
    }
    let exts = extensions(cursor.vec16()?)?;
    if !cursor.0.is_empty() || exts.find(41).is_some() || exts.find(42).is_some() {
        return None;
    }
    let mut version_cursor = Cursor(exts.find(43)?);
    if !words(version_cursor.vec8()?)?.any(|version| version == 0x0304)
        || !version_cursor.0.is_empty()
    {
        return None;
    }
    let mut group_cursor = Cursor(exts.find(10)?);
    let mut groups = [0_u64; 1024];
    for group in words(group_cursor.vec16()?)? {
        let entry = &mut groups[usize::from(group / 64)];
        let bit = 1_u64 << (group % 64);
        if *entry & bit != 0 {
            return None;
        }
        *entry |= bit;
    }
    if !group_cursor.0.is_empty() {
        return None;
    }
    let shares = parse_shares(exts.find(51)?, &groups)?;
    // Full (non-PSK) TLS 1.3 must offer a nonempty, correctly framed signature list.
    let mut signatures = Cursor(exts.find(13)?);
    let _ = words(signatures.vec16()?)?;
    if !signatures.0.is_empty() || ciphers == 0 || shares.is_empty() {
        return None;
    }
    Some(ClientOffer {
        session_id: session_id.to_vec(),
        ciphers,
        shares,
    })
}

fn parse_server_hello(input: &[u8], offer: &ClientOffer) -> bool {
    parse_server_hello_fields(input, offer).is_some()
}

fn parse_server_hello_fields(input: &[u8], offer: &ClientOffer) -> Option<()> {
    let mut cursor = Cursor(input);
    if cursor.word()? != 0x0303 || cursor.take(32)? == HRR_RANDOM {
        return None;
    }
    if cursor.vec8()? != offer.session_id {
        return None;
    }
    if cipher_bit(cursor.word()?) & offer.ciphers == 0 || cursor.byte()? != 0 {
        return None;
    }
    let exts = extensions(cursor.vec16()?)?;
    if !cursor.0.is_empty() || exts.find(41).is_some() || exts.find(42).is_some() {
        return None;
    }
    if exts.find(43)? != [3, 4] {
        return None;
    }
    let mut share = Cursor(exts.find(51)?);
    let group = share.word()?;
    let key = share.vec16()?;
    if !share.0.is_empty() || !offer.shares.contains(&group) || !valid_key(group, key, true) {
        return None;
    }
    Some(())
}

#[cfg(test)]
mod tests;
