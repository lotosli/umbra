//! RFC 8701 GREASE helpers.

/// Return true when `value` is a GREASE value.
#[must_use]
pub const fn is_grease(value: u16) -> bool {
    let high = value >> 8;
    let low = value & 0x00ff;
    high == low && (value & 0x0f0f) == 0x0a0a
}

/// Remove GREASE values while preserving order of all other values.
#[must_use]
pub fn without_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect()
}
