//! Secret byte wrappers with zeroization and redacted formatting.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Fixed-size secret bytes that are zeroized on drop.
///
/// The wrapper intentionally does not expose `Display`, and its `Debug`
/// implementation is redacted. Use [`Secret::expose_secret`] only at primitive
/// call sites that require raw bytes.
pub struct Secret<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Secret<N> {
    /// Wrap raw secret bytes.
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Return a shared reference to the raw secret bytes.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consume the wrapper and return the contained bytes.
    ///
    /// This intentionally transfers the secret to the caller instead of
    /// zeroizing it immediately.
    #[must_use]
    pub fn into_inner(mut self) -> [u8; N] {
        let mut out = [0_u8; N];
        core::mem::swap(&mut out, &mut self.bytes);
        out
    }

    /// Compare two secrets using constant-time byte equality.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.bytes.ct_eq(&other.bytes))
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl<const N: usize> Eq for Secret<N> {}

/// Variable-length secret bytes that are zeroized on drop.
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    /// Wrap raw secret bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Return a shared view of the raw secret bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the secret length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when the secret has zero length.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consume the wrapper and return the contained bytes.
    #[must_use]
    pub fn into_inner(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        core::mem::swap(&mut out, &mut self.bytes);
        out
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}
