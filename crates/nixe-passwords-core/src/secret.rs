//! Values that must never be printed, logged or serialized: decrypted fields, the master
//! password, its server hash, tokens. `Debug` and `Display` print `[redacted]`, there is
//! no `Serialize`, and the memory is zeroized on drop.

use std::fmt;

use zeroize::Zeroizing;

pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The plaintext. Callers hand it straight to where it's used (the clipboard, an
    /// encryption call, an HTTP form) and keep no copy.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Constant-time comparison, for checking whether the clipboard still holds a copy.
    pub fn same_as(&self, other: &[u8]) -> bool {
        let mine = self.0.as_bytes();
        if mine.len() != other.len() {
            return false;
        }
        mine.iter().zip(other).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Secret bytes (attachment contents, key material handed to the store).
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SecretBytes([redacted; {}])", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_prints() {
        let s = Secret::new("hunter2-canary");
        assert_eq!(format!("{s:?}"), "Secret([redacted])");
        assert_eq!(format!("{s}"), "[redacted]");
        assert_eq!(format!("{:?}", Some(&s)), "Some(Secret([redacted]))");
        let b = SecretBytes::new(b"hunter2-canary".to_vec());
        assert!(!format!("{b:?}").contains("hunter2"));
        assert_eq!(s.expose(), "hunter2-canary");
    }

    #[test]
    fn compares_in_full() {
        let s = Secret::new("abc");
        assert!(s.same_as(b"abc"));
        assert!(!s.same_as(b"abd"));
        assert!(!s.same_as(b"ab"));
        assert!(!s.same_as(b"abcd"));
    }
}
