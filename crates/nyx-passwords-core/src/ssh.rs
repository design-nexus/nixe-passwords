//! Keys for SSH key items, stored the way the official clients store them: the private
//! key in OpenSSH format, the public key as an `authorized_keys` line, and the
//! fingerprint as `SHA256:…`. The public key and fingerprint always come from the
//! private key, so they can't disagree with it.

use std::fmt;

use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

use crate::secret::Secret;

pub struct SshKey {
    pub private: Secret,
    pub public: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshError {
    /// Protected by a passphrase; this client doesn't take passphrases yet.
    Encrypted,
    Unreadable,
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::Encrypted => "this key has a passphrase; import a copy without one (ssh-keygen -p -N \"\" -f COPY)",
            Self::Unreadable => "this isn't an OpenSSH private key",
        })
    }
}

impl std::error::Error for SshError {}

/// A new Ed25519 key, as the official clients generate.
pub fn generate() -> SshKey {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("Ed25519 key generation");
    describe(&key)
}

/// An OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`), with its public key
/// and fingerprint.
pub fn read(private: &str) -> Result<SshKey, SshError> {
    let key = PrivateKey::from_openssh(private.trim()).map_err(|_| SshError::Unreadable)?;
    if key.is_encrypted() {
        return Err(SshError::Encrypted);
    }
    Ok(describe(&key))
}

fn describe(key: &PrivateKey) -> SshKey {
    let private = key.to_openssh(LineEnding::LF).expect("an unencrypted key encodes");
    let public = key.public_key().to_openssh().expect("a public key encodes");
    SshKey { private: Secret::new(private.as_str()), public, fingerprint: key.fingerprint(HashAlg::Sha256).to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    // An Ed25519 test key made with `ssh-keygen -t ed25519 -N ""`; never used anywhere.
    const KEY: &str = include_str!("../tests/fixtures/ssh-ed25519");
    const PUBLIC: &str = include_str!("../tests/fixtures/ssh-ed25519.pub");
    const FINGERPRINT: &str = include_str!("../tests/fixtures/ssh-ed25519.fp");

    #[test]
    fn reads_what_ssh_keygen_writes() {
        let key = read(KEY).unwrap();
        assert_eq!(key.public, PUBLIC.trim());
        assert_eq!(key.fingerprint, FINGERPRINT.trim());
        assert_eq!(read(key.private.expose()).unwrap().fingerprint, key.fingerprint);
    }

    #[test]
    fn generated_keys_read_back() {
        let made = generate();
        assert!(made.public.starts_with("ssh-ed25519 ") && made.fingerprint.starts_with("SHA256:"));
        let again = read(made.private.expose()).unwrap();
        assert_ne!(generate().fingerprint, again.fingerprint);
        assert_eq!((again.public, again.fingerprint), (made.public, made.fingerprint));
    }

    #[test]
    fn refuses_passphrases_and_junk() {
        assert_eq!(read(include_str!("../tests/fixtures/ssh-ed25519-passphrase")).err(), Some(SshError::Encrypted));
        assert_eq!(read("not a key").err(), Some(SshError::Unreadable));
        assert_eq!(read(PUBLIC).err(), Some(SshError::Unreadable));
    }
}
