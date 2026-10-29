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
    /// Protected by a passphrase: open it with `read_with_passphrase`.
    Encrypted,
    WrongPassphrase,
    Unreadable,
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::Encrypted => "this key has a passphrase",
            Self::WrongPassphrase => "that passphrase doesn't open this key",
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

/// A private key protected by a passphrase, opened with it. The key is kept without the
/// passphrase, as the official clients store keys (the vault encrypts it instead).
pub fn read_with_passphrase(private: &str, passphrase: &Secret) -> Result<SshKey, SshError> {
    let key = PrivateKey::from_openssh(private.trim()).map_err(|_| SshError::Unreadable)?;
    if !key.is_encrypted() {
        return Ok(describe(&key));
    }
    let opened = key.decrypt(passphrase.expose().as_bytes()).map_err(|_| SshError::WrongPassphrase)?;
    Ok(describe(&opened))
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
    fn opens_keys_with_their_passphrase() {
        // Made with `ssh-keygen -t ed25519 -N 'nyx test passphrase'`; never used anywhere.
        let locked = include_str!("../tests/fixtures/ssh-ed25519-known-passphrase");
        assert_eq!(read(locked).err(), Some(SshError::Encrypted));
        let wrong = read_with_passphrase(locked, &Secret::new("not it"));
        assert_eq!(wrong.err(), Some(SshError::WrongPassphrase));
        let opened = read_with_passphrase(locked, &Secret::new("nyx test passphrase")).unwrap();
        assert!(opened.public.starts_with("ssh-ed25519 ") && opened.fingerprint.starts_with("SHA256:"));
        // Stored without the passphrase: it reads back as is.
        assert_eq!(read(opened.private.expose()).unwrap().fingerprint, opened.fingerprint);
        // A key without one opens whatever the passphrase.
        assert_eq!(read_with_passphrase(KEY, &Secret::new("x")).unwrap().fingerprint, FINGERPRINT.trim());
    }

    #[test]
    fn refuses_passphrases_and_junk() {
        assert_eq!(read(include_str!("../tests/fixtures/ssh-ed25519-passphrase")).err(), Some(SshError::Encrypted));
        assert_eq!(read("not a key").err(), Some(SshError::Unreadable));
        assert_eq!(read(PUBLIC).err(), Some(SshError::Unreadable));
    }
}
