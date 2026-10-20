//! The desktop keyring (Secret Service, through `secret-tool`): the refresh token, and,
//! when "unlock with the system keyring" is on, the vault's user key. Secrets go in on
//! stdin and come back on stdout, never in arguments; the arguments hold only the
//! server and email, which name the entry, and which of the two it is.

use std::fmt;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

use crate::secret::Secret;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyringError {
    /// `secret-tool` isn't installed.
    Missing,
    /// The keyring refused: usually locked, or no Secret Service is running.
    Refused,
}

impl fmt::Display for KeyringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "install libsecret to keep the session between restarts",
            Self::Refused => "the desktop keyring is locked or unavailable",
        })
    }
}

impl std::error::Error for KeyringError {}

/// Where one account's secrets live in the keyring.
pub struct Entry {
    pub server: String,
    pub email: String,
}

/// The two kinds of entry. They differ in `application`, not in an extra attribute: a
/// lookup matches every entry that has the attributes asked for, so a session lookup
/// must not be able to find the unlock key.
#[derive(Clone, Copy)]
enum Kind {
    Session,
    UnlockKey,
}

impl Entry {
    fn tool(&self, verb: &str, kind: Kind) -> Command {
        let (application, label) = match kind {
            Kind::Session => ("nixe-passwords", "Nixe Passwords session"),
            Kind::UnlockKey => ("nixe-passwords-unlock", "Nixe Passwords unlock key"),
        };
        let mut c = Command::new("secret-tool");
        c.arg(verb);
        if verb == "store" {
            c.arg(format!("--label={label}"));
        }
        c.args(["application", application, "server", &self.server, "account", &self.email]);
        c.stderr(Stdio::null());
        c
    }

    /// Saves the refresh token.
    pub fn save(&self, token: &Secret) -> Result<(), KeyringError> {
        self.store(token, Kind::Session)
    }

    /// The refresh token; `None` when there's none saved.
    pub fn load(&self) -> Result<Option<Secret>, KeyringError> {
        self.lookup(Kind::Session)
    }

    pub fn clear(&self) -> Result<(), KeyringError> {
        self.remove(Kind::Session)
    }

    /// Saves the user key, for unlocking without the master password.
    pub fn save_unlock_key(&self, key: &Secret) -> Result<(), KeyringError> {
        self.store(key, Kind::UnlockKey)
    }

    pub fn load_unlock_key(&self) -> Result<Option<Secret>, KeyringError> {
        self.lookup(Kind::UnlockKey)
    }

    pub fn clear_unlock_key(&self) -> Result<(), KeyringError> {
        self.remove(Kind::UnlockKey)
    }

    fn store(&self, token: &Secret, kind: Kind) -> Result<(), KeyringError> {
        let mut child =
            self.tool("store", kind).stdin(Stdio::piped()).stdout(Stdio::null()).spawn().map_err(|_| KeyringError::Missing)?;
        let wrote = child.stdin.take().map(|mut input| input.write_all(token.expose().as_bytes()));
        let status = child.wait().map_err(|_| KeyringError::Refused)?;
        match (wrote, status.success()) {
            (Some(Ok(())), true) => Ok(()),
            _ => Err(KeyringError::Refused),
        }
    }

    fn lookup(&self, kind: Kind) -> Result<Option<Secret>, KeyringError> {
        let mut child =
            self.tool("lookup", kind).stdin(Stdio::null()).stdout(Stdio::piped()).spawn().map_err(|_| KeyringError::Missing)?;
        let mut out = Zeroizing::new(Vec::new());
        let read = child.stdout.take().map(|mut s| s.read_to_end(&mut out));
        let status = child.wait().map_err(|_| KeyringError::Refused)?;
        if !matches!(read, Some(Ok(_))) {
            return Err(KeyringError::Refused);
        }
        // secret-tool exits 1 with no output when nothing matches.
        if !status.success() || out.is_empty() {
            return Ok(None);
        }
        let text = std::str::from_utf8(&out).map_err(|_| KeyringError::Refused)?;
        let token = text.trim_end_matches('\n');
        Ok((!token.is_empty()).then(|| Secret::new(token)))
    }

    fn remove(&self, kind: Kind) -> Result<(), KeyringError> {
        let status =
            self.tool("clear", kind).stdin(Stdio::null()).stdout(Stdio::null()).status().map_err(|_| KeyringError::Missing)?;
        if status.success() { Ok(()) } else { Err(KeyringError::Refused) }
    }
}
