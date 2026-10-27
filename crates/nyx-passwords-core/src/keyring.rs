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

/// Which name the suite had when an entry was saved. Entries saved as Nixe are moved
/// to the Nyx names the first time they're read.
#[derive(Clone, Copy, PartialEq)]
enum Era {
    Nyx,
    Nixe,
}

fn application(kind: Kind, era: Era) -> &'static str {
    match (kind, era) {
        (Kind::Session, Era::Nyx) => "nyx-passwords",
        (Kind::UnlockKey, Era::Nyx) => "nyx-passwords-unlock",
        (Kind::Session, Era::Nixe) => "nixe-passwords",
        (Kind::UnlockKey, Era::Nixe) => "nixe-passwords-unlock",
    }
}

impl Entry {
    fn tool(&self, verb: &str, kind: Kind) -> Command {
        self.tool_for(verb, kind, Era::Nyx)
    }

    fn tool_for(&self, verb: &str, kind: Kind, era: Era) -> Command {
        let application = application(kind, era);
        let label = match kind {
            Kind::Session => "Nyx Passwords session",
            Kind::UnlockKey => "Nyx Passwords unlock key",
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

    /// The entry under its Nyx name, else under its Nixe name, which is then copied to
    /// the Nyx name and cleared once the copy reads back.
    fn lookup(&self, kind: Kind) -> Result<Option<Secret>, KeyringError> {
        if let Some(secret) = self.lookup_in(kind, Era::Nyx)? {
            return Ok(Some(secret));
        }
        let Some(secret) = self.lookup_in(kind, Era::Nixe)? else { return Ok(None) };
        if self.store(&secret, kind).is_ok()
            && self.lookup_in(kind, Era::Nyx).ok().flatten().is_some_and(|copy| copy.expose() == secret.expose())
        {
            let _ = self.tool_for("clear", kind, Era::Nixe).stdin(Stdio::null()).stdout(Stdio::null()).status();
        }
        Ok(Some(secret))
    }

    fn lookup_in(&self, kind: Kind, era: Era) -> Result<Option<Secret>, KeyringError> {
        let mut child = self
            .tool_for("lookup", kind, era)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| KeyringError::Missing)?;
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
        let _ = self.tool_for("clear", kind, Era::Nixe).stdin(Stdio::null()).stdout(Stdio::null()).status();
        let status =
            self.tool("clear", kind).stdin(Stdio::null()).stdout(Stdio::null()).status().map_err(|_| KeyringError::Missing)?;
        if status.success() { Ok(()) } else { Err(KeyringError::Refused) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Uses the desktop keyring with a throwaway entry and clears it after:
    /// `cargo test -p nyx-passwords-core keyring -- --ignored`.
    #[test]
    #[ignore]
    fn moves_a_nixe_entry_to_the_nyx_name() {
        let entry =
            Entry { server: format!("https://rename-test-{}.invalid", std::process::id()), email: "test@example.com".into() };
        let mut old = entry.tool_for("store", Kind::Session, Era::Nixe);
        let mut child = old.stdin(Stdio::piped()).stdout(Stdio::null()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(b"token-1").unwrap();
        assert!(child.wait().unwrap().success());

        assert_eq!(entry.load().unwrap().unwrap().expose(), "token-1");
        assert_eq!(entry.lookup_in(Kind::Session, Era::Nyx).unwrap().unwrap().expose(), "token-1");
        assert!(entry.lookup_in(Kind::Session, Era::Nixe).unwrap().is_none());

        entry.clear().unwrap();
        assert!(entry.load().unwrap().is_none());
    }
}
