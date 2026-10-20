//! The refresh token in the desktop keyring (Secret Service, through `secret-tool`). The
//! token goes in on stdin and comes back on stdout, never in arguments; the arguments
//! hold only the server and email, which name the entry.

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

/// Where the refresh token of one account lives.
pub struct Entry {
    pub server: String,
    pub email: String,
}

impl Entry {
    fn tool(&self, verb: &str) -> Command {
        let mut c = Command::new("secret-tool");
        c.arg(verb);
        if verb == "store" {
            c.arg("--label=Nixe Passwords session");
        }
        c.args(["application", "nixe-passwords", "server", &self.server, "account", &self.email]);
        c.stderr(Stdio::null());
        c
    }

    pub fn save(&self, token: &Secret) -> Result<(), KeyringError> {
        let mut child =
            self.tool("store").stdin(Stdio::piped()).stdout(Stdio::null()).spawn().map_err(|_| KeyringError::Missing)?;
        let wrote = child.stdin.take().map(|mut input| input.write_all(token.expose().as_bytes()));
        let status = child.wait().map_err(|_| KeyringError::Refused)?;
        match (wrote, status.success()) {
            (Some(Ok(())), true) => Ok(()),
            _ => Err(KeyringError::Refused),
        }
    }

    /// `None` when there's no saved token.
    pub fn load(&self) -> Result<Option<Secret>, KeyringError> {
        let mut child =
            self.tool("lookup").stdin(Stdio::null()).stdout(Stdio::piped()).spawn().map_err(|_| KeyringError::Missing)?;
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

    pub fn clear(&self) -> Result<(), KeyringError> {
        let status = self.tool("clear").stdin(Stdio::null()).stdout(Stdio::null()).status().map_err(|_| KeyringError::Missing)?;
        if status.success() { Ok(()) } else { Err(KeyringError::Refused) }
    }
}
