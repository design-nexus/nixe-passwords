//! The Nixe Passwords daemon's interface, for the programs that talk to it (the app,
//! Glimpse, the Settings page, the browser bridge). No crypto and no vault code: the
//! daemon holds every key, and clients get metadata or a result. See
//! apps/passwords/docs/GLIMPSE_API.md.

use std::path::PathBuf;

#[cfg(feature = "client")]
pub mod client;

/// Owned on the session bus for single-instance only; vault calls never go there.
pub const BUS_NAME: &str = "io.github.design_nexus.nixe.Passwords";
pub const INTERFACE: &str = "io.github.design_nexus.nixe.Passwords1";
pub const OBJECT_PATH: &str = "/io/github/design_nexus/nixe/Passwords";
/// The systemd user unit that runs the daemon.
pub const SERVICE: &str = "nixe-passwords.service";

/// `$XDG_RUNTIME_DIR/nixe-passwords/bus`: the daemon's peer-to-peer D-Bus socket.
pub fn socket_path() -> Option<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty())?;
    Some(PathBuf::from(runtime).join("nixe-passwords").join("bus"))
}

/// The D-Bus address for `socket_path`.
pub fn address() -> Option<String> {
    socket_path().map(|p| format!("unix:path={}", p.display()))
}

/// Vault states, as `Status` reports them.
pub mod state {
    pub const LOGGED_OUT: &str = "logged_out";
    pub const LOCKED: &str = "locked";
    pub const UNLOCKED: &str = "unlocked";
}

/// Fields `Copy` takes.
pub mod field {
    pub const USERNAME: &str = "username";
    pub const PASSWORD: &str = "password";
    pub const TOTP: &str = "totp";
}

/// One search result: `(id, name, username, host, has_totp, kind)`. `kind` is `login`,
/// `note`, `card`, `identity`, `ssh` or `other`; `username` and `host` may be empty.
pub type Item = (String, String, String, String, bool, String);

/// D-Bus error names the daemon replies with, under `INTERFACE.Error.`. Their messages
/// never carry vault data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Locked,
    LoggedOut,
    Denied,
    NotFound,
    NoField,
    NoUrl,
    Clipboard,
    RateLimited,
    /// The item asks for the master password again before showing secrets
    /// (`VerifyPassword`, from the app only).
    Reprompt,
    /// The item changed elsewhere since it was last synced; the latest copy is now in
    /// the vault and the edit wasn't saved.
    Conflict,
    /// Signing in, unlocking or syncing failed; the message says why.
    Failed,
}

impl Error {
    pub const ALL: [Error; 11] = [
        Error::Locked,
        Error::LoggedOut,
        Error::Denied,
        Error::NotFound,
        Error::NoField,
        Error::NoUrl,
        Error::Clipboard,
        Error::RateLimited,
        Error::Reprompt,
        Error::Conflict,
        Error::Failed,
    ];

    pub fn short(self) -> &'static str {
        match self {
            Error::Locked => "Locked",
            Error::LoggedOut => "LoggedOut",
            Error::Denied => "Denied",
            Error::NotFound => "NotFound",
            Error::NoField => "NoField",
            Error::NoUrl => "NoUrl",
            Error::Clipboard => "Clipboard",
            Error::RateLimited => "RateLimited",
            Error::Reprompt => "Reprompt",
            Error::Conflict => "Conflict",
            Error::Failed => "Failed",
        }
    }

    /// The full D-Bus error name.
    pub fn name(self) -> String {
        format!("{INTERFACE}.Error.{}", self.short())
    }

    pub fn from_name(name: &str) -> Option<Error> {
        let short = name.strip_prefix(INTERFACE)?.strip_prefix(".Error.")?;
        Error::ALL.into_iter().find(|e| e.short() == short)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_names_round_trip() {
        for e in Error::ALL {
            assert_eq!(Error::from_name(&e.name()), Some(e));
        }
        assert_eq!(Error::Locked.name(), "io.github.design_nexus.nixe.Passwords1.Error.Locked");
        assert_eq!(Error::from_name("org.example.Error.Locked"), None);
    }
}
