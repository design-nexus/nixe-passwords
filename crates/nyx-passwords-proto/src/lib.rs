//! The Nyx Passwords daemon's interface, for the programs that talk to it (the app,
//! Glimpse, the Settings page, the browser bridge). No crypto and no vault code: the
//! daemon holds every key, and clients get metadata or a result. See
//! apps/passwords/docs/GLIMPSE_API.md.

use std::path::PathBuf;

#[cfg(feature = "client")]
pub mod client;

/// Owned on the session bus for single-instance only; vault calls never go there.
pub const BUS_NAME: &str = "io.github.design_nexus.nyx.Passwords";
pub const INTERFACE: &str = "io.github.design_nexus.nyx.Passwords1";
pub const OBJECT_PATH: &str = "/io/github/design_nexus/nyx/Passwords";
/// The systemd user unit that runs the daemon.
pub const SERVICE: &str = "nyx-passwords.service";

/// `$XDG_RUNTIME_DIR/nyx-passwords/bus`: the daemon's peer-to-peer D-Bus socket.
pub fn socket_path() -> Option<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty())?;
    Some(PathBuf::from(runtime).join("nyx-passwords").join("bus"))
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

/// The fields of cards, identities and SSH keys, for the daemon (which reads and
/// writes them) and the window (which shows and edits them).
pub mod fields {
    /// A field of a card, identity or SSH key: where it is in the item, its name in the
    /// interface, what to call it, and whether it stays hidden until asked for.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Spec {
        pub section: &'static str,
        pub key: &'static str,
        pub name: &'static str,
        pub label: &'static str,
        pub secret: bool,
    }

    const fn spec(section: &'static str, key: &'static str, name: &'static str, label: &'static str, secret: bool) -> Spec {
        Spec { section, key, name, label, secret }
    }

    pub const CARD: &[Spec] = &[
        spec("card", "cardholderName", "card.cardholderName", "Cardholder", false),
        spec("card", "brand", "card.brand", "Brand", false),
        spec("card", "number", "card.number", "Number", true),
        spec("card", "expMonth", "card.expMonth", "Expiry month", false),
        spec("card", "expYear", "card.expYear", "Expiry year", false),
        spec("card", "code", "card.code", "Security code", true),
    ];

    pub const IDENTITY: &[Spec] = &[
        spec("identity", "title", "identity.title", "Title", false),
        spec("identity", "firstName", "identity.firstName", "First name", false),
        spec("identity", "middleName", "identity.middleName", "Middle name", false),
        spec("identity", "lastName", "identity.lastName", "Last name", false),
        spec("identity", "username", "identity.username", "Username", false),
        spec("identity", "company", "identity.company", "Company", false),
        spec("identity", "email", "identity.email", "Email", false),
        spec("identity", "phone", "identity.phone", "Phone", false),
        spec("identity", "address1", "identity.address1", "Address", false),
        spec("identity", "address2", "identity.address2", "Address 2", false),
        spec("identity", "address3", "identity.address3", "Address 3", false),
        spec("identity", "city", "identity.city", "City", false),
        spec("identity", "state", "identity.state", "State or province", false),
        spec("identity", "postalCode", "identity.postalCode", "Postal code", false),
        spec("identity", "country", "identity.country", "Country", false),
        spec("identity", "ssn", "identity.ssn", "Social security number", true),
        spec("identity", "passportNumber", "identity.passportNumber", "Passport number", true),
        spec("identity", "licenseNumber", "identity.licenseNumber", "License number", true),
    ];

    pub const SSH_KEY: &[Spec] = &[
        spec("sshKey", "publicKey", "ssh.publicKey", "Public key", false),
        spec("sshKey", "keyFingerprint", "ssh.keyFingerprint", "Fingerprint", false),
        spec("sshKey", "privateKey", "ssh.privateKey", "Private key", true),
    ];

    /// A kind's fields (`card`, `identity`, `ssh`), in the order they're shown.
    pub fn of_kind(kind: &str) -> &'static [Spec] {
        match kind {
            "card" => CARD,
            "identity" => IDENTITY,
            "ssh" => SSH_KEY,
            _ => &[],
        }
    }
}

/// Custom fields with a meaning for Passwords and its extension. They're ordinary custom
/// fields to the official clients, which keep them.
pub mod custom {
    /// The sign-in provider a login uses instead of a password (universal sign-on): one
    /// of `PROVIDERS`.
    pub const SIGN_IN_WITH: &str = "nyx:sign-in-with";
    /// True or false: this login isn't filled as its page loads.
    pub const NO_FILL_ON_LOAD: &str = "nyx:no-fill-on-load";
    /// Providers the extension recognizes: id and name.
    pub const PROVIDERS: &[(&str, &str)] = &[
        ("google", "Google"),
        ("apple", "Apple"),
        ("microsoft", "Microsoft"),
        ("github", "GitHub"),
        ("facebook", "Facebook"),
        ("gitlab", "GitLab"),
        ("twitter", "X"),
        ("linkedin", "LinkedIn"),
        ("amazon", "Amazon"),
        ("slack", "Slack"),
    ];
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
    /// The file is protected by a password: ask for it and try again.
    NeedsPassword,
}

impl Error {
    pub const ALL: [Error; 12] = [
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
        Error::NeedsPassword,
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
            Error::NeedsPassword => "NeedsPassword",
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
        assert_eq!(Error::Locked.name(), "io.github.design_nexus.nyx.Passwords1.Error.Locked");
        assert_eq!(Error::from_name("org.example.Error.Locked"), None);
    }
}
