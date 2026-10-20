//! The D-Bus interface each peer connection is served (docs/GLIMPSE_API.md). One
//! object per connection, carrying that peer's scope; the methods hand over to `Vault`,
//! which checks it.

use std::sync::Arc;

use nixe_passwords_core::api::{TwoFactor, TwoFactorAnswer};
use nixe_passwords_core::secret::Secret;
use nixe_passwords_proto::{Error as Code, Item};
use zbus::{DBusError, interface};

use super::peer::Scope;
use super::vault::{Failure, SignInResult, Vault};

/// D-Bus errors, named as `nixe_passwords_proto::Error` (a test keeps them in step).
#[derive(Debug, DBusError)]
#[zbus(prefix = "io.github.design_nexus.nixe.Passwords1.Error")]
pub enum Error {
    #[zbus(error)]
    ZBus(zbus::Error),
    Locked(String),
    LoggedOut(String),
    Denied(String),
    NotFound(String),
    NoField(String),
    NoUrl(String),
    Clipboard(String),
    RateLimited(String),
    Reprompt(String),
    Conflict(String),
    Failed(String),
}

impl From<Failure> for Error {
    fn from(f: Failure) -> Self {
        let m = f.message;
        match f.kind {
            Code::Locked => Error::Locked(m),
            Code::LoggedOut => Error::LoggedOut(m),
            Code::Denied => Error::Denied(m),
            Code::NotFound => Error::NotFound(m),
            Code::NoField => Error::NoField(m),
            Code::NoUrl => Error::NoUrl(m),
            Code::Clipboard => Error::Clipboard(m),
            Code::RateLimited => Error::RateLimited(m),
            Code::Reprompt => Error::Reprompt(m),
            Code::Conflict => Error::Conflict(m),
            Code::Failed => Error::Failed(m),
        }
    }
}

/// Two-step methods as `(number, hint)`: 0 authenticator, 1 email (hint: the masked
/// address), others the client can't complete.
type Methods = Vec<(u8, String)>;

pub struct Service {
    pub vault: Arc<Vault>,
    pub scope: Scope,
    /// For the browser bridge: the browser that started it.
    pub browser: Option<(i32, String)>,
    /// The peer's process, so its own window isn't taken for the one in front.
    pub pid: i32,
}

#[interface(name = "io.github.design_nexus.nixe.Passwords1")]
impl Service {
    /// `(state, server host, seconds a copy stays on the clipboard)`.
    async fn status(&self) -> (String, String, u32) {
        self.vault.status().await
    }

    async fn search(&self, query: String, limit: u32) -> Result<Vec<Item>, Error> {
        Ok(self.vault.search(self.scope, &query, limit).await?)
    }

    async fn suggest(&self, limit: u32) -> Result<(String, Vec<Item>), Error> {
        Ok(self.vault.suggest(self.scope, self.pid, limit).await?)
    }

    /// Puts `field` (`username`, `password`, `totp`) of item `id` on the clipboard.
    /// Returns only the seconds until it's cleared.
    async fn copy(&self, id: String, field: String) -> Result<u32, Error> {
        Ok(self.vault.copy(self.scope, &id, &field).await?)
    }

    async fn open_url(&self, id: String) -> Result<String, Error> {
        Ok(self.vault.open_url(self.scope, &id).await?)
    }

    async fn generate(&self) -> Result<u32, Error> {
        Ok(self.vault.generate(self.scope).await?)
    }

    async fn lock(&self) -> Result<(), Error> {
        if matches!(self.scope, Scope::Glimpse) && !self.vault.settings().await.glimpse {
            return Err(Error::Denied("not allowed".into()));
        }
        self.vault.lock().await;
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        Ok(self.vault.sync(self.scope).await?)
    }

    // ---- the app ----

    /// Signs in. `method` 255 means no two-step answer. Returns `(done, methods)`: when
    /// not done, ask for one of `methods` and call again with its code.
    async fn sign_in(
        &self,
        server: String,
        email: String,
        password: String,
        method: u8,
        code: String,
    ) -> Result<(bool, Methods), Error> {
        let answer = (method != 255).then(|| TwoFactorAnswer { method, code: Secret::new(code) });
        match self.vault.sign_in(self.scope, &server, &email, Secret::new(password), answer).await? {
            SignInResult::Done => Ok((true, Vec::new())),
            SignInResult::TwoFactor(methods) => Ok((false, methods.iter().map(method_pair).collect())),
        }
    }

    async fn send_email_code(&self, server: String, email: String, password: String) -> Result<(), Error> {
        Ok(self.vault.send_email_code(self.scope, &server, &email, Secret::new(password)).await?)
    }

    /// Confirms the master password for items that ask for it again (five minutes).
    async fn verify_password(&self, password: String) -> Result<(), Error> {
        Ok(self.vault.verify_password(self.scope, Secret::new(password)).await?)
    }

    async fn unlock(&self, password: String) -> Result<(), Error> {
        Ok(self.vault.unlock(self.scope, Secret::new(password)).await?)
    }

    async fn sign_out(&self) -> Result<(), Error> {
        Ok(self.vault.sign_out(self.scope).await?)
    }

    /// The vault listing as JSON (names, usernames, addresses, folders; no secrets).
    async fn list(&self) -> Result<String, Error> {
        Ok(self.vault.list(self.scope).await?)
    }

    /// One field's plaintext: `username`, `password`, `totp` (the current code),
    /// `notes` or `custom:N`.
    async fn reveal(&self, id: String, field: String) -> Result<String, Error> {
        Ok(self.vault.reveal(self.scope, &id, &field).await?.expose().to_string())
    }

    /// A password for the editor, from rules as JSON (`{"kind":"password",…}`).
    async fn generate_password(&self, rules: String) -> Result<String, Error> {
        Ok(self.vault.generate_password(self.scope, &rules).await?.expose().to_string())
    }

    /// Creates a login from a JSON draft; returns its id.
    async fn create_login(&self, draft: String) -> Result<String, Error> {
        Ok(self.vault.create_login(self.scope, &draft).await?)
    }

    async fn update_login(&self, id: String, draft: String) -> Result<(), Error> {
        Ok(self.vault.update_login(self.scope, &id, &draft).await?)
    }

    async fn trash(&self, id: String) -> Result<(), Error> {
        Ok(self.vault.trash(self.scope, &id, false).await?)
    }

    async fn restore(&self, id: String) -> Result<(), Error> {
        Ok(self.vault.trash(self.scope, &id, true).await?)
    }

    /// Browser extensions waiting for confirmation (with their codes) and paired ones, as
    /// JSON.
    async fn pairings(&self) -> Result<String, Error> {
        Ok(self.vault.pairings(self.scope).await?)
    }

    async fn confirm_pairing(&self, id: String) -> Result<(), Error> {
        Ok(self.vault.confirm_pairing(self.scope, &id).await?)
    }

    async fn remove_pairing(&self, id: String) -> Result<(), Error> {
        Ok(self.vault.remove_pairing(self.scope, &id).await?)
    }

    // ---- the browser bridge ----

    /// One Native Messaging frame from extension `caller`; returns the reply frame.
    async fn relay(&self, caller: String, frame: Vec<u8>) -> Result<Vec<u8>, Error> {
        let Some(browser) = &self.browser else { return Err(Error::Denied("not allowed".into())) };
        Ok(self.vault.relay(self.scope, &caller, browser, &frame).await?)
    }
}

fn method_pair(m: &TwoFactor) -> (u8, String) {
    let hint = match m {
        TwoFactor::Email { hint } => hint.clone().unwrap_or_default(),
        _ => String::new(),
    };
    (m.number(), hint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_names_match_the_protocol() {
        for code in Code::ALL {
            let e = Error::from(Failure::new(code, "x"));
            assert_eq!(e.name().as_str(), code.name());
        }
    }
}
