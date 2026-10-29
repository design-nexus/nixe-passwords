//! The D-Bus interface each peer connection is served (docs/GLIMPSE_API.md). One
//! object per connection, carrying that peer's scope; the methods hand over to `Vault`,
//! which checks it.

use std::sync::Arc;

use nyx_passwords_core::api::{TwoFactor, TwoFactorAnswer};
use nyx_passwords_core::secret::Secret;
use nyx_passwords_proto::{Error as Code, Item};
use zbus::{DBusError, interface};

use super::peer::Scope;
use super::vault::{Failure, SignInResult, Vault};

/// D-Bus errors, named as `nyx_passwords_proto::Error` (a test keeps them in step).
#[derive(Debug, DBusError)]
#[zbus(prefix = "io.github.design_nexus.nyx.Passwords1.Error")]
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
    NeedsPassword(String),
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
            Code::NeedsPassword => Error::NeedsPassword(m),
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

#[interface(name = "io.github.design_nexus.nyx.Passwords1")]
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

    /// A site's icon (website icons must be turned on); `NoField` when it has none.
    async fn icon(&self, host: String) -> Result<Vec<u8>, Error> {
        Ok(self.vault.icon(self.scope, &host).await?)
    }

    /// Goes up with each sync applied, so the window knows when to list again.
    async fn revision(&self) -> Result<u64, Error> {
        Ok(self.vault.revision(self.scope).await?)
    }

    /// Whether an update has replaced this daemon's binary since it started.
    async fn outdated(&self) -> bool {
        super::replaced()
    }

    /// Locks and starts again on the updated binary.
    async fn restart(&self) -> Result<(), Error> {
        Ok(self.vault.restart_for_update(self.scope)?)
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

    /// Signs in with the account's API key (`user.<id>` and its secret), then opens the
    /// vault with the master password.
    async fn sign_in_with_api_key(
        &self,
        server: String,
        client_id: String,
        secret: String,
        password: String,
    ) -> Result<(), Error> {
        Ok(self.vault.sign_in_with_api_key(self.scope, &server, &client_id, Secret::new(secret), Secret::new(password)).await?)
    }

    /// Asks the account's other devices to approve signing in here; returns the
    /// fingerprint phrase both show.
    async fn request_device_sign_in(&self, server: String, email: String) -> Result<String, Error> {
        Ok(self.vault.request_device_sign_in(self.scope, &server, &email).await?)
    }

    /// True once another device approved and the vault is open.
    async fn poll_device_sign_in(&self) -> Result<bool, Error> {
        Ok(self.vault.poll_device_sign_in(self.scope).await?)
    }

    async fn cancel_device_sign_in(&self) -> Result<(), Error> {
        Ok(self.vault.cancel_device_sign_in(self.scope).await?)
    }

    /// Other devices asking to sign in with this account, as JSON.
    async fn sign_in_requests(&self) -> Result<String, Error> {
        Ok(self.vault.sign_in_requests(self.scope).await?)
    }

    async fn answer_sign_in(&self, id: String, approve: bool) -> Result<(), Error> {
        Ok(self.vault.answer_sign_in(self.scope, &id, approve).await?)
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

    /// The current one-time code: `(code, period, seconds left)`.
    async fn totp(&self, id: String) -> Result<(String, u32, u32), Error> {
        let (code, period, left) = self.vault.totp(self.scope, &id).await?;
        Ok((code.expose().to_string(), period, left))
    }

    /// An item's other fields (card, identity, SSH key, custom) as JSON; secret values
    /// are left out.
    async fn fields(&self, id: String) -> Result<String, Error> {
        Ok(self.vault.fields(self.scope, &id).await?)
    }

    /// A password for the editor, from rules as JSON (`{"kind":"password",…}`).
    async fn generate_password(&self, rules: String) -> Result<String, Error> {
        Ok(self.vault.generate_password(self.scope, &rules).await?.expose().to_string())
    }

    /// A username from the generator settings; `site` is the login's address or empty.
    async fn generate_username(&self, site: String) -> Result<String, Error> {
        Ok(self.vault.generate_username(self.scope, &site).await?.expose().to_string())
    }

    /// Saves an email alias service's API token in the keyring; empty removes it.
    async fn set_forwarder_token(&self, service: String, token: String) -> Result<(), Error> {
        Ok(self.vault.set_forwarder_token(self.scope, &service, Secret::new(token)).await?)
    }

    /// Which alias services have a token saved, as JSON `{service: bool}`.
    async fn forwarder_tokens(&self) -> Result<String, Error> {
        Ok(self.vault.forwarder_tokens(self.scope).await?)
    }

    /// An item's passkeys, as JSON (no keys).
    async fn passkeys(&self, id: String) -> Result<String, Error> {
        Ok(self.vault.passkeys(self.scope, &id).await?)
    }

    async fn delete_passkey(&self, id: String, credential_id: String) -> Result<(), Error> {
        Ok(self.vault.delete_passkey(self.scope, &id, &credential_id).await?)
    }

    /// Emergency contacts both ways, as JSON.
    async fn emergency_contacts(&self) -> Result<String, Error> {
        Ok(self.vault.emergency_contacts(self.scope).await?)
    }

    /// An emergency-access action on contact `arg` (or `invite` with an email and the
    /// wait in days); returns a fingerprint phrase for `fingerprint` and `me`.
    async fn emergency(&self, action: String, arg: String, days: u32) -> Result<String, Error> {
        Ok(self.vault.emergency(self.scope, &action, &arg, days).await?)
    }

    /// Opens a grantor's vault for viewing; its listing as JSON.
    async fn view_emergency(&self, id: String) -> Result<String, Error> {
        Ok(self.vault.view_emergency(self.scope, &id).await?)
    }

    /// One field of an item in the open grantor's vault.
    async fn emergency_reveal(&self, id: String, field: String) -> Result<String, Error> {
        Ok(self.vault.emergency_reveal(self.scope, &id, &field).await?.expose().to_string())
    }

    /// Copies the n-th value of the generator history; returns the seconds until cleared.
    async fn copy_generated(&self, index: u32) -> Result<u32, Error> {
        Ok(self.vault.copy_generated(self.scope, index).await?)
    }

    /// What the generators made while the vault was open: JSON `[{what, value, when}]`.
    async fn generator_history(&self) -> Result<String, Error> {
        Ok(self.vault.generator_history(self.scope).await?)
    }

    /// Creates a login from a JSON draft; returns its id.
    async fn create_login(&self, draft: String) -> Result<String, Error> {
        Ok(self.vault.create_login(self.scope, &draft).await?)
    }

    async fn update_login(&self, id: String, draft: String) -> Result<(), Error> {
        Ok(self.vault.update_login(self.scope, &id, &draft).await?)
    }

    /// A new Ed25519 key as JSON `{private, public, fingerprint}`.
    async fn generate_ssh_key(&self) -> Result<String, Error> {
        Ok(self.vault.generate_ssh_key(self.scope)?)
    }

    /// The public key and fingerprint of an OpenSSH private key, as JSON.
    async fn read_ssh_key(&self, private: String) -> Result<String, Error> {
        Ok(self.vault.read_ssh_key(self.scope, &private)?)
    }

    /// Creates a note, card, identity or SSH key from a JSON draft; returns its id.
    async fn create_item(&self, draft: String) -> Result<String, Error> {
        Ok(self.vault.create_item(self.scope, &draft).await?)
    }

    async fn update_item(&self, id: String, draft: String) -> Result<(), Error> {
        Ok(self.vault.update_item(self.scope, &id, &draft).await?)
    }

    /// Logins with a reused, weak or old password, as JSON.
    async fn report(&self) -> Result<String, Error> {
        Ok(self.vault.report(self.scope).await?)
    }

    /// Breach counts from Have I Been Pwned (k-anonymity: hash prefixes only), as JSON.
    async fn check_breaches(&self) -> Result<String, Error> {
        Ok(self.vault.check_breaches(self.scope).await?)
    }

    /// An item's attachments as JSON `[{id, name, size}]`.
    async fn attachments(&self, id: String) -> Result<String, Error> {
        Ok(self.vault.attachments(self.scope, &id).await?)
    }

    /// Decrypts an attachment into `file` (a handle to where the user chose to save it);
    /// returns the bytes written.
    async fn save_attachment(&self, id: String, attachment: String, file: zbus::zvariant::OwnedFd) -> Result<u64, Error> {
        let file = std::fs::File::from(std::os::fd::OwnedFd::from(file));
        Ok(self.vault.save_attachment(self.scope, &id, &attachment, file).await?)
    }

    /// Encrypts `file` (a handle to the file the user picked) as a new attachment.
    async fn add_attachment(&self, id: String, name: String, file: zbus::zvariant::OwnedFd) -> Result<(), Error> {
        let file = std::fs::File::from(std::os::fd::OwnedFd::from(file));
        Ok(self.vault.add_attachment(self.scope, &id, &name, file).await?)
    }

    async fn delete_attachment(&self, id: String, attachment: String) -> Result<(), Error> {
        Ok(self.vault.delete_attachment(self.scope, &id, &attachment).await?)
    }

    /// Unlocks with the key saved in the desktop keyring.
    async fn unlock_with_keyring(&self) -> Result<(), Error> {
        Ok(self.vault.unlock_with_keyring(self.scope).await?)
    }

    /// Whether unlocking with the keyring is set up.
    async fn keyring_unlock(&self) -> Result<bool, Error> {
        Ok(self.vault.keyring_unlock(self.scope).await?)
    }

    /// Turns unlocking with the keyring on (the vault must be unlocked) or off.
    async fn set_keyring_unlock(&self, on: bool) -> Result<(), Error> {
        Ok(self.vault.set_keyring_unlock(self.scope, on).await?)
    }

    async fn trash(&self, id: String) -> Result<(), Error> {
        Ok(self.vault.trash(self.scope, &id, false).await?)
    }

    async fn restore(&self, id: String) -> Result<(), Error> {
        Ok(self.vault.trash(self.scope, &id, true).await?)
    }

    /// `ids` is a JSON list of item ids.
    async fn trash_items(&self, ids: String) -> Result<(), Error> {
        Ok(self.vault.trash_many(self.scope, &ids, false).await?)
    }

    async fn restore_items(&self, ids: String) -> Result<(), Error> {
        Ok(self.vault.trash_many(self.scope, &ids, true).await?)
    }

    /// Deletes items in the trash for good.
    async fn delete_forever(&self, ids: String) -> Result<(), Error> {
        Ok(self.vault.delete_forever(self.scope, &ids).await?)
    }

    /// Puts items in a folder; an empty `folder` means none.
    async fn move_items(&self, ids: String, folder: String) -> Result<(), Error> {
        Ok(self.vault.move_items(self.scope, &ids, &folder).await?)
    }

    async fn create_folder(&self, name: String) -> Result<String, Error> {
        Ok(self.vault.create_folder(self.scope, &name).await?)
    }

    async fn rename_folder(&self, id: String, name: String) -> Result<(), Error> {
        Ok(self.vault.rename_folder(self.scope, &id, &name).await?)
    }

    async fn delete_folder(&self, id: String) -> Result<(), Error> {
        Ok(self.vault.delete_folder(self.scope, &id).await?)
    }

    /// An item's old passwords as JSON `[{index, date}]`, newest first.
    async fn history(&self, id: String) -> Result<String, Error> {
        Ok(self.vault.history(self.scope, &id).await?)
    }

    /// Writes an export into `file` (a handle the app opened where the user chose).
    async fn export(&self, format: String, password: String, file: zbus::zvariant::OwnedFd) -> Result<(), Error> {
        let file = std::fs::File::from(std::os::fd::OwnedFd::from(file));
        Ok(self.vault.export(self.scope, &format, &password, file).await?)
    }

    /// What importing `file` would add, as JSON.
    async fn import_preview(&self, password: String, file: zbus::zvariant::OwnedFd) -> Result<String, Error> {
        let file = std::fs::File::from(std::os::fd::OwnedFd::from(file));
        Ok(self.vault.import_preview(self.scope, &password, file).await?)
    }

    /// Imports `file`; returns how many items it added.
    async fn import(&self, password: String, file: zbus::zvariant::OwnedFd) -> Result<u32, Error> {
        let file = std::fs::File::from(std::os::fd::OwnedFd::from(file));
        Ok(self.vault.import(self.scope, &password, file).await?)
    }

    /// Opens a private key that has a passphrase: JSON `{private, public, fingerprint}`.
    async fn open_ssh_key(&self, private: String, passphrase: String) -> Result<String, Error> {
        Ok(self.vault.open_ssh_key(self.scope, &private, &passphrase)?)
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
