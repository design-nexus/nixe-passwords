//! Creating, editing, trashing and restoring logins. Changes go to the server first; the
//! local copy and the view take the server's answer, so they never hold an edit the
//! server refused.
//!
//! An edit is sent with the revision it was based on. If the item changed elsewhere in
//! the meantime the server refuses it (`ApiError::Conflict`); the latest copy is then
//! fetched into the vault and the caller still has its draft to show against it.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use uuid::Uuid;

use crate::api::{ApiError, Server};
use crate::crypto::{ItemKey, uri_checksum};
use crate::model::{Cipher, Kind, Login, LoginUri};
use crate::secret::Secret;
use crate::session::{Result, Session, SessionError};
use crate::store::Store;

/// Official clients keep this many old passwords per item.
const HISTORY: usize = 5;

/// What the user typed for a login. Empty options mean "none".
pub struct LoginDraft {
    pub name: Secret,
    pub username: Option<Secret>,
    pub password: Option<Secret>,
    /// An `otpauth://` URI or a base32 secret.
    pub totp: Option<Secret>,
    pub uris: Vec<Secret>,
    pub notes: Option<Secret>,
    pub folder: Option<Uuid>,
    pub favorite: bool,
    /// Ask for the master password again before showing the item's secrets.
    pub reprompt: bool,
}

impl Session {
    /// Creates a personal login and returns its id.
    pub async fn create_login(
        &mut self,
        store: &mut Store,
        server: &Server,
        refresh: &Secret,
        draft: &LoginDraft,
    ) -> Result<Uuid> {
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let body = {
            let mut key = self.keys.item(None, None)?;
            let login = fill_login(&mut key, Login::default(), None, draft)?;
            json!({
                "type": Kind::Login.number(),
                "name": key.encrypt(draft.name.expose())?,
                "notes": encrypt_opt(&mut key, draft.notes.as_ref())?,
                "folderId": draft.folder,
                "organizationId": null,
                "key": null,
                "favorite": draft.favorite,
                "reprompt": i64::from(draft.reprompt),
                "fields": null,
                "passwordHistory": null,
                "login": login,
                "encryptedFor": self.snapshot.profile.id,
            })
        };
        let made = server.create_cipher(&access, &body).await?;
        let id = made.id;
        self.take(store, made)?;
        Ok(id)
    }

    /// Saves a changed login. Fields this client doesn't edit (custom fields, passkeys,
    /// attachments, unknown fields) are sent back as they were.
    pub async fn update_login(
        &mut self,
        store: &mut Store,
        server: &Server,
        refresh: &Secret,
        id: Uuid,
        draft: &LoginDraft,
    ) -> Result<()> {
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let old = self.cipher(id)?.clone();
        if old.kind() != Kind::Login {
            return Err(SessionError::Api(ApiError::Protocol));
        }
        let mut new = old.clone();
        {
            let mut key = self.keys.item(old.organization_id, old.key.as_deref())?;
            new.name = key.encrypt(draft.name.expose())?;
            new.notes = encrypt_opt(&mut key, draft.notes.as_ref())?;
            new.folder_id = draft.folder;
            new.favorite = draft.favorite;
            new.reprompt = i64::from(draft.reprompt);
            let login = fill_login(&mut key, old.login.clone().unwrap_or_default(), old.login.as_ref(), draft)?;
            let old_password = old.login.as_ref().and_then(|l| l.password.as_deref());
            if password_changed(&mut key, old_password, draft.password.as_ref())? {
                push_history(&mut new, old_password);
            }
            new.login = Some(login);
        }
        let body = new.to_request(self.snapshot.profile.id, Some(&old.revision_date));
        match server.update_cipher(&access, id, &body).await {
            Ok(saved) => self.take(store, saved),
            Err(ApiError::Conflict) => {
                // Bring in what the server has now; the caller keeps the draft.
                let latest = server.get_cipher(&access, id).await?;
                self.take(store, latest)?;
                Err(SessionError::Api(ApiError::Conflict))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Moves an item to the trash (it can be restored there).
    pub async fn trash(&mut self, store: &mut Store, server: &Server, refresh: &Secret, id: Uuid) -> Result<()> {
        let access = Secret::new(self.access(server, refresh).await?.expose());
        self.cipher(id)?;
        server.trash_cipher(&access, id).await?;
        let trashed = server.get_cipher(&access, id).await?;
        self.take(store, trashed)
    }

    pub async fn restore(&mut self, store: &mut Store, server: &Server, refresh: &Secret, id: Uuid) -> Result<()> {
        let access = Secret::new(self.access(server, refresh).await?.expose());
        self.cipher(id)?;
        let restored = server.restore_cipher(&access, id).await?;
        self.take(store, restored)
    }

    fn cipher(&self, id: Uuid) -> Result<&Cipher> {
        self.snapshot.ciphers.iter().find(|c| c.id == id).ok_or(SessionError::Api(ApiError::NotFound))
    }

    /// Puts the server's copy of an item into the store, the snapshot and the view.
    fn take(&mut self, store: &mut Store, cipher: Cipher) -> Result<()> {
        store.put_cipher(&cipher)?;
        self.view.put(&self.keys, &cipher);
        match self.snapshot.ciphers.iter_mut().find(|c| c.id == cipher.id) {
            Some(slot) => *slot = cipher,
            None => self.snapshot.ciphers.push(cipher),
        }
        Ok(())
    }
}

fn encrypt_opt(key: &mut ItemKey, value: Option<&Secret>) -> Result<Option<String>> {
    match value.filter(|v| !v.is_empty()) {
        Some(v) => Ok(Some(key.encrypt(v.expose())?)),
        None => Ok(None),
    }
}

/// The login part of a request. A web address that was already there keeps its match
/// rule and other settings; each one carries the checksum official clients check.
fn fill_login(key: &mut ItemKey, mut login: Login, old: Option<&Login>, draft: &LoginDraft) -> Result<Login> {
    login.username = encrypt_opt(key, draft.username.as_ref())?;
    login.password = encrypt_opt(key, draft.password.as_ref())?;
    login.totp = encrypt_opt(key, draft.totp.as_ref())?;
    let mut previous = Vec::new();
    for u in old.and_then(|l| l.uris.as_ref()).into_iter().flatten() {
        if let Ok(Some(plain)) = key.decrypt_opt(u.uri.as_deref()) {
            previous.push((plain, u));
        }
    }
    let mut uris = Vec::new();
    for uri in draft.uris.iter().filter(|u| !u.expose().trim().is_empty()) {
        let text = uri.expose().trim();
        let kept = previous.iter().find(|(plain, _)| plain.expose() == text).map(|(_, u)| (*u).clone());
        let mut entry = kept.unwrap_or(LoginUri { uri: None, uri_checksum: None, match_rule: None, extra: Default::default() });
        entry.uri = Some(key.encrypt(text)?);
        entry.uri_checksum = Some(key.encrypt(uri_checksum(text).expose())?);
        uris.push(entry);
    }
    login.uris = (!uris.is_empty()).then_some(uris);
    if old.is_some_and(|o| o.password != login.password) || old.is_none() && login.password.is_some() {
        login.extra.insert("passwordRevisionDate".into(), Value::String(iso8601(now())));
    }
    Ok(login)
}

fn password_changed(key: &mut ItemKey, old: Option<&str>, new: Option<&Secret>) -> Result<bool> {
    let old = key.decrypt_opt(old)?;
    Ok(match (old, new.filter(|n| !n.is_empty())) {
        (Some(o), Some(n)) => !n.same_as(o.expose().as_bytes()),
        (Some(_), None) => true,
        _ => false,
    })
}

/// Adds the old password (still encrypted) to the item's history, newest first.
fn push_history(cipher: &mut Cipher, old_password: Option<&str>) {
    let Some(old) = old_password else { return };
    let mut history = match cipher.extra.remove("passwordHistory") {
        Some(Value::Array(list)) => list,
        _ => Vec::new(),
    };
    history.insert(0, json!({"password": old, "lastUsedDate": iso8601(now())}));
    history.truncate(HISTORY);
    cipher.extra.insert("passwordHistory".into(), Value::Array(history));
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// `2026-10-19T01:37:14.000Z` for seconds since the epoch (UTC, proleptic Gregorian).
fn iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's days-to-civil.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00.000Z");
        assert_eq!(iso8601(1_792_373_834), "2026-10-19T01:37:14.000Z");
    }

    #[test]
    fn history_is_newest_first_and_capped() {
        let raw = std::fs::read_to_string(format!("{}/tests/fixtures/pbkdf2-sync.json", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let sync: crate::model::Sync = serde_json::from_str(&raw).unwrap();
        let mut c = sync.ciphers[0].clone();
        for n in 0..7 {
            push_history(&mut c, Some(&format!("2.old{n}")));
        }
        let list = c.extra["passwordHistory"].as_array().unwrap();
        assert_eq!(list.len(), HISTORY);
        assert_eq!(list[0]["password"], "2.old6");
        assert_eq!(c.to_request(Uuid::nil(), None)["passwordHistory"], c.extra["passwordHistory"]);
    }
}
