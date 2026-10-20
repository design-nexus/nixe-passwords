//! Creating, editing, trashing and restoring logins. Changes go to the server first; the
//! local copy and the view take the server's answer, so they never hold an edit the
//! server refused.
//!
//! An edit is sent with the revision it was based on. If the item changed elsewhere in
//! the meantime the server refuses it (`ApiError::Conflict`); the latest copy is then
//! fetched into the vault and the caller still has its draft to show against it.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::api::{ApiError, Server};
use crate::crypto::{ItemKey, uri_checksum};
use crate::model::{Cipher, Kind, Login, LoginUri};
use crate::secret::Secret;
use crate::session::{Result, Session, SessionError};
use crate::store::Store;
use crate::vault::specs;

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

/// What the user typed for a note, card or identity. `fields` are the kind's own fields
/// by name (`card.number`, …; see `vault::specs`); one left out or empty is cleared.
pub struct ItemDraft {
    pub kind: Kind,
    pub name: Secret,
    pub fields: Vec<(String, Secret)>,
    pub notes: Option<Secret>,
    pub folder: Option<Uuid>,
    pub favorite: bool,
    pub reprompt: bool,
}

/// The kinds `create_item` and `update_item` handle (logins have their own draft).
pub fn editable(kind: Kind) -> bool {
    matches!(kind, Kind::Note | Kind::Card | Kind::Identity)
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
            let has_password = draft.password.as_ref().is_some_and(|p| !p.is_empty());
            let login = fill_login(&mut key, Login::default(), None, draft, has_password)?;
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
            let old_password = old.login.as_ref().and_then(|l| l.password.as_deref());
            let changed = password_changed(&mut key, old_password, draft.password.as_ref())?;
            let login = fill_login(&mut key, old.login.clone().unwrap_or_default(), old.login.as_ref(), draft, changed)?;
            if changed {
                push_history(&mut new, old_password);
            }
            new.login = Some(login);
        }
        self.send_update(store, server, &access, &old, &new).await
    }

    /// Creates a personal note, card or identity and returns its id.
    pub async fn create_item(&mut self, store: &mut Store, server: &Server, refresh: &Secret, draft: &ItemDraft) -> Result<Uuid> {
        if !editable(draft.kind) {
            return Err(SessionError::Api(ApiError::Protocol));
        }
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let body = {
            let mut key = self.keys.item(None, None)?;
            let mut body = json!({
                "type": draft.kind.number(),
                "name": key.encrypt(draft.name.expose())?,
                "notes": encrypt_opt(&mut key, draft.notes.as_ref())?,
                "folderId": draft.folder,
                "organizationId": null,
                "key": null,
                "favorite": draft.favorite,
                "reprompt": i64::from(draft.reprompt),
                "fields": null,
                "passwordHistory": null,
                "encryptedFor": self.snapshot.profile.id,
            });
            body[section_name(draft.kind)] = fill_section(&mut key, None, draft)?;
            body
        };
        let made = server.create_cipher(&access, &body).await?;
        let id = made.id;
        self.take(store, made)?;
        Ok(id)
    }

    /// Saves a changed note, card or identity. Its custom fields, attachments and any
    /// field this client doesn't know are sent back as they were.
    pub async fn update_item(
        &mut self,
        store: &mut Store,
        server: &Server,
        refresh: &Secret,
        id: Uuid,
        draft: &ItemDraft,
    ) -> Result<()> {
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let old = self.cipher(id)?.clone();
        if old.kind() != draft.kind || !editable(draft.kind) {
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
            let section = match draft.kind {
                Kind::Note => &mut new.secure_note,
                Kind::Card => &mut new.card,
                _ => &mut new.identity,
            };
            *section = Some(fill_section(&mut key, section.as_ref(), draft)?);
        }
        self.send_update(store, server, &access, &old, &new).await
    }

    /// Sends an edit based on `old`. If the item changed elsewhere since, the server's
    /// copy is brought in and the caller keeps its draft.
    async fn send_update(
        &mut self,
        store: &mut Store,
        server: &Server,
        access: &Secret,
        old: &Cipher,
        new: &Cipher,
    ) -> Result<()> {
        let body = new.to_request(self.snapshot.profile.id, Some(&old.revision_date));
        match server.update_cipher(access, old.id, &body).await {
            Ok(saved) => self.take(store, saved),
            Err(ApiError::Conflict) => {
                let latest = server.get_cipher(access, old.id).await?;
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

fn section_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Note => "secureNote",
        Kind::Card => "card",
        _ => "identity",
    }
}

/// A note's, card's or identity's own part of a request: each of the kind's fields from
/// the draft, encrypted, or null when empty. Keys this client doesn't know stay as they
/// were.
fn fill_section(key: &mut ItemKey, old: Option<&Value>, draft: &ItemDraft) -> Result<Value> {
    let mut section = match old {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    };
    if draft.kind == Kind::Note {
        section.entry("type").or_insert(json!(0));
    }
    for spec in specs(draft.kind) {
        let value = draft.fields.iter().find(|(name, _)| name == spec.name).map(|(_, v)| v);
        section.insert(spec.key.into(), encrypt_opt(key, value)?.map_or(Value::Null, Value::String));
    }
    Ok(Value::Object(section))
}

/// The login part of a request. A web address that was already there keeps its match
/// rule and other settings; each one carries the checksum official clients check. The
/// password's date moves only when the password itself changed.
fn fill_login(key: &mut ItemKey, mut login: Login, old: Option<&Login>, draft: &LoginDraft, new_password: bool) -> Result<Login> {
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
    if new_password {
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
