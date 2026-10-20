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
use crate::crypto::{ItemKey, is_enc_string, uri_checksum};
use crate::model::{Cipher, Kind, Login, LoginUri};
use crate::secret::Secret;
use crate::session::{Result, Session, SessionError};
use crate::ssh;
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
    pub place: Place,
}

/// Where an item lives: personal (`organization: None`), or in some of an
/// organization's collections. A personal item can move into an organization; an
/// organization item can change collections but not leave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Place {
    pub organization: Option<Uuid>,
    pub collections: Vec<Uuid>,
}

/// What the user typed for a note, card, identity or SSH key. `fields` are the kind's own
/// fields by name (`card.number`, …; see `vault::specs`); one left out or empty is
/// cleared. An SSH key needs only `ssh.privateKey`: its public key and fingerprint are
/// worked out from it.
pub struct ItemDraft {
    pub kind: Kind,
    pub name: Secret,
    pub fields: Vec<(String, Secret)>,
    pub notes: Option<Secret>,
    pub folder: Option<Uuid>,
    pub favorite: bool,
    pub reprompt: bool,
    pub place: Place,
}

/// The kinds `create_item` and `update_item` handle (logins have their own draft).
pub fn editable(kind: Kind) -> bool {
    matches!(kind, Kind::Note | Kind::Card | Kind::Identity | Kind::SshKey)
}

impl Session {
    /// Creates a login, personal or in an organization's collections, and returns its id.
    pub async fn create_login(
        &mut self,
        store: &mut Store,
        server: &Server,
        refresh: &Secret,
        draft: &LoginDraft,
    ) -> Result<Uuid> {
        self.check_place(&Place::default(), &draft.place)?;
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let body = {
            let mut key = self.keys.item(draft.place.organization, None)?;
            let has_password = draft.password.as_ref().is_some_and(|p| !p.is_empty());
            let login = fill_login(&mut key, Login::default(), None, draft, has_password)?;
            json!({
                "type": Kind::Login.number(),
                "name": key.encrypt(draft.name.expose())?,
                "notes": encrypt_opt(&mut key, draft.notes.as_ref())?,
                "folderId": draft.folder,
                "organizationId": draft.place.organization,
                "key": null,
                "favorite": draft.favorite,
                "reprompt": i64::from(draft.reprompt),
                "fields": null,
                "passwordHistory": null,
                "login": login,
                "encryptedFor": self.snapshot.profile.id,
            })
        };
        self.send_create(store, server, &access, &body, &draft.place).await
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
        let old = self.cipher(id)?.clone();
        if old.kind() != Kind::Login {
            return Err(SessionError::Api(ApiError::Protocol));
        }
        self.check_edit(&old, &draft.place)?;
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let mut new = old.clone();
        {
            let mut key = self.keys.item(old.organization_id, old.key.as_deref())?;
            new.name = key.encrypt(draft.name.expose())?;
            new.notes = encrypt_opt(&mut key, draft.notes.as_ref())?;
            new.folder_id = draft.folder;
            new.favorite = draft.favorite;
            new.reprompt = i64::from(draft.reprompt);
            let old_login = old.login.clone().unwrap_or_default();
            let old_password = old_login.password.as_deref();
            // A password this account can't see can't be changed here either: the draft
            // never had it, so the stored one and its code key stay.
            let visible = old.can_view_password();
            let changed = visible && password_changed(&mut key, old_password, draft.password.as_ref())?;
            let mut login = fill_login(&mut key, old_login.clone(), old.login.as_ref(), draft, changed)?;
            if !visible {
                login.password = old_login.password.clone();
                login.totp = old_login.totp.clone();
            }
            if changed {
                push_history(&mut new, old_password);
            }
            new.login = Some(login);
        }
        self.send_update(store, server, &access, &old, &new).await?;
        self.move_to(store, server, &access, id, &draft.place).await
    }

    /// Creates a note, card, identity or SSH key, personal or in an organization's
    /// collections, and returns its id.
    pub async fn create_item(&mut self, store: &mut Store, server: &Server, refresh: &Secret, draft: &ItemDraft) -> Result<Uuid> {
        if !editable(draft.kind) {
            return Err(SessionError::Api(ApiError::Protocol));
        }
        self.check_place(&Place::default(), &draft.place)?;
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let body = {
            let mut key = self.keys.item(draft.place.organization, None)?;
            let mut body = json!({
                "type": draft.kind.number(),
                "name": key.encrypt(draft.name.expose())?,
                "notes": encrypt_opt(&mut key, draft.notes.as_ref())?,
                "folderId": draft.folder,
                "organizationId": draft.place.organization,
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
        self.send_create(store, server, &access, &body, &draft.place).await
    }

    /// Saves a changed note, card, identity or SSH key. Its custom fields, attachments and
    /// any field this client doesn't know are sent back as they were.
    pub async fn update_item(
        &mut self,
        store: &mut Store,
        server: &Server,
        refresh: &Secret,
        id: Uuid,
        draft: &ItemDraft,
    ) -> Result<()> {
        let old = self.cipher(id)?.clone();
        if old.kind() != draft.kind || !editable(draft.kind) {
            return Err(SessionError::Api(ApiError::Protocol));
        }
        self.check_edit(&old, &draft.place)?;
        let access = Secret::new(self.access(server, refresh).await?.expose());
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
                Kind::SshKey => &mut new.ssh_key,
                _ => &mut new.identity,
            };
            if old.can_view_password() {
                *section = Some(fill_section(&mut key, section.as_ref(), draft)?);
            } else if draft.kind != Kind::SshKey {
                // Secret fields this account can't see weren't in the draft: they stay.
                // (An SSH key is all one secret, so it stays whole.)
                let kept = section.clone();
                let mut filled = fill_section(&mut key, section.as_ref(), draft)?;
                for spec in specs(draft.kind).iter().filter(|s| s.secret) {
                    filled[spec.key] = kept.as_ref().and_then(|k| k.get(spec.key)).cloned().unwrap_or(Value::Null);
                }
                *section = Some(filled);
            }
        }
        self.send_update(store, server, &access, &old, &new).await?;
        self.move_to(store, server, &access, id, &draft.place).await
    }

    /// Whether this account may move items between `from` and `to`: an organization item
    /// stays in its organization, and every collection added or removed must be one it
    /// can write to. An organization item needs at least one collection.
    fn check_place(&self, from: &Place, to: &Place) -> Result<()> {
        let Some(org) = to.organization else {
            return match from.organization {
                Some(_) => Err(SessionError::NotAllowed("an item can't be moved out of its organization")),
                None => Ok(()),
            };
        };
        if from.organization.is_some_and(|o| o != org) {
            return Err(SessionError::NotAllowed("an item can't be moved to another organization"));
        }
        if to.collections.is_empty() {
            return Err(SessionError::NotAllowed("choose at least one collection"));
        }
        let changed = to.collections.iter().filter(|c| !from.collections.contains(c));
        let changed = changed.chain(from.collections.iter().filter(|c| !to.collections.contains(c)));
        for id in changed {
            let collection = self.snapshot.collections.iter().find(|c| c.id == *id && c.organization_id == org);
            if !collection.is_some_and(|c| c.writable()) {
                return Err(SessionError::NotAllowed("you can't add items to that collection or take them out of it"));
            }
        }
        Ok(())
    }

    /// An edit of `old` is allowed: the account may change it, and may move it to `place`.
    fn check_edit(&self, old: &Cipher, place: &Place) -> Result<()> {
        if !old.can_edit() {
            return Err(SessionError::NotAllowed("this item is read-only for you"));
        }
        let from = Place { organization: old.organization_id, collections: old.collection_ids.clone() };
        self.check_place(&from, place)
    }

    async fn send_create(
        &mut self,
        store: &mut Store,
        server: &Server,
        access: &Secret,
        body: &Value,
        place: &Place,
    ) -> Result<Uuid> {
        let made = match place.organization {
            Some(_) => server.create_org_cipher(access, body, &place.collections).await?,
            None => server.create_cipher(access, body).await?,
        };
        let id = made.id;
        self.take(store, made)?;
        Ok(id)
    }

    /// Moves a saved item to `place` if it isn't there: into an organization, or to
    /// other collections of its own. `check_edit` has allowed the move.
    async fn move_to(&mut self, store: &mut Store, server: &Server, access: &Secret, id: Uuid, place: &Place) -> Result<()> {
        let old = self.cipher(id)?.clone();
        match (old.organization_id, place.organization) {
            (None, Some(org)) => {
                let body = self.rekeyed(&old, org)?;
                let moved = server.share_cipher(access, id, &body, &place.collections).await?;
                self.take(store, moved)
            }
            (Some(_), Some(_)) if !same_set(&old.collection_ids, &place.collections) => {
                server.set_collections(access, id, &place.collections).await?;
                let latest = server.get_cipher(access, id).await?;
                self.take(store, latest)
            }
            _ => Ok(()),
        }
    }

    /// A personal item as a request for moving it into `org`. An item with its own key
    /// keeps it, rewrapped by the organization's key. One without gets one now, and every
    /// encrypted value is re-encrypted with it: the attachments' keys too, which the
    /// server takes separately (`attachments2`).
    fn rekeyed(&self, old: &Cipher, org: Uuid) -> Result<Value> {
        let mut new = old.clone();
        new.organization_id = Some(org);
        let attachments = old.extra.get("attachments").and_then(Value::as_array).cloned().unwrap_or_default();
        if attachments.iter().any(|a| a.get("key").and_then(Value::as_str).is_none()) {
            return Err(SessionError::NotAllowed("items with old-style attachments can't be moved here; use the web vault"));
        }
        match &old.key {
            Some(own) => new.key = Some(self.keys.rewrap(own, None, Some(org))?),
            None => {
                let mut from = self.keys.item(None, None)?;
                let (mut to, wrapped) = self.keys.new_item(Some(org))?;
                let mut value = serde_json::to_value(&new).expect("cipher serializes");
                for section in REKEYED {
                    if let Some(v) = value.get_mut(*section) {
                        reencrypt(v, &mut from, &mut to, *section == "attachments")?;
                    }
                }
                new = serde_json::from_value(value).map_err(|_| SessionError::Api(ApiError::Protocol))?;
                new.key = Some(wrapped);
            }
        }
        let mut body = new.to_request(self.snapshot.profile.id, Some(&old.revision_date));
        let moved = new.extra.get("attachments").and_then(Value::as_array).cloned().unwrap_or_default();
        if !moved.is_empty() {
            let by_id: Map<String, Value> = moved
                .iter()
                .filter_map(|a| Some((a["id"].as_str()?.to_string(), json!({"fileName": a["fileName"], "key": a["key"]}))))
                .collect();
            body["attachments2"] = Value::Object(by_id);
        }
        Ok(body)
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
        if !self.cipher(id)?.can_delete() {
            return Err(SessionError::NotAllowed("you can't delete this item"));
        }
        let access = Secret::new(self.access(server, refresh).await?.expose());
        server.trash_cipher(&access, id).await?;
        let trashed = server.get_cipher(&access, id).await?;
        self.take(store, trashed)
    }

    pub async fn restore(&mut self, store: &mut Store, server: &Server, refresh: &Secret, id: Uuid) -> Result<()> {
        if !self.cipher(id)?.can_restore() {
            return Err(SessionError::NotAllowed("you can't restore this item"));
        }
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let restored = server.restore_cipher(&access, id).await?;
        self.take(store, restored)
    }

    pub(crate) fn cipher(&self, id: Uuid) -> Result<&Cipher> {
        self.snapshot.ciphers.iter().find(|c| c.id == id).ok_or(SessionError::Api(ApiError::NotFound))
    }

    /// Puts the server's copy of an item into the store, the snapshot and the view.
    pub(crate) fn take(&mut self, store: &mut Store, cipher: Cipher) -> Result<()> {
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

/// The parts of an item whose encrypted values are re-encrypted when it gets a new key.
const REKEYED: &[&str] = &[
    "name",
    "notes",
    "login",
    "fields",
    "passwordHistory",
    "card",
    "identity",
    "secureNote",
    "sshKey",
    "bankAccount",
    "driversLicense",
    "passport",
    "attachments",
];

/// Re-encrypts every encrypted string in `value` from one key to another. In attachments,
/// `key` holds a key (bytes, not text).
fn reencrypt(value: &mut Value, from: &mut ItemKey, to: &mut ItemKey, attachments: bool) -> Result<()> {
    match value {
        Value::String(s) if is_enc_string(s) => *s = to.encrypt(from.decrypt(s)?.expose())?,
        Value::Array(list) => {
            for v in list {
                reencrypt(v, from, to, attachments)?;
            }
        }
        Value::Object(map) => {
            for (name, v) in map.iter_mut() {
                match v {
                    Value::String(s) if attachments && name == "key" => {
                        *s = to.encrypt_key_bytes(from.decrypt_bytes(s)?.expose())?;
                    }
                    _ => reencrypt(v, from, to, attachments)?,
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn same_set(a: &[Uuid], b: &[Uuid]) -> bool {
    a.len() == b.len() && a.iter().all(|x| b.contains(x))
}

fn section_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Note => "secureNote",
        Kind::Card => "card",
        Kind::SshKey => "sshKey",
        _ => "identity",
    }
}

/// An item's own part of a request: each of the kind's fields from the draft, encrypted,
/// or null when empty. Keys this client doesn't know stay as they were.
fn fill_section(key: &mut ItemKey, old: Option<&Value>, draft: &ItemDraft) -> Result<Value> {
    let mut section = match old {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    };
    if draft.kind == Kind::Note {
        section.entry("type").or_insert(json!(0));
    }
    let derived = match draft.kind {
        Kind::SshKey => Some(ssh_fields(draft)?),
        _ => None,
    };
    for spec in specs(draft.kind) {
        let given = draft.fields.iter().find(|(name, _)| name == spec.name).map(|(_, v)| v);
        let value = match &derived {
            Some(fields) => fields.iter().find(|(name, _)| *name == spec.name).map(|(_, v)| v),
            None => given,
        };
        section.insert(spec.key.into(), encrypt_opt(key, value)?.map_or(Value::Null, Value::String));
    }
    Ok(Value::Object(section))
}

/// An SSH key draft's three fields, from its private key.
fn ssh_fields(draft: &ItemDraft) -> Result<Vec<(&'static str, Secret)>> {
    let private = draft.fields.iter().find(|(name, _)| name == "ssh.privateKey").map(|(_, v)| v.expose());
    let key = ssh::read(private.unwrap_or_default()).map_err(SessionError::BadSshKey)?;
    Ok(vec![
        ("ssh.privateKey", key.private),
        ("ssh.publicKey", Secret::new(key.public)),
        ("ssh.keyFingerprint", Secret::new(key.fingerprint)),
    ])
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
