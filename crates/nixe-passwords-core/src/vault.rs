//! The unlocked vault as the app and Glimpse see it: decrypted names, usernames, web
//! addresses, folders and collections, for listing and search. Passwords, codes, notes
//! and other secret fields are not in the view; `reveal` decrypts one when it's used.
//!
//! Every decrypted string is a `Secret`, so nothing in the view can be logged by
//! accident, and dropping the view (on lock) zeroizes it.

use uuid::Uuid;

use crate::crypto::{CryptoError, Keys};
use crate::model::{Cipher, Kind, Sync};
use crate::secret::Secret;
use crate::totp;

/// One item, as listed. `readable` is false when its key couldn't be opened (an
/// organization this device has no key for); such items show without a name.
pub struct Entry {
    pub id: Uuid,
    pub kind: Kind,
    pub name: Secret,
    pub username: Option<Secret>,
    pub uris: Vec<Secret>,
    /// Each address's match rule (`matching::DOMAIN`, …; `None` is the default).
    pub uri_rules: Vec<Option<i64>>,
    /// The first web address's host, lowercase, for icons and matching.
    pub host: Option<String>,
    pub folder: Option<Uuid>,
    pub organization: Option<Uuid>,
    pub collections: Vec<Uuid>,
    pub favorite: bool,
    pub has_password: bool,
    pub has_totp: bool,
    /// The item asks for the master password again before showing secrets.
    pub reprompt: bool,
    pub deleted: bool,
    pub readable: bool,
    pub revision: String,
    /// What this account may do with it (see `Cipher::can_edit` and the rest).
    pub editable: bool,
    pub view_password: bool,
    pub deletable: bool,
    pub restorable: bool,
}

pub struct Named {
    pub id: Uuid,
    pub organization: Option<Uuid>,
    pub name: Secret,
    /// For collections: items can be added, changed and removed. Folders always are.
    pub writable: bool,
}

#[derive(Default)]
pub struct View {
    pub entries: Vec<Entry>,
    pub folders: Vec<Named>,
    pub collections: Vec<Named>,
    /// Organization names come unencrypted from the server.
    pub organizations: Vec<(Uuid, String)>,
}

/// A secret field of one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Username,
    Password,
    /// The current one-time code.
    Totp,
    /// The one-time code's seed, as stored (for the editor).
    TotpSeed,
    Notes,
    /// The value of the item's n-th custom field.
    Custom(usize),
    /// A field of a card, identity or SSH key (`card.number`, …; see `sub_field`).
    Sub(&'static Spec),
}

pub use nixe_passwords_proto::fields::{CARD, IDENTITY, SSH_KEY, Spec};

/// The fields of a kind of item, in the order they're shown.
pub fn specs(kind: Kind) -> &'static [Spec] {
    match kind {
        Kind::Card => CARD,
        Kind::Identity => IDENTITY,
        Kind::SshKey => SSH_KEY,
        _ => &[],
    }
}

/// `card.number`, `identity.ssn`, `ssh.privateKey`, … as a field; `None` for other names.
pub fn sub_field(name: &str) -> Option<Field> {
    CARD.iter().chain(IDENTITY).chain(SSH_KEY).find(|s| s.name == name).map(Field::Sub)
}

/// One field as listed: its interface name, label, and value. A secret field's value is
/// withheld (`None`) even when present; ask for it with `reveal`.
pub struct Shown {
    pub name: String,
    pub label: String,
    pub value: Option<Secret>,
    pub secret: bool,
}

fn section<'a>(c: &'a Cipher, name: &str) -> Option<&'a serde_json::Value> {
    match name {
        "card" => c.card.as_ref(),
        "identity" => c.identity.as_ref(),
        "sshKey" => c.ssh_key.as_ref(),
        _ => None,
    }
}

/// The fields an item has, besides a login's username, password, code and addresses:
/// its kind's fields and its custom fields. Secret ones come without their values.
pub fn fields(keys: &Keys, sync: &Sync, id: Uuid) -> Result<Vec<Shown>, RevealError> {
    let c = sync.ciphers.iter().find(|c| c.id == id).ok_or(RevealError::NotFound)?;
    let mut key = keys.item(c.organization_id, c.key.as_deref()).map_err(RevealError::Crypto)?;
    let mut out = Vec::new();
    for spec in specs(c.kind()) {
        let stored = section(c, spec.section).and_then(|v| v[spec.key].as_str()).filter(|v| !v.is_empty());
        let Some(stored) = stored else { continue };
        let value = if spec.secret { None } else { Some(key.decrypt(stored).map_err(RevealError::Crypto)?) };
        out.push(Shown { name: spec.name.into(), label: spec.label.into(), value, secret: spec.secret });
    }
    for (i, f) in c.fields.iter().flatten().enumerate() {
        // Linked fields (3) point at another field and hold no value of their own.
        if f.kind == 3 {
            continue;
        }
        let label = key.decrypt_opt(f.name.as_deref()).map_err(RevealError::Crypto)?;
        let label = label.map(|l| l.expose().to_string()).filter(|l| !l.is_empty()).unwrap_or_else(|| format!("Field {}", i + 1));
        let secret = f.kind == 1;
        let value = if secret { None } else { key.decrypt_opt(f.value.as_deref()).map_err(RevealError::Crypto)? };
        out.push(Shown { name: format!("custom:{i}"), label, value, secret });
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealError {
    NotFound,
    /// The item has no such field.
    Empty,
    BadTotp,
    /// The item's organization hides this field from this account.
    Hidden,
    Crypto(CryptoError),
}

impl std::fmt::Display for RevealError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such item"),
            Self::Empty => f.write_str("the item doesn't have that"),
            Self::BadTotp => f.write_str("the item's one-time code setting isn't valid"),
            Self::Hidden => f.write_str("the organization hides this from you"),
            Self::Crypto(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for RevealError {}

impl View {
    pub fn build(keys: &Keys, sync: &Sync) -> View {
        let mut view = View {
            organizations: sync.profile.organizations.iter().map(|o| (o.id, o.name.clone().unwrap_or_default())).collect(),
            ..View::default()
        };
        for f in &sync.folders {
            if let Ok(name) = keys.item(None, None).and_then(|mut k| k.decrypt(&f.name)) {
                view.folders.push(Named { id: f.id, organization: None, name, writable: true });
            }
        }
        for c in &sync.collections {
            if let Ok(name) = keys.item(Some(c.organization_id), None).and_then(|mut k| k.decrypt(&c.name)) {
                view.collections.push(Named { id: c.id, organization: Some(c.organization_id), name, writable: c.writable() });
            }
        }
        view.entries = sync.ciphers.iter().map(|c| entry(keys, c)).collect();
        view.sort();
        view
    }

    /// Replaces (or adds) one item after an edit.
    pub fn put(&mut self, keys: &Keys, cipher: &Cipher) {
        self.entries.retain(|e| e.id != cipher.id);
        self.entries.push(entry(keys, cipher));
        self.sort();
    }

    pub fn get(&self, id: Uuid) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn folder_name(&self, id: Uuid) -> Option<&str> {
        self.folders.iter().find(|f| f.id == id).map(|f| f.name.expose())
    }

    fn sort(&mut self) {
        self.entries.sort_by_cached_key(|e| (e.name.expose().to_lowercase(), e.id));
    }

    /// Items matching every word of `query`, best first, not counting the trash. Words
    /// match anywhere in the name, username, web addresses, folder or collections; a
    /// match at the start of the name or host ranks higher, then favorites.
    pub fn search(&self, query: &str, limit: usize) -> Vec<&Entry> {
        let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
        let mut hits: Vec<(u32, &Entry)> = self
            .entries
            .iter()
            .filter(|e| !e.deleted && e.readable)
            .filter_map(|e| self.score(e, &words).map(|s| (s, e)))
            .collect();
        // Stable: equal scores keep name order.
        hits.sort_by_key(|(s, _)| std::cmp::Reverse(*s));
        hits.into_iter().take(limit).map(|(_, e)| e).collect()
    }

    /// Logins with a web address that matches `page` under its rule, favorites first.
    /// The trash and unreadable items are left out.
    pub fn matching(&self, page: &url::Url) -> Vec<&Entry> {
        let mut hits: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| !e.deleted && e.readable && e.kind == Kind::Login)
            .filter(|e| e.uris.iter().zip(&e.uri_rules).any(|(u, r)| crate::matching::matches(*r, u.expose(), page)))
            .collect();
        hits.sort_by_key(|e| !e.favorite);
        hits
    }

    fn score(&self, e: &Entry, words: &[String]) -> Option<u32> {
        let name = e.name.expose().to_lowercase();
        let user = e.username.as_ref().map(|u| u.expose().to_lowercase()).unwrap_or_default();
        let host = e.host.clone().unwrap_or_default();
        let uris: Vec<String> = e.uris.iter().map(|u| u.expose().to_lowercase()).collect();
        let mut places: Vec<String> = e.folder.and_then(|f| self.folder_name(f)).map(str::to_lowercase).into_iter().collect();
        places.extend(self.collections.iter().filter(|c| e.collections.contains(&c.id)).map(|c| c.name.expose().to_lowercase()));
        let mut score = u32::from(e.favorite);
        for w in words {
            let word_score = if name.starts_with(w.as_str())
                || name.split(|c: char| !c.is_alphanumeric()).any(|p| p.starts_with(w.as_str()))
            {
                40
            } else if host.starts_with(w.as_str()) || host.split('.').any(|p| p.starts_with(w.as_str())) {
                30
            } else if name.contains(w.as_str()) {
                20
            } else if user.contains(w.as_str()) || host.contains(w.as_str()) || uris.iter().any(|u| u.contains(w.as_str())) {
                10
            } else if places.iter().any(|p| p.contains(w.as_str())) {
                5
            } else {
                return None;
            };
            score += word_score;
        }
        Some(score)
    }
}

/// Decrypts one secret field of one item for the user to see or copy. TOTP gives the
/// current code. Fields the item's organization hides from this account (the password,
/// the one-time code key, hidden custom fields, and the secret fields of cards,
/// identities and SSH keys) are refused; the current code isn't.
pub fn reveal(keys: &Keys, sync: &Sync, id: Uuid, field: Field) -> Result<Secret, RevealError> {
    let c = sync.ciphers.iter().find(|c| c.id == id).ok_or(RevealError::NotFound)?;
    if !c.can_view_password() && hides(c, field) {
        return Err(RevealError::Hidden);
    }
    reveal_for_use(keys, sync, id, field)
}

/// Whether hiding passwords covers this field of this item.
fn hides(c: &Cipher, field: Field) -> bool {
    match field {
        Field::Password | Field::TotpSeed => true,
        Field::Custom(n) => c.fields.as_ref().and_then(|f| f.get(n)).is_some_and(|f| f.kind == 1),
        Field::Sub(spec) => spec.secret,
        _ => false,
    }
}

/// Decrypts one field for the daemon's own use, never shown: filling a page (official
/// clients fill hidden passwords too) or carrying a field through an edit.
pub fn reveal_for_use(keys: &Keys, sync: &Sync, id: Uuid, field: Field) -> Result<Secret, RevealError> {
    let c = sync.ciphers.iter().find(|c| c.id == id).ok_or(RevealError::NotFound)?;
    let mut key = keys.item(c.organization_id, c.key.as_deref()).map_err(RevealError::Crypto)?;
    let login = c.login.as_ref();
    let value = match field {
        Field::Username => login.and_then(|l| l.username.as_deref()),
        Field::Password => login.and_then(|l| l.password.as_deref()),
        Field::Totp | Field::TotpSeed => login.and_then(|l| l.totp.as_deref()),
        Field::Notes => c.notes.as_deref(),
        Field::Custom(n) => c.fields.as_ref().and_then(|f| f.get(n)).and_then(|f| f.value.as_deref()),
        Field::Sub(spec) => section(c, spec.section).and_then(|v| v[spec.key].as_str()),
    };
    let plain = key.decrypt_opt(value).map_err(RevealError::Crypto)?.ok_or(RevealError::Empty)?;
    if field == Field::Totp {
        let generator = totp::Generator::parse(&plain).map_err(|_| RevealError::BadTotp)?;
        return Ok(generator.now().code);
    }
    Ok(plain)
}

/// The host of a web address as Bitwarden clients read it: a missing scheme means https.
pub fn host_of(uri: &str) -> Option<String> {
    let uri = uri.trim();
    let parsed =
        url::Url::parse(uri).ok().filter(|u| u.has_host()).or_else(|| url::Url::parse(&format!("https://{uri}")).ok())?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    parsed.host_str().map(|h| h.trim_start_matches("www.").to_ascii_lowercase())
}

fn entry(keys: &Keys, c: &Cipher) -> Entry {
    let mut e = Entry {
        id: c.id,
        kind: c.kind(),
        name: Secret::new(""),
        username: None,
        uris: Vec::new(),
        uri_rules: Vec::new(),
        host: None,
        folder: c.folder_id,
        organization: c.organization_id,
        collections: c.collection_ids.clone(),
        favorite: c.favorite,
        has_password: c.login.as_ref().is_some_and(|l| l.password.as_deref().is_some_and(|p| !p.is_empty())),
        has_totp: c.login.as_ref().is_some_and(|l| l.totp.as_deref().is_some_and(|t| !t.is_empty())),
        reprompt: c.reprompt != 0,
        deleted: c.is_deleted(),
        readable: false,
        revision: c.revision_date.clone(),
        editable: c.can_edit(),
        view_password: c.can_view_password(),
        deletable: c.can_delete(),
        restorable: c.can_restore(),
    };
    let Ok(mut key) = keys.item(c.organization_id, c.key.as_deref()) else {
        return e;
    };
    let Ok(name) = key.decrypt(&c.name) else {
        return e;
    };
    e.name = name;
    e.readable = true;
    if let Some(login) = &c.login {
        e.username = key.decrypt_opt(login.username.as_deref()).ok().flatten().filter(|u| !u.is_empty());
        for u in login.uris.iter().flatten() {
            if let Ok(Some(uri)) = key.decrypt_opt(u.uri.as_deref()) {
                e.uris.push(uri);
                e.uri_rules.push(u.match_rule);
            }
        }
        e.host = e.uris.iter().find_map(|u| host_of(u.expose()));
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(host_of("https://github.com/login").as_deref(), Some("github.com"));
        assert_eq!(host_of("github.com").as_deref(), Some("github.com"));
        assert_eq!(host_of("https://www.Example.COM:8443/x").as_deref(), Some("example.com"));
        assert_eq!(host_of("androidapp://com.example"), None);
        assert_eq!(host_of("  "), None);
    }
}
