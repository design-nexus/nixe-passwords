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
}

pub struct Named {
    pub id: Uuid,
    pub organization: Option<Uuid>,
    pub name: Secret,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealError {
    NotFound,
    /// The item has no such field.
    Empty,
    BadTotp,
    Crypto(CryptoError),
}

impl std::fmt::Display for RevealError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such item"),
            Self::Empty => f.write_str("the item doesn't have that"),
            Self::BadTotp => f.write_str("the item's one-time code setting isn't valid"),
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
                view.folders.push(Named { id: f.id, organization: None, name });
            }
        }
        for c in &sync.collections {
            if let Ok(name) = keys.item(Some(c.organization_id), None).and_then(|mut k| k.decrypt(&c.name)) {
                view.collections.push(Named { id: c.id, organization: Some(c.organization_id), name });
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

/// Decrypts one secret field of one item. TOTP gives the current code.
pub fn reveal(keys: &Keys, sync: &Sync, id: Uuid, field: Field) -> Result<Secret, RevealError> {
    let c = sync.ciphers.iter().find(|c| c.id == id).ok_or(RevealError::NotFound)?;
    let mut key = keys.item(c.organization_id, c.key.as_deref()).map_err(RevealError::Crypto)?;
    let login = c.login.as_ref();
    let value = match field {
        Field::Username => login.and_then(|l| l.username.as_deref()),
        Field::Password => login.and_then(|l| l.password.as_deref()),
        Field::Totp | Field::TotpSeed => login.and_then(|l| l.totp.as_deref()),
        Field::Notes => c.notes.as_deref(),
        Field::Custom(n) => c.fields.as_ref().and_then(|f| f.get(n)).and_then(|f| f.value.as_deref()),
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
