//! The daemon's `List` answer: what the window shows. Metadata only; secret fields are
//! asked for one at a time (`client::reveal`).

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Listing {
    pub account: Account,
    pub entries: Vec<Entry>,
    pub folders: Vec<Named>,
    pub collections: Vec<Collection>,
    pub organizations: Vec<Named>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Account {
    pub email: String,
    pub server: String,
    /// Seconds since the epoch.
    pub last_sync: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Entry {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub username: Option<String>,
    pub uris: Vec<String>,
    pub host: Option<String>,
    pub folder: Option<String>,
    pub organization: Option<String>,
    pub collections: Vec<String>,
    pub favorite: bool,
    pub has_password: bool,
    pub has_totp: bool,
    pub reprompt: bool,
    pub deleted: bool,
    pub readable: bool,
    /// What this account may do with it; organizations can limit each.
    #[serde(default = "yes")]
    pub editable: bool,
    #[serde(default = "yes")]
    pub view_password: bool,
    #[serde(default = "yes")]
    pub deletable: bool,
    #[serde(default = "yes")]
    pub restorable: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct Named {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Collection {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub organization: String,
    /// Items can be added, changed and removed.
    #[serde(default)]
    pub writable: bool,
}

/// The kinds, as the sidebar lists them: id, label, icon.
pub const KINDS: &[(&str, &str, &str)] = &[
    ("login", "Logins", "dialog-password-symbolic"),
    ("note", "Secure notes", "text-x-generic-symbolic"),
    ("card", "Cards", "nixe-card-symbolic"),
    ("identity", "Identities", "avatar-default-symbolic"),
    ("ssh", "SSH keys", "nixe-key-symbolic"),
];

pub fn kind_icon(kind: &str) -> &'static str {
    KINDS.iter().find(|(k, _, _)| *k == kind).map_or("dialog-password-symbolic", |(_, _, i)| i)
}

pub fn kind_name(kind: &str) -> &'static str {
    match kind {
        "login" => "Login",
        "note" => "Secure note",
        "card" => "Card",
        "identity" => "Identity",
        "ssh" => "SSH key",
        _ => "Other item",
    }
}

impl Entry {
    /// Whether the entry belongs in `section` (see `ui::navigate`).
    pub fn in_section(&self, section: &str) -> bool {
        if section == "trash" {
            return self.deleted;
        }
        if self.deleted {
            return false;
        }
        match section {
            "all" => true,
            "favorites" => self.favorite,
            "nofolder" => self.folder.is_none() && self.organization.is_none(),
            s => {
                if let Some(id) = s.strip_prefix("folder:") {
                    self.folder.as_deref() == Some(id)
                } else if let Some(id) = s.strip_prefix("collection:") {
                    self.collections.iter().any(|c| c == id)
                } else {
                    self.kind == s
                }
            }
        }
    }

    /// Whether every word of `query` is in the name, username, host or addresses.
    pub fn matches(&self, query: &str) -> bool {
        let hay = format!(
            "{} {} {} {}",
            self.name,
            self.username.as_deref().unwrap_or(""),
            self.host.as_deref().unwrap_or(""),
            self.uris.join(" ")
        )
        .to_lowercase();
        query.split_whitespace().all(|w| hay.contains(&w.to_lowercase()))
    }

    /// The line under the name in the list.
    pub fn subtitle(&self) -> String {
        if !self.readable {
            return "Can't be opened on this device".into();
        }
        self.username.clone().or_else(|| self.host.clone()).unwrap_or_else(|| kind_name(&self.kind).into())
    }
}

/// "just now", "5 min ago", "3 h ago", "2 days ago".
pub fn ago(epoch: u64) -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let s = now.saturating_sub(epoch);
    match s {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", s / 60),
        3600..86_400 => format!("{} h ago", s / 3600),
        _ => format!("{} days ago", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            id: "1".into(),
            kind: "login".into(),
            name: "GitHub".into(),
            username: Some("octo".into()),
            uris: vec!["https://github.com/login".into()],
            host: Some("github.com".into()),
            folder: Some("f".into()),
            organization: None,
            collections: vec![],
            favorite: true,
            has_password: true,
            has_totp: false,
            reprompt: false,
            deleted: false,
            readable: true,
            editable: true,
            view_password: true,
            deletable: true,
            restorable: true,
        }
    }

    #[test]
    fn sections_and_search() {
        let e = entry();
        for s in ["all", "favorites", "login", "folder:f"] {
            assert!(e.in_section(s), "{s}");
        }
        for s in ["trash", "note", "folder:g", "nofolder", "collection:c"] {
            assert!(!e.in_section(s), "{s}");
        }
        let gone = Entry { deleted: true, ..entry() };
        assert!(gone.in_section("trash") && !gone.in_section("all"));
        assert!(e.matches("git octo") && e.matches("GITHUB.com") && !e.matches("gitlab"));
        assert_eq!(e.subtitle(), "octo");
    }
}
