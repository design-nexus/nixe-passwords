//! The server's objects as they arrive: every encrypted field stays an EncString, and
//! fields this client doesn't know are kept in `extra` so an edit sends them back
//! unchanged (newer item types, passkeys, attachments, flags other clients set).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

pub type Extra = Map<String, Value>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Sync {
    pub profile: Profile,
    #[serde(default)]
    pub folders: Vec<Folder>,
    #[serde(default)]
    pub collections: Vec<Collection>,
    #[serde(default)]
    pub ciphers: Vec<Cipher>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: Uuid,
    pub email: String,
    /// The user key, wrapped by the master key.
    pub key: String,
    /// The private key, wrapped by the user key.
    pub private_key: Option<String>,
    #[serde(default)]
    pub organizations: Vec<ProfileOrganization>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProfileOrganization {
    pub id: Uuid,
    pub name: Option<String>,
    /// The organization key, wrapped for the account's public key.
    pub key: Option<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    pub id: Uuid,
    pub name: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Collection {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Item kinds by their wire number. Unknown numbers are kept, shown as "Other" and not
/// editable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Login,
    Note,
    Card,
    Identity,
    SshKey,
    Other(i64),
}

impl Kind {
    pub fn of(number: i64) -> Kind {
        match number {
            1 => Kind::Login,
            2 => Kind::Note,
            3 => Kind::Card,
            4 => Kind::Identity,
            5 => Kind::SshKey,
            n => Kind::Other(n),
        }
    }

    pub fn number(self) -> i64 {
        match self {
            Kind::Login => 1,
            Kind::Note => 2,
            Kind::Card => 3,
            Kind::Identity => 4,
            Kind::SshKey => 5,
            Kind::Other(n) => n,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    pub id: Uuid,
    #[serde(rename = "type")]
    pub kind: i64,
    pub organization_id: Option<Uuid>,
    pub folder_id: Option<Uuid>,
    /// The item's own key, wrapped by the organization or user key.
    pub key: Option<String>,
    pub name: String,
    pub notes: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub reprompt: i64,
    pub revision_date: String,
    pub deleted_date: Option<String>,
    #[serde(default)]
    pub collection_ids: Vec<Uuid>,
    pub login: Option<Login>,
    pub fields: Option<Vec<Field>>,
    /// Cards, identities, notes and SSH keys stay as sent until their editors exist.
    pub card: Option<Value>,
    pub identity: Option<Value>,
    pub secure_note: Option<Value>,
    pub ssh_key: Option<Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Option<Vec<LoginUri>>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LoginUri {
    pub uri: Option<String>,
    /// Encrypted base64 SHA-256 of the URI; official clients drop a URI without it.
    pub uri_checksum: Option<String>,
    #[serde(rename = "match")]
    pub match_rule: Option<i64>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub name: Option<String>,
    pub value: Option<String>,
    #[serde(rename = "type")]
    pub kind: i64,
    #[serde(flatten)]
    pub extra: Extra,
}

/// What a create or update request may carry (Vaultwarden's `CipherData`). Everything
/// else in a synced cipher is server state and is left out.
const REQUEST_FIELDS: &[&str] = &[
    "folderId",
    "organizationId",
    "key",
    "type",
    "name",
    "notes",
    "fields",
    "login",
    "secureNote",
    "card",
    "identity",
    "sshKey",
    "bankAccount",
    "driversLicense",
    "passport",
    "favorite",
    "reprompt",
    "passwordHistory",
    "archivedDate",
];

impl Cipher {
    pub fn kind(&self) -> Kind {
        Kind::of(self.kind)
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted_date.is_some()
    }

    /// The body for `POST /api/ciphers` (no `last_known`) or `PUT /api/ciphers/{id}`.
    /// `user` is the account's id (`encryptedFor`), which Vaultwarden requires.
    pub fn to_request(&self, user: Uuid, last_known: Option<&str>) -> Value {
        let full = serde_json::to_value(self).expect("cipher serializes");
        let mut body = Map::new();
        for &field in REQUEST_FIELDS {
            if let Some(v) = full.get(field) {
                body.insert(field.to_string(), v.clone());
            }
        }
        body.insert("encryptedFor".into(), Value::String(user.to_string()));
        if let Some(rev) = last_known {
            body.insert("lastKnownRevisionDate".into(), Value::String(rev.to_string()));
        }
        Value::Object(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Value {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn sync_round_trips_unchanged() {
        for name in ["pbkdf2-sync.json", "argon2-sync.json"] {
            let raw = fixture(name);
            let sync: Sync = serde_json::from_value(raw.clone()).unwrap();
            assert_eq!(sync.ciphers.len(), 5);
            assert_eq!(serde_json::to_value(&sync).unwrap(), raw, "{name}");
        }
    }

    #[test]
    fn unknown_types_and_fields_survive() {
        let mut raw = fixture("pbkdf2-sync.json")["ciphers"][0].clone();
        raw["type"] = 8.into();
        raw["passport"] = serde_json::json!({"number": "2.abc|def|ghi"});
        raw["futureFlag"] = true.into();
        let c: Cipher = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(c.kind(), Kind::Other(8));
        let body = c.to_request(Uuid::nil(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(body["passport"], raw["passport"]);
        assert_eq!(serde_json::to_value(&c).unwrap()["futureFlag"], true);
    }

    #[test]
    fn request_has_only_request_fields() {
        let c: Cipher = serde_json::from_value(fixture("pbkdf2-sync.json")["ciphers"][0].clone()).unwrap();
        let body = c.to_request(Uuid::nil(), Some("rev"));
        for server_only in ["id", "revisionDate", "object", "edit", "permissions", "collectionIds"] {
            assert!(body.get(server_only).is_none(), "{server_only}");
        }
        assert_eq!(body["encryptedFor"], Uuid::nil().to_string());
        assert_eq!(body["lastKnownRevisionDate"], "rev");
        assert_eq!(body["name"], serde_json::to_value(&c.name).unwrap());
    }
}
