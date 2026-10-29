//! Moving a vault in and out. Exports in Bitwarden's formats: JSON, CSV, JSON
//! protected by a password, and JSON encrypted with this account's key. Imports from
//! Bitwarden (those JSON forms and CSV), 1Password (`.1pux`), Chrome and Firefox (CSV)
//! and KeePassXC (CSV), told apart by their contents.
//!
//! Exports hold personal items only (organization items are exported by their admins),
//! not the trash, not attachments; as the official clients do. Everything is decrypted
//! or encrypted here, in memory; the daemon writes the result only to the file the
//! user chose and reads imports only from the file the user picked.

use std::io::Read;

use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::crypto::{CryptoError, ExportKey, ItemKey, Kdf, Keys, export_salt, is_enc_string, uri_checksum};
use crate::model::{Kind, Sync};
use crate::secret::Secret;

/// The largest file read for an import.
pub const IMPORT_MAX: usize = 64 << 20;
/// The most items one import takes.
const ITEMS_MAX: usize = 20_000;
/// The KDF for password-protected exports: what the official clients use.
const EXPORT_KDF: Kdf = Kdf::Pbkdf2 { iterations: 600_000 };

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    /// The file isn't in a format this client reads.
    Unknown,
    /// It looked like `format` but couldn't be read.
    Unreadable(&'static str),
    /// Protected by a password: ask for it.
    NeedsPassword,
    WrongPassword,
    /// Encrypted for another account.
    OtherAccount,
    TooLarge,
    Crypto(CryptoError),
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Unknown => f.write_str("this file isn't an export Passwords can read"),
            Self::Unreadable(format) => write!(f, "this {format} file couldn't be read"),
            Self::NeedsPassword => f.write_str("this export is protected by a password"),
            Self::WrongPassword => f.write_str("that password doesn't open this export"),
            Self::OtherAccount => f.write_str("this export is encrypted for another account; export it with a password instead"),
            Self::TooLarge => f.write_str("the file is too large"),
            Self::Crypto(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for TransferError {}

impl From<CryptoError> for TransferError {
    fn from(e: CryptoError) -> Self {
        TransferError::Crypto(e)
    }
}

pub type Result<T> = std::result::Result<T, TransferError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
    /// JSON encrypted with a password, readable by any Bitwarden client that has it.
    PasswordJson,
    /// JSON encrypted with this account's key: only this account can import it.
    AccountJson,
}

impl ExportFormat {
    pub fn parse(name: &str) -> Option<ExportFormat> {
        Some(match name {
            "json" => ExportFormat::Json,
            "csv" => ExportFormat::Csv,
            "password_json" => ExportFormat::PasswordJson,
            "account_json" => ExportFormat::AccountJson,
            _ => return None,
        })
    }
}

// ---- which values are encrypted ----

/// Applies `f` to every encrypted value of an item in Bitwarden's shape (the server's,
/// or an export's): its name and notes, a login's username, password, code key, web
/// addresses and passkeys, custom field names and values, old passwords, and every
/// field of a card, identity or SSH key. Nulls stay null.
fn each_secret(item: &mut Value, f: &mut dyn FnMut(&mut Value) -> std::result::Result<(), CryptoError>) -> Result<()> {
    let mut at = |v: Option<&mut Value>| -> Result<()> {
        if let Some(v) = v.filter(|v| v.is_string()) {
            f(v)?;
        }
        Ok(())
    };
    at(item.get_mut("name"))?;
    at(item.get_mut("notes"))?;
    if let Some(login) = item.get_mut("login").filter(|l| l.is_object()) {
        for key in ["username", "password", "totp"] {
            at(login.get_mut(key))?;
        }
        for uri in login.get_mut("uris").and_then(Value::as_array_mut).into_iter().flatten() {
            at(uri.get_mut("uri"))?;
        }
        for passkey in login.get_mut("fido2Credentials").and_then(Value::as_array_mut).into_iter().flatten() {
            for (_, v) in passkey.as_object_mut().into_iter().flatten() {
                at(Some(v))?;
            }
        }
    }
    for field in item.get_mut("fields").and_then(Value::as_array_mut).into_iter().flatten() {
        at(field.get_mut("name"))?;
        at(field.get_mut("value"))?;
    }
    for old in item.get_mut("passwordHistory").and_then(Value::as_array_mut).into_iter().flatten() {
        at(old.get_mut("password"))?;
    }
    for section in ["card", "identity", "sshKey"] {
        for (_, v) in item.get_mut(section).and_then(Value::as_object_mut).into_iter().flatten() {
            at(Some(v))?;
        }
    }
    Ok(())
}

fn decrypt_item(item: &mut Value, key: &mut ItemKey) -> Result<()> {
    each_secret(item, &mut |v| {
        let text = v.as_str().unwrap_or_default();
        if is_enc_string(text) {
            *v = Value::String(key.decrypt(text)?.expose().to_string());
        }
        Ok(())
    })?;
    if let Some(uris) = item.pointer_mut("/login/uris").and_then(Value::as_array_mut) {
        for uri in uris {
            if let Some(map) = uri.as_object_mut() {
                map.remove("uriChecksum");
            }
        }
    }
    Ok(())
}

/// Encrypts a plain item for the server, adding each web address's checksum.
fn encrypt_item(item: &mut Value, key: &mut ItemKey) -> Result<()> {
    if let Some(uris) = item.pointer_mut("/login/uris").and_then(Value::as_array_mut) {
        for uri in uris {
            if let Some(text) = uri.get("uri").and_then(Value::as_str).map(str::to_string) {
                uri["uriChecksum"] = Value::String(key.encrypt(uri_checksum(&text).expose())?);
            }
        }
    }
    each_secret(item, &mut |v| {
        let text = v.as_str().unwrap_or_default().to_string();
        *v = if text.is_empty() { Value::Null } else { Value::String(key.encrypt(&text)?) };
        Ok(())
    })
}

// ---- export ----

/// The parts of a stored item an export carries, in Bitwarden's export shape.
fn export_shape(cipher: &Value, keep_key: bool) -> Value {
    let mut out = Map::new();
    for key in [
        "passwordHistory",
        "revisionDate",
        "creationDate",
        "deletedDate",
        "id",
        "organizationId",
        "folderId",
        "type",
        "reprompt",
        "name",
        "notes",
        "favorite",
        "fields",
        "login",
        "secureNote",
        "card",
        "identity",
        "sshKey",
    ] {
        if let Some(v) = cipher.get(key).filter(|v| !v.is_null()) {
            out.insert(key.into(), v.clone());
        }
    }
    if keep_key && let Some(k) = cipher.get("key").filter(|v| !v.is_null()) {
        out.insert("key".into(), k.clone());
    }
    out.insert("collectionIds".into(), Value::Null);
    Value::Object(out)
}

/// An export of the personal, non-deleted items and the folders. `password` is needed
/// for `PasswordJson`. The result is the file's contents.
pub fn export(keys: &Keys, sync: &Sync, format: ExportFormat, password: Option<&Secret>) -> Result<Secret> {
    let personal = sync.ciphers.iter().filter(|c| c.organization_id.is_none() && !c.is_deleted());
    let mut user = keys.item(None, None)?;
    let mut folders = Vec::new();
    for f in &sync.folders {
        let name = if format == ExportFormat::AccountJson { f.name.clone() } else { user.decrypt(&f.name)?.expose().to_string() };
        folders.push(json!({"id": f.id, "name": name}));
    }
    drop(user);
    let mut items = Vec::new();
    for c in personal {
        let raw = serde_json::to_value(c).map_err(|_| TransferError::Unreadable("vault"))?;
        if format == ExportFormat::AccountJson {
            items.push(export_shape(&raw, true));
            continue;
        }
        let mut item = export_shape(&raw, false);
        let mut key = keys.item(None, c.key.as_deref())?;
        decrypt_item(&mut item, &mut key)?;
        items.push(item);
    }
    let text = match format {
        ExportFormat::Json => pretty(&json!({"encrypted": false, "folders": folders, "items": items})),
        ExportFormat::Csv => csv_export(&folders, &items)?,
        ExportFormat::PasswordJson => {
            let password = password.filter(|p| !p.is_empty()).ok_or(TransferError::NeedsPassword)?;
            let plain = pretty(&json!({"encrypted": false, "folders": folders, "items": items}));
            let salt = export_salt();
            let key = ExportKey::derive(password, &salt, &EXPORT_KDF)?;
            let Kdf::Pbkdf2 { iterations } = EXPORT_KDF else { unreachable!() };
            pretty(&json!({
                "encrypted": true,
                "passwordProtected": true,
                "salt": salt,
                "kdfType": 0,
                "kdfIterations": iterations,
                "kdfMemory": null,
                "kdfParallelism": null,
                "encKeyValidation_DO_NOT_EDIT": key.encrypt(&Uuid::new_v4().to_string())?,
                "data": key.encrypt(&plain)?,
            }))
        }
        ExportFormat::AccountJson => {
            let mut user = keys.item(None, None)?;
            let check = user.encrypt(&Uuid::new_v4().to_string())?;
            pretty(&json!({"encrypted": true, "encKeyValidation_DO_NOT_EDIT": check, "folders": folders, "items": items}))
        }
    };
    Ok(Secret::new(text))
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

/// Bitwarden's CSV: logins and notes only, as the official clients export.
fn csv_export(folders: &[Value], items: &[Value]) -> Result<String> {
    let mut out = csv::Writer::from_writer(Vec::new());
    let bad = |_| TransferError::Unreadable("CSV");
    out.write_record([
        "folder",
        "favorite",
        "type",
        "name",
        "notes",
        "fields",
        "reprompt",
        "login_uri",
        "login_username",
        "login_password",
        "login_totp",
    ])
    .map_err(bad)?;
    let s = |v: &Value| v.as_str().unwrap_or_default().to_string();
    for item in items {
        let kind = match Kind::of(item["type"].as_i64().unwrap_or(0)) {
            Kind::Login => "login",
            Kind::Note => "note",
            _ => continue,
        };
        let folder = folders.iter().find(|f| f["id"] == item["folderId"]).map(|f| s(&f["name"])).unwrap_or_default();
        let fields: Vec<String> = item["fields"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|f| f["type"].as_i64() != Some(3))
            .map(|f| format!("{}: {}", s(&f["name"]), s(&f["value"])))
            .collect();
        let login = &item["login"];
        let uris: Vec<String> = login["uris"].as_array().into_iter().flatten().map(|u| s(&u["uri"])).collect();
        out.write_record([
            folder,
            if item["favorite"] == true { "1".into() } else { String::new() },
            kind.into(),
            s(&item["name"]),
            s(&item["notes"]),
            fields.join("\n"),
            item["reprompt"].as_i64().unwrap_or(0).to_string(),
            uris.join(","),
            s(&login["username"]),
            s(&login["password"]),
            s(&login["totp"]),
        ])
        .map_err(bad)?;
    }
    String::from_utf8(out.into_inner().map_err(|_| TransferError::Unreadable("CSV"))?)
        .map_err(|_| TransferError::Unreadable("CSV"))
}

// ---- import ----

/// What an import found: plain items in Bitwarden's shape, and folder names. An item's
/// `folderId` is replaced by its folder's position in `folders`.
#[derive(Debug, Default)]
pub struct Parsed {
    pub format: &'static str,
    pub folders: Vec<String>,
    pub items: Vec<(Value, Option<usize>)>,
}

impl Parsed {
    /// How many items of each kind: `{"login": 3, …}`.
    pub fn counts(&self) -> Map<String, Value> {
        let mut counts = Map::new();
        for (item, _) in &self.items {
            let kind = match Kind::of(item["type"].as_i64().unwrap_or(0)) {
                Kind::Login => "login",
                Kind::Note => "note",
                Kind::Card => "card",
                Kind::Identity => "identity",
                Kind::SshKey => "ssh",
                Kind::Other(_) => "other",
            };
            let n = counts.get(kind).and_then(Value::as_u64).unwrap_or(0);
            counts.insert(kind.into(), (n + 1).into());
        }
        counts
    }

    fn folder(&mut self, name: &str) -> Option<usize> {
        let name = name.trim().trim_start_matches("Root/").trim_start_matches('/').trim();
        if name.is_empty() || name == "Root" {
            return None;
        }
        Some(self.folders.iter().position(|f| f == name).unwrap_or_else(|| {
            self.folders.push(name.to_string());
            self.folders.len() - 1
        }))
    }

    fn push(&mut self, item: Value, folder: Option<usize>) -> Result<()> {
        if self.items.len() >= ITEMS_MAX {
            return Err(TransferError::TooLarge);
        }
        self.items.push((normalized(item), folder));
        Ok(())
    }
}

/// An item ready to encrypt: a known kind, a name, no ids or organization, and only the
/// fields the server takes.
fn normalized(mut item: Value) -> Value {
    let kind = item["type"].as_i64().filter(|k| (1..=5).contains(k)).unwrap_or(2);
    let name = item["name"].as_str().map(str::trim).filter(|n| !n.is_empty()).unwrap_or("Untitled").to_string();
    let mut out = export_shape(&item, false);
    for key in ["id", "organizationId", "folderId", "collectionIds", "revisionDate", "creationDate", "deletedDate"] {
        out.as_object_mut().expect("object").remove(key);
    }
    out["type"] = kind.into();
    out["name"] = name.into();
    out["favorite"] = (item["favorite"] == true).into();
    out["reprompt"] = item["reprompt"].as_i64().filter(|r| *r == 1).unwrap_or(0).into();
    if kind == 2 && out.get("secureNote").is_none() {
        out["secureNote"] = json!({"type": 0});
    }
    if let Some(fields) = item.get_mut("fields").and_then(Value::as_array_mut) {
        // Linked fields point at fields of the original item's kind; they don't survive.
        fields.retain(|f| f["type"].as_i64() != Some(3));
        out["fields"] = Value::Array(fields.clone());
    }
    out
}

/// Reads an export, telling the format from its contents. `keys` open an export
/// encrypted with this account's key; `password` one protected by a password.
pub fn parse(data: &[u8], password: Option<&Secret>, keys: &Keys) -> Result<Parsed> {
    if data.len() > IMPORT_MAX {
        return Err(TransferError::TooLarge);
    }
    if data.starts_with(b"PK\x03\x04") {
        return one_pux(data);
    }
    let text = std::str::from_utf8(data).map_err(|_| TransferError::Unknown)?.trim_start_matches('\u{feff}');
    if text.trim_start().starts_with('{') {
        let v: Value = serde_json::from_str(text).map_err(|_| TransferError::Unreadable("JSON"))?;
        return bitwarden_json(v, password, keys);
    }
    csv_import(text)
}

fn bitwarden_json(v: Value, password: Option<&Secret>, keys: &Keys) -> Result<Parsed> {
    if v.get("items").is_none() && v.get("data").is_none() {
        return Err(TransferError::Unknown);
    }
    if v["encrypted"] == true && v["passwordProtected"] == true {
        let password = password.filter(|p| !p.is_empty()).ok_or(TransferError::NeedsPassword)?;
        let n = |k: &str| v[k].as_u64();
        let kdf = Kdf::from_server(
            n("kdfType").unwrap_or(0),
            n("kdfIterations").ok_or(TransferError::Unreadable("Bitwarden"))?,
            n("kdfMemory"),
            n("kdfParallelism"),
        )?;
        let salt = v["salt"].as_str().ok_or(TransferError::Unreadable("Bitwarden"))?;
        let key = ExportKey::derive(password, salt, &kdf)?;
        let check = v["encKeyValidation_DO_NOT_EDIT"].as_str().ok_or(TransferError::Unreadable("Bitwarden"))?;
        key.decrypt(check).map_err(|_| TransferError::WrongPassword)?;
        let data = key.decrypt(v["data"].as_str().ok_or(TransferError::Unreadable("Bitwarden"))?)?;
        let inner: Value = serde_json::from_str(data.expose()).map_err(|_| TransferError::Unreadable("Bitwarden"))?;
        return plain_bitwarden(inner, "Bitwarden (password-protected)");
    }
    if v["encrypted"] == true {
        let mut user = keys.item(None, None)?;
        let check = v["encKeyValidation_DO_NOT_EDIT"].as_str().ok_or(TransferError::Unreadable("Bitwarden"))?;
        user.decrypt(check).map_err(|_| TransferError::OtherAccount)?;
        let mut v = v;
        for f in v["folders"].as_array_mut().into_iter().flatten() {
            if let Some(name) = f["name"].as_str().map(str::to_string) {
                f["name"] = Value::String(user.decrypt(&name)?.expose().to_string());
            }
        }
        drop(user);
        for item in v["items"].as_array_mut().into_iter().flatten() {
            let own = item["key"].as_str().map(str::to_string);
            let mut key = keys.item(None, own.as_deref())?;
            decrypt_item(item, &mut key)?;
        }
        return plain_bitwarden(v, "Bitwarden (encrypted)");
    }
    plain_bitwarden(v, "Bitwarden JSON")
}

fn plain_bitwarden(v: Value, format: &'static str) -> Result<Parsed> {
    let mut parsed = Parsed { format, ..Parsed::default() };
    let names: Vec<(String, String)> = v["folders"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|f| (f["id"].as_str().unwrap_or_default().to_string(), f["name"].as_str().unwrap_or_default().to_string()))
        .collect();
    for item in v["items"].as_array().into_iter().flatten() {
        if !item["deletedDate"].is_null() {
            continue;
        }
        let folder = item["folderId"]
            .as_str()
            .and_then(|id| names.iter().find(|(i, _)| i == id))
            .and_then(|(_, name)| parsed.folder(&name.clone()));
        parsed.push(item.clone(), folder)?;
    }
    Ok(parsed)
}

fn login(name: &str, username: &str, password: &str, uris: &[String], notes: &str, totp: &str) -> Value {
    let opt = |s: &str| if s.trim().is_empty() { Value::Null } else { Value::String(s.to_string()) };
    let uris: Vec<Value> =
        uris.iter().map(|u| u.trim()).filter(|u| !u.is_empty()).map(|u| json!({"uri": u, "match": null})).collect();
    json!({
        "type": 1, "name": name, "notes": opt(notes), "favorite": false, "reprompt": 0,
        "login": {"username": opt(username), "password": opt(password), "totp": opt(totp), "uris": uris},
    })
}

/// A name for a login from its address when the export has none.
fn host_name(uri: &str) -> String {
    crate::vault::host_of(uri).unwrap_or_else(|| uri.to_string())
}

fn csv_import(text: &str) -> Result<Parsed> {
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(text.as_bytes());
    let headers: Vec<String> =
        reader.headers().map_err(|_| TransferError::Unknown)?.iter().map(|h| h.trim().to_ascii_lowercase()).collect();
    let has = |names: &[&str]| names.iter().all(|n| headers.iter().any(|h| h == n));
    let format = if has(&["login_uri", "login_username", "login_password", "type", "name"]) {
        "Bitwarden CSV"
    } else if has(&["group", "title", "username", "password", "url"]) {
        "KeePassXC CSV"
    } else if has(&["url", "username", "password", "httprealm"]) {
        "Firefox CSV"
    } else if has(&["name", "url", "username", "password"]) {
        "Chrome CSV"
    } else {
        return Err(TransferError::Unknown);
    };
    let mut parsed = Parsed { format, ..Parsed::default() };
    for row in reader.records() {
        let row = row.map_err(|_| TransferError::Unreadable(format))?;
        let get = |name: &str| headers.iter().position(|h| h == name).and_then(|i| row.get(i)).unwrap_or_default().to_string();
        match format {
            "Bitwarden CSV" => {
                let uris: Vec<String> = get("login_uri").split(',').map(str::to_string).collect();
                let mut item = if get("type") == "note" {
                    json!({"type": 2, "name": get("name"), "notes": get("notes"), "secureNote": {"type": 0}})
                } else {
                    login(&get("name"), &get("login_username"), &get("login_password"), &uris, &get("notes"), &get("login_totp"))
                };
                item["favorite"] = (get("favorite") == "1").into();
                item["reprompt"] = (if get("reprompt") == "1" { 1 } else { 0 }).into();
                let fields: Vec<Value> = get("fields")
                    .lines()
                    .filter_map(|l| l.split_once(": "))
                    .map(|(n, v)| json!({"name": n, "value": v, "type": 0}))
                    .collect();
                if !fields.is_empty() {
                    item["fields"] = Value::Array(fields);
                }
                let folder = parsed.folder(&get("folder"));
                parsed.push(item, folder)?;
            }
            "KeePassXC CSV" => {
                let item = login(&get("title"), &get("username"), &get("password"), &[get("url")], &get("notes"), &get("totp"));
                let folder = parsed.folder(&get("group"));
                parsed.push(item, folder)?;
            }
            "Firefox CSV" => {
                let url = get("url");
                parsed.push(login(&host_name(&url), &get("username"), &get("password"), &[url], "", ""), None)?;
            }
            _ => {
                let url = get("url");
                let name = Some(get("name")).filter(|n| !n.trim().is_empty()).unwrap_or_else(|| host_name(&url));
                let notes = if headers.iter().any(|h| h == "note") { get("note") } else { get("notes") };
                parsed.push(login(&name, &get("username"), &get("password"), &[url], &notes, ""), None)?;
            }
        }
    }
    Ok(parsed)
}

/// 1Password's `.1pux`: a zip holding `export.data`, its accounts' vaults and items.
/// Vaults become folders; logins, passwords, notes, cards and identities map to their
/// kinds, and anything else becomes a note with its fields as custom fields.
fn one_pux(data: &[u8]) -> Result<Parsed> {
    let bad = || TransferError::Unreadable("1Password");
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(data)).map_err(|_| bad())?;
    let mut text = String::new();
    zip.by_name("export.data").map_err(|_| bad())?.take(IMPORT_MAX as u64 + 1).read_to_string(&mut text).map_err(|_| bad())?;
    if text.len() > IMPORT_MAX {
        return Err(TransferError::TooLarge);
    }
    let v: Value = serde_json::from_str(&text).map_err(|_| bad())?;
    let mut parsed = Parsed { format: "1Password", ..Parsed::default() };
    for account in v["accounts"].as_array().into_iter().flatten() {
        for vault in account["vaults"].as_array().into_iter().flatten() {
            let folder = parsed.folder(vault["attrs"]["name"].as_str().unwrap_or_default());
            for item in vault["items"].as_array().into_iter().flatten() {
                if item["state"].as_str().is_some_and(|s| s != "active") {
                    continue;
                }
                parsed.push(one_pux_item(item), folder)?;
            }
        }
    }
    Ok(parsed)
}

/// A 1Password field's value as text, and whether it's secret.
fn one_pux_value(value: &Value) -> Option<(String, bool)> {
    let (kind, v) = value.as_object()?.iter().next()?;
    let text = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Object(o) if kind == "email" => o.get("email_address")?.as_str()?.to_string(),
        Value::Object(o) if kind == "address" => ["street", "city", "state", "zip", "country"]
            .iter()
            .filter_map(|k| o.get(*k).and_then(Value::as_str).filter(|s| !s.is_empty()))
            .collect::<Vec<_>>()
            .join(", "),
        _ => return None,
    };
    let secret = matches!(kind.as_str(), "concealed" | "creditCardNumber" | "totp");
    (!text.is_empty()).then_some((text, secret))
}

fn one_pux_item(item: &Value) -> Value {
    let details = &item["details"];
    let overview = &item["overview"];
    let title = overview["title"].as_str().unwrap_or_default();
    let notes = details["notesPlain"].as_str().unwrap_or_default();
    let mut uris: Vec<String> = overview["url"].as_str().map(str::to_string).into_iter().collect();
    for u in overview["urls"].as_array().into_iter().flatten() {
        if let Some(url) = u["url"].as_str().filter(|u| !uris.iter().any(|x| x == u)) {
            uris.push(url.to_string());
        }
    }
    let mut username = String::new();
    let mut password = details["password"].as_str().unwrap_or_default().to_string();
    for f in details["loginFields"].as_array().into_iter().flatten() {
        match f["designation"].as_str() {
            Some("username") => username = f["value"].as_str().unwrap_or_default().to_string(),
            Some("password") => password = f["value"].as_str().unwrap_or_default().to_string(),
            _ => {}
        }
    }
    // Section fields: the card's and identity's own, a code key, or custom fields.
    let mut totp = String::new();
    let mut own: Vec<(String, String)> = Vec::new();
    let mut custom = Vec::new();
    for section in details["sections"].as_array().into_iter().flatten() {
        for f in section["fields"].as_array().into_iter().flatten() {
            let Some((text, secret)) = one_pux_value(&f["value"]) else { continue };
            let id = f["id"].as_str().unwrap_or_default().to_string();
            if f["value"].get("totp").is_some() && totp.is_empty() {
                totp = text;
                continue;
            }
            if f["value"].get("monthYear").is_some() && id == "expiry" {
                own.push(("expMonth".into(), text.get(4..).unwrap_or_default().trim_start_matches('0').to_string()));
                own.push(("expYear".into(), text.get(..4).unwrap_or_default().to_string()));
                continue;
            }
            own.push((id.clone(), text.clone()));
            let label = f["title"].as_str().filter(|t| !t.is_empty()).unwrap_or(&id).to_string();
            custom.push((id, json!({"name": label, "value": text, "type": i64::from(secret)})));
        }
    }
    let take = |own: &[(String, String)], ids: &[&str]| -> Value {
        ids.iter().find_map(|id| own.iter().find(|(k, _)| k == id)).map_or(Value::Null, |(_, v)| Value::String(v.clone()))
    };
    let used = |ids: &[&str], custom: &mut Vec<(String, Value)>| custom.retain(|(id, _)| !ids.contains(&id.as_str()));
    let mut out = match item["categoryUuid"].as_str().unwrap_or_default() {
        "001" | "005" => login(title, &username, &password, &uris, notes, &totp),
        "002" => {
            let ids = ["cardholder", "type", "ccnum", "cvv", "expiry", "expMonth", "expYear"];
            let card = json!({
                "cardholderName": take(&own, &["cardholder"]), "brand": take(&own, &["type"]),
                "number": take(&own, &["ccnum"]), "code": take(&own, &["cvv"]),
                "expMonth": take(&own, &["expMonth"]), "expYear": take(&own, &["expYear"]),
            });
            used(&ids, &mut custom);
            json!({"type": 3, "name": title, "notes": notes, "card": card})
        }
        "004" => {
            let ids = ["firstname", "initial", "lastname", "email", "defphone", "phone", "company", "address", "username"];
            let identity = json!({
                "firstName": take(&own, &["firstname"]), "middleName": take(&own, &["initial"]),
                "lastName": take(&own, &["lastname"]), "email": take(&own, &["email"]),
                "phone": take(&own, &["defphone", "phone"]), "company": take(&own, &["company"]),
                "address1": take(&own, &["address"]), "username": take(&own, &["username"]),
            });
            used(&ids, &mut custom);
            json!({"type": 4, "name": title, "notes": notes, "identity": identity})
        }
        _ => json!({"type": 2, "name": title, "notes": notes, "secureNote": {"type": 0}}),
    };
    let fields: Vec<Value> = custom.into_iter().map(|(_, f)| f).collect();
    if !fields.is_empty() {
        out["fields"] = Value::Array(fields);
    }
    out["favorite"] = (item["favIndex"].as_i64().unwrap_or(0) > 0).into();
    out
}

/// The import request: every item and folder encrypted with the user key, and which
/// folder each item goes in.
pub fn import_request(keys: &Keys, user: Uuid, parsed: &Parsed) -> Result<Value> {
    let mut key = keys.item(None, None)?;
    let folders: Vec<Value> = parsed.folders.iter().map(|f| Ok(json!({"name": key.encrypt(f)?}))).collect::<Result<_>>()?;
    let mut ciphers = Vec::new();
    let mut relationships = Vec::new();
    for (i, (item, folder)) in parsed.items.iter().enumerate() {
        let mut item = item.clone();
        encrypt_item(&mut item, &mut key)?;
        item["encryptedFor"] = Value::String(user.to_string());
        ciphers.push(item);
        if let Some(f) = folder {
            relationships.push(json!({"key": i, "value": f}));
        }
    }
    Ok(json!({"ciphers": ciphers, "folders": folders, "folderRelationships": relationships}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_formats_are_told_apart() {
        let chrome = "name,url,username,password,note\nGitHub,https://github.com/login,octo,pw1,hello\n";
        let p = csv_import(chrome).unwrap();
        assert_eq!(p.format, "Chrome CSV");
        assert_eq!(p.items[0].0["login"]["username"], "octo");
        assert_eq!(p.items[0].0["notes"], "hello");

        let firefox = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\"\n\"https://www.example.com\",\"me\",\"pw\",,\"\",\"{x}\"\n";
        let p = csv_import(firefox).unwrap();
        assert_eq!(p.format, "Firefox CSV");
        assert_eq!(p.items[0].0["name"], "example.com");

        let keepass = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"\n\"Root/Work\",\"Mail\",\"me\",\"pw\",\"https://mail.example\",\"\",\"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\"\n";
        let p = csv_import(keepass).unwrap();
        assert_eq!((p.format, p.folders.as_slice()), ("KeePassXC CSV", &["Work".to_string()][..]));
        assert_eq!(p.items[0].1, Some(0));
        assert!(p.items[0].0["login"]["totp"].as_str().unwrap().starts_with("otpauth://"));

        let bitwarden = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,1,login,GitHub,,\"pin: 1234\",0,\"https://a.example,https://b.example\",octo,pw,\n,,note,Memo,remember,,0,,,,\n";
        let p = csv_import(bitwarden).unwrap();
        assert_eq!(p.format, "Bitwarden CSV");
        assert_eq!(p.items.len(), 2);
        assert_eq!(p.items[0].0["login"]["uris"].as_array().unwrap().len(), 2);
        assert_eq!(p.items[0].0["fields"][0]["value"], "1234");
        assert_eq!(p.items[0].0["favorite"], true);
        assert_eq!(p.items[1].0["type"], 2);
        assert_eq!(p.counts()["note"], 1);

        assert_eq!(csv_import("a,b,c\n1,2,3\n").err(), Some(TransferError::Unknown));
    }

    #[test]
    fn one_password_items() {
        let item = json!({
            "uuid": "x", "favIndex": 1, "state": "active", "categoryUuid": "001",
            "overview": {"title": "GitHub", "url": "https://github.com", "urls": [{"url": "https://gist.github.com"}]},
            "details": {
                "loginFields": [{"designation": "username", "value": "octo"}, {"designation": "password", "value": "pw"}],
                "notesPlain": "n",
                "sections": [{"fields": [
                    {"title": "one-time password", "id": "TOTP_1", "value": {"totp": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"}},
                    {"title": "PIN", "id": "pin", "value": {"concealed": "1234"}},
                ]}],
            },
        });
        let v = one_pux_item(&item);
        assert_eq!(v["type"], 1);
        assert_eq!(v["login"]["password"], "pw");
        assert_eq!(v["login"]["uris"].as_array().unwrap().len(), 2);
        assert!(v["login"]["totp"].as_str().unwrap().starts_with("otpauth://"));
        assert_eq!((v["fields"][0]["name"].as_str(), v["fields"][0]["type"].as_i64()), (Some("PIN"), Some(1)));
        assert_eq!(v["favorite"], true);

        let card = json!({"categoryUuid": "002", "overview": {"title": "Visa"}, "details": {"sections": [{"fields": [
            {"title": "number", "id": "ccnum", "value": {"creditCardNumber": "4111111111111111"}},
            {"title": "expiry", "id": "expiry", "value": {"monthYear": 202709}},
            {"title": "bank", "id": "bank", "value": {"string": "ACME"}},
        ]}]}});
        let v = one_pux_item(&card);
        assert_eq!(
            (v["card"]["number"].as_str(), v["card"]["expMonth"].as_str(), v["card"]["expYear"].as_str()),
            (Some("4111111111111111"), Some("9"), Some("2027"))
        );
        assert_eq!(v["fields"].as_array().unwrap().len(), 1, "only the bank is left over");
    }

    #[test]
    fn imported_items_are_normalized() {
        let v = normalized(json!({"id": "x", "organizationId": "o", "type": 9, "name": " ", "collectionIds": ["c"],
                                   "fields": [{"name": "l", "value": null, "type": 3, "linkedId": 100}]}));
        assert_eq!((v["type"].as_i64(), v["name"].as_str()), (Some(2), Some("Untitled")));
        assert!(v.get("id").is_none() && v.get("organizationId").is_none() && v.get("collectionIds").is_none());
        assert_eq!(v["fields"], json!([]));
    }
}
