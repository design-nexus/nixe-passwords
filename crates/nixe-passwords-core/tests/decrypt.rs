//! Offline: decrypts the recorded sync of two throwaway accounts (tests/fixtures, made by
//! the spike) and compares every field with what the official `bw` CLI decrypted.

use nixe_passwords_core::crypto::{CryptoError, Kdf, Keys, MasterKey};
use nixe_passwords_core::model::Sync;
use nixe_passwords_core::secret::Secret;
use serde_json::{Value, json};

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

struct Account {
    email: String,
    password: Secret,
    kdf: Kdf,
    sync: Sync,
    bw: Vec<Value>,
}

fn account(tag: &str) -> Account {
    let meta = fixture(&format!("{tag}-account.json"));
    let pre = &meta["prelogin"];
    Account {
        email: meta["email"].as_str().unwrap().into(),
        password: Secret::new(meta["password"].as_str().unwrap()),
        kdf: Kdf::from_server(
            pre["kdf"].as_u64().unwrap(),
            pre["kdfIterations"].as_u64().unwrap(),
            pre["kdfMemory"].as_u64(),
            pre["kdfParallelism"].as_u64(),
        )
        .unwrap(),
        sync: serde_json::from_value(fixture(&format!("{tag}-sync.json"))).unwrap(),
        bw: serde_json::from_value(fixture(&format!("{tag}-bw.json"))).unwrap(),
    }
}

fn unlock(a: &Account) -> Keys {
    let master = MasterKey::derive(&a.password, &a.email, &a.kdf).unwrap();
    let keys = Keys::unlock(&master, &a.sync.profile.key).unwrap();
    keys.add_private_key(a.sync.profile.private_key.as_deref().unwrap()).unwrap();
    for org in &a.sync.profile.organizations {
        keys.add_organization(org.id, org.key.as_deref().unwrap()).unwrap();
    }
    keys
}

fn opt(s: Option<Secret>) -> Value {
    s.map(|s| Value::String(s.expose().to_string())).unwrap_or(Value::Null)
}

fn check(tag: &str) {
    let a = account(tag);
    let keys = unlock(&a);
    assert_eq!(a.sync.ciphers.len(), a.bw.len());
    for c in &a.sync.ciphers {
        let mut k = keys.item(c.organization_id, c.key.as_deref()).unwrap();
        let login = c.login.as_ref();
        let card = c.card.as_ref();
        let field = c.fields.as_ref().and_then(|f| f.first());
        let card_field = |name: &str| card.and_then(|c| c[name].as_str());
        let ours = json!({
            "name": k.decrypt(&c.name).unwrap().expose(),
            "notes": opt(k.decrypt_opt(c.notes.as_deref()).unwrap()),
            "username": opt(k.decrypt_opt(login.and_then(|l| l.username.as_deref())).unwrap()),
            "password": opt(k.decrypt_opt(login.and_then(|l| l.password.as_deref())).unwrap()),
            "totp": opt(k.decrypt_opt(login.and_then(|l| l.totp.as_deref())).unwrap()),
            "uri": opt(k.decrypt_opt(login.and_then(|l| l.uris.as_ref()?.first()?.uri.as_deref())).unwrap()),
            "card_number": opt(k.decrypt_opt(card_field("number")).unwrap()),
            "field": opt(k.decrypt_opt(field.and_then(|f| f.value.as_deref())).unwrap()),
        });
        let bw = a.bw.iter().find(|b| b["id"] == c.id.to_string()).unwrap();
        let theirs = json!({
            "name": bw["name"], "notes": bw["notes"],
            "username": bw["login"]["username"], "password": bw["login"]["password"],
            "totp": bw["login"]["totp"], "uri": bw["login"]["uris"][0]["uri"],
            "card_number": bw["card"]["number"], "field": bw["fields"][0]["value"],
        });
        assert_eq!(ours, theirs, "[{tag}] cipher {}", c.id);
    }
    for f in &a.sync.folders {
        let name = keys.item(None, None).unwrap().decrypt(&f.name).unwrap();
        assert!(name.expose().starts_with("Work "));
    }
    for col in &a.sync.collections {
        let name = keys.item(Some(col.organization_id), None).unwrap().decrypt(&col.name).unwrap();
        assert_eq!(name.expose(), "Shared");
    }
}

#[test]
fn pbkdf2_account_matches_bw() {
    check("pbkdf2");
}

#[test]
fn argon2_account_matches_bw() {
    check("argon2");
}

#[test]
fn wrong_password_is_reported() {
    let a = account("pbkdf2");
    let master = MasterKey::derive(&Secret::new("not the password"), &a.email, &a.kdf).unwrap();
    assert_eq!(Keys::unlock(&master, &a.sync.profile.key).err(), Some(CryptoError::WrongPassword));
}

#[test]
fn server_hash_is_stable_and_not_the_password() {
    let a = account("pbkdf2");
    let master = MasterKey::derive(&a.password, &a.email, &a.kdf).unwrap();
    let hash = master.server_hash(&a.password);
    assert_ne!(hash.expose(), a.password.expose());
    // The same email in other case and spacing gives the same key.
    let upper = MasterKey::derive(&a.password, &format!(" {} ", a.email.to_uppercase()), &a.kdf).unwrap();
    assert_eq!(upper.server_hash(&a.password).expose(), hash.expose());
}

#[test]
fn lock_drops_every_key() {
    let a = account("pbkdf2");
    let keys = unlock(&a);
    let org = a.sync.profile.organizations[0].id;
    assert!(keys.is_unlocked() && keys.has_organization(org));
    keys.lock();
    assert!(!keys.is_unlocked() && !keys.has_organization(org));
    assert_eq!(keys.item(None, None).err(), Some(CryptoError::MissingKey));
    assert_eq!(keys.item(Some(org), None).err(), Some(CryptoError::MissingKey));
}

#[test]
fn new_item_key_round_trips() {
    let a = account("pbkdf2");
    let keys = unlock(&a);
    let org = a.sync.profile.organizations[0].id;
    for owner in [None, Some(org)] {
        let (mut k, wrapped) = keys.new_item(owner).unwrap();
        let enc = k.encrypt("canary-new-Pw!9").unwrap();
        assert!(enc.starts_with("2.") && !enc.contains("canary"));
        drop(k);
        let mut again = keys.item(owner, Some(&wrapped)).unwrap();
        assert_eq!(again.decrypt(&enc).unwrap().expose(), "canary-new-Pw!9");
        // Not readable with the bare user/org key.
        assert!(keys.item(owner, None).unwrap().decrypt(&enc).is_err());
    }
}

#[test]
fn tampered_values_fail() {
    let a = account("pbkdf2");
    let keys = unlock(&a);
    let c = a.sync.ciphers.iter().find(|c| c.organization_id.is_none()).unwrap();
    let mut k = keys.item(None, c.key.as_deref()).unwrap();
    let mut parts: Vec<String> = c.name.split('|').map(str::to_string).collect();
    // One different, still valid base64 character in the ciphertext: only the MAC can tell.
    let first = parts[1].remove(0);
    parts[1].insert(0, if first == 'A' { 'B' } else { 'A' });
    assert_eq!(k.decrypt(&parts.join("|")).err(), Some(CryptoError::Decrypt));
    assert_eq!(k.decrypt("not an encstring").err(), Some(CryptoError::Malformed));
}
