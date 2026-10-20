//! Phase 0 spike against a throwaway Vaultwarden (see apps/passwords/docs/PLAN.md):
//!
//!   NIXE_PW_TEST_SERVER=https://127.0.0.1:8087 \
//!   NIXE_PW_TEST_CA=target/vaultwarden-test/data/cert.pem \
//!     cargo test -p nixe-passwords-core --test spike -- --ignored --nocapture
//!
//! Registers fresh accounts (PBKDF2 and Argon2id), lets the official `bw` CLI create
//! items in them, then logs in, syncs and decrypts every item with bitwarden-crypto,
//! comparing the result with what `bw` decrypts. Test data only; never a real server.
#![allow(deprecated)] // the *_key_unsigned helpers; the adapter will use the key store

use std::num::NonZeroU32;
use std::process::Command;
use std::str::FromStr;

use bitwarden_crypto::{
    BitwardenLegacyKeyBytes, EncString, HashPurpose, Kdf, KeyDecryptable, KeyEncryptable, MasterKey, Pkcs8PrivateKeyBytes,
    PrivateKey, PublicKey, SpkiPublicKeyBytes, SymmetricCryptoKey, SymmetricKeyAlgorithm, UnsignedSharedKey, UserKey,
};
use bitwarden_encoding::B64;
use reqwest::blocking::Client;
use serde_json::{Value, json};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// The test server's self-signed certificate; trusted only by this test and its `bw`.
fn test_ca() -> String {
    let path = std::env::var("NIXE_PW_TEST_CA").expect("set NIXE_PW_TEST_CA to the test server's cert");
    std::fs::canonicalize(path).expect("NIXE_PW_TEST_CA").display().to_string()
}

fn server() -> String {
    std::env::var("NIXE_PW_TEST_SERVER").expect("set NIXE_PW_TEST_SERVER to the test server")
}

/// A field from a Vaultwarden response, which may be camelCase or PascalCase.
fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
    let mut pascal = key.to_string();
    pascal[..1].make_ascii_uppercase();
    match v.get(key) {
        Some(found) if !found.is_null() => found,
        _ => v.get(&pascal).unwrap_or(&Value::Null),
    }
}

fn s(v: &Value) -> Option<&str> {
    v.as_str()
}

fn kdf_fields(kdf: &Kdf) -> Value {
    match kdf {
        Kdf::PBKDF2 { iterations } => json!({"kdf": 0, "kdfIterations": iterations.get()}),
        Kdf::Argon2id { iterations, memory, parallelism } => json!({
            "kdf": 1, "kdfIterations": iterations.get(),
            "kdfMemory": memory.get(), "kdfParallelism": parallelism.get(),
        }),
    }
}

fn kdf_from_prelogin(v: &Value) -> Kdf {
    let n = |k: &str| NonZeroU32::new(get(v, k).as_u64().unwrap() as u32).unwrap();
    match get(v, "kdf").as_u64().unwrap() {
        0 => Kdf::PBKDF2 { iterations: n("kdfIterations") },
        1 => Kdf::Argon2id { iterations: n("kdfIterations"), memory: n("kdfMemory"), parallelism: n("kdfParallelism") },
        other => panic!("unknown kdf {other}"),
    }
}

fn check(resp: reqwest::blocking::Response, what: &str) -> Res<Value> {
    let status = resp.status();
    let text = resp.text()?;
    if !status.is_success() {
        return Err(format!("{what}: {status} {text}").into());
    }
    Ok(if text.is_empty() { Value::Null } else { serde_json::from_str(&text)? })
}

/// Account creation is test-fixture code: `bw` can't register accounts.
fn register(http: &Client, email: &str, password: &str, kdf: &Kdf) -> Res<()> {
    let master = MasterKey::derive(password, email, kdf)?;
    let hash = master.derive_master_key_hash(password.as_bytes(), HashPurpose::ServerAuthorization);
    let (user_key, protected) = master.make_user_key()?;
    let pair = user_key.make_key_pair()?;
    // With no mail configured, Vaultwarden returns the verification token directly.
    let token = http
        .post(format!("{}/identity/accounts/register/send-verification-email", server()))
        .json(&json!({"email": email, "name": "Spike", "receiveMarketingEmails": false}))
        .send()?
        .text()?;
    let mut body = json!({
        "email": email, "emailVerificationToken": token.trim().trim_matches('"'),
        "masterPasswordHash": hash.to_string(), "masterPasswordHint": null,
        "userSymmetricKey": protected,
        "userAsymmetricKeys": {"publicKey": pair.public.to_string(), "encryptedPrivateKey": pair.private},
    });
    body.as_object_mut().unwrap().extend(kdf_fields(kdf).as_object().unwrap().clone());
    check(http.post(format!("{}/identity/accounts/register/finish", server())).json(&body).send()?, "register")?;
    Ok(())
}

struct Session {
    access: String,
    refresh: String,
    master: MasterKey,
}

fn login(http: &Client, email: &str, password: &str, device: &str) -> Res<Session> {
    let pre =
        check(http.post(format!("{}/identity/accounts/prelogin", server())).json(&json!({"email": email})).send()?, "prelogin")?;
    let kdf = kdf_from_prelogin(&pre);
    let master = MasterKey::derive(password, email, &kdf)?;
    let hash = master.derive_master_key_hash(password.as_bytes(), HashPurpose::ServerAuthorization);
    let token = check(
        http.post(format!("{}/identity/connect/token", server()))
            .form(&[
                ("grant_type", "password"),
                ("username", email),
                ("password", &hash.to_string()),
                ("scope", "api offline_access"),
                ("client_id", "desktop"),
                ("deviceType", "8"),
                ("deviceIdentifier", device),
                ("deviceName", "nixe-passwords-spike"),
            ])
            .send()?,
        "token",
    )?;
    Ok(Session {
        access: s(get(&token, "access_token")).unwrap().into(),
        refresh: s(get(&token, "refresh_token")).unwrap().into(),
        master,
    })
}

fn pre_for(http: &Client, email: &str) -> Res<Value> {
    check(http.post(format!("{}/identity/accounts/prelogin", server())).json(&json!({"email": email})).send()?, "prelogin")
}

fn dec_str(v: &Value, key: &SymmetricCryptoKey) -> Res<Option<String>> {
    match s(v) {
        None => Ok(None),
        Some(text) => Ok(Some(EncString::from_str(text)?.decrypt_with_key(key)?)),
    }
}

/// Runs the official CLI with its own data directory, so the user's `bw` is untouched.
struct Bw {
    dir: tempfile::TempDir,
    session: String,
}

impl Bw {
    fn cmd(&self) -> Command {
        let mut c = Command::new("bw");
        c.env("BITWARDENCLI_APPDATA_DIR", self.dir.path()).env("BW_NOINTERACTION", "true").env("NODE_EXTRA_CA_CERTS", test_ca());
        if !self.session.is_empty() {
            c.env("BW_SESSION", &self.session);
        }
        c
    }

    fn run(&self, args: &[&str]) -> Res<String> {
        let out = self.cmd().args(args).output()?;
        if !out.status.success() {
            return Err(format!("bw {args:?}: {}", String::from_utf8_lossy(&out.stderr)).into());
        }
        Ok(String::from_utf8(out.stdout)?)
    }

    fn login(email: &str, password: &str) -> Res<Bw> {
        let mut bw = Bw { dir: tempfile::tempdir()?, session: String::new() };
        bw.run(&["config", "server", &server()])?;
        let out =
            bw.cmd().env("NIXE_SPIKE_PW", password).args(["login", email, "--passwordenv", "NIXE_SPIKE_PW", "--raw"]).output()?;
        if !out.status.success() {
            return Err(format!("bw login: {}", String::from_utf8_lossy(&out.stderr)).into());
        }
        bw.session = String::from_utf8(out.stdout)?.trim().to_string();
        Ok(bw)
    }

    fn create(&self, kind: &str, value: Value) -> Res<Value> {
        let encoded = B64::from(serde_json::to_vec(&value)?).to_string();
        Ok(serde_json::from_str(&self.run(&["create", kind, &encoded])?)?)
    }
}

fn create_org(http: &Client, sess: &Session, email: &str, public: &PublicKey) -> Res<(String, String)> {
    let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
    let shared = UnsignedSharedKey::encapsulate_key_unsigned(&org_key, public)?;
    let pair = UserKey::new(org_key.clone()).make_key_pair()?;
    let collection: EncString = "Shared".encrypt_with_key(&org_key)?;
    let org = check(
        http.post(format!("{}/api/organizations", server()))
            .bearer_auth(&sess.access)
            .json(&json!({
                "name": "Spike Org", "billingEmail": email, "collectionName": collection,
                "key": shared.to_string(), "planType": 0,
                "keys": {"publicKey": pair.public.to_string(), "encryptedPrivateKey": pair.private},
            }))
            .send()?,
        "create org",
    )?;
    let id = s(get(&org, "id")).unwrap().to_string();
    let cols = check(
        http.get(format!("{}/api/organizations/{id}/collections", server())).bearer_auth(&sess.access).send()?,
        "collections",
    )?;
    let col = s(get(&get(&cols, "data")[0], "id")).unwrap().to_string();
    Ok((id, col))
}

fn items_for(bw: &Bw, folder: &str, org: Option<(&str, &str)>, tag: &str) -> Res<()> {
    let (org_id, cols) = match org {
        Some((o, c)) => (json!(o), json!([c])),
        None => (Value::Null, Value::Null),
    };
    let base = |kind: u8, name: &str| {
        json!({
            "type": kind, "name": name, "notes": format!("{tag} notes for {name}"), "favorite": false,
            "fields": [{"name": "recovery", "value": format!("{tag}-field"), "type": 1}],
            "reprompt": 0, "folderId": if org.is_some() { Value::Null } else { json!(folder) },
            "organizationId": org_id, "collectionIds": cols,
            "login": null, "secureNote": null, "card": null, "identity": null,
        })
    };
    let mut login = base(1, &format!("GitHub {tag}"));
    login["login"] = json!({
        "username": format!("octo-{tag}"), "password": format!("canary-{tag}-Pw!9"),
        "totp": "otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        "uris": [{"match": null, "uri": "https://github.com/login"}],
    });
    bw.create("item", login)?;
    if org.is_some() {
        return Ok(());
    }
    let mut note = base(2, &format!("Note {tag}"));
    note["secureNote"] = json!({"type": 0});
    bw.create("item", note)?;
    let mut card = base(3, &format!("Card {tag}"));
    card["card"] = json!({"cardholderName": "Octo Cat", "brand": "Visa", "number": "4111111111111111",
                          "expMonth": "12", "expYear": "2030", "code": "123"});
    bw.create("item", card)?;
    let mut ident = base(4, &format!("Identity {tag}"));
    ident["identity"] = json!({"firstName": "Octo", "lastName": "Cat", "email": "octo@example.com"});
    bw.create("item", ident)?;
    Ok(())
}

/// Our decryption of one synced cipher, as the fields `bw list items` also shows.
fn decrypt_cipher(c: &Value, user_key: &SymmetricCryptoKey, org_keys: &[(String, SymmetricCryptoKey)]) -> Res<(Value, bool)> {
    let base = match s(get(c, "organizationId")) {
        Some(org) => &org_keys.iter().find(|(id, _)| id == org).ok_or("no org key")?.1,
        None => user_key,
    };
    let own_key = s(get(c, "key"));
    let cipher_key;
    let key = match own_key {
        Some(text) => {
            let bytes: Vec<u8> = EncString::from_str(text)?.decrypt_with_key(base)?;
            cipher_key = SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(bytes))?;
            &cipher_key
        }
        None => base,
    };
    let d = |v: &Value| dec_str(v, key);
    let login = get(c, "login");
    let card = get(c, "card");
    let ident = get(c, "identity");
    let fields = get(c, "fields");
    Ok((
        json!({
            "name": d(get(c, "name"))?,
            "notes": d(get(c, "notes"))?,
            "username": d(get(login, "username"))?,
            "password": d(get(login, "password"))?,
            "totp": d(get(login, "totp"))?,
            "uri": d(get(&get(login, "uris")[0], "uri"))?,
            "card_number": d(get(card, "number"))?,
            "card_code": d(get(card, "code"))?,
            "first_name": d(get(ident, "firstName"))?,
            "field": d(get(&fields[0], "value"))?,
        }),
        own_key.is_some(),
    ))
}

fn bw_view(item: &Value) -> Value {
    let o = |v: &Value| v.as_str().map(str::to_string);
    json!({
        "name": o(&item["name"]), "notes": o(&item["notes"]),
        "username": o(&item["login"]["username"]), "password": o(&item["login"]["password"]),
        "totp": o(&item["login"]["totp"]), "uri": o(&item["login"]["uris"][0]["uri"]),
        "card_number": o(&item["card"]["number"]), "card_code": o(&item["card"]["code"]),
        "first_name": o(&item["identity"]["firstName"]), "field": o(&item["fields"][0]["value"]),
    })
}

fn run_account(http: &Client, tag: &str, kdf: Kdf) -> Res<()> {
    let email = format!("spike-{tag}-{}@example.com", &uuid::Uuid::new_v4().to_string()[..8]);
    let password = format!("correct horse {tag} battery");
    let device = uuid::Uuid::new_v4().to_string();
    register(http, &email, &password, &kdf)?;
    println!("[{tag}] registered {email}");

    // An organization needs the account's keys; create it with our own session.
    let sess = login(http, &email, &password, &device)?;
    let sync = check(http.get(format!("{}/api/sync?excludeDomains=true", server())).bearer_auth(&sess.access).send()?, "sync")?;
    let profile = get(&sync, "profile");
    let user_key = sess.master.decrypt_user_key(EncString::from_str(s(get(profile, "key")).unwrap())?)?;
    let private_der: Vec<u8> = EncString::from_str(s(get(profile, "privateKey")).unwrap())?.decrypt_with_key(&user_key)?;
    let private = PrivateKey::from_der(&Pkcs8PrivateKeyBytes::from(private_der))?;
    let public = PublicKey::from_der(&SpkiPublicKeyBytes::from(private.to_public_key().to_der()?.as_ref().to_vec()))?;
    let (org_id, col_id) = create_org(http, &sess, &email, &public)?;
    println!("[{tag}] created organization");

    let bw = Bw::login(&email, &password)?;
    let folder = bw.create("folder", json!({"name": format!("Work {tag}")}))?;
    let folder_id = folder["id"].as_str().unwrap().to_string();
    items_for(&bw, &folder_id, None, tag)?;
    bw.run(&["sync"])?;
    items_for(&bw, &folder_id, Some((&org_id, &col_id)), &format!("{tag}-org"))?;
    let expected: Vec<Value> = serde_json::from_str(&bw.run(&["list", "items"])?)?;
    println!("[{tag}] bw created {} items", expected.len());

    // Now the client side under test: a fresh login, sync, decrypt everything.
    let sess = login(http, &email, &password, &device)?;
    let sync = check(http.get(format!("{}/api/sync?excludeDomains=true", server())).bearer_auth(&sess.access).send()?, "sync")?;
    let profile = get(&sync, "profile");
    let user_key = sess.master.decrypt_user_key(EncString::from_str(s(get(profile, "key")).unwrap())?)?;
    let private_der: Vec<u8> = EncString::from_str(s(get(profile, "privateKey")).unwrap())?.decrypt_with_key(&user_key)?;
    let private = PrivateKey::from_der(&Pkcs8PrivateKeyBytes::from(private_der))?;
    let mut org_keys = Vec::new();
    for org in get(profile, "organizations").as_array().unwrap() {
        let shared = UnsignedSharedKey::from_str(s(get(org, "key")).unwrap())?;
        org_keys.push((s(get(org, "id")).unwrap().to_string(), shared.decapsulate_key_unsigned(&private)?));
    }
    let ciphers = get(&sync, "ciphers").as_array().unwrap();
    assert_eq!(ciphers.len(), expected.len(), "cipher count");
    // NIXE_PW_FIXTURES=dir saves this throwaway account's encrypted sync and bw's
    // decrypted view, for the offline unit tests.
    if let Ok(dir) = std::env::var("NIXE_PW_FIXTURES") {
        let dir = std::path::Path::new(&dir);
        std::fs::create_dir_all(dir)?;
        let meta = json!({"email": email, "password": password, "prelogin": pre_for(http, &email)?});
        std::fs::write(dir.join(format!("{tag}-account.json")), serde_json::to_string_pretty(&meta)?)?;
        std::fs::write(dir.join(format!("{tag}-sync.json")), serde_json::to_string_pretty(&sync)?)?;
        std::fs::write(dir.join(format!("{tag}-bw.json")), serde_json::to_string_pretty(&expected)?)?;
    }
    let mut with_own_key = 0;
    for c in ciphers {
        let id = s(get(c, "id")).unwrap();
        let (ours, own) = decrypt_cipher(c, &user_key, &org_keys)?;
        with_own_key += own as usize;
        let theirs = bw_view(expected.iter().find(|e| e["id"] == id).ok_or("missing in bw")?);
        assert_eq!(ours, theirs, "cipher {id}");
    }
    for f in get(&sync, "folders").as_array().unwrap() {
        assert_eq!(dec_str(get(f, "name"), &user_key)?.as_deref(), Some(format!("Work {tag}").as_str()));
    }
    println!(
        "[{tag}] decrypted {} ciphers ({} with their own key), {} org key(s): all match bw",
        ciphers.len(),
        with_own_key,
        org_keys.len()
    );
    let encs: Vec<&str> = ciphers.iter().filter_map(|c| s(get(c, "name"))).map(|n| &n[..2]).collect();
    println!("[{tag}] EncString types seen in names: {:?}", {
        let mut e = encs.clone();
        e.sort();
        e.dedup();
        e
    });

    // Writing: a cipher with its own key, made here, must read back in `bw`.
    let cipher_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
    let wrapped: EncString = (&cipher_key.to_encoded()).encrypt_with_key(&user_key)?;
    let e = |text: &str| -> Res<EncString> { Ok(text.encrypt_with_key(&cipher_key)?) };
    // Clients drop a URI whose encrypted SHA-256 checksum is missing or wrong.
    let checksum = B64::from(<sha2::Sha256 as sha2::Digest>::digest(b"https://example.com").to_vec()).to_string();
    let made = check(
        http.post(format!("{}/api/ciphers", server()))
            .bearer_auth(&sess.access)
            .json(&json!({
                "type": 1, "name": e("Written by nixe")?, "notes": null, "key": wrapped,
                "encryptedFor": get(profile, "id"), "folderId": null, "organizationId": null,
                "favorite": false, "reprompt": 0, "fields": null,
                "login": {"username": e("nixe-user")?, "password": e("canary-nixe-Pw!9")?,
                          "uris": [{"uri": e("https://example.com")?, "uriChecksum": e(&checksum)?, "match": null}], "totp": null},
            }))
            .send()?,
        "create cipher",
    )?;
    bw.run(&["sync"])?;
    let read_back: Value = serde_json::from_str(&bw.run(&["get", "item", s(get(&made, "id")).unwrap()])?)?;
    assert_eq!(read_back["name"], "Written by nixe");
    assert_eq!(read_back["login"]["password"], "canary-nixe-Pw!9");
    assert_eq!(read_back["login"]["uris"][0]["uri"], "https://example.com");
    let (ours, own) = decrypt_cipher(&made, &user_key, &org_keys)?;
    assert!(own && ours["password"] == "canary-nixe-Pw!9");
    println!("[{tag}] a cipher with its own key, written here, reads back in bw and here");

    // Token refresh.
    let refreshed = check(
        http.post(format!("{}/identity/connect/token", server()))
            .form(&[("grant_type", "refresh_token"), ("client_id", "desktop"), ("refresh_token", &sess.refresh)])
            .send()?,
        "refresh",
    )?;
    assert!(s(get(&refreshed, "access_token")).is_some());
    println!("[{tag}] refresh token works");

    // Revision conflicts: an update with a stale lastKnownRevisionDate.
    let synced = ciphers.iter().find(|c| get(c, "organizationId").is_null()).unwrap();
    let id = s(get(synced, "id")).unwrap().to_string();
    let mut c = json!({});
    for k in [
        "type",
        "folderId",
        "organizationId",
        "key",
        "name",
        "notes",
        "fields",
        "login",
        "card",
        "identity",
        "secureNote",
        "favorite",
        "reprompt",
        "passwordHistory",
    ] {
        c[k] = get(synced, k).clone();
    }
    c["lastKnownRevisionDate"] = get(synced, "revisionDate").clone();
    c["encryptedFor"] = get(get(&sync, "profile"), "id").clone();
    check(http.put(format!("{}/api/ciphers/{id}", server())).bearer_auth(&sess.access).json(&c).send()?, "first update")?;
    // Vaultwarden only rejects a copy more than a second older than its own.
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let second = http.put(format!("{}/api/ciphers/{id}", server())).bearer_auth(&sess.access).json(&c).send()?;
    let rejected = !second.status().is_success();
    println!("[{tag}] stale update: HTTP {} (rejected = {rejected})", second.status());
    assert!(rejected, "stale update accepted");

    // Soft delete and restore.
    check(http.put(format!("{}/api/ciphers/{id}/delete", server())).bearer_auth(&sess.access).send()?, "soft delete")?;
    check(http.put(format!("{}/api/ciphers/{id}/restore", server())).bearer_auth(&sess.access).send()?, "restore")?;
    println!("[{tag}] soft delete and restore work");
    Ok(())
}

#[test]
#[ignore = "needs NIXE_PW_TEST_SERVER (a throwaway Vaultwarden)"]
fn vaultwarden_round_trip() {
    let ca = reqwest::Certificate::from_pem(&std::fs::read(test_ca()).unwrap()).unwrap();
    let http = Client::builder().tls_certs_only([ca]).build().unwrap();
    run_account(&http, "pbkdf2", Kdf::PBKDF2 { iterations: NonZeroU32::new(600_000).unwrap() }).unwrap();
    run_account(
        &http,
        "argon2",
        Kdf::Argon2id {
            iterations: NonZeroU32::new(3).unwrap(),
            memory: NonZeroU32::new(64).unwrap(),
            parallelism: NonZeroU32::new(4).unwrap(),
        },
    )
    .unwrap();
}
