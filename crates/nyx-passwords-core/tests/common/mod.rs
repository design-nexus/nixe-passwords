//! Shared helpers for tests against the throwaway Vaultwarden from
//! apps/passwords/scripts/test-server.sh (NYX_PW_TEST_SERVER, NYX_PW_TEST_CA).
#![allow(dead_code)]

use bitwarden_crypto::{HashPurpose, Kdf, MasterKey};
use serde_json::{Value, json};

pub fn server_url() -> String {
    std::env::var("NYX_PW_TEST_SERVER").expect("set NYX_PW_TEST_SERVER to the test server")
}

pub fn ca_pem() -> Vec<u8> {
    std::fs::read(std::env::var("NYX_PW_TEST_CA").expect("set NYX_PW_TEST_CA")).expect("NYX_PW_TEST_CA")
}

pub fn http() -> reqwest::Client {
    let ca = reqwest::Certificate::from_pem(&ca_pem()).unwrap();
    reqwest::Client::builder().tls_certs_only([ca]).build().unwrap()
}

pub fn fresh_email(tag: &str) -> String {
    format!("{tag}-{}@example.com", &uuid::Uuid::new_v4().simple().to_string()[..10])
}

/// Creates an account (test fixture: real clients do this in the web vault) and returns
/// its public key.
pub async fn register(email: &str, password: &str, kdf: &Kdf) -> String {
    let master = MasterKey::derive(password, email, kdf).unwrap();
    let hash = master.derive_master_key_hash(password.as_bytes(), HashPurpose::ServerAuthorization);
    let (user_key, protected) = master.make_user_key().unwrap();
    let pair = user_key.make_key_pair().unwrap();
    let http = http();
    let token = http
        .post(format!("{}/identity/accounts/register/send-verification-email", server_url()))
        .json(&json!({"email": email, "name": "Test", "receiveMarketingEmails": false}))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let mut body = json!({
        "email": email, "emailVerificationToken": token.trim().trim_matches('"'),
        "masterPasswordHash": hash.to_string(), "masterPasswordHint": null,
        "userSymmetricKey": protected,
        "userAsymmetricKeys": {"publicKey": pair.public.to_string(), "encryptedPrivateKey": pair.private},
    });
    let extra = match kdf {
        Kdf::PBKDF2 { iterations } => json!({"kdf": 0, "kdfIterations": iterations.get()}),
        Kdf::Argon2id { iterations, memory, parallelism } => json!({
            "kdf": 1, "kdfIterations": iterations.get(), "kdfMemory": memory.get(), "kdfParallelism": parallelism.get()
        }),
    };
    body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    let resp = http.post(format!("{}/identity/accounts/register/finish", server_url())).json(&body).send().await.unwrap();
    assert!(resp.status().is_success(), "register: {}", resp.status());
    pair.public.to_string()
}

/// An organization made by `create_org`: its id, its first collection, and its key.
pub struct Org {
    pub id: String,
    pub collection: String,
    pub key: bitwarden_crypto::SymmetricCryptoKey,
}

/// The organization key wrapped for an account's public key (base64 DER).
#[allow(deprecated)] // the *_key_unsigned helper
fn share_key(key: &bitwarden_crypto::SymmetricCryptoKey, public: &str) -> String {
    use bitwarden_crypto::{PublicKey, SpkiPublicKeyBytes, UnsignedSharedKey};
    let der = bitwarden_encoding::B64::try_from(public).unwrap();
    let public = PublicKey::from_der(&SpkiPublicKeyBytes::from(der.as_bytes().to_vec())).unwrap();
    UnsignedSharedKey::encapsulate_key_unsigned(key, &public).unwrap().to_string()
}

/// Creates an organization owned by the account (test fixture: real clients do this in
/// the web vault).
pub async fn create_org(access: &str, email: &str, public: &str) -> Org {
    use bitwarden_crypto::{KeyEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm, UserKey};
    let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
    let shared = share_key(&org_key, public);
    let pair = UserKey::new(org_key.clone()).make_key_pair().unwrap();
    let collection = "Shared".encrypt_with_key(&org_key).unwrap();
    let http = http();
    let org: Value = http
        .post(format!("{}/api/organizations", server_url()))
        .bearer_auth(access)
        .json(&json!({
            "name": "Test Org", "billingEmail": email, "collectionName": collection.to_string(),
            "key": shared, "planType": 0,
            "keys": {"publicKey": pair.public.to_string(), "encryptedPrivateKey": pair.private},
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = org["id"].as_str().expect("organization created").to_string();
    let cols: Value = http
        .get(format!("{}/api/organizations/{id}/collections", server_url()))
        .bearer_auth(access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let collection = cols["data"][0]["id"].as_str().unwrap().to_string();
    Org { id, collection, key: org_key }
}

/// Adds a collection to the organization and returns its id.
pub async fn create_collection(access: &str, org: &Org, name: &str) -> String {
    use bitwarden_crypto::KeyEncryptable;
    let name = name.encrypt_with_key(&org.key).unwrap().to_string();
    let made: Value = http()
        .post(format!("{}/api/organizations/{}/collections", server_url(), org.id))
        .bearer_auth(access)
        .json(&json!({"name": name, "externalId": null, "groups": [], "users": []}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    made["id"].as_str().expect("collection created").to_string()
}

/// Removes a member from the organization (test fixture: an owner does this in the web
/// vault).
pub async fn remove_member(access: &str, org: &Org, email: &str) {
    let http = http();
    let members: Value = http
        .get(format!("{}/api/organizations/{}/users", server_url(), org.id))
        .bearer_auth(access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let member = members["data"].as_array().unwrap().iter().find(|m| m["email"] == email).expect("a member");
    let resp = http
        .delete(format!("{}/api/organizations/{}/users/{}", server_url(), org.id, member["id"].as_str().unwrap()))
        .bearer_auth(access)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "remove member: {}", resp.status());
}

/// Makes an existing account a member (a plain user) with access to `collections`, given
/// as `(id, read_only, hide_passwords)`, and confirms it. The test server sends no
/// mail, so an invited account is accepted at once.
pub async fn add_member(access: &str, org: &Org, email: &str, public: &str, collections: &[(&str, bool, bool)]) {
    let http = http();
    let access_to: Vec<Value> = collections
        .iter()
        .map(|(id, ro, hide)| json!({"id": id, "readOnly": ro, "hidePasswords": hide, "manage": false}))
        .collect();
    let resp = http
        .post(format!("{}/api/organizations/{}/users/invite", server_url(), org.id))
        .bearer_auth(access)
        .json(
            &json!({"emails": [email], "type": 2, "collections": access_to, "groups": [], "accessAll": false, "permissions": {}}),
        )
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "invite: {} {}", resp.status(), resp.text().await.unwrap_or_default());
    let members: Value = http
        .get(format!("{}/api/organizations/{}/users", server_url(), org.id))
        .bearer_auth(access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let member = members["data"].as_array().unwrap().iter().find(|m| m["email"] == email).expect("invited");
    let resp = http
        .post(format!("{}/api/organizations/{}/users/{}/confirm", server_url(), org.id, member["id"].as_str().unwrap()))
        .bearer_auth(access)
        .json(&json!({"key": share_key(&org.key, public)}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "confirm: {} {}", resp.status(), resp.text().await.unwrap_or_default());
}

/// Turns on authenticator two-step login and returns its base32 key.
pub async fn enable_authenticator(access: &str, hash: &str) -> String {
    let http = http();
    let got: Value = http
        .post(format!("{}/api/two-factor/get-authenticator", server_url()))
        .bearer_auth(access)
        .json(&json!({"masterPasswordHash": hash}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key = got["key"].as_str().unwrap().to_string();
    let resp = http
        .post(format!("{}/api/two-factor/authenticator", server_url()))
        .bearer_auth(access)
        .json(&json!({"key": key, "token": totp(&key), "masterPasswordHash": hash}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "enable authenticator: {}", resp.status());
    key
}

pub fn totp(base32: &str) -> String {
    let secret = totp_rs::Secret::try_from_base32(base32).unwrap();
    totp_rs::Builder::new().with_secret(secret).build().unwrap().generate_current().to_string()
}

/// The official CLI with its own data directory, so the user's `bw` is untouched.
pub struct Bw {
    dir: tempfile::TempDir,
    session: String,
}

impl Bw {
    fn cmd(&self) -> std::process::Command {
        let mut c = std::process::Command::new("bw");
        c.env("BITWARDENCLI_APPDATA_DIR", self.dir.path())
            .env("BW_NOINTERACTION", "true")
            .env("NODE_EXTRA_CA_CERTS", std::env::var("NYX_PW_TEST_CA").unwrap());
        if !self.session.is_empty() {
            c.env("BW_SESSION", &self.session);
        }
        c
    }

    pub fn run(&self, args: &[&str]) -> String {
        let out = self.cmd().args(args).output().unwrap();
        assert!(out.status.success(), "bw {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap()
    }

    pub fn login(email: &str, password: &str) -> Bw {
        let mut bw = Bw { dir: tempfile::tempdir().unwrap(), session: String::new() };
        bw.run(&["config", "server", &server_url()]);
        let out = bw
            .cmd()
            .env("NYX_TEST_PW", password)
            .args(["login", email, "--passwordenv", "NYX_TEST_PW", "--raw"])
            .output()
            .unwrap();
        assert!(out.status.success(), "bw login: {}", String::from_utf8_lossy(&out.stderr));
        bw.session = String::from_utf8(out.stdout).unwrap().trim().to_string();
        bw
    }

    pub fn item(&self, id: &str) -> Value {
        self.run(&["sync"]);
        serde_json::from_str(&self.run(&["get", "item", id])).unwrap()
    }

    pub fn create(&self, item: &Value) -> Value {
        let encoded = bitwarden_encoding::B64::from(serde_json::to_vec(item).unwrap()).to_string();
        serde_json::from_str(&self.run(&["create", "item", &encoded])).unwrap()
    }

    /// Attaches a file to an item.
    pub fn attach(&self, id: &str, file: &std::path::Path) {
        self.run(&["create", "attachment", "--itemid", id, "--file", file.to_str().unwrap()]);
    }

    /// The contents of an item's attachment, by file name.
    pub fn attachment(&self, id: &str, name: &str) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join(name);
        self.run(&["get", "attachment", name, "--itemid", id, "--output", out.to_str().unwrap()]);
        std::fs::read(out).unwrap()
    }

    pub fn edit(&self, id: &str, item: &Value) {
        let encoded = bitwarden_encoding::B64::from(serde_json::to_vec(item).unwrap()).to_string();
        self.run(&["edit", "item", id, &encoded]);
    }
}
