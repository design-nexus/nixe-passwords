//! Shared helpers for tests against the throwaway Vaultwarden from
//! apps/passwords/scripts/test-server.sh (NIXE_PW_TEST_SERVER, NIXE_PW_TEST_CA).
#![allow(dead_code)]

use bitwarden_crypto::{HashPurpose, Kdf, MasterKey};
use serde_json::{Value, json};

pub fn server_url() -> String {
    std::env::var("NIXE_PW_TEST_SERVER").expect("set NIXE_PW_TEST_SERVER to the test server")
}

pub fn ca_pem() -> Vec<u8> {
    std::fs::read(std::env::var("NIXE_PW_TEST_CA").expect("set NIXE_PW_TEST_CA")).expect("NIXE_PW_TEST_CA")
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

/// Creates an organization owned by the account and returns its id and the id of its
/// one collection (test fixture: real clients do this in the web vault).
#[allow(deprecated)] // the *_key_unsigned helper
pub async fn create_org(access: &str, email: &str, public: &str) -> (String, String) {
    use bitwarden_crypto::{
        KeyEncryptable, PublicKey, SpkiPublicKeyBytes, SymmetricCryptoKey, SymmetricKeyAlgorithm, UnsignedSharedKey, UserKey,
    };
    let der = bitwarden_encoding::B64::try_from(public).unwrap();
    let public = PublicKey::from_der(&SpkiPublicKeyBytes::from(der.as_bytes().to_vec())).unwrap();
    let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
    let shared = UnsignedSharedKey::encapsulate_key_unsigned(&org_key, &public).unwrap();
    let pair = UserKey::new(org_key.clone()).make_key_pair().unwrap();
    let collection = "Shared".encrypt_with_key(&org_key).unwrap();
    let http = http();
    let org: Value = http
        .post(format!("{}/api/organizations", server_url()))
        .bearer_auth(access)
        .json(&json!({
            "name": "Test Org", "billingEmail": email, "collectionName": collection.to_string(),
            "key": shared.to_string(), "planType": 0,
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
    let col = cols["data"][0]["id"].as_str().unwrap().to_string();
    (id, col)
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
            .env("NODE_EXTRA_CA_CERTS", std::env::var("NIXE_PW_TEST_CA").unwrap());
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
            .env("NIXE_TEST_PW", password)
            .args(["login", email, "--passwordenv", "NIXE_TEST_PW", "--raw"])
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
