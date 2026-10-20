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

/// Creates an account (test fixture: real clients do this in the web vault).
pub async fn register(email: &str, password: &str, kdf: &Kdf) {
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

    pub fn edit(&self, id: &str, item: &Value) {
        let encoded = bitwarden_encoding::B64::from(serde_json::to_vec(item).unwrap()).to_string();
        self.run(&["edit", "item", id, &encoded]);
    }
}
