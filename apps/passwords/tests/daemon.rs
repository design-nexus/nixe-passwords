//! The real daemon in a scratch session: who may connect, what each peer may ask, and
//! (with NIXE_PW_TEST_SERVER) a signed-in vault seen from the app and from Glimpse.
//!
//! Clients must be suite binaries next to the daemon, so the test copies the daemon into
//! a temp directory together with copies of this test executable named `nixe-passwords`
//! and `nixe-glimpse`; each copy re-runs `client` below in that role.
//!
//! The daemon gets no Wayland or Hyprland environment (a copy can't reach the real
//! clipboard), an empty PATH (no keyring), and notifications off.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const OBJECT: &str = "/io/github/design_nexus/nixe/Passwords";
const IFACE: &str = "io.github.design_nexus.nixe.Passwords1";

struct Scratch {
    dir: tempfile::TempDir,
    daemon: Child,
}

impl Scratch {
    fn start(extra_settings: &str) -> Scratch {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::copy(env!("CARGO_BIN_EXE_nixe-passwordsd"), bin.join("nixe-passwordsd")).unwrap();
        let me = std::env::current_exe().unwrap();
        for name in ["nixe-passwords", "nixe-glimpse", "stranger"] {
            std::fs::copy(&me, bin.join(name)).unwrap();
        }
        let config = dir.path().join("config/nixe-passwords");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("settings.toml"), format!("notify_copies = false\n{extra_settings}")).unwrap();
        for d in ["run", "data", "empty"] {
            std::fs::create_dir_all(dir.path().join(d)).unwrap();
        }
        let daemon = Command::new(bin.join("nixe-passwordsd"))
            .env_clear()
            .env("HOME", dir.path())
            .env("PATH", dir.path().join("empty"))
            .env("XDG_RUNTIME_DIR", dir.path().join("run"))
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .spawn()
            .unwrap();
        let s = Scratch { dir, daemon };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !s.socket().exists() {
            assert!(Instant::now() < deadline, "daemon didn't start");
            std::thread::sleep(Duration::from_millis(50));
        }
        s
    }

    fn socket(&self) -> PathBuf {
        self.dir.path().join("run/nixe-passwords/bus")
    }

    /// Runs `calls` (JSON: [[method, args...], ...]) as `role`; returns each result.
    fn as_peer(&self, role: &str, calls: Value) -> Vec<Value> {
        let out = Command::new(self.dir.path().join("bin").join(role))
            .args(["--exact", "client", "--ignored", "--nocapture", "--test-threads=1"])
            .env("NIXE_PW_CLIENT_SOCKET", self.socket())
            .env("NIXE_PW_CLIENT_CALLS", calls.to_string())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        let line =
            text.lines().find_map(|l| l.split_once("RESULTS ").map(|(_, r)| r)).unwrap_or_else(|| panic!("{role}: {text}"));
        serde_json::from_str(line).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // SAFETY: signalling our own child.
        unsafe { libc::kill(self.daemon.id() as i32, libc::SIGTERM) };
        let _ = self.daemon.wait();
    }
}

/// The client side, run inside a copy of this executable.
#[test]
#[ignore = "run by the daemon tests as a peer"]
fn client() {
    let Ok(socket) = std::env::var("NIXE_PW_CLIENT_SOCKET") else { return };
    let calls: Vec<Vec<Value>> = serde_json::from_str(&std::env::var("NIXE_PW_CLIENT_CALLS").unwrap()).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let results = rt.block_on(async move {
        let stream = match tokio::net::UnixStream::connect(&socket).await {
            Ok(s) => s,
            Err(_) => return vec![json!({"connect": "refused"})],
        };
        let built = zbus::connection::Builder::unix_stream(stream).p2p().build();
        let conn = match tokio::time::timeout(Duration::from_secs(3), built).await {
            Ok(Ok(c)) => c,
            _ => return vec![json!({"connect": "closed"})],
        };
        let mut results = Vec::new();
        for call in calls {
            results.push(call_one(&conn, &call).await);
        }
        results
    });
    println!("RESULTS {}", Value::Array(results));
}

async fn call_one(conn: &zbus::Connection, call: &[Value]) -> Value {
    let method = call[0].as_str().unwrap();
    let s = |i: usize| call[i].as_str().unwrap().to_string();
    let reply = match method {
        "Status" | "Lock" | "Sync" | "List" | "Generate" | "SignOut" => {
            conn.call_method(None::<&str>, OBJECT, Some(IFACE), method, &()).await
        }
        "Search" => conn.call_method(None::<&str>, OBJECT, Some(IFACE), method, &(s(1), call[2].as_u64().unwrap() as u32)).await,
        "Copy" | "Reveal" | "UpdateLogin" => conn.call_method(None::<&str>, OBJECT, Some(IFACE), method, &(s(1), s(2))).await,
        "Unlock" | "CreateLogin" | "OpenUrl" | "Trash" | "Restore" | "VerifyPassword" => {
            conn.call_method(None::<&str>, OBJECT, Some(IFACE), method, &(s(1),)).await
        }
        "SignIn" => conn.call_method(None::<&str>, OBJECT, Some(IFACE), method, &(s(1), s(2), s(3), 255u8, String::new())).await,
        other => panic!("unknown call {other}"),
    };
    match reply {
        Ok(msg) => {
            let body = msg.body();
            let sig = body.signature().to_string();
            match sig.as_str() {
                "" => json!({"ok": null}),
                "s" => json!({"ok": body.deserialize::<String>().unwrap()}),
                "u" => json!({"ok": body.deserialize::<u32>().unwrap()}),
                "ssu" | "(ssu)" => json!({"ok": body.deserialize::<(String, String, u32)>().unwrap()}),
                "a(ssssbs)" => {
                    json!({"ok": body.deserialize::<Vec<(String, String, String, String, bool, String)>>().unwrap()})
                }
                "ba(ys)" | "(ba(ys))" => json!({"ok": body.deserialize::<(bool, Vec<(u8, String)>)>().unwrap()}),
                other => json!({"ok": format!("signature {other}")}),
            }
        }
        Err(zbus::Error::MethodError(name, _, _)) => json!({"error": name.as_str().rsplit('.').next().unwrap()}),
        Err(e) => json!({"error": format!("{e}")}),
    }
}

fn ok(v: &Value) -> &Value {
    v.get("ok").unwrap_or_else(|| panic!("expected ok, got {v}"))
}

fn err(v: &Value) -> &str {
    v["error"].as_str().unwrap_or_else(|| panic!("expected an error, got {v}"))
}

#[test]
fn strangers_and_scopes() {
    let s = Scratch::start("");
    // An executable that isn't one of the suite's is cut off before any message.
    assert_eq!(s.as_peer("stranger", json!([["Status"]]))[0], json!({"connect": "closed"}));

    let app = s.as_peer("nixe-passwords", json!([["Status"], ["Search", "x", 5]]));
    assert_eq!(ok(&app[0])[0], "logged_out");
    assert_eq!(err(&app[1]), "Locked");

    // Glimpse can't sign in, unlock, list, reveal or sync.
    let g = s.as_peer(
        "nixe-glimpse",
        json!([
            ["Status"],
            ["SignIn", "https://x.example", "a@b.c", "pw"],
            ["Unlock", "pw"],
            ["List"],
            ["Reveal", "00000000-0000-0000-0000-000000000000", "password"],
            ["Sync"]
        ]),
    );
    assert_eq!(ok(&g[0])[0], "logged_out");
    for denied in &g[1..] {
        assert_eq!(err(denied), "Denied", "{denied}");
    }
    let meta = std::fs::metadata(s.socket()).unwrap();
    assert_eq!(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777, 0o600);
}

#[test]
fn glimpse_switched_off() {
    let s = Scratch::start("glimpse = false\n");
    let g = s.as_peer("nixe-glimpse", json!([["Search", "x", 5], ["Generate"], ["Lock"]]));
    for r in &g {
        assert_eq!(err(r), "Denied", "{r}");
    }
}

fn test_server() -> Option<(String, PathBuf)> {
    Some((std::env::var("NIXE_PW_TEST_SERVER").ok()?, std::env::var("NIXE_PW_TEST_CA").ok()?.into()))
}

/// Creates an account (test fixture; real accounts are made in the web vault).
async fn register(server: &str, ca: &Path, email: &str, password: &str) {
    use bitwarden_crypto::{HashPurpose, Kdf, MasterKey};
    let kdf = Kdf::PBKDF2 { iterations: std::num::NonZeroU32::new(600_000).unwrap() };
    let master = MasterKey::derive(password, email, &kdf).unwrap();
    let hash = master.derive_master_key_hash(password.as_bytes(), HashPurpose::ServerAuthorization);
    let (user_key, protected) = master.make_user_key().unwrap();
    let pair = user_key.make_key_pair().unwrap();
    let ca = reqwest::Certificate::from_pem(&std::fs::read(ca).unwrap()).unwrap();
    let http = reqwest::Client::builder().tls_certs_only([ca]).build().unwrap();
    let token = http
        .post(format!("{server}/identity/accounts/register/send-verification-email"))
        .json(&json!({"email": email, "name": "Test", "receiveMarketingEmails": false}))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let resp = http
        .post(format!("{server}/identity/accounts/register/finish"))
        .json(&json!({
            "email": email, "emailVerificationToken": token.trim().trim_matches('"'),
            "masterPasswordHash": hash.to_string(), "masterPasswordHint": null, "userSymmetricKey": protected,
            "userAsymmetricKeys": {"publicKey": pair.public.to_string(), "encryptedPrivateKey": pair.private},
            "kdf": 0, "kdfIterations": 600000,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
}

#[tokio::test]
#[ignore = "needs NIXE_PW_TEST_SERVER"]
async fn signed_in_vault() {
    let (server, ca) = test_server().expect("NIXE_PW_TEST_SERVER and NIXE_PW_TEST_CA");
    let email = format!("daemon-{}@example.com", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let password = "correct horse daemon battery";
    register(&server, &ca, &email, password).await;
    let s = Scratch::start(&format!("extra_ca = {:?}\n", ca.display().to_string()));

    let draft = json!({"name": "GitHub", "username": "octo", "password": "canary-daemon-Pw!9",
                       "uris": ["https://github.com/login"], "totp": "JBSWY3DPEHPK3PXP"})
    .to_string();
    let app = s.as_peer("nixe-passwords", json!([["SignIn", server, email, password], ["CreateLogin", draft], ["Status"]]));
    assert_eq!(ok(&app[0])[0], true, "{:?}", app[0]);
    let id = ok(&app[1]).as_str().unwrap().to_string();
    assert_eq!(ok(&app[2])[0], "unlocked");

    // Glimpse finds it by name and host; results carry no password.
    let g = s.as_peer(
        "nixe-glimpse",
        json!([
            ["Search", "git", 5],
            ["Search", "github.com", 5],
            ["OpenUrl", id],
            ["Copy", id, "password"],
            ["Reveal", id, "password"]
        ]),
    );
    let hits = ok(&g[0]).as_array().unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0], json!([id, "GitHub", "octo", "github.com", true, "login"]));
    assert!(!g[0].to_string().contains("canary") && !g[1].to_string().contains("canary"));
    assert_eq!(ok(&g[2]), "https://github.com/login");
    // No compositor here: the copy fails instead of returning the value.
    assert_eq!(err(&g[3]), "Clipboard");
    assert!(!g[3].to_string().contains("canary"));
    assert_eq!(err(&g[4]), "Denied");

    // The app may reveal; then lock, and everything needs unlocking again.
    let app = s.as_peer("nixe-passwords", json!([["Reveal", id, "password"], ["Lock"], ["Search", "git", 5], ["Status"]]));
    assert_eq!(ok(&app[0]), "canary-daemon-Pw!9");
    assert_eq!(err(&app[2]), "Locked");
    assert_eq!(ok(&app[3])[0], "locked");

    // Offline unlock from the local copy; a wrong password is refused.
    let app = s.as_peer("nixe-passwords", json!([["Unlock", "wrong"], ["Unlock", password], ["Search", "github", 5]]));
    assert_eq!(err(&app[0]), "Failed");
    assert_eq!(ok(&app[2]).as_array().unwrap().len(), 1);

    // An item that asks for the master password again: Glimpse never gets its secrets,
    // the app only after confirming the password.
    let guarded = json!({"name": "Bank", "username": "me", "password": "canary-guarded-Pw!9", "reprompt": true}).to_string();
    let app = s.as_peer("nixe-passwords", json!([["CreateLogin", guarded]]));
    let bank = ok(&app[0]).as_str().unwrap().to_string();
    let g = s.as_peer("nixe-glimpse", json!([["Copy", bank, "password"], ["Copy", bank, "totp"]]));
    assert_eq!((err(&g[0]), err(&g[1])), ("Reprompt", "Reprompt"));
    let app = s.as_peer(
        "nixe-passwords",
        json!([
            ["Reveal", bank, "password"],
            ["Reveal", bank, "username"],
            ["VerifyPassword", "wrong"],
            ["Reveal", bank, "password"],
            ["VerifyPassword", password],
            ["Reveal", bank, "password"]
        ]),
    );
    assert_eq!(err(&app[0]), "Reprompt");
    assert_eq!(ok(&app[1]), "me");
    assert_eq!(err(&app[2]), "Failed");
    assert_eq!(err(&app[3]), "Reprompt");
    assert_eq!(ok(&app[5]), "canary-guarded-Pw!9");

    // Nothing decrypted reached the disk.
    for path in walk(s.dir.path()) {
        if !path.starts_with(s.dir.path().join("bin")) {
            let bytes = std::fs::read(&path).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("canary-daemon") && !text.contains("canary-guarded"), "{}", path.display());
        }
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p))
        } else if p.is_file() {
            out.push(p)
        }
    }
    out
}
