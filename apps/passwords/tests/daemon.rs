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
        for name in ["nixe-passwords", "nixe-glimpse", "stranger", "firefox"] {
            std::fs::copy(&me, bin.join(name)).unwrap();
        }
        std::fs::copy(env!("CARGO_BIN_EXE_nixe-passwords-bridge"), bin.join("nixe-passwords-bridge")).unwrap();
        std::fs::copy(env!("CARGO_BIN_EXE_nixe-passwords-assistant"), bin.join("nixe-passwords-assistant")).unwrap();
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

impl Scratch {
    /// Runs the assistant ability with these tool calls (`[name, arguments]`), after the
    /// MCP handshake; returns each call's result.
    fn assistant(&self, calls: &[(&str, Value)]) -> Vec<Value> {
        use std::io::Write;
        let mut lines = vec![
            json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        ];
        for (i, (name, args)) in calls.iter().enumerate() {
            lines.push(
                json!({"jsonrpc": "2.0", "id": i + 2, "method": "tools/call", "params": {"name": name, "arguments": args}}),
            );
        }
        let mut child = Command::new(self.dir.path().join("bin/nixe-passwords-assistant"))
            .env_clear()
            .env("XDG_RUNTIME_DIR", self.dir.path().join("run"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        for line in &lines {
            writeln!(stdin, "{line}").unwrap();
        }
        drop(stdin);
        let out = child.wait_with_output().unwrap();
        let replies: Vec<Value> =
            String::from_utf8_lossy(&out.stdout).lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(replies[0]["result"]["serverInfo"]["name"], "nixe-passwords");
        let tools: Vec<&str> =
            replies[1]["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(tools, ["passwords.find", "passwords.copy"]);
        replies[2..].iter().map(|r| r["result"].clone()).collect()
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
        "Status" | "Lock" | "Sync" | "List" | "Generate" | "SignOut" | "Pairings" => {
            conn.call_method(None::<&str>, OBJECT, Some(IFACE), method, &()).await
        }
        "Search" => conn.call_method(None::<&str>, OBJECT, Some(IFACE), method, &(s(1), call[2].as_u64().unwrap() as u32)).await,
        "Copy" | "Reveal" | "UpdateLogin" => conn.call_method(None::<&str>, OBJECT, Some(IFACE), method, &(s(1), s(2))).await,
        "Unlock" | "CreateLogin" | "OpenUrl" | "Trash" | "Restore" | "VerifyPassword" | "ConfirmPairing" | "RemovePairing" => {
            conn.call_method(None::<&str>, OBJECT, Some(IFACE), method, &(s(1),)).await
        }
        "SignIn" => conn.call_method(None::<&str>, OBJECT, Some(IFACE), method, &(s(1), s(2), s(3), 255u8, String::new())).await,
        "Attachments" => conn.call_method(None::<&str>, OBJECT, Some(IFACE), method, &(s(1),)).await,
        "DeleteAttachment" => conn.call_method(None::<&str>, OBJECT, Some(IFACE), method, &(s(1), s(2))).await,
        // [method, id, name or attachment, path]: the file goes as a handle.
        "AddAttachment" | "SaveAttachment" => {
            let file =
                if method == "AddAttachment" { std::fs::File::open(s(3)).unwrap() } else { std::fs::File::create(s(3)).unwrap() };
            let fd = zbus::zvariant::Fd::from(std::os::fd::AsFd::as_fd(&file));
            conn.call_method(None::<&str>, OBJECT, Some(IFACE), method, &(s(1), s(2), fd)).await
        }
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
                "t" => json!({"ok": body.deserialize::<u64>().unwrap()}),
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

    // Attachments go in from a file the app opened and come out into another one; the
    // contents never pass through the call itself. Glimpse gets neither.
    let files = tempfile::tempdir().unwrap();
    let (original, saved) = (files.path().join("codes.txt"), files.path().join("saved.txt"));
    std::fs::write(&original, "canary-daemon attachment\n").unwrap();
    let path = |p: &Path| p.display().to_string();
    let app = s.as_peer("nixe-passwords", json!([["AddAttachment", id, "codes.txt", path(&original)], ["Attachments", id]]));
    ok(&app[0]);
    let listed: Value = serde_json::from_str(ok(&app[1]).as_str().unwrap()).unwrap();
    assert_eq!(listed[0]["name"], "codes.txt");
    let attachment = listed[0]["id"].as_str().unwrap().to_string();
    let app = s.as_peer("nixe-passwords", json!([["SaveAttachment", id, attachment, path(&saved)]]));
    assert_eq!(ok(&app[0]), 25);
    assert_eq!(std::fs::read(&saved).unwrap(), std::fs::read(&original).unwrap());
    let g = s.as_peer(
        "nixe-glimpse",
        json!([["Attachments", id], ["SaveAttachment", id, attachment, path(&files.path().join("g.txt"))]]),
    );
    assert_eq!((err(&g[0]), err(&g[1])), ("Denied", "Denied"));
    let app = s.as_peer("nixe-passwords", json!([["DeleteAttachment", id, attachment], ["Attachments", id]]));
    ok(&app[0]);
    assert_eq!(ok(&app[1]), "[]");

    // The Assistant: refused until turned on; then it finds logins as names and sites
    // only, and copying never hands back the value.
    let found = s.assistant(&[("passwords.find", json!({"query": "git"}))]);
    assert_eq!(found[0]["isError"], true);
    assert!(found[0]["content"][0]["text"].as_str().unwrap().contains("turn on"));
    std::thread::sleep(Duration::from_millis(20));
    let settings = s.dir.path().join("config/nixe-passwords/settings.toml");
    let text = std::fs::read_to_string(&settings).unwrap();
    std::fs::write(&settings, format!("{text}assistant = true\n")).unwrap();
    let got = s.assistant(&[
        ("passwords.find", json!({"query": "git"})),
        ("passwords.copy", json!({"query": "github", "field": "password"})),
        ("passwords.copy", json!({"id": bank, "field": "password"})),
        ("passwords.copy", json!({"query": "nothing like this", "field": "password"})),
    ]);
    let logins = &got[0]["structuredContent"]["logins"];
    assert_eq!(logins[0]["name"], "GitHub");
    assert_eq!(logins[0]["site"], "github.com");
    // No compositor here, so the copy itself fails, without the value.
    assert_eq!(got[1]["isError"], true);
    assert!(got[2]["content"][0]["text"].as_str().unwrap().contains("master password"));
    assert!(got[3]["content"][0]["text"].as_str().unwrap().contains("no login matches"));
    assert!(!Value::Array(got.clone()).to_string().contains("canary"));

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

// ---- browsers ----

impl Scratch {
    /// Runs the `browser` role as a program called `firefox`, so the bridge it starts has a
    /// browser for a parent. `step` is "hello" or a JSON list of requests.
    fn as_browser(&self, step: &str) -> Vec<Value> {
        let out = Command::new(self.dir.path().join("bin/firefox"))
            .args(["--exact", "browser", "--ignored", "--nocapture", "--test-threads=1"])
            .env("NIXE_PW_BROWSER_STEP", step)
            .env("NIXE_PW_BROWSER_STATE", self.dir.path().join("extension.json"))
            // The scratch session's daemon, never the real one.
            .env("XDG_RUNTIME_DIR", self.dir.path().join("run"))
            .env("XDG_CONFIG_HOME", self.dir.path().join("config"))
            .env("HOME", self.dir.path())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        let line =
            text.lines().find_map(|l| l.split_once("RESULTS ").map(|(_, r)| r)).unwrap_or_else(|| panic!("browser: {text}"));
        serde_json::from_str(line).unwrap()
    }
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(text).unwrap()
}

/// The extension's side, run inside a copy of this executable named `firefox`: it talks
/// to the real bridge exactly as a WebExtension would.
#[test]
#[ignore = "run by the daemon tests as a browser"]
fn browser() {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use std::io::{Read, Write};
    let Ok(step) = std::env::var("NIXE_PW_BROWSER_STEP") else { return };
    let state_file = std::env::var("NIXE_PW_BROWSER_STATE").unwrap();
    let bridge = std::env::current_exe().unwrap().with_file_name("nixe-passwords-bridge");
    let mut child = Command::new(bridge)
        .args(["/tmp/manifest.json", "passwords@nixe"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut send = |frame: &Value| -> Value {
        let bytes = frame.to_string().into_bytes();
        input.write_all(&(bytes.len() as u32).to_ne_bytes()).unwrap();
        input.write_all(&bytes).unwrap();
        input.flush().unwrap();
        let mut len = [0u8; 4];
        output.read_exact(&mut len).unwrap();
        let mut reply = vec![0u8; u32::from_ne_bytes(len) as usize];
        output.read_exact(&mut reply).unwrap();
        serde_json::from_slice(&reply).unwrap()
    };
    let mut results = Vec::new();
    if step == "hello" {
        let secret = x25519_dalek::StaticSecret::random();
        let public = x25519_dalek::PublicKey::from(&secret);
        let reply = send(&json!({"t": "hello", "v": 1, "pub": b64(public.as_bytes())}));
        if reply["t"] == "pairing" {
            let theirs: [u8; 32] = unb64(reply["pub"].as_str().unwrap()).try_into().unwrap();
            let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(theirs));
            let salt = [public.as_bytes().as_slice(), &theirs].concat();
            let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), shared.as_bytes());
            let mut key = [0u8; 32];
            hk.expand(b"nixe-passwords pair v1", &mut key).unwrap();
            let mut code = [0u8; 4];
            hk.expand(b"nixe-passwords code v1", &mut code).unwrap();
            let code = format!("{:06}", u32::from_be_bytes(code) % 1_000_000);
            std::fs::write(&state_file, json!({"id": reply["p"], "key": b64(&key)}).to_string()).unwrap();
            results.push(json!({"id": reply["p"], "code": code}));
        } else {
            results.push(reply);
        }
    } else {
        let state: Value = serde_json::from_str(&std::fs::read_to_string(&state_file).unwrap()).unwrap();
        let id = state["id"].as_str().unwrap().to_string();
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(&unb64(state["key"].as_str().unwrap())).unwrap();
        let requests: Vec<Value> = serde_json::from_str(&step).unwrap();
        let mut counter = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let mut last: Option<Value> = None;
        for request in requests {
            let frame = if request["replay"] == true {
                last.clone().unwrap()
            } else {
                counter += 1;
                let n = if request["stale"] == true { counter - 10 * 60 * 1000 } else { counter };
                let mut nonce = [0u8; 12];
                rand::Rng::fill_bytes(&mut rand::rng(), &mut nonce);
                let aad = format!("{id}|{n}");
                let sealed =
                    cipher.encrypt(&nonce.into(), Payload { msg: request.to_string().as_bytes(), aad: aad.as_bytes() }).unwrap();
                json!({"t": "msg", "p": id, "n": n, "c": b64(&[&nonce[..], &sealed].concat())})
            };
            last = Some(frame.clone());
            let reply = send(&frame);
            if reply["t"] == "msg" {
                let n = reply["n"].as_u64().unwrap();
                let sealed = unb64(reply["c"].as_str().unwrap());
                let (nonce, body) = sealed.split_at(12);
                let nonce: [u8; 12] = nonce.try_into().unwrap();
                let aad = format!("{id}|{n}|r");
                let plain = cipher.decrypt(&nonce.into(), Payload { msg: body, aad: aad.as_bytes() }).unwrap();
                results.push(serde_json::from_slice(&plain).unwrap());
            } else {
                results.push(reply);
            }
        }
    }
    drop(input);
    let _ = child.wait();
    println!("RESULTS {}", Value::Array(results));
}

#[test]
fn bridge_needs_a_browser() {
    use std::io::{Read, Write};
    let s = Scratch::start("");
    // Started by this test, not a browser: the daemon won't serve it.
    let mut child = Command::new(s.dir.path().join("bin/nixe-passwords-bridge"))
        .arg("passwords@nixe")
        .env("XDG_RUNTIME_DIR", s.dir.path().join("run"))
        .env("XDG_CONFIG_HOME", s.dir.path().join("config"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let frame = br#"{"t":"hello","v":1,"pub":"AAAA"}"#;
    let mut input = child.stdin.take().unwrap();
    input.write_all(&(frame.len() as u32).to_ne_bytes()).unwrap();
    input.write_all(frame).unwrap();
    input.flush().unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut len = [0u8; 4];
    out.read_exact(&mut len).unwrap();
    let mut reply = vec![0u8; u32::from_ne_bytes(len) as usize];
    out.read_exact(&mut reply).unwrap();
    drop(input);
    let _ = child.wait();
    assert_eq!(serde_json::from_slice::<Value>(&reply).unwrap()["t"], "unavailable");
}

#[tokio::test]
#[ignore = "needs NIXE_PW_TEST_SERVER"]
async fn paired_browser() {
    let (server, ca) = test_server().expect("NIXE_PW_TEST_SERVER and NIXE_PW_TEST_CA");
    let email = format!("browser-{}@example.com", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let password = "correct horse browser battery";
    register(&server, &ca, &email, password).await;
    let s = Scratch::start(&format!("extra_ca = {:?}\n", ca.display().to_string()));
    let github = json!({"name": "GitHub", "username": "octo", "password": "canary-gh-Pw!9", "uris": ["https://github.com/login"], "totp": "JBSWY3DPEHPK3PXP"}).to_string();
    let other =
        json!({"name": "Other", "username": "x", "password": "canary-other-Pw!9", "uris": ["https://example.org"]}).to_string();
    let app = s
        .as_peer("nixe-passwords", json!([["SignIn", server, email, password], ["CreateLogin", github], ["CreateLogin", other]]));
    assert_eq!(ok(&app[0])[0], true);
    let (gh, other_id) = (ok(&app[1]).as_str().unwrap().to_string(), ok(&app[2]).as_str().unwrap().to_string());

    // Pairing: the extension and the window show the same code; the user confirms.
    let hello = s.as_browser("hello");
    let (id, code) = (hello[0]["id"].as_str().unwrap().to_string(), hello[0]["code"].as_str().unwrap().to_string());
    let before = s.as_browser(r#"[{"r":"status"}]"#);
    assert_eq!(before[0]["t"], "pending");
    let app = s.as_peer("nixe-passwords", json!([["Pairings"]]));
    let listing: Value = serde_json::from_str(ok(&app[0]).as_str().unwrap()).unwrap();
    assert_eq!(listing["pending"][0]["code"], code.as_str());
    assert_eq!(listing["pending"][0]["browser"], "Firefox");
    let app = s.as_peer("nixe-passwords", json!([["ConfirmPairing", id]]));
    assert!(app[0].get("ok").is_some(), "{:?}", app[0]);

    let page = "https://github.com/login";
    let requests = json!([
        {"r": "status"},
        {"r": "match", "url": page},
        {"r": "fill", "url": page, "id": gh},
        {"r": "totp", "url": page, "id": gh},
        {"r": "fill", "url": page, "id": other_id},
        {"r": "fill", "url": page, "id": gh, "frame": "https://evil.example/frame"},
        {"r": "fill", "url": page, "id": gh, "frame": "https://gist.github.com/x"},
        {"r": "fill", "url": "http://github.com/login", "id": gh},
        {"r": "match", "url": "https://github.com.evil.example/"},
        {"replay": true},
        {"r": "status", "stale": true},
        {"r": "context", "url": page},
    ]);
    let r = s.as_browser(&requests.to_string());
    assert_eq!(r[0]["state"], "unlocked");
    let items = r[1]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!((items[0]["name"].as_str(), items[0]["username"].as_str()), (Some("GitHub"), Some("octo")));
    assert_eq!(r[2], json!({"username": "octo", "password": "canary-gh-Pw!9"}));
    assert_eq!(r[3]["code"].as_str().unwrap().len(), 6);
    assert_eq!(r[4]["error"], "Denied", "another site's item");
    assert_eq!(r[5]["error"], "Denied", "a frame from another site");
    assert_eq!(r[6]["username"], "octo", "a frame on the same site");
    assert_eq!(r[7]["error"], "Denied", "plain http");
    assert_eq!(r[8]["items"], json!([]), "a lookalike domain");
    assert_eq!(r[9]["t"], "error", "a replayed frame");
    assert_eq!(r[10]["t"], "error", "a stale counter");
    // Saving from the page: a new login, then a new password for the same username.
    let r = s.as_browser(
        &json!([
            {"r": "save", "url": "https://example.net/signin", "username": "newbie", "password": "canary-saved-Pw!9"},
            {"r": "save", "url": "https://example.net/login", "username": "newbie", "password": "canary-changed-Pw!9"},
            {"r": "match", "url": "https://example.net/"},
            {"r": "save", "url": "https://example.net/", "username": "x", "password": ""},
        ])
        .to_string(),
    );
    assert_eq!(r[0]["saved"], "created");
    assert_eq!(r[1]["saved"], "updated");
    assert_eq!(r[0]["id"], r[1]["id"]);
    let saved = r[2]["items"].as_array().unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0]["username"], "newbie");
    assert_eq!(r[3]["error"], "NoField");
    let id_saved = saved[0]["id"].as_str().unwrap().to_string();
    let r = s.as_browser(&json!([{"r": "fill", "url": "https://example.net/", "id": id_saved}]).to_string());
    assert_eq!(r[0]["password"], "canary-changed-Pw!9");

    // No secret ever came back in clear.
    for reply in &r {
        assert_ne!(reply["t"], "msg");
    }

    // Locked: the extension learns only that.
    let app = s.as_peer("nixe-passwords", json!([["Lock"]]));
    assert!(app[0].get("ok").is_some());
    let r = s.as_browser(r#"[{"r":"status"}]"#);
    assert_eq!(r[0]["t"], "locked");

    // After unlocking, the stored pairing works again; removing it ends it.
    let app = s.as_peer("nixe-passwords", json!([["Unlock", password], ["RemovePairing", id]]));
    assert!(app[0].get("ok").is_some() && app[1].get("ok").is_some());
    let r = s.as_browser(r#"[{"r":"status"}]"#);
    assert_eq!(r[0]["t"], "unknown");
}
