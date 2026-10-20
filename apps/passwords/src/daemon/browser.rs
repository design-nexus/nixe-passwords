//! Browser extensions (docs/NATIVE_MESSAGING.md): pairing, sealed messages, and the
//! few things a paired extension may ask for, each about the page it's on.
//!
//! The bridge relays frames and is trusted with nothing: every request after pairing
//! is sealed with the pairing key (AES-256-GCM, the pairing id and a counter as
//! associated data), and the counter must rise and stay within five minutes of now, so
//! a recorded request can't be replayed. Pairing keys are stored under the user key and
//! loaded on unlock; while locked an extension only learns that.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nixe_passwords_core::crypto::{self, PairKey};
use nixe_passwords_core::matching;
use nixe_passwords_core::secret::Secret;
use nixe_passwords_core::store::Pairing;
use nixe_passwords_core::vault::{Field, reveal};
use nixe_passwords_proto::{Error as Code, state};
use serde_json::{Value, json};
use url::Url;

use super::peer::Scope;
use super::vault::{Failure, Result, State, Vault, generated, need, parse_id, within};

const MAX_FRAME: usize = 64 * 1024;
const PENDING_FOR: Duration = Duration::from_secs(120);
const MAX_PENDING: usize = 4;
const CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
const FILLS_PER_MINUTE: usize = 30;
const MATCHES: usize = 20;

#[derive(Default)]
pub struct Browser {
    pending: Vec<Pending>,
    active: HashMap<String, Active>,
    pub context: Option<Context>,
}

struct Pending {
    id: String,
    extension: String,
    browser: String,
    key: PairKey,
    code: String,
    at: Instant,
}

struct Active {
    pairing: Pairing,
    key: PairKey,
    last: u64,
    fills: VecDeque<Instant>,
}

/// The tab a paired extension last said was active, in which browser process. It holds
/// until the extension reports another or the vault locks: the extension reports every
/// tab switch, navigation and window focus, so the last report is that browser's tab.
pub struct Context {
    pub url: Url,
    pub pid: i32,
}

impl Browser {
    /// On lock: keys and the active tab go; confirmed pairings stay stored.
    pub fn lock(&mut self) {
        self.pending.clear();
        self.active.clear();
        self.context = None;
    }
}

/// Opens the stored pairings' keys with the user key (after unlock).
pub fn load(st: &mut State) {
    let Some(session) = st.session.as_ref() else { return };
    let Ok(pairings) = st.store.pairings() else { return };
    for p in pairings {
        let key = session.keys.item(None, None).and_then(|mut k| k.decrypt(&p.key)).and_then(|plain| PairKey::import(&plain));
        if let Ok(key) = key {
            st.browser.active.insert(p.id.clone(), Active { pairing: p, key, last: 0, fills: VecDeque::new() });
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn error(code: Code) -> Value {
    json!({"error": code.short()})
}

impl Vault {
    /// One frame from the bridge: `extension` is the id the browser started it for,
    /// `browser` the browser process (pid, name). Returns the reply frame.
    pub async fn relay(&self, scope: Scope, extension: &str, browser: &(i32, String), frame: &[u8]) -> Result<Vec<u8>> {
        need(scope, Scope::Browser)?;
        if frame.len() > MAX_FRAME {
            return Err(Failure::new(Code::Failed, "frame too large"));
        }
        let msg: Value = serde_json::from_slice(frame).map_err(|_| Failure::new(Code::Failed, "not JSON"))?;
        let reply = match msg["t"].as_str() {
            Some("hello") => self.hello(extension, &browser.1, &msg).await,
            Some("msg") => self.sealed(extension, browser, &msg).await,
            _ => json!({"t": "error", "error": "unknown"}),
        };
        Ok(reply.to_string().into_bytes())
    }

    async fn hello(&self, extension: &str, browser: &str, msg: &Value) -> Value {
        let Some(public) = msg["pub"].as_str().and_then(unb64) else {
            return json!({"t": "error", "error": "bad key"});
        };
        let Ok(paired) = crypto::pair(&public) else {
            return json!({"t": "error", "error": "bad key"});
        };
        let id = random_id();
        {
            let mut st = self.state.lock().await;
            if st.session.is_none() {
                return json!({"t": "locked"});
            }
            st.browser.pending.retain(|p| p.at.elapsed() < PENDING_FOR);
            if st.browser.pending.len() >= MAX_PENDING {
                return json!({"t": "error", "error": "busy"});
            }
            st.browser.pending.push(Pending {
                id: id.clone(),
                extension: extension.to_string(),
                browser: browser.to_string(),
                key: paired.key,
                code: paired.code,
                at: Instant::now(),
            });
        }
        self.notifier.send(&format!("Pair {browser} with Passwords?"), "Open Passwords to compare the code and confirm.").await;
        json!({"t": "pairing", "p": id, "pub": b64(&paired.public)})
    }

    async fn sealed(&self, extension: &str, browser: &(i32, String), msg: &Value) -> Value {
        let (Some(p), Some(n), Some(c)) = (msg["p"].as_str(), msg["n"].as_u64(), msg["c"].as_str().and_then(unb64)) else {
            return json!({"t": "error", "error": "malformed"});
        };
        let mut st = self.state.lock().await;
        let st = &mut *st;
        if st.browser.pending.iter().any(|x| x.id == p && x.at.elapsed() < PENDING_FOR) {
            return json!({"t": "pending"});
        }
        let Some(active) = st.browser.active.get_mut(p) else {
            let stored = st.store.pairings().ok().is_some_and(|all| all.iter().any(|x| x.id == p));
            return json!({"t": if stored && st.session.is_none() { "locked" } else { "unknown" }});
        };
        // A pairing belongs to one extension, and counters only go up, near the clock.
        let now = now_ms();
        if active.pairing.extension != extension || n <= active.last || n.abs_diff(now) > CLOCK_SKEW_MS {
            return json!({"t": "error", "error": "rejected"});
        }
        let Ok(plain) = active.key.open(format!("{p}|{n}").as_bytes(), &c) else {
            return json!({"t": "error", "error": "rejected"});
        };
        active.last = n;
        let request: Value = serde_json::from_slice(plain.expose()).unwrap_or(Value::Null);
        let answer = handle(st, p, browser, &request);
        let Some(active) = st.browser.active.get(p) else { return json!({"t": "unknown"}) };
        match active.key.seal(format!("{p}|{n}|r").as_bytes(), answer.to_string().as_bytes()) {
            Ok(sealed) => json!({"t": "msg", "p": p, "n": n, "c": b64(&sealed)}),
            Err(_) => json!({"t": "error", "error": "seal"}),
        }
    }

    /// For the app: pairings waiting for confirmation (with their codes) and paired ones.
    pub async fn pairings(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        st.browser.pending.retain(|p| p.at.elapsed() < PENDING_FOR);
        let pending: Vec<Value> = st
            .browser
            .pending
            .iter()
            .map(|p| json!({"id": p.id, "browser": p.browser, "extension": p.extension, "code": p.code}))
            .collect();
        let paired: Vec<Value> = st
            .store
            .pairings()
            .unwrap_or_default()
            .iter()
            .map(|p| json!({"id": p.id, "browser": p.browser, "extension": p.extension, "created": p.created}))
            .collect();
        Ok(json!({"pending": pending, "paired": paired}).to_string())
    }

    /// The user compared the codes and said yes.
    pub async fn confirm_pairing(&self, scope: Scope, id: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let at = st.browser.pending.iter().position(|p| p.id == id && p.at.elapsed() < PENDING_FOR);
        let Some(at) = at else { return Err(Failure::new(Code::NotFound, "that pairing request has expired")) };
        let pending = st.browser.pending.remove(at);
        let session = st.session.as_ref().ok_or_else(super::vault::locked)?;
        let stored_key = session
            .keys
            .item(None, None)
            .and_then(|mut k| k.encrypt(pending.key.export().expose()))
            .map_err(|e| Failure::new(Code::Failed, e.to_string()))?;
        let pairing = Pairing {
            id: pending.id.clone(),
            extension: pending.extension,
            browser: pending.browser,
            key: stored_key,
            created: now_ms() / 1000,
        };
        st.store.put_pairing(&pairing).map_err(|e| Failure::new(Code::Failed, e.to_string()))?;
        st.browser.active.insert(pending.id, Active { pairing, key: pending.key, last: 0, fills: VecDeque::new() });
        Ok(())
    }

    /// Forgets a pairing (or turns down a request).
    pub async fn remove_pairing(&self, scope: Scope, id: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        st.browser.pending.retain(|p| p.id != id);
        st.browser.active.remove(id);
        st.store.remove_pairing(id).map_err(|e| Failure::new(Code::Failed, e.to_string()))
    }
}

/// One opened request from a paired extension.
fn handle(st: &mut State, pairing: &str, browser: &(i32, String), request: &Value) -> Value {
    let url = || request["url"].as_str().and_then(|u| Url::parse(u).ok()).filter(|u| matches!(u.scheme(), "http" | "https"));
    match request["r"].as_str() {
        Some("status") => {
            let st_name = if st.session.is_some() { state::UNLOCKED } else { state::LOCKED };
            json!({"state": st_name})
        }
        Some("context") => {
            if let Some(url) = url() {
                st.browser.context = Some(Context { url, pid: browser.0 });
            }
            json!({})
        }
        Some("match") => {
            let Some(url) = url() else { return error(Code::NoUrl) };
            let Some(session) = st.session.as_ref() else { return error(Code::Locked) };
            let items: Vec<Value> = session
                .view
                .matching(&url)
                .into_iter()
                .take(MATCHES)
                .map(|e| {
                    json!({
                        "id": e.id, "name": e.name.expose(),
                        "username": e.username.as_ref().map(|u| u.expose()).unwrap_or(""),
                        "has_totp": e.has_totp, "reprompt": e.reprompt,
                    })
                })
                .collect();
            json!({"items": items})
        }
        Some(r @ ("fill" | "totp")) => {
            let Some(url) = url() else { return error(Code::NoUrl) };
            let Some(id) = request["id"].as_str().and_then(|i| parse_id(i).ok()) else { return error(Code::NotFound) };
            let Some(session) = st.session.as_ref() else { return error(Code::Locked) };
            let Some(entry) = session.view.matching(&url).into_iter().find(|e| e.id == id) else {
                // Only an item that belongs to this page, never one named by id alone.
                return error(Code::Denied);
            };
            // A login form in a frame from another site gets nothing.
            if let Some(frame) = request["frame"].as_str().filter(|f| !f.is_empty()) {
                let same_site = Url::parse(frame).ok().is_some_and(|f| {
                    matches!(f.scheme(), "http" | "https")
                        && f.host_str()
                            .zip(url.host_str())
                            .is_some_and(|(a, b)| matching::base_domain(a) == matching::base_domain(b))
                });
                if !same_site {
                    return error(Code::Denied);
                }
            }
            if entry.reprompt {
                return error(Code::Reprompt);
            }
            let Some(active) = st.browser.active.get_mut(pairing) else { return error(Code::Denied) };
            if !within(&mut active.fills, FILLS_PER_MINUTE) {
                return error(Code::RateLimited);
            }
            let get = |field| reveal(&session.keys, &session.snapshot, id, field).ok().map(|s: Secret| s.expose().to_string());
            let answer = if r == "fill" {
                json!({"username": get(Field::Username).unwrap_or_default(), "password": get(Field::Password).unwrap_or_default()})
            } else {
                match get(Field::Totp) {
                    Some(code) => json!({"code": code}),
                    None => return error(Code::NoField),
                }
            };
            st.recent.retain(|r| *r != id);
            st.recent.push_front(id);
            st.last_used = Instant::now();
            answer
        }
        Some("generate") => match generated(&st.settings.refresh().clone(), None) {
            Ok(p) => json!({"password": p.expose()}),
            Err(_) => error(Code::Failed),
        },
        Some("unlock") => {
            if let Some(app) = super::peer::allowed_dir().map(|d| d.join("nixe-passwords")) {
                let _ = std::process::Command::new(app)
                    .arg("--unlock")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
            }
            json!({})
        }
        _ => error(Code::Failed),
    }
}

/// The trusted active site for Glimpse: the tab a paired extension last reported, if
/// that browser was the window in front (`front`). Window titles are never used.
pub fn active_site(st: &State, front: Option<i32>) -> Option<Url> {
    let ctx = st.browser.context.as_ref()?;
    (front == Some(ctx.pid)).then(|| ctx.url.clone())
}
