//! The daemon's vault: the store, the unlocked session, the server, and every operation
//! the interface offers. Scopes are checked here, not only at the D-Bus layer, so an
//! operation can't be reached with the wrong one.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime};

use nyx_passwords_core::api::{ApiError, MAX_ATTACHMENT, Server, TwoFactor, TwoFactorAnswer};
use nyx_passwords_core::audit::{self, StrengthCache};
use nyx_passwords_core::crypto::CryptoError;
use nyx_passwords_core::edit::{CustomDraft, ItemDraft, LoginDraft, Place};
use nyx_passwords_core::generate;
use nyx_passwords_core::keyring;
use nyx_passwords_core::model::Kind;
use nyx_passwords_core::secret::{Secret, SecretBytes};
use nyx_passwords_core::session::{self, Session, SessionError, SignIn};
use nyx_passwords_core::store::Store;
use nyx_passwords_core::vault::{Entry, Field, RevealError, reveal, specs};
use nyx_passwords_proto::{Error as Code, Item, field, state};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use uuid::Uuid;

use super::clipboard::Clipboard;
use super::notify::Notifier;
use super::peer::Scope;
use super::settings::{Settings, Watched};

const RECENT: usize = 20;
const SEARCH_MAX: u32 = 50;
const QUERY_MAX: usize = 256;
/// The largest item draft (JSON) the app may send.
const DRAFT_MAX: usize = 256 * 1024;
/// The largest private key text `ReadSshKey` takes.
const SSH_KEY_MAX: usize = 64 * 1024;
/// Copies Glimpse may ask for in a minute; reveals the app may ask for.
const GLIMPSE_COPIES_PER_MINUTE: usize = 10;
const APP_REVEALS_PER_MINUTE: usize = 60;
/// Generated passwords and usernames kept for the history.
const GENERATED_KEPT: usize = 20;
/// How long a master-password confirmation opens items that ask for it again.
const REPROMPT_GRACE: Duration = Duration::from_secs(5 * 60);

/// An error for the interface: its D-Bus name and a message without vault data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub kind: Code,
    pub message: String,
}

impl Failure {
    pub fn new(kind: Code, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }
}

impl From<SessionError> for Failure {
    fn from(e: SessionError) -> Self {
        let kind = match &e {
            SessionError::SignedOut => Code::LoggedOut,
            SessionError::Api(ApiError::NotFound) => Code::NotFound,
            SessionError::Api(ApiError::RateLimited) => Code::RateLimited,
            SessionError::Api(ApiError::Conflict) => Code::Conflict,
            SessionError::NotAllowed(_) => Code::Denied,
            _ => Code::Failed,
        };
        Failure::new(kind, e.to_string())
    }
}

impl From<RevealError> for Failure {
    fn from(e: RevealError) -> Self {
        match e {
            RevealError::NotFound => Failure::new(Code::NotFound, "no such item"),
            RevealError::Empty | RevealError::BadTotp => Failure::new(Code::NoField, e.to_string()),
            RevealError::Hidden => Failure::new(Code::Denied, e.to_string()),
            RevealError::Crypto(CryptoError::MissingKey) => Failure::new(Code::Locked, "the vault is locked"),
            RevealError::Crypto(c) => Failure::new(Code::Failed, c.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, Failure>;

pub(super) fn denied() -> Failure {
    Failure::new(Code::Denied, "not allowed")
}

pub(super) fn locked() -> Failure {
    Failure::new(Code::Locked, "the vault is locked")
}

pub enum SignInResult {
    Done,
    TwoFactor(Vec<TwoFactor>),
}

pub(super) struct State {
    pub(super) store: Store,
    pub(super) settings: Watched,
    pub(super) session: Option<Session>,
    pub(super) server: Option<Server>,
    pub(super) refresh: Option<Secret>,
    pub(super) last_used: Instant,
    pub(super) recent: VecDeque<Uuid>,
    pub(super) glimpse_copies: VecDeque<Instant>,
    pub(super) assistant_copies: VecDeque<Instant>,
    pub(super) app_reveals: VecDeque<Instant>,
    /// When the app last confirmed the master password (for re-prompting items).
    pub(super) confirmed: Option<Instant>,
    /// Counts edits, so a sync fetched before one isn't applied over it.
    pub(super) edits: u64,
    /// Counts syncs applied (`Revision`).
    pub(super) revision: u64,
    /// This device's request to sign in with another's approval, while it waits.
    pub(super) device_sign_in: Option<(Server, session::DeviceSignIn)>,
    /// Other devices' requests, as last fetched, and whether the hub announced a new one.
    pub(super) sign_in_requests: Option<(Instant, Vec<session::SignInRequest>)>,
    pub(super) auth_pending: bool,
    /// What the generators made while the vault was open, newest first: `(what, value,
    /// when)`. Only in memory; dropped on lock.
    pub(super) generated: VecDeque<(&'static str, Secret, u64)>,
    /// A grantor's vault opened through emergency access; dropped on lock.
    pub(super) grantor: Option<nyx_passwords_core::emergency::Grantor>,
    /// Browser pairings and the active site (`browser.rs`).
    pub(super) browser: super::browser::Browser,
    /// Password strength per item and revision, for the security report. No passwords.
    pub(super) strength: StrengthCache,
}

pub struct Vault {
    pub(super) state: Mutex<State>,
    clipboard: Arc<StdMutex<Clipboard>>,
    pub(super) notifier: Notifier,
    icons: super::icons::Icons,
}

impl Vault {
    pub fn new(store: Store, settings: Watched, notifier: Notifier) -> Vault {
        Vault {
            state: Mutex::new(State {
                store,
                settings,
                session: None,
                server: None,
                refresh: None,
                last_used: Instant::now(),
                recent: VecDeque::new(),
                glimpse_copies: VecDeque::new(),
                assistant_copies: VecDeque::new(),
                app_reveals: VecDeque::new(),
                confirmed: None,
                edits: 0,
                revision: 0,
                device_sign_in: None,
                sign_in_requests: None,
                auth_pending: false,
                generated: VecDeque::new(),
                grantor: None,
                browser: Default::default(),
                strength: StrengthCache::new(),
            }),
            clipboard: Arc::new(StdMutex::new(Clipboard::default())),
            notifier,
            icons: Default::default(),
        }
    }

    /// A site's icon, when website icons are turned on.
    pub async fn icon(&self, scope: Scope, host: &str) -> Result<Vec<u8>> {
        need(scope, Scope::App)?;
        let server = {
            let mut st = self.state.lock().await;
            if !st.settings.refresh().icons {
                return Err(Failure::new(Code::Denied, "website icons are turned off"));
            }
            st.session.as_ref().ok_or_else(locked)?;
            st.server.clone().ok_or_else(|| Failure::new(Code::Failed, "no server"))?
        };
        self.icons.get(&server, host).await
    }

    pub async fn settings(&self) -> Settings {
        self.state.lock().await.settings.refresh().clone()
    }

    /// `(state, server host, clear seconds)`.
    pub async fn status(&self) -> (String, String, u32) {
        let mut st = self.state.lock().await;
        let clear = st.settings.refresh().clipboard_seconds as u32;
        let account = st.store.account().ok().flatten();
        let host = account.as_ref().and_then(|a| url_host(&a.server)).unwrap_or_default();
        let state = match (&account, &st.session) {
            (None, _) => state::LOGGED_OUT,
            (Some(_), None) => state::LOCKED,
            (Some(_), Some(_)) => state::UNLOCKED,
        };
        (state.to_string(), host, clear)
    }

    pub async fn search(&self, scope: Scope, query: &str, limit: u32) -> Result<Vec<Item>> {
        let mut st = self.state.lock().await;
        allow_finder(scope, &mut st)?;
        st.last_used = Instant::now();
        let session = st.session.as_ref().ok_or_else(locked)?;
        let query: String = query.chars().take(QUERY_MAX).collect();
        Ok(session.view.search(&query, limit.min(SEARCH_MAX) as usize).into_iter().map(item).collect())
    }

    /// Items for the active site when a paired browser reported it and was the window
    /// in front before the caller's (its host is returned too); otherwise recently used
    /// items and an empty host.
    pub async fn suggest(&self, scope: Scope, caller: i32, limit: u32) -> Result<(String, Vec<Item>)> {
        let focused = super::watch::front_pid(caller).await;
        let mut st = self.state.lock().await;
        allow_glimpse(scope, &mut st)?;
        let site = super::browser::active_site(&st, focused);
        let session = st.session.as_ref().ok_or_else(locked)?;
        let limit = limit.min(SEARCH_MAX) as usize;
        if let Some(url) = site {
            let items: Vec<Item> = session.view.matching(&url).into_iter().take(limit).map(item).collect();
            if !items.is_empty() {
                return Ok((url.host_str().unwrap_or_default().to_string(), items));
            }
        }
        let items = st
            .recent
            .iter()
            .filter_map(|id| session.view.get(*id))
            .filter(|e| !e.deleted && e.readable)
            .take(limit)
            .map(item)
            .collect();
        Ok((String::new(), items))
    }

    /// Puts one field on the clipboard; returns the seconds until it's cleared.
    pub async fn copy(self: &Arc<Self>, scope: Scope, id: &str, field_name: &str) -> Result<u32> {
        let field = match (field_name, scope) {
            (field::USERNAME, _) => Field::Username,
            (field::PASSWORD, _) => Field::Password,
            (field::TOTP, _) => Field::Totp,
            // The window may copy any field; Glimpse and the Assistant only those three.
            (other, Scope::App) => any_field(other)?,
            _ => return Err(Failure::new(Code::NoField, "unknown field")),
        };
        let id = parse_id(id)?;
        let (value, settings, label) = {
            let mut st = self.state.lock().await;
            allow_finder(scope, &mut st)?;
            let copies = match scope {
                Scope::Glimpse => Some(&mut st.glimpse_copies),
                Scope::Assistant => Some(&mut st.assistant_copies),
                _ => None,
            };
            if copies.is_some_and(|c| !within(c, GLIMPSE_COPIES_PER_MINUTE)) {
                return Err(Failure::new(Code::RateLimited, "too many copies; wait a minute"));
            }
            let settings = st.settings.refresh().clone();
            reprompt_check(&st, scope, id, field)?;
            let session = st.session.as_ref().ok_or_else(locked)?;
            let value = reveal(&session.keys, &session.snapshot, id, field)?;
            st.last_used = Instant::now();
            st.recent.retain(|r| *r != id);
            st.recent.push_front(id);
            st.recent.truncate(RECENT);
            let label = match field {
                Field::Username => "Username",
                Field::Password => "Password",
                Field::Totp => "One-time code",
                Field::Sub(spec) => spec.label,
                _ => "Field",
            };
            (value, settings, label)
        };
        self.put_on_clipboard(value, &settings, label).await
    }

    /// Generates with the saved rules and copies the result.
    pub async fn generate(self: &Arc<Self>, scope: Scope) -> Result<u32> {
        let settings = {
            let mut st = self.state.lock().await;
            allow_glimpse(scope, &mut st)?;
            st.settings.refresh().clone()
        };
        let value = generated(&settings, None)?;
        self.remember("password", &value).await;
        self.put_on_clipboard(value, &settings, "Generated password").await
    }

    pub(super) async fn put_on_clipboard(&self, value: Secret, settings: &Settings, label: &str) -> Result<u32> {
        let clipboard = self.clipboard.clone();
        let paste_once = settings.paste_once;
        let serial = tokio::task::spawn_blocking(move || clipboard.lock().expect("clipboard").copy(value, paste_once))
            .await
            .map_err(|_| Failure::new(Code::Clipboard, "couldn't copy"))?
            .map_err(|_| Failure::new(Code::Clipboard, "no clipboard: the compositor lacks the data-control protocol"))?;
        let seconds = settings.clipboard_seconds;
        if seconds > 0 {
            let clipboard = self.clipboard.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(seconds)).await;
                let _ =
                    tokio::task::spawn_blocking(move || clipboard.lock().expect("clipboard").clear_if_unchanged(serial)).await;
            });
        }
        if settings.notify_copies {
            let body = if seconds > 0 { format!("Clears in {seconds} s") } else { String::new() };
            self.notifier.send(&format!("{label} copied"), &body).await;
        }
        Ok(seconds as u32)
    }

    pub async fn open_url(&self, scope: Scope, id: &str) -> Result<String> {
        let id = parse_id(id)?;
        let mut st = self.state.lock().await;
        allow_glimpse(scope, &mut st)?;
        let session = st.session.as_ref().ok_or_else(locked)?;
        let entry = session.view.get(id).ok_or_else(|| Failure::new(Code::NotFound, "no such item"))?;
        let url =
            entry.uris.iter().find_map(|u| web_url(u.expose())).ok_or_else(|| Failure::new(Code::NoUrl, "no web address"))?;
        st.last_used = Instant::now();
        Ok(url)
    }

    pub async fn verify_password(&self, scope: Scope, password: Secret) -> Result<()> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let session = st.session.as_ref().ok_or_else(locked)?;
        if session.verify(&password).await? {
            st.confirmed = Some(Instant::now());
            Ok(())
        } else {
            Err(Failure::new(Code::Failed, "wrong master password"))
        }
    }

    /// Locks: drops the session and its keys, and clears a copy still on the clipboard.
    pub async fn lock(&self) {
        let session = {
            let mut st = self.state.lock().await;
            st.confirmed = None;
            st.generated.clear();
            if let Some(g) = st.grantor.take() {
                g.keys.lock();
            }
            st.browser.lock();
            st.strength.clear();
            st.session.take()
        };
        self.icons.forget().await;
        if let Some(s) = session {
            s.lock();
            let clipboard = self.clipboard.clone();
            let _ = tokio::task::spawn_blocking(move || clipboard.lock().expect("clipboard").clear_now()).await;
        }
    }

    pub async fn is_unlocked(&self) -> bool {
        self.state.lock().await.session.is_some()
    }

    /// Locked, and not in the middle of signing in with another device's approval.
    pub async fn idle_while_locked(&self) -> bool {
        let st = self.state.lock().await;
        st.session.is_none() && st.device_sign_in.is_none()
    }

    /// Starts the daemon again on the binary an update put in place; it locks first.
    pub fn restart_for_update(&self, scope: Scope) -> Result<()> {
        need(scope, Scope::App)?;
        super::restart();
        Ok(())
    }

    /// Locks if the vault has been unused for the configured time.
    pub async fn lock_if_idle(&self) {
        let idle = {
            let mut st = self.state.lock().await;
            let minutes = st.settings.refresh().lock_minutes;
            st.session.is_some() && minutes > 0 && st.last_used.elapsed() >= Duration::from_secs(minutes * 60)
        };
        if idle {
            self.lock().await;
        }
    }

    // ---- app only ----

    pub async fn sign_in(
        self: &Arc<Self>,
        scope: Scope,
        server_url: &str,
        email: &str,
        password: Secret,
        answer: Option<TwoFactorAnswer>,
    ) -> Result<SignInResult> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let extra_ca = st.settings.refresh().extra_ca.clone();
        let server = make_server(server_url, extra_ca.as_deref())?;
        let st = &mut *st;
        let signed = session::sign_in(&mut st.store, &server, email, &password, &device_name(), answer.as_ref()).await?;
        let session = match signed {
            SignIn::Done(s) => *s,
            SignIn::TwoFactor(methods) => return Ok(SignInResult::TwoFactor(methods)),
        };
        signed_in(st, server, session).await;
        Ok(SignInResult::Done)
    }

    /// Signs in with the account's API key, then opens the vault with the master password.
    pub async fn sign_in_with_api_key(
        &self,
        scope: Scope,
        server_url: &str,
        client_id: &str,
        secret: Secret,
        password: Secret,
    ) -> Result<()> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let extra_ca = st.settings.refresh().extra_ca.clone();
        let server = make_server(server_url, extra_ca.as_deref())?;
        let st = &mut *st;
        let session =
            session::sign_in_with_api_key(&mut st.store, &server, client_id, &secret, &password, &device_name()).await?;
        signed_in(st, server, session).await;
        Ok(())
    }

    /// Asks the account's other devices to approve signing in here; returns the words
    /// both sides show. `PollDeviceSignIn` then waits for the answer.
    pub async fn request_device_sign_in(&self, scope: Scope, server_url: &str, email: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let extra_ca = st.settings.refresh().extra_ca.clone();
        let server = make_server(server_url, extra_ca.as_deref())?;
        let request = session::request_device_sign_in(&mut st.store, &server, email, &device_name()).await.map_err(|e| match e {
            SessionError::Api(ApiError::Server { status: 400, .. }) => Failure::new(
                Code::Failed,
                "this computer hasn't signed in to this account before, which Vaultwarden needs for this: sign in with the master password once",
            ),
            e => e.into(),
        })?;
        let fingerprint = request.fingerprint.clone();
        st.device_sign_in = Some((server, request));
        Ok(fingerprint)
    }

    /// Whether the other device has approved (the vault is then open). Declined or
    /// expired: `Failed`.
    pub async fn poll_device_sign_in(&self, scope: Scope) -> Result<bool> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let Some((server, request)) = st.device_sign_in.as_mut() else {
            return Err(Failure::new(Code::Failed, "no sign-in request is waiting"));
        };
        let server = server.clone();
        let polled = request.poll(&mut st.store, &server).await;
        match polled {
            Ok(None) => Ok(false),
            Ok(Some(session)) => {
                st.device_sign_in = None;
                signed_in(st, server, session).await;
                Ok(true)
            }
            Err(e) => {
                st.device_sign_in = None;
                Err(e.into())
            }
        }
    }

    pub async fn cancel_device_sign_in(&self, scope: Scope) -> Result<()> {
        need(scope, Scope::App)?;
        self.state.lock().await.device_sign_in = None;
        Ok(())
    }

    /// Other devices asking to sign in with this account, as JSON `[{id, device, ip,
    /// created, fingerprint}]`. The server is asked when the hub said there's a request,
    /// or at most once a minute otherwise.
    pub async fn sign_in_requests(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let stale = st.sign_in_requests.as_ref().is_none_or(|(at, _)| at.elapsed() > Duration::from_secs(60));
        if st.auth_pending || stale {
            let (server, refresh) = online(st)?;
            let session = st.session.as_mut().ok_or_else(locked)?;
            let list = session.sign_in_requests(&server, &refresh).await?;
            st.auth_pending = false;
            st.sign_in_requests = Some((Instant::now(), list));
        }
        let list: Vec<_> = st
            .sign_in_requests
            .as_ref()
            .map(|(_, l)| l.as_slice())
            .unwrap_or_default()
            .iter()
            .map(|r| json!({"id": r.id, "device": r.device_type, "ip": r.ip, "created": r.created, "fingerprint": r.fingerprint}))
            .collect();
        Ok(serde_json::Value::Array(list).to_string())
    }

    /// Approves or declines another device's request to sign in.
    pub async fn answer_sign_in(&self, scope: Scope, id: &str, approve: bool) -> Result<()> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        let session = st.session.as_mut().ok_or_else(locked)?;
        session.answer_sign_in(&server, &refresh, id, approve).await?;
        st.sign_in_requests = None;
        st.last_used = Instant::now();
        Ok(())
    }

    /// The hub said another device asks to sign in: tell the user, and fetch the list
    /// next time the window asks.
    pub async fn sign_in_requested(&self) {
        self.state.lock().await.auth_pending = true;
        self.notifier.send("A device asks to sign in", "Open Passwords to approve or decline it.").await;
    }

    pub async fn send_email_code(&self, scope: Scope, server_url: &str, email: &str, password: Secret) -> Result<()> {
        need(scope, Scope::App)?;
        let extra_ca = self.state.lock().await.settings.refresh().extra_ca.clone();
        let server = make_server(server_url, extra_ca.as_deref())?;
        Ok(session::send_email_code(&server, email, &password).await?)
    }

    /// Unlocks from the local copy, then syncs in the background.
    pub async fn unlock(self: &Arc<Self>, scope: Scope, password: Secret) -> Result<()> {
        need(scope, Scope::App)?;
        {
            let mut st = self.state.lock().await;
            if st.session.is_some() {
                return Ok(());
            }
            let session = session::unlock(&mut st.store, &password).await?;
            opened(&mut st, session).await;
        }
        self.sync_soon();
        Ok(())
    }

    /// Unlocks with the user key saved in the desktop keyring, when that's turned on. A
    /// stale key (the master password changed elsewhere) is removed.
    pub async fn unlock_with_keyring(self: &Arc<Self>, scope: Scope) -> Result<()> {
        need(scope, Scope::App)?;
        {
            let mut st = self.state.lock().await;
            if st.session.is_some() {
                return Ok(());
            }
            let entry = unlock_entry(&st).ok_or_else(|| Failure::new(Code::LoggedOut, "not signed in"))?;
            let (entry, saved) = tokio::task::spawn_blocking(move || {
                let saved = entry.load_unlock_key();
                (entry, saved)
            })
            .await
            .map_err(|_| Failure::new(Code::Failed, "the keyring couldn't be read"))?;
            let key = saved
                .map_err(|e| Failure::new(Code::Failed, e.to_string()))?
                .ok_or_else(|| Failure::new(Code::Failed, "unlocking with the keyring isn't set up"))?;
            let session = match session::unlock_with_key(&mut st.store, &key) {
                Ok(s) => s,
                Err(SessionError::KeysChanged) => {
                    let _ = tokio::task::spawn_blocking(move || entry.clear_unlock_key()).await;
                    return Err(Failure::new(Code::Failed, "the saved key no longer fits: unlock with the master password"));
                }
                Err(e) => return Err(e.into()),
            };
            opened(&mut st, session).await;
        }
        self.sync_soon();
        Ok(())
    }

    /// Whether a key for unlocking is saved in the keyring for this account.
    pub async fn keyring_unlock(&self, scope: Scope) -> Result<bool> {
        need(scope, Scope::App)?;
        let Some(entry) = unlock_entry(&*self.state.lock().await) else { return Ok(false) };
        let saved = tokio::task::spawn_blocking(move || entry.load_unlock_key()).await.ok().and_then(|r| r.ok().flatten());
        Ok(saved.is_some())
    }

    /// Turns unlocking with the keyring on (saving the user key there; the vault must be
    /// unlocked, and the master password confirmed just before, as for re-prompting
    /// items) or off (removing it).
    pub async fn set_keyring_unlock(&self, scope: Scope, on: bool) -> Result<()> {
        need(scope, Scope::App)?;
        let st = self.state.lock().await;
        // Otherwise anything that can act as the app while the vault is open could keep
        // a way in after it locks.
        if on && !st.confirmed.is_some_and(|t| t.elapsed() < REPROMPT_GRACE) {
            return Err(Failure::new(Code::Reprompt, "confirm the master password first"));
        }
        let entry = unlock_entry(&st).ok_or_else(|| Failure::new(Code::LoggedOut, "not signed in"))?;
        let saved = if on {
            let key = st.session.as_ref().ok_or_else(locked)?.keys.export_user_key().map_err(SessionError::from)?;
            drop(st);
            tokio::task::spawn_blocking(move || entry.save_unlock_key(&key)).await
        } else {
            drop(st);
            tokio::task::spawn_blocking(move || entry.clear_unlock_key()).await
        };
        saved
            .map_err(|_| Failure::new(Code::Failed, "the keyring couldn't be reached"))?
            .map_err(|e| Failure::new(Code::Failed, e.to_string()))
    }

    fn sync_soon(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            let _ = me.sync(Scope::App).await;
        });
    }

    /// Fetches the vault without holding the lock, then applies it. A fetch that began
    /// before an edit finished would undo that edit locally, so it's fetched again.
    pub async fn sync(&self, scope: Scope) -> Result<()> {
        need_any(scope, &[Scope::App, Scope::Settings])?;
        for _ in 0..3 {
            let (server, refresh, access, edits) = {
                let st = self.state.lock().await;
                let session = st.session.as_ref().ok_or_else(locked)?;
                let server = st.server.clone().ok_or_else(|| Failure::new(Code::Failed, "no server"))?;
                let refresh = st.refresh.as_ref().map(|r| Secret::new(r.expose()));
                let access = session.tokens.as_ref().filter(|t| !t.stale()).map(|t| Secret::new(t.access.expose()));
                (server, refresh, access, st.edits)
            };
            let mut new_tokens = None;
            let access = match access {
                Some(a) => a,
                None => {
                    let refresh = refresh.ok_or_else(|| Failure::new(Code::Failed, "sign in again to sync"))?;
                    let tokens = server.refresh(&refresh).await.map_err(SessionError::from)?;
                    let access = Secret::new(tokens.access.expose());
                    new_tokens = Some(tokens);
                    access
                }
            };
            let sync = server.sync(&access).await.map_err(SessionError::from)?;
            let mut st = self.state.lock().await;
            let st = &mut *st;
            let session = st.session.as_mut().ok_or_else(locked)?;
            if let Some(tokens) = new_tokens {
                if !tokens.refresh.is_empty() && st.refresh.as_ref().is_none_or(|r| r.expose() != tokens.refresh.expose()) {
                    let entry = keyring::Entry { server: session.account.server.clone(), email: session.account.email.clone() };
                    let token = Secret::new(tokens.refresh.expose());
                    st.refresh = Some(Secret::new(tokens.refresh.expose()));
                    tokio::task::spawn_blocking(move || entry.save(&token));
                }
                session.tokens = Some(tokens);
            }
            if st.edits != edits {
                continue;
            }
            let applied = session.apply(&mut st.store, sync);
            if applied == Err(SessionError::KeysChanged)
                && let Some(entry) = unlock_entry(st)
            {
                // A key saved for unlocking is stale now too.
                tokio::task::spawn_blocking(move || entry.clear_unlock_key());
            }
            applied?;
            st.revision += 1;
            return Ok(());
        }
        Err(Failure::new(Code::Failed, "the vault kept changing during sync; try again"))
    }

    /// Goes up each time a sync brings the vault in, so an open window can tell that
    /// something changed without asking for the listing.
    pub async fn revision(&self, scope: Scope) -> Result<u64> {
        need(scope, Scope::App)?;
        Ok(self.state.lock().await.revision)
    }

    /// Connects to the server's notification hub with a fresh access token.
    pub async fn connect_hub(&self) -> Result<nyx_passwords_core::live::Hub> {
        let (server, access, device) = {
            let mut st = self.state.lock().await;
            let st = &mut *st;
            let (server, refresh) = online(st)?;
            let session = st.session.as_mut().ok_or_else(locked)?;
            let access = Secret::new(session.access(&server, &refresh).await?.expose());
            (server, access, session.account.device_id)
        };
        server.connect_hub(&access, device).await.map_err(|e| Failure::from(SessionError::from(e)))
    }

    /// Signs out: forgets the session, the local copy and the saved token.
    pub async fn sign_out(&self, scope: Scope) -> Result<()> {
        need(scope, Scope::App)?;
        self.lock().await;
        let mut st = self.state.lock().await;
        if let Some(account) = st.store.account().ok().flatten() {
            let entry = keyring::Entry { server: account.server, email: account.email };
            let _ = tokio::task::spawn_blocking(move || {
                let _ = entry.clear_unlock_key();
                entry.clear()
            })
            .await;
        }
        st.store.clear().map_err(|e| Failure::new(Code::Failed, e.to_string()))?;
        st.refresh = None;
        st.server = None;
        st.recent.clear();
        Ok(())
    }

    /// The listing for the app, as JSON: metadata only, no secret fields.
    pub async fn list(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        st.last_used = Instant::now();
        let session = st.session.as_ref().ok_or_else(locked)?;
        let v = &session.view;
        let entries: Vec<_> = v.entries.iter().map(entry_json).collect();
        let folders: Vec<_> = v.folders.iter().map(|f| json!({"id": f.id, "name": f.name.expose()})).collect();
        let collections: Vec<_> = v
            .collections
            .iter()
            .map(|c| json!({"id": c.id, "organization": c.organization, "name": c.name.expose(), "writable": c.writable}))
            .collect();
        let orgs: Vec<_> = v.organizations.iter().map(|(id, name)| json!({"id": id, "name": name})).collect();
        let account = &session.account;
        Ok(json!({
            "account": {"email": account.email, "server": account.server, "last_sync": account.last_sync},
            "entries": entries, "folders": folders, "collections": collections, "organizations": orgs,
        })
        .to_string())
    }

    /// One field's plaintext, for the window's reveal and editor.
    pub async fn reveal(&self, scope: Scope, id: &str, field_name: &str) -> Result<Secret> {
        need(scope, Scope::App)?;
        let field = any_field(field_name)?;
        let id = parse_id(id)?;
        let mut st = self.state.lock().await;
        if !within(&mut st.app_reveals, APP_REVEALS_PER_MINUTE) {
            return Err(Failure::new(Code::RateLimited, "too many requests; wait a minute"));
        }
        st.last_used = Instant::now();
        reprompt_check(&st, scope, id, field)?;
        let session = st.session.as_ref().ok_or_else(locked)?;
        Ok(reveal(&session.keys, &session.snapshot, id, field)?)
    }

    /// The current one-time code for the item view: `(code, period, seconds left)`. The
    /// view asks again at each new period, so this doesn't count as use: an open item
    /// mustn't keep the vault from locking.
    pub async fn totp(&self, scope: Scope, id: &str) -> Result<(Secret, u32, u32)> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let mut st = self.state.lock().await;
        if !within(&mut st.app_reveals, APP_REVEALS_PER_MINUTE) {
            return Err(Failure::new(Code::RateLimited, "too many requests; wait a minute"));
        }
        reprompt_check(&st, scope, id, Field::Totp)?;
        let session = st.session.as_ref().ok_or_else(locked)?;
        let code = nyx_passwords_core::vault::current_code(&session.keys, &session.snapshot, id)?;
        Ok((code.code, code.period as u32, code.remaining as u32))
    }

    /// An item's other fields as JSON: `[{name, label, value, secret}]`, secret values
    /// left out (`Reveal` them one at a time).
    pub async fn fields(&self, scope: Scope, id: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let st = self.state.lock().await;
        let session = st.session.as_ref().ok_or_else(locked)?;
        let shown = nyx_passwords_core::vault::fields(&session.keys, &session.snapshot, id)?;
        let list: Vec<_> = shown
            .iter()
            .map(|f| {
                json!({"name": f.name, "label": f.label, "value": f.value.as_ref().map(|v| v.expose()),
                       "secret": f.secret, "kind": f.kind})
            })
            .collect();
        Ok(serde_json::Value::Array(list).to_string())
    }

    /// A new Ed25519 key for the editor: `{private, public, fingerprint}`.
    pub fn generate_ssh_key(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let key = nyx_passwords_core::ssh::generate();
        Ok(json!({"private": key.private.expose(), "public": key.public, "fingerprint": key.fingerprint}).to_string())
    }

    /// The public key and fingerprint of a private key the editor imported:
    /// `{public, fingerprint}`.
    pub fn read_ssh_key(&self, scope: Scope, private: &str) -> Result<String> {
        need(scope, Scope::App)?;
        if private.len() > SSH_KEY_MAX {
            return Err(Failure::new(Code::Failed, "that file is too large to be a private key"));
        }
        let key = nyx_passwords_core::ssh::read(private).map_err(|e| Failure::new(Code::Failed, e.to_string()))?;
        Ok(json!({"public": key.public, "fingerprint": key.fingerprint}).to_string())
    }

    pub async fn generate_password(&self, scope: Scope, rules: &str) -> Result<Secret> {
        need(scope, Scope::App)?;
        let settings = self.settings().await;
        let made = generated(&settings, Some(rules))?;
        self.remember("password", &made).await;
        Ok(made)
    }

    /// Keeps a generated value in the history, while the vault is open.
    pub(super) async fn remember(&self, what: &'static str, value: &Secret) {
        let mut st = self.state.lock().await;
        if st.session.is_none() {
            return;
        }
        let when = SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        st.generated.push_front((what, Secret::new(value.expose()), when));
        st.generated.truncate(GENERATED_KEPT);
    }

    /// A username from the generator settings; `site` is the login's address, for
    /// tags and for the alias service's note.
    pub async fn generate_username(&self, scope: Scope, site: &str) -> Result<Secret> {
        use nyx_passwords_core::alias::{self, UsernameKind};
        need_any(scope, &[Scope::App, Scope::Browser])?;
        let (rules, entry) = {
            let mut st = self.state.lock().await;
            st.session.as_ref().ok_or_else(locked)?;
            (st.settings.refresh().username_rules.clone(), unlock_entry(&st))
        };
        let site = (!site.is_empty()).then_some(site);
        let made = if rules.kind == UsernameKind::Forwarded {
            let entry = entry.ok_or_else(|| Failure::new(Code::LoggedOut, "not signed in"))?;
            let service = rules.service.clone();
            let token = tokio::task::spawn_blocking(move || entry.load_forwarder_token(&service))
                .await
                .map_err(|_| Failure::new(Code::Failed, "the keyring couldn't be read"))?
                .map_err(|e| Failure::new(Code::Failed, e.to_string()))?
                .unwrap_or_else(|| Secret::new(""));
            alias::forwarded(&rules, &token, site, None).await
        } else {
            alias::local(&rules, site)
        }
        .map_err(|e| Failure::new(Code::Failed, e.to_string()))?;
        self.remember("username", &made).await;
        Ok(made)
    }

    /// Saves an alias service's API token in the keyring (an empty token removes it).
    pub async fn set_forwarder_token(&self, scope: Scope, service: &str, token: Secret) -> Result<()> {
        need(scope, Scope::App)?;
        let entry = unlock_entry(&*self.state.lock().await).ok_or_else(|| Failure::new(Code::LoggedOut, "not signed in"))?;
        let service = service.to_string();
        tokio::task::spawn_blocking(move || {
            if token.is_empty() { entry.clear_forwarder_token(&service) } else { entry.save_forwarder_token(&service, &token) }
        })
        .await
        .map_err(|_| Failure::new(Code::Failed, "the keyring couldn't be reached"))?
        .map_err(|e| Failure::new(Code::Failed, e.to_string()))
    }

    /// Which alias services have a token saved: JSON `{service: bool}`.
    pub async fn forwarder_tokens(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let Some(entry) = unlock_entry(&*self.state.lock().await) else { return Ok("{}".into()) };
        let saved = tokio::task::spawn_blocking(move || {
            nyx_passwords_core::alias::SERVICES
                .iter()
                .map(|(id, _)| (id.to_string(), entry.load_forwarder_token(id).ok().flatten().is_some().into()))
                .collect::<serde_json::Map<String, serde_json::Value>>()
        })
        .await
        .map_err(|_| Failure::new(Code::Failed, "the keyring couldn't be reached"))?;
        Ok(serde_json::Value::Object(saved).to_string())
    }

    /// Emergency contacts both ways, as JSON `{trusted: […], granted: […]}`, each
    /// `{id, name, email, status, wait_days}`.
    pub async fn emergency_contacts(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        let session = st.session.as_mut().ok_or_else(locked)?;
        let (trusted, granted) = session.emergency_contacts(&server, &refresh).await?;
        let json_of = |list: Vec<nyx_passwords_core::emergency::Contact>| -> Vec<serde_json::Value> {
            list.into_iter()
                .map(|c| json!({"id": c.id, "name": c.name, "email": c.email, "status": c.status.name(), "wait_days": c.wait_days, "takeover": c.takeover}))
                .collect()
        };
        Ok(json!({"trusted": json_of(trusted), "granted": json_of(granted)}).to_string())
    }

    /// One emergency-access action: `invite` (`arg`: email, `days`), `fingerprint` (the
    /// contact's phrase, returned), `confirm`, `request`, `approve`, `reject`, `remove`,
    /// `me` (this account's own phrase, returned).
    pub async fn emergency(&self, scope: Scope, action: &str, arg: &str, days: u32) -> Result<String> {
        use nyx_passwords_core::emergency::Step;
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        let session = st.session.as_mut().ok_or_else(locked)?;
        st.last_used = Instant::now();
        let step = match action {
            "request" => Some(Step::Request),
            "approve" => Some(Step::Approve),
            "reject" => Some(Step::Reject),
            "remove" => Some(Step::Remove),
            _ => None,
        };
        let done = |r: std::result::Result<(), SessionError>| r.map(|()| String::new());
        let out = match (action, step) {
            (_, Some(step)) => done(session.emergency_step(&server, &refresh, arg, step).await),
            ("invite", _) => done(session.invite_emergency(&server, &refresh, arg, days).await),
            ("fingerprint", _) => session.emergency_fingerprint(&server, &refresh, arg).await,
            ("confirm", _) => done(session.confirm_emergency(&server, &refresh, arg).await),
            ("me", _) => session.my_fingerprint(&server, &refresh).await,
            _ => return Err(Failure::new(Code::Failed, "unknown action")),
        };
        Ok(out?)
    }

    /// Opens a grantor's vault (they approved): the listing as JSON, like `List`'s
    /// entries. It stays open in the daemon until the vault locks or another is opened.
    pub async fn view_emergency(&self, scope: Scope, id: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        let session = st.session.as_mut().ok_or_else(locked)?;
        let opened = session.view_emergency(&server, &refresh, id).await?;
        let entries: Vec<_> = opened.view.entries.iter().map(entry_json).collect();
        st.grantor = Some(opened);
        st.last_used = Instant::now();
        Ok(serde_json::Value::Array(entries).to_string())
    }

    /// A field of an item in the open grantor's vault (`username`, `password`, `totp`,
    /// `notes`, …), for showing.
    pub async fn emergency_reveal(&self, scope: Scope, id: &str, field_name: &str) -> Result<Secret> {
        need(scope, Scope::App)?;
        let field = any_field(field_name)?;
        let id = parse_id(id)?;
        let mut st = self.state.lock().await;
        if !within(&mut st.app_reveals, APP_REVEALS_PER_MINUTE) {
            return Err(Failure::new(Code::RateLimited, "too many requests; wait a minute"));
        }
        st.last_used = Instant::now();
        let grantor = st.grantor.as_ref().ok_or_else(|| Failure::new(Code::NotFound, "no vault is open for emergency access"))?;
        Ok(nyx_passwords_core::vault::reveal_in(&grantor.keys, &grantor.ciphers, id, field)?)
    }

    /// An item's passkeys as JSON `[{credential_id, rp_id, rp_name, user_name, created}]`.
    pub async fn passkeys(&self, scope: Scope, id: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let st = self.state.lock().await;
        let session = st.session.as_ref().ok_or_else(locked)?;
        let list: Vec<_> = session
            .passkeys(id)?
            .into_iter()
            .map(|p| {
                json!({"credential_id": p.credential_id, "rp_id": p.rp_id, "rp_name": p.rp_name,
                       "user_name": p.user_name, "created": p.creation_date})
            })
            .collect();
        Ok(serde_json::Value::Array(list).to_string())
    }

    pub async fn delete_passkey(&self, scope: Scope, id: &str, credential_id: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        st.edits += 1;
        let session = st.session.as_mut().ok_or_else(locked)?;
        session.delete_passkey(&mut st.store, &server, &refresh, id, credential_id).await?;
        st.last_used = Instant::now();
        Ok(())
    }

    /// Copies the n-th value of the generator history, cleared later like any copy.
    pub async fn copy_generated(self: &Arc<Self>, scope: Scope, index: u32) -> Result<u32> {
        need(scope, Scope::App)?;
        let (value, settings) = {
            let mut st = self.state.lock().await;
            let value = st.generated.get(index as usize).map(|(_, v, _)| Secret::new(v.expose()));
            (value.ok_or_else(|| Failure::new(Code::NotFound, "no such value"))?, st.settings.refresh().clone())
        };
        self.put_on_clipboard(value, &settings, "Generated value").await
    }

    /// The generator history: JSON `[{what, value, when}]`, newest first.
    pub async fn generator_history(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let st = self.state.lock().await;
        st.session.as_ref().ok_or_else(locked)?;
        let list: Vec<_> =
            st.generated.iter().map(|(what, value, when)| json!({"what": what, "value": value.expose(), "when": when})).collect();
        Ok(serde_json::Value::Array(list).to_string())
    }

    pub async fn create_login(&self, scope: Scope, draft: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let draft = parse_draft(draft)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        let session = st.session.as_mut().ok_or_else(locked)?;
        st.edits += 1;
        let id = session.create_login(&mut st.store, &server, &refresh, &draft).await?;
        st.last_used = Instant::now();
        Ok(id.to_string())
    }

    pub async fn update_login(&self, scope: Scope, id: &str, draft: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let draft = parse_draft(draft)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        let session = st.session.as_mut().ok_or_else(locked)?;
        st.edits += 1;
        session.update_login(&mut st.store, &server, &refresh, id, &draft).await?;
        st.last_used = Instant::now();
        Ok(())
    }

    pub async fn create_item(&self, scope: Scope, draft: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let draft = parse_item_draft(draft)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        let session = st.session.as_mut().ok_or_else(locked)?;
        st.edits += 1;
        let id = session.create_item(&mut st.store, &server, &refresh, &draft).await?;
        st.last_used = Instant::now();
        Ok(id.to_string())
    }

    pub async fn update_item(&self, scope: Scope, id: &str, draft: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let draft = parse_item_draft(draft)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        let session = st.session.as_mut().ok_or_else(locked)?;
        st.edits += 1;
        session.update_item(&mut st.store, &server, &refresh, id, &draft).await?;
        st.last_used = Instant::now();
        Ok(())
    }

    /// The security report as JSON `[{id, reused, weak, age_days}]`: logins with a
    /// reused, weak or old password. Worked out here, in memory.
    pub async fn report(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let session = st.session.as_ref().ok_or_else(locked)?;
        let found = audit::audit(&session.keys, &session.snapshot, SystemTime::now(), &mut st.strength);
        let list: Vec<_> =
            found.iter().map(|f| json!({"id": f.id, "reused": f.reused, "weak": f.weak, "age_days": f.age_days})).collect();
        Ok(serde_json::Value::Array(list).to_string())
    }

    /// Checks every login's password against Have I Been Pwned's breach data, when the
    /// user asks: only the first five characters of each password's SHA-1 hash are sent.
    /// JSON `[{id, count}]`, for the logins found.
    pub async fn check_breaches(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let hashes = {
            let st = self.state.lock().await;
            let session = st.session.as_ref().ok_or_else(locked)?;
            audit::breach_hashes(&session.keys, &session.snapshot)
        };
        // The vault lock is released while the lookups run.
        let found = audit::breaches(audit::BREACH_API, &hashes)
            .await
            .map_err(|_| Failure::new(Code::Failed, "Have I Been Pwned couldn't be reached"))?;
        let list: Vec<_> = found.iter().map(|(id, count)| json!({"id": id, "count": count})).collect();
        Ok(serde_json::Value::Array(list).to_string())
    }

    /// An item's attachments as JSON `[{id, name, size}]`.
    pub async fn attachments(&self, scope: Scope, id: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let st = self.state.lock().await;
        let session = st.session.as_ref().ok_or_else(locked)?;
        let list: Vec<_> =
            session.attachments(id)?.iter().map(|a| json!({"id": a.id, "name": a.name.expose(), "size": a.size})).collect();
        Ok(serde_json::Value::Array(list).to_string())
    }

    /// Downloads and decrypts an attachment into `file`, which the app opened where the
    /// user chose. The decrypted bytes go nowhere else. Returns how many were written.
    pub async fn save_attachment(&self, scope: Scope, id: &str, attachment: &str, file: std::fs::File) -> Result<u64> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let data = {
            let mut st = self.state.lock().await;
            // Like revealing a secret field: items that ask for the master password do.
            reprompt_check(&st, scope, id, Field::Notes)?;
            let st = &mut *st;
            let (server, refresh) = online(st)?;
            let session = st.session.as_mut().ok_or_else(locked)?;
            st.last_used = Instant::now();
            session.download_attachment(&mut st.store, &server, &refresh, id, attachment).await?
        };
        tokio::task::spawn_blocking(move || {
            use std::io::Write;
            let mut file = file;
            file.write_all(data.expose())?;
            file.sync_all()?;
            Ok::<u64, std::io::Error>(data.expose().len() as u64)
        })
        .await
        .map_err(|_| Failure::new(Code::Failed, "the file couldn't be written"))?
        .map_err(|e| Failure::new(Code::Failed, format!("the file couldn't be written: {e}")))
    }

    /// Encrypts the contents of `file` (opened by the app) and adds them to the item as
    /// an attachment called `name`.
    pub async fn add_attachment(&self, scope: Scope, id: &str, name: &str, file: std::fs::File) -> Result<()> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let name = name.rsplit('/').next().unwrap_or_default().trim();
        if name.is_empty() || name.len() > 255 {
            return Err(Failure::new(Code::Failed, "the file needs a name of at most 255 bytes"));
        }
        let data = tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut data = Vec::new();
            file.take(MAX_ATTACHMENT as u64 + 1).read_to_end(&mut data).map(|_| SecretBytes::new(data))
        })
        .await
        .map_err(|_| Failure::new(Code::Failed, "the file couldn't be read"))?
        .map_err(|e| Failure::new(Code::Failed, format!("the file couldn't be read: {e}")))?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        let session = st.session.as_mut().ok_or_else(locked)?;
        st.edits += 1;
        session.add_attachment(&mut st.store, &server, &refresh, id, name, data.expose()).await?;
        st.last_used = Instant::now();
        Ok(())
    }

    pub async fn delete_attachment(&self, scope: Scope, id: &str, attachment: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        let session = st.session.as_mut().ok_or_else(locked)?;
        st.edits += 1;
        session.delete_attachment(&mut st.store, &server, &refresh, id, attachment).await?;
        st.last_used = Instant::now();
        Ok(())
    }

    pub async fn trash(&self, scope: Scope, id: &str, restore: bool) -> Result<()> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        st.edits += 1;
        let session = st.session.as_mut().ok_or_else(locked)?;
        if restore {
            session.restore(&mut st.store, &server, &refresh, id).await?;
        } else {
            session.trash(&mut st.store, &server, &refresh, id).await?;
        }
        st.last_used = Instant::now();
        Ok(())
    }

    /// Moves several items (`ids`, a JSON list) to the trash, or restores them.
    pub async fn trash_many(&self, scope: Scope, ids: &str, restore: bool) -> Result<()> {
        need(scope, Scope::App)?;
        let ids = parse_ids(ids)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        st.edits += 1;
        let session = st.session.as_mut().ok_or_else(locked)?;
        session.trash_many(&mut st.store, &server, &refresh, &ids, restore).await?;
        st.last_used = Instant::now();
        Ok(())
    }

    /// Deletes items in the trash for good (`ids`, a JSON list).
    pub async fn delete_forever(&self, scope: Scope, ids: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let ids = parse_ids(ids)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        st.edits += 1;
        let session = st.session.as_mut().ok_or_else(locked)?;
        session.delete_forever(&mut st.store, &server, &refresh, &ids).await?;
        st.last_used = Instant::now();
        Ok(())
    }

    /// Puts several items in folder `folder` (empty: no folder).
    pub async fn move_items(&self, scope: Scope, ids: &str, folder: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let ids = parse_ids(ids)?;
        let folder = if folder.is_empty() { None } else { Some(parse_id(folder)?) };
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        st.edits += 1;
        let session = st.session.as_mut().ok_or_else(locked)?;
        session.move_many(&mut st.store, &server, &refresh, &ids, folder).await?;
        st.last_used = Instant::now();
        Ok(())
    }

    pub async fn create_folder(&self, scope: Scope, name: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        let session = st.session.as_mut().ok_or_else(locked)?;
        let id = session.create_folder(&mut st.store, &server, &refresh, &Secret::new(name)).await?;
        st.last_used = Instant::now();
        Ok(id.to_string())
    }

    pub async fn rename_folder(&self, scope: Scope, id: &str, name: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        let session = st.session.as_mut().ok_or_else(locked)?;
        session.rename_folder(&mut st.store, &server, &refresh, id, &Secret::new(name)).await?;
        st.last_used = Instant::now();
        Ok(())
    }

    /// Deletes a folder; its items stay, in no folder.
    pub async fn delete_folder(&self, scope: Scope, id: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        st.edits += 1;
        let session = st.session.as_mut().ok_or_else(locked)?;
        session.delete_folder(&mut st.store, &server, &refresh, id).await?;
        st.last_used = Instant::now();
        Ok(())
    }

    /// An item's old passwords as JSON `[{index, date}]`, newest first; reveal one with
    /// the field `history:N`.
    pub async fn history(&self, scope: Scope, id: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let st = self.state.lock().await;
        let session = st.session.as_ref().ok_or_else(locked)?;
        let dates = nyx_passwords_core::vault::history(&session.snapshot, id)?;
        let list: Vec<_> = dates.iter().enumerate().map(|(i, d)| json!({"index": i, "date": d})).collect();
        Ok(serde_json::Value::Array(list).to_string())
    }

    /// Writes an export (`json`, `csv`, `password_json`, `account_json`) into `file`,
    /// which the app opened where the user chose. Needs the master password confirmed
    /// just before, as for items that ask for it.
    pub async fn export(&self, scope: Scope, format: &str, password: &str, file: std::fs::File) -> Result<()> {
        use nyx_passwords_core::transfer;
        need(scope, Scope::App)?;
        let format = transfer::ExportFormat::parse(format).ok_or_else(|| Failure::new(Code::Failed, "unknown format"))?;
        let made = {
            let mut st = self.state.lock().await;
            if !st.confirmed.is_some_and(|t| t.elapsed() < REPROMPT_GRACE) {
                return Err(Failure::new(Code::Reprompt, "confirm the master password first"));
            }
            st.last_used = Instant::now();
            let session = st.session.as_ref().ok_or_else(locked)?;
            let password = Secret::new(password);
            transfer::export(&session.keys, &session.snapshot, format, Some(&password)).map_err(transfer_failure)?
        };
        tokio::task::spawn_blocking(move || {
            use std::io::Write;
            let mut file = file;
            file.write_all(made.expose().as_bytes())?;
            file.sync_all()
        })
        .await
        .map_err(|_| Failure::new(Code::Failed, "the file couldn't be written"))?
        .map_err(|e| Failure::new(Code::Failed, format!("the file couldn't be written: {e}")))
    }

    /// What importing `file` would add: `{format, items, folders, counts}`.
    /// `NeedsPassword` for an export protected by a password not given.
    pub async fn import_preview(&self, scope: Scope, password: &str, file: std::fs::File) -> Result<String> {
        need(scope, Scope::App)?;
        let data = read_import(file).await?;
        let st = self.state.lock().await;
        let session = st.session.as_ref().ok_or_else(locked)?;
        let parsed = parse_import(&data, password, session)?;
        Ok(json!({"format": parsed.format, "items": parsed.items.len(), "folders": parsed.folders.len(), "counts": parsed.counts()})
            .to_string())
    }

    /// Imports `file` as personal items; returns how many.
    pub async fn import(&self, scope: Scope, password: &str, file: std::fs::File) -> Result<u32> {
        need(scope, Scope::App)?;
        let data = read_import(file).await?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st)?;
        st.edits += 1;
        let session = st.session.as_mut().ok_or_else(locked)?;
        let parsed = parse_import(&data, password, session)?;
        session.import(&mut st.store, &server, &refresh, &parsed).await?;
        st.revision += 1;
        st.last_used = Instant::now();
        Ok(parsed.items.len() as u32)
    }

    /// A private key with a passphrase, opened for the editor: `{private, public,
    /// fingerprint}`, the private key without the passphrase (as items keep it).
    pub fn open_ssh_key(&self, scope: Scope, private: &str, passphrase: &str) -> Result<String> {
        need(scope, Scope::App)?;
        if private.len() > SSH_KEY_MAX {
            return Err(Failure::new(Code::Failed, "that file is too large to be a private key"));
        }
        let key = nyx_passwords_core::ssh::read_with_passphrase(private, &Secret::new(passphrase))
            .map_err(|e| Failure::new(Code::Failed, e.to_string()))?;
        Ok(json!({"private": key.private.expose(), "public": key.public, "fingerprint": key.fingerprint}).to_string())
    }
}

fn transfer_failure(e: nyx_passwords_core::transfer::TransferError) -> Failure {
    use nyx_passwords_core::transfer::TransferError;
    let code = match e {
        TransferError::NeedsPassword => Code::NeedsPassword,
        _ => Code::Failed,
    };
    Failure::new(code, e.to_string())
}

async fn read_import(file: std::fs::File) -> Result<Vec<u8>> {
    use nyx_passwords_core::transfer::IMPORT_MAX;
    let data = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut data = Vec::new();
        file.take(IMPORT_MAX as u64 + 1).read_to_end(&mut data).map(|_| data)
    })
    .await
    .map_err(|_| Failure::new(Code::Failed, "the file couldn't be read"))?
    .map_err(|e| Failure::new(Code::Failed, format!("the file couldn't be read: {e}")))?;
    if data.len() > IMPORT_MAX {
        return Err(Failure::new(Code::Failed, "the file is too large"));
    }
    Ok(data)
}

fn parse_import(data: &[u8], password: &str, session: &Session) -> Result<nyx_passwords_core::transfer::Parsed> {
    let password = (!password.is_empty()).then(|| Secret::new(password));
    let data = SecretBytes::new(data.to_vec());
    nyx_passwords_core::transfer::parse(data.expose(), password.as_ref(), &session.keys).map_err(transfer_failure)
}

/// A field by its interface name: `username`, `password`, `totp`, `totp_seed`, `notes`,
/// `custom:N`, or a card, identity or SSH key field (`card.number`, …).
fn any_field(name: &str) -> Result<Field> {
    let field = match name {
        field::USERNAME => Field::Username,
        field::PASSWORD => Field::Password,
        field::TOTP => Field::Totp,
        "totp_seed" => Field::TotpSeed,
        "notes" => Field::Notes,
        other => match other.strip_prefix("custom:").and_then(|n| n.parse().ok()) {
            Some(n) => Field::Custom(n),
            None => match other.strip_prefix("history:").and_then(|n| n.parse().ok()) {
                Some(n) => Field::History(n),
                None => {
                    nyx_passwords_core::vault::sub_field(other).ok_or_else(|| Failure::new(Code::NoField, "unknown field"))?
                }
            },
        },
    };
    Ok(field)
}

pub(super) fn need(scope: Scope, wanted: Scope) -> Result<()> {
    if scope == wanted { Ok(()) } else { Err(denied()) }
}

fn need_any(scope: Scope, wanted: &[Scope]) -> Result<()> {
    if wanted.contains(&scope) { Ok(()) } else { Err(denied()) }
}

/// After signing in by any route: the token kept in the keyring, the session open.
async fn signed_in(st: &mut State, server: Server, session: Session) {
    if let Some(old) = st.session.take() {
        old.lock();
    }
    st.refresh = session.refresh_token().map(|r| Secret::new(r.expose()));
    if let Some(refresh) = &st.refresh {
        let entry = keyring::Entry { server: session.account.server.clone(), email: session.account.email.clone() };
        let token = Secret::new(refresh.expose());
        // Without a keyring the session lasts until the daemon stops.
        let _ = tokio::task::spawn_blocking(move || entry.save(&token)).await;
    }
    st.server = Some(server);
    st.session = Some(session);
    st.last_used = Instant::now();
    st.recent.clear();
    super::browser::load(st);
}

/// After an unlock: the server, the saved session token, browser pairings.
async fn opened(st: &mut State, session: Session) {
    let extra_ca = st.settings.refresh().extra_ca.clone();
    st.server = make_server(&session.account.server, extra_ca.as_deref()).ok();
    if st.refresh.is_none() {
        let entry = keyring::Entry { server: session.account.server.clone(), email: session.account.email.clone() };
        st.refresh = tokio::task::spawn_blocking(move || entry.load()).await.ok().and_then(|r| r.ok().flatten());
    }
    st.session = Some(session);
    st.last_used = Instant::now();
    super::browser::load(st);
}

/// The keyring entry for the signed-in account, from the local copy (so it works while
/// locked).
fn unlock_entry(st: &State) -> Option<keyring::Entry> {
    let account = st.store.account().ok().flatten()?;
    Some(keyring::Entry { server: account.server, email: account.email })
}

/// Searching and copying: the app always; Glimpse and the Assistant when their
/// integration is turned on.
fn allow_finder(scope: Scope, st: &mut State) -> Result<()> {
    match scope {
        Scope::Assistant if st.settings.refresh().assistant => Ok(()),
        Scope::Assistant => Err(Failure::new(Code::Denied, "turn on Nyx Assistant in Passwords' settings first")),
        _ => allow_glimpse(scope, st),
    }
}

/// Glimpse calls are refused when the Glimpse integration is turned off.
fn allow_glimpse(scope: Scope, st: &mut State) -> Result<()> {
    match scope {
        Scope::App => Ok(()),
        Scope::Glimpse if st.settings.refresh().glimpse => Ok(()),
        _ => Err(denied()),
    }
}

/// Items marked to ask for the master password again: everything but the username
/// needs a recent confirmation from the app, and Glimpse can't get it at all.
fn reprompt_check(st: &State, scope: Scope, id: Uuid, field: Field) -> Result<()> {
    let asks = st.session.as_ref().and_then(|s| s.view.get(id)).is_some_and(|e| e.reprompt);
    if !asks || field == Field::Username {
        return Ok(());
    }
    match scope {
        Scope::App if st.confirmed.is_some_and(|t| t.elapsed() < REPROMPT_GRACE) => Ok(()),
        Scope::App => Err(Failure::new(Code::Reprompt, "this item asks for the master password")),
        _ => Err(Failure::new(Code::Reprompt, "this item asks for the master password: open it in Passwords")),
    }
}

/// Whether one more event fits in `per_minute`, recording it if so.
pub(super) fn within(times: &mut VecDeque<Instant>, per_minute: usize) -> bool {
    let now = Instant::now();
    while times.front().is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60)) {
        times.pop_front();
    }
    if times.len() >= per_minute {
        return false;
    }
    times.push_back(now);
    true
}

pub(super) fn online(st: &State) -> Result<(Server, Secret)> {
    let server = st.server.clone().ok_or_else(|| Failure::new(Code::Failed, "no server"))?;
    let refresh = st.refresh.as_ref().map(|r| Secret::new(r.expose()));
    // An access token from this session works without a refresh token.
    let refresh = match refresh {
        Some(r) => r,
        None if st.session.as_ref().is_some_and(|s| s.tokens.as_ref().is_some_and(|t| !t.stale())) => Secret::new(""),
        None => return Err(Failure::new(Code::Failed, "sign in again to make changes")),
    };
    Ok((server, refresh))
}

fn make_server(url: &str, extra_ca: Option<&std::path::Path>) -> Result<Server> {
    let roots = match extra_ca {
        Some(path) => {
            vec![std::fs::read(path).map_err(|_| Failure::new(Code::Failed, "couldn't read the extra certificate file"))?]
        }
        None => Vec::new(),
    };
    Server::new(url, &roots).map_err(|e| Failure::new(Code::Failed, e.to_string()))
}

pub(super) fn generated(settings: &Settings, rules: Option<&str>) -> Result<Secret> {
    #[derive(Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum Rules {
        Password(generate::PasswordRules),
        Passphrase(generate::PassphraseRules),
    }
    let rules = match rules {
        Some(text) => serde_json::from_str(text).map_err(|_| Failure::new(Code::Failed, "bad generator settings"))?,
        None if settings.generate_passphrase => Rules::Passphrase(settings.passphrase_rules.clone()),
        None => Rules::Password(settings.password_rules.clone()),
    };
    let made = match rules {
        Rules::Password(r) => generate::password(&r),
        Rules::Passphrase(r) => generate::passphrase(&r),
    };
    made.map_err(|e| Failure::new(Code::Failed, e.to_string()))
}

pub(super) fn parse_id(id: &str) -> Result<Uuid> {
    Uuid::parse_str(id).map_err(|_| Failure::new(Code::NotFound, "no such item"))
}

fn too_large(text: &str) -> Result<()> {
    if text.len() > DRAFT_MAX { Err(Failure::new(Code::Failed, "the item is too large")) } else { Ok(()) }
}

fn parse_draft(text: &str) -> Result<LoginDraft> {
    too_large(text)?;
    #[derive(Deserialize)]
    struct Draft {
        name: String,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        totp: Option<String>,
        #[serde(default)]
        uris: Vec<String>,
        #[serde(default)]
        notes: Option<String>,
        #[serde(default)]
        folder: Option<Uuid>,
        #[serde(default)]
        favorite: bool,
        #[serde(default)]
        reprompt: bool,
        #[serde(default)]
        organization: Option<Uuid>,
        #[serde(default)]
        collections: Vec<Uuid>,
        #[serde(default)]
        custom: Option<Vec<CustomJson>>,
    }
    let d: Draft = serde_json::from_str(text).map_err(|_| Failure::new(Code::Failed, "the item couldn't be read"))?;
    if d.name.trim().is_empty() {
        return Err(Failure::new(Code::Failed, "the item needs a name"));
    }
    let opt = |v: Option<String>| v.filter(|s| !s.is_empty()).map(Secret::new);
    Ok(LoginDraft {
        name: Secret::new(d.name),
        username: opt(d.username),
        password: opt(d.password),
        totp: opt(d.totp),
        uris: d.uris.into_iter().map(Secret::new).collect(),
        notes: opt(d.notes),
        folder: d.folder,
        favorite: d.favorite,
        reprompt: d.reprompt,
        place: Place { organization: d.organization, collections: d.collections },
        custom: custom_fields(d.custom)?,
    })
}

/// A custom field in a draft: `{name, value, kind, from}` (see `CustomDraft`).
#[derive(Deserialize)]
struct CustomJson {
    name: String,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    kind: i64,
    #[serde(default)]
    from: Option<usize>,
}

/// The most custom fields an item may have here.
const CUSTOM_MAX: usize = 200;

fn custom_fields(list: Option<Vec<CustomJson>>) -> Result<Option<Vec<CustomDraft>>> {
    let Some(list) = list else { return Ok(None) };
    if list.len() > CUSTOM_MAX {
        return Err(Failure::new(Code::Failed, "too many custom fields"));
    }
    if list.iter().any(|f| !(0..=2).contains(&f.kind)) {
        return Err(Failure::new(Code::Failed, "a custom field has an unknown type"));
    }
    Ok(Some(
        list.into_iter()
            .map(|f| CustomDraft { name: Secret::new(f.name), value: f.value.map(Secret::new), kind: f.kind, from: f.from })
            .collect(),
    ))
}

/// A list of item ids, as JSON (`["…", …]`), for the actions on several items.
fn parse_ids(text: &str) -> Result<Vec<Uuid>> {
    too_large(text)?;
    let ids: Vec<Uuid> = serde_json::from_str(text).map_err(|_| Failure::new(Code::NotFound, "no such item"))?;
    if ids.is_empty() {
        return Err(Failure::new(Code::Failed, "no items chosen"));
    }
    Ok(ids)
}

/// A note, card, identity or SSH key draft: `{kind, name, fields: {"card.number": …},
/// notes, folder, favorite, reprompt}`. Field names must belong to the kind.
fn parse_item_draft(text: &str) -> Result<ItemDraft> {
    too_large(text)?;
    #[derive(Deserialize)]
    struct Draft {
        kind: String,
        name: String,
        #[serde(default)]
        fields: std::collections::BTreeMap<String, String>,
        #[serde(default)]
        notes: Option<String>,
        #[serde(default)]
        folder: Option<Uuid>,
        #[serde(default)]
        favorite: bool,
        #[serde(default)]
        reprompt: bool,
        #[serde(default)]
        organization: Option<Uuid>,
        #[serde(default)]
        collections: Vec<Uuid>,
        #[serde(default)]
        custom: Option<Vec<CustomJson>>,
    }
    let unreadable = || Failure::new(Code::Failed, "the item couldn't be read");
    let d: Draft = serde_json::from_str(text).map_err(|_| unreadable())?;
    let kind = match d.kind.as_str() {
        "note" => Kind::Note,
        "card" => Kind::Card,
        "identity" => Kind::Identity,
        "ssh" => Kind::SshKey,
        _ => return Err(Failure::new(Code::Failed, "this kind of item can't be edited here")),
    };
    if d.name.trim().is_empty() {
        return Err(Failure::new(Code::Failed, "the item needs a name"));
    }
    if d.fields.keys().any(|name| !specs(kind).iter().any(|s| s.name == name)) {
        return Err(Failure::new(Code::NoField, "unknown field"));
    }
    Ok(ItemDraft {
        kind,
        name: Secret::new(d.name),
        fields: d.fields.into_iter().map(|(n, v)| (n, Secret::new(v))).collect(),
        notes: d.notes.filter(|s| !s.is_empty()).map(Secret::new),
        folder: d.folder,
        favorite: d.favorite,
        reprompt: d.reprompt,
        place: Place { organization: d.organization, collections: d.collections },
        custom: custom_fields(d.custom)?,
    })
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Login => "login",
        Kind::Note => "note",
        Kind::Card => "card",
        Kind::Identity => "identity",
        Kind::SshKey => "ssh",
        Kind::Other(_) => "other",
    }
}

fn item(e: &Entry) -> Item {
    (
        e.id.to_string(),
        e.name.expose().to_string(),
        e.username.as_ref().map(|u| u.expose().to_string()).unwrap_or_default(),
        e.host.clone().unwrap_or_default(),
        e.has_totp,
        kind_name(e.kind).to_string(),
    )
}

fn entry_json(e: &Entry) -> serde_json::Value {
    json!({
        "id": e.id, "kind": kind_name(e.kind), "name": e.name.expose(),
        "username": e.username.as_ref().map(|u| u.expose()),
        "uris": e.uris.iter().map(|u| u.expose()).collect::<Vec<_>>(),
        "host": e.host, "folder": e.folder, "organization": e.organization, "collections": e.collections,
        "favorite": e.favorite, "has_password": e.has_password, "has_totp": e.has_totp,
        "reprompt": e.reprompt, "deleted": e.deleted, "readable": e.readable, "revision": e.revision,
        "editable": e.editable, "view_password": e.view_password, "deletable": e.deletable, "restorable": e.restorable,
    })
}

/// An item's address as something to open: http(s) only, without user name or password.
fn web_url(uri: &str) -> Option<String> {
    let uri = uri.trim();
    let mut url =
        url::Url::parse(uri).ok().filter(|u| u.has_host()).or_else(|| url::Url::parse(&format!("https://{uri}")).ok())?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let _ = url.set_username("");
    let _ = url.set_password(None);
    Some(url.to_string())
}

fn url_host(url: &str) -> Option<String> {
    url::Url::parse(url).ok()?.host_str().map(str::to_string)
}

fn device_name() -> String {
    let host = std::fs::read_to_string("/etc/hostname").map(|h| h.trim().to_string()).unwrap_or_default();
    if host.is_empty() { "Nyx Passwords".into() } else { format!("Nyx Passwords on {host}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_urls() {
        assert_eq!(web_url("github.com").as_deref(), Some("https://github.com/"));
        assert_eq!(web_url("https://u:p@example.com/x").as_deref(), Some("https://example.com/x"));
        assert_eq!(web_url("androidapp://com.example"), None);
        assert_eq!(web_url("javascript:alert(1)"), None);
    }

    #[test]
    fn rate_limit_window() {
        let mut times = VecDeque::new();
        for _ in 0..3 {
            assert!(within(&mut times, 3));
        }
        assert!(!within(&mut times, 3));
    }

    #[test]
    fn drafts() {
        let d = parse_draft(r#"{"name":"GitHub","password":"pw","uris":["github.com"],"username":""}"#).unwrap();
        assert_eq!(d.name.expose(), "GitHub");
        assert!(d.username.is_none() && d.password.is_some());
        assert!(parse_draft(r#"{"name":"  "}"#).is_err());
        assert!(parse_draft("not json").is_err());
        let d = parse_item_draft(r#"{"kind":"card","name":"Visa","fields":{"card.number":"4111"},"notes":""}"#).unwrap();
        assert_eq!((d.kind, d.fields.len(), d.notes.is_none()), (Kind::Card, 1, true));
        assert!(parse_item_draft(r#"{"kind":"card","name":"Visa","fields":{"identity.ssn":"1"}}"#).is_err());
        assert!(parse_item_draft(r#"{"kind":"login","name":"GitHub"}"#).is_err());
        assert!(parse_item_draft(r#"{"kind":"ssh","name":"Key","fields":{"ssh.privateKey":"…"}}"#).is_ok());
        assert!(parse_item_draft(r#"{"kind":"other","name":"Key"}"#).is_err());
    }

    #[test]
    fn generator_rules() {
        let s = Settings::default();
        assert_eq!(generated(&s, None).unwrap().expose().chars().count(), 20);
        let p = generated(&s, Some(r#"{"kind":"passphrase","words":4,"separator":" "}"#)).unwrap();
        assert_eq!(p.expose().split(' ').count(), 4);
        assert!(generated(&s, Some(r#"{"kind":"password","length":2}"#)).is_err());
    }
}
