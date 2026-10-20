//! The daemon's vault: the store, the unlocked session, the server, and every operation
//! the interface offers. Scopes are checked here, not only at the D-Bus layer, so an
//! operation can't be reached with the wrong one.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use nixe_passwords_core::api::{ApiError, Server, TwoFactor, TwoFactorAnswer};
use nixe_passwords_core::crypto::CryptoError;
use nixe_passwords_core::edit::{ItemDraft, LoginDraft};
use nixe_passwords_core::generate;
use nixe_passwords_core::keyring;
use nixe_passwords_core::model::Kind;
use nixe_passwords_core::secret::Secret;
use nixe_passwords_core::session::{self, Session, SessionError, SignIn};
use nixe_passwords_core::store::Store;
use nixe_passwords_core::vault::{Entry, Field, RevealError, reveal, specs};
use nixe_passwords_proto::{Error as Code, Item, field, state};
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
/// Copies Glimpse may ask for in a minute; reveals the app may ask for.
const GLIMPSE_COPIES_PER_MINUTE: usize = 10;
const APP_REVEALS_PER_MINUTE: usize = 60;
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
    pub(super) app_reveals: VecDeque<Instant>,
    /// When the app last confirmed the master password (for re-prompting items).
    pub(super) confirmed: Option<Instant>,
    /// Counts edits, so a sync fetched before one isn't applied over it.
    pub(super) edits: u64,
    /// Browser pairings and the active site (`browser.rs`).
    pub(super) browser: super::browser::Browser,
}

pub struct Vault {
    pub(super) state: Mutex<State>,
    clipboard: Arc<StdMutex<Clipboard>>,
    pub(super) notifier: Notifier,
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
                app_reveals: VecDeque::new(),
                confirmed: None,
                edits: 0,
                browser: Default::default(),
            }),
            clipboard: Arc::new(StdMutex::new(Clipboard::default())),
            notifier,
        }
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
        allow_glimpse(scope, &mut st)?;
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
            // The window may copy any field; Glimpse only those three.
            (other, Scope::App) => any_field(other)?,
            _ => return Err(Failure::new(Code::NoField, "unknown field")),
        };
        let id = parse_id(id)?;
        let (value, settings, label) = {
            let mut st = self.state.lock().await;
            allow_glimpse(scope, &mut st)?;
            if scope == Scope::Glimpse && !within(&mut st.glimpse_copies, GLIMPSE_COPIES_PER_MINUTE) {
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
        self.put_on_clipboard(value, &settings, "Generated password").await
    }

    async fn put_on_clipboard(self: &Arc<Self>, value: Secret, settings: &Settings, label: &str) -> Result<u32> {
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
            st.browser.lock();
            st.session.take()
        };
        if let Some(s) = session {
            s.lock();
            let clipboard = self.clipboard.clone();
            let _ = tokio::task::spawn_blocking(move || clipboard.lock().expect("clipboard").clear_now()).await;
        }
    }

    pub async fn is_unlocked(&self) -> bool {
        self.state.lock().await.session.is_some()
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
        Ok(SignInResult::Done)
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
            let extra_ca = st.settings.refresh().extra_ca.clone();
            st.server = make_server(&session.account.server, extra_ca.as_deref()).ok();
            if st.refresh.is_none() {
                let entry = keyring::Entry { server: session.account.server.clone(), email: session.account.email.clone() };
                st.refresh = tokio::task::spawn_blocking(move || entry.load()).await.ok().and_then(|r| r.ok().flatten());
            }
            st.session = Some(session);
            st.last_used = Instant::now();
            super::browser::load(&mut st);
        }
        let me = self.clone();
        tokio::spawn(async move {
            let _ = me.sync(Scope::App).await;
        });
        Ok(())
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
            session.apply(&mut st.store, sync)?;
            return Ok(());
        }
        Err(Failure::new(Code::Failed, "the vault kept changing during sync; try again"))
    }

    /// Signs out: forgets the session, the local copy and the saved token.
    pub async fn sign_out(&self, scope: Scope) -> Result<()> {
        need(scope, Scope::App)?;
        self.lock().await;
        let mut st = self.state.lock().await;
        if let Some(account) = st.store.account().ok().flatten() {
            let entry = keyring::Entry { server: account.server, email: account.email };
            let _ = tokio::task::spawn_blocking(move || entry.clear()).await;
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
        let collections: Vec<_> =
            v.collections.iter().map(|c| json!({"id": c.id, "organization": c.organization, "name": c.name.expose()})).collect();
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

    /// An item's other fields as JSON: `[{name, label, value, secret}]`, secret values
    /// left out (`Reveal` them one at a time).
    pub async fn fields(&self, scope: Scope, id: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let st = self.state.lock().await;
        let session = st.session.as_ref().ok_or_else(locked)?;
        let shown = nixe_passwords_core::vault::fields(&session.keys, &session.snapshot, id)?;
        let list: Vec<_> = shown
            .iter()
            .map(|f| json!({"name": f.name, "label": f.label, "value": f.value.as_ref().map(|v| v.expose()), "secret": f.secret}))
            .collect();
        Ok(serde_json::Value::Array(list).to_string())
    }

    /// A new Ed25519 key for the editor: `{private, public, fingerprint}`.
    pub fn generate_ssh_key(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let key = nixe_passwords_core::ssh::generate();
        Ok(json!({"private": key.private.expose(), "public": key.public, "fingerprint": key.fingerprint}).to_string())
    }

    /// The public key and fingerprint of a private key the editor imported:
    /// `{public, fingerprint}`.
    pub fn read_ssh_key(&self, scope: Scope, private: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let key = nixe_passwords_core::ssh::read(private).map_err(|e| Failure::new(Code::Failed, e.to_string()))?;
        Ok(json!({"public": key.public, "fingerprint": key.fingerprint}).to_string())
    }

    pub async fn generate_password(&self, scope: Scope, rules: &str) -> Result<Secret> {
        need(scope, Scope::App)?;
        let settings = self.settings().await;
        generated(&settings, Some(rules))
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
            None => nixe_passwords_core::vault::sub_field(other).ok_or_else(|| Failure::new(Code::NoField, "unknown field"))?,
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

fn parse_draft(text: &str) -> Result<LoginDraft> {
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
    })
}

/// A note, card, identity or SSH key draft: `{kind, name, fields: {"card.number": …},
/// notes, folder, favorite, reprompt}`. Field names must belong to the kind.
fn parse_item_draft(text: &str) -> Result<ItemDraft> {
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
    if host.is_empty() { "Nixe Passwords".into() } else { format!("Nixe Passwords on {host}") }
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
