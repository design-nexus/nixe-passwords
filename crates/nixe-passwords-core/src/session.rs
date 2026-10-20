//! Signing in, unlocking and syncing: the server, the keys and the local store together.
//!
//! The master password goes to the server (as its hash) only when signing in. Unlocking
//! afterwards is local: the stored KDF and protected user key, as last synced. A sync
//! then needs only the refresh token.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use crate::api::{self, ApiError, Device, Login, Server, Tokens, TwoFactor, TwoFactorAnswer};
use crate::crypto::{CryptoError, Kdf, Keys, MasterKey};
use crate::model::Sync;
use crate::secret::Secret;
use crate::ssh::SshError;
use crate::store::{Account, Store, StoreError};
use crate::vault::View;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    Api(ApiError),
    Crypto(CryptoError),
    Store(StoreError),
    /// The server reports weaker key derivation than this device knows for the account.
    /// Signing out and in again accepts the change.
    KdfDowngrade,
    /// No account on this device yet.
    SignedOut,
    /// The account's keys changed elsewhere (a new master password or key rotation):
    /// unlock again.
    KeysChanged,
    /// An SSH key item's private key can't be used.
    BadSshKey(SshError),
    /// This account may not do that (a read-only collection, moving an item out of its
    /// organization, …); the text says what.
    NotAllowed(&'static str),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Api(e) => e.fmt(f),
            Self::Crypto(e) => e.fmt(f),
            Self::Store(e) => e.fmt(f),
            Self::KdfDowngrade => {
                f.write_str("the server now asks for weaker key derivation than before; sign out and in again to accept it")
            }
            Self::SignedOut => f.write_str("not signed in"),
            Self::KeysChanged => f.write_str("the account's keys changed; unlock again"),
            Self::BadSshKey(e) => e.fmt(f),
            Self::NotAllowed(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<ApiError> for SessionError {
    fn from(e: ApiError) -> Self {
        match e {
            ApiError::Crypto(c) => Self::Crypto(c),
            e => Self::Api(e),
        }
    }
}

impl From<CryptoError> for SessionError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<StoreError> for SessionError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

pub type Result<T> = std::result::Result<T, SessionError>;

/// An unlocked vault: its keys, the encrypted snapshot they open, and server tokens when
/// online.
pub struct Session {
    pub account: Account,
    pub keys: Keys,
    pub snapshot: Sync,
    /// The decrypted listing; rebuilt on every sync.
    pub view: View,
    pub tokens: Option<Tokens>,
}

pub enum SignIn {
    Done(Box<Session>),
    /// Retry `sign_in` with one of these answered.
    TwoFactor(Vec<TwoFactor>),
}

/// Signs in to `server`, syncs, stores the snapshot and unlocks. Signing in to a
/// different server or account replaces what this device held.
pub async fn sign_in(
    store: &mut Store,
    server: &Server,
    email: &str,
    password: &Secret,
    device_name: &str,
    answer: Option<&TwoFactorAnswer>,
) -> Result<SignIn> {
    let email = email.trim().to_string();
    let kdf = server.prelogin(&email).await?;
    let previous = store.account()?.filter(|a| a.server == server.url() && a.email.eq_ignore_ascii_case(&email));
    if let Some(prev) = &previous
        && !kdf.at_least(&prev.kdf)
    {
        return Err(SessionError::KdfDowngrade);
    }
    let device = Device { id: previous.as_ref().map_or_else(Uuid::new_v4, |a| a.device_id), name: device_name.to_string() };

    let master = derive(password, &email, kdf).await?;
    let hash = master.server_hash(password);
    let tokens = match server.login(&email, &hash, &device, answer).await? {
        Login::Done(tokens) => tokens,
        Login::TwoFactor(methods) => return Ok(SignIn::TwoFactor(methods)),
    };
    let sync = server.sync(&tokens.access).await?;
    let kdf = checked_kdf(&sync, kdf)?;
    let keys = open(&master, &sync)?;

    if previous.is_none() {
        store.clear()?;
    }
    let account = Account {
        server: server.url().to_string(),
        email,
        kdf,
        device_id: device.id,
        user_id: Some(sync.profile.id),
        last_sync: None,
    };
    store.set_account(&account)?;
    store.replace_snapshot(&sync, kdf, now())?;
    let account = store.account()?.ok_or(SessionError::SignedOut)?;
    let view = View::build(&keys, &sync);
    Ok(SignIn::Done(Box::new(Session { account, keys, snapshot: sync, view, tokens: Some(tokens) })))
}

/// Asks the server to mail a two-step login code (for `TwoFactor::Email`).
pub async fn send_email_code(server: &Server, email: &str, password: &Secret) -> Result<()> {
    let kdf = server.prelogin(email.trim()).await?;
    let master = derive(password, email.trim(), kdf).await?;
    Ok(server.send_email_code(email.trim(), &master.server_hash(password)).await?)
}

/// Unlocks from the local copy, without the network.
pub async fn unlock(store: &mut Store, password: &Secret) -> Result<Session> {
    let account = store.account()?.ok_or(SessionError::SignedOut)?;
    let snapshot = store.snapshot()?.ok_or(SessionError::SignedOut)?;
    let master = derive(password, &account.email, account.kdf).await?;
    let keys = open(&master, &snapshot)?;
    let view = View::build(&keys, &snapshot);
    Ok(Session { account, keys, snapshot, view, tokens: None })
}

/// Unlocks from the local copy with a user key saved by `Keys::export_user_key`. A key
/// that no longer opens the account's private key is stale (the master password changed
/// or the keys were rotated elsewhere): `KeysChanged`.
pub fn unlock_with_key(store: &mut Store, user_key: &Secret) -> Result<Session> {
    let account = store.account()?.ok_or(SessionError::SignedOut)?;
    let snapshot = store.snapshot()?.ok_or(SessionError::SignedOut)?;
    let keys = Keys::from_user_key(user_key).map_err(|_| SessionError::KeysChanged)?;
    match snapshot.profile.private_key.as_deref() {
        Some(private) => keys.add_private_key(private).map_err(|_| SessionError::KeysChanged)?,
        // Nothing to check the key against: refuse rather than open a vault it may not fit.
        None => return Err(SessionError::KeysChanged),
    }
    add_organizations(&keys, &snapshot);
    let view = View::build(&keys, &snapshot);
    Ok(Session { account, keys, snapshot, view, tokens: None })
}

impl Session {
    /// Fetches the vault and replaces the local copy. Gets a fresh access token from
    /// `refresh` first when there is none or it's about to run out.
    pub async fn sync(&mut self, store: &mut Store, server: &Server, refresh: &Secret) -> Result<()> {
        self.ensure_token(server, refresh).await?;
        let access = &self.tokens.as_ref().expect("token ensured").access;
        let sync = server.sync(access).await?;
        self.apply(store, sync)
    }

    /// Takes a sync response fetched elsewhere (so a caller can fetch without holding the
    /// session) and replaces the local copy with it.
    pub fn apply(&mut self, store: &mut Store, sync: Sync) -> Result<()> {
        let kdf = checked_kdf(&sync, self.account.kdf)?;
        if sync.profile.id != self.snapshot.profile.id {
            return Err(SessionError::KeysChanged);
        }
        // The private key is wrapped by the user key: if it no longer opens, the user key
        // was rotated elsewhere and these keys are stale.
        if let Some(private) = sync.profile.private_key.as_deref() {
            self.keys.add_private_key(private).map_err(|_| SessionError::KeysChanged)?;
        }
        add_organizations(&self.keys, &sync);
        store.replace_snapshot(&sync, kdf, now())?;
        self.account = store.account()?.ok_or(SessionError::SignedOut)?;
        self.view = View::build(&self.keys, &sync);
        self.snapshot = sync;
        Ok(())
    }

    /// A usable access token, refreshing it with `refresh` when needed.
    pub async fn access(&mut self, server: &Server, refresh: &Secret) -> Result<&Secret> {
        self.ensure_token(server, refresh).await?;
        Ok(&self.tokens.as_ref().expect("token ensured").access)
    }

    async fn ensure_token(&mut self, server: &Server, refresh: &Secret) -> Result<()> {
        if self.tokens.as_ref().is_none_or(Tokens::stale) {
            self.tokens = Some(server.refresh(refresh).await?);
        }
        Ok(())
    }

    /// Checks the master password against this account's keys, without the network
    /// (for items that ask for it again before showing secrets).
    pub async fn verify(&self, password: &Secret) -> Result<bool> {
        let master = derive(password, &self.account.email, self.account.kdf).await?;
        Ok(Keys::unlock(&master, &self.snapshot.profile.key).is_ok())
    }

    /// The refresh token to keep for next time, if the server issued one.
    pub fn refresh_token(&self) -> Option<&Secret> {
        self.tokens.as_ref().map(|t| &t.refresh).filter(|r| !r.is_empty())
    }

    /// Locks: the keys are cleared and the decrypted view is dropped (and zeroized).
    pub fn lock(self) {
        self.keys.lock();
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Runs the KDF on the blocking pool: it takes about a second by design.
async fn derive(password: &Secret, email: &str, kdf: Kdf) -> Result<MasterKey> {
    let password = Secret::new(password.expose());
    let email = email.to_string();
    tokio::task::spawn_blocking(move || MasterKey::derive(&password, &email, &kdf))
        .await
        .map_err(|_| SessionError::Crypto(CryptoError::KdfParameters))?
        .map_err(SessionError::from)
}

/// The KDF to keep after a sync: the one it reports, unless that's weaker than `known`.
fn checked_kdf(sync: &Sync, known: Kdf) -> Result<Kdf> {
    match api::sync_kdf(sync).transpose()? {
        Some(kdf) if !kdf.at_least(&known) => Err(SessionError::KdfDowngrade),
        Some(kdf) => Ok(kdf),
        None => Ok(known),
    }
}

/// Opens the snapshot's keys with the master key.
fn open(master: &MasterKey, sync: &Sync) -> Result<Keys> {
    let keys = Keys::unlock(master, &sync.profile.key)?;
    if let Some(private) = sync.profile.private_key.as_deref() {
        keys.add_private_key(private)?;
    }
    add_organizations(&keys, sync);
    Ok(keys)
}

/// Loads the keys of enabled organizations. One that won't open is skipped: its items
/// show as unreadable rather than locking the whole vault.
fn add_organizations(keys: &Keys, sync: &Sync) {
    for org in sync.profile.organizations.iter().filter(|o| o.enabled) {
        if let Some(wrapped) = org.key.as_deref()
            && !keys.has_organization(org.id)
        {
            let _ = keys.add_organization(org.id, wrapped);
        }
    }
}
