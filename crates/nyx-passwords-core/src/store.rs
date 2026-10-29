//! The local copy of the vault: the server's sync response as it arrived (ciphertext),
//! plus account settings. Nothing in here is decrypted, so an offline unlock works the
//! same as an online one and the file is no more useful than the server's own copy.
//!
//! The file and its directory are private to the user (0600/0700), deleted rows are
//! overwritten (`secure_delete`), and a snapshot is replaced in one transaction so a
//! failed sync leaves the last good one in place.

use std::fmt;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::Kdf;
use crate::model::{Cipher, Folder, Sync};

const SCHEMA: i64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// The database couldn't be opened, created or given private permissions.
    Open,
    /// The database is from a newer version of the app.
    TooNew,
    Read,
    Write,
    /// A stored object no longer parses.
    Corrupt,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::Open => "couldn't open the local vault",
            Self::TooNew => "the local vault was written by a newer version",
            Self::Read => "couldn't read the local vault",
            Self::Write => "couldn't write the local vault",
            Self::Corrupt => "the local vault is damaged",
        })
    }
}

impl std::error::Error for StoreError {}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Who this device is signed in as, and where.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Account {
    pub server: String,
    pub email: String,
    pub kdf: Kdf,
    /// Random per install, sent as `deviceIdentifier`.
    pub device_id: Uuid,
    /// From the last sync.
    pub user_id: Option<Uuid>,
    /// Seconds since the epoch.
    pub last_sync: Option<u64>,
}

/// A browser extension paired with this device (docs/NATIVE_MESSAGING.md). The key is
/// encrypted with the user key, so it's usable only while the vault is unlocked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pairing {
    pub id: String,
    /// The extension's id as the browser reports it.
    pub extension: String,
    /// "Firefox", "Zen", "Chromium", …
    pub browser: String,
    /// The pairing key, an EncString under the user key.
    pub key: String,
    /// Seconds since the epoch.
    pub created: u64,
}

pub struct Store {
    db: Connection,
    path: PathBuf,
}

impl Store {
    /// Opens or creates the vault database at `path`, creating its directory 0700.
    pub fn open(path: &Path) -> Result<Store> {
        if let Some(dir) = path.parent() {
            fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|_| StoreError::Open)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|_| StoreError::Open)?;
        }
        // Create the file 0600 before SQLite does; its journal files take the same mode.
        fs::OpenOptions::new().create(true).append(true).mode(0o600).open(path).map_err(|_| StoreError::Open)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|_| StoreError::Open)?;
        let db = Connection::open(path).map_err(|_| StoreError::Open)?;
        db.execute_batch(
            "PRAGMA secure_delete = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS account (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS object (
                 kind TEXT NOT NULL,
                 id TEXT NOT NULL,
                 json TEXT NOT NULL,
                 PRIMARY KEY (kind, id)
             );
             CREATE TABLE IF NOT EXISTS pairing (
                 id TEXT PRIMARY KEY,
                 json TEXT NOT NULL
             );",
        )
        .map_err(|_| StoreError::Open)?;
        let version: Option<i64> = db
            .query_row("SELECT value FROM meta WHERE key = 'schema'", [], |r| r.get::<_, String>(0))
            .optional()
            .map_err(|_| StoreError::Open)?
            .and_then(|v| v.parse().ok());
        match version {
            Some(v) if v > SCHEMA => return Err(StoreError::TooNew),
            Some(_) => {}
            None => {
                db.execute("INSERT INTO meta (key, value) VALUES ('schema', ?1)", [SCHEMA.to_string()])
                    .map_err(|_| StoreError::Open)?;
            }
        }
        Ok(Store { db, path: path.to_path_buf() })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn account(&self) -> Result<Option<Account>> {
        let json: Option<String> = self
            .db
            .query_row("SELECT json FROM account WHERE id = 1", [], |r| r.get(0))
            .optional()
            .map_err(|_| StoreError::Read)?;
        json.map(|j| serde_json::from_str(&j).map_err(|_| StoreError::Corrupt)).transpose()
    }

    pub fn set_account(&self, account: &Account) -> Result<()> {
        let json = serde_json::to_string(account).map_err(|_| StoreError::Write)?;
        self.db
            .execute("INSERT INTO account (id, json) VALUES (1, ?1) ON CONFLICT (id) DO UPDATE SET json = ?1", [json])
            .map_err(|_| StoreError::Write)?;
        Ok(())
    }

    /// Replaces the stored snapshot with a new sync response, all or nothing, and records
    /// the sync time, user id and KDF on the account. Needs the account to be set.
    pub fn replace_snapshot(&mut self, sync: &Sync, kdf: Kdf, synced_at: u64) -> Result<()> {
        let tx = self.db.transaction().map_err(|_| StoreError::Write)?;
        tx.execute("DELETE FROM object WHERE kind != 'setting'", []).map_err(|_| StoreError::Write)?;
        {
            let mut put = tx.prepare("INSERT INTO object (kind, id, json) VALUES (?1, ?2, ?3)").map_err(|_| StoreError::Write)?;
            let mut row = |kind: &str, id: String, json: Result<String>| -> Result<()> {
                put.execute(params![kind, id, json?]).map(|_| ()).map_err(|_| StoreError::Write)
            };
            // Everything but the lists, kept so a snapshot reads back as the same Sync.
            let mut rest = sync.clone();
            rest.ciphers.clear();
            rest.folders.clear();
            rest.collections.clear();
            row("sync", String::new(), to_json(&rest))?;
            for c in &sync.ciphers {
                row("cipher", c.id.to_string(), to_json(c))?;
            }
            for f in &sync.folders {
                row("folder", f.id.to_string(), to_json(f))?;
            }
            for c in &sync.collections {
                row("collection", c.id.to_string(), to_json(c))?;
            }
        }
        let account: Option<String> =
            tx.query_row("SELECT json FROM account WHERE id = 1", [], |r| r.get(0)).optional().map_err(|_| StoreError::Write)?;
        let mut account: Account = serde_json::from_str(&account.ok_or(StoreError::Write)?).map_err(|_| StoreError::Corrupt)?;
        account.user_id = Some(sync.profile.id);
        account.last_sync = Some(synced_at);
        account.kdf = kdf;
        tx.execute("UPDATE account SET json = ?1 WHERE id = 1", [to_json(&account)?]).map_err(|_| StoreError::Write)?;
        tx.commit().map_err(|_| StoreError::Write)
    }

    /// The stored snapshot, or `None` before the first sync.
    pub fn snapshot(&self) -> Result<Option<Sync>> {
        let Some(head) = self.one("sync", "")? else {
            return Ok(None);
        };
        let mut sync: Sync = serde_json::from_str(&head).map_err(|_| StoreError::Corrupt)?;
        sync.ciphers = self.all("cipher")?;
        sync.folders = self.all("folder")?;
        sync.collections = self.all("collection")?;
        Ok(Some(sync))
    }

    /// Stores one cipher as the server returned it after a create or update.
    pub fn put_cipher(&self, cipher: &Cipher) -> Result<()> {
        let json = serde_json::to_string(cipher).map_err(|_| StoreError::Write)?;
        self.db
            .execute(
                "INSERT INTO object (kind, id, json) VALUES ('cipher', ?1, ?2)
                 ON CONFLICT (kind, id) DO UPDATE SET json = ?2",
                params![cipher.id.to_string(), json],
            )
            .map(|_| ())
            .map_err(|_| StoreError::Write)
    }

    pub fn remove_cipher(&self, id: Uuid) -> Result<()> {
        self.db
            .execute("DELETE FROM object WHERE kind = 'cipher' AND id = ?1", [id.to_string()])
            .map(|_| ())
            .map_err(|_| StoreError::Write)
    }

    /// A value kept beside the vault (`kind` names it). Callers store only ciphertext or
    /// values that say nothing about the vault.
    pub fn setting(&self, kind: &str) -> Result<Option<String>> {
        self.one("setting", kind)
    }

    pub fn set_setting(&self, kind: &str, value: &str) -> Result<()> {
        self.db
            .execute(
                "INSERT INTO object (kind, id, json) VALUES ('setting', ?1, ?2) ON CONFLICT (kind, id) DO UPDATE SET json = ?2",
                params![kind, value],
            )
            .map(|_| ())
            .map_err(|_| StoreError::Write)
    }

    /// This install's device id, kept across sign-outs as the official apps keep theirs:
    /// Vaultwarden lets only a device that signed in before ask another to approve it.
    pub fn device_id(&self) -> Result<Uuid> {
        let kept: Option<String> = self
            .db
            .query_row("SELECT value FROM meta WHERE key = 'device'", [], |r| r.get(0))
            .optional()
            .map_err(|_| StoreError::Read)?;
        if let Some(id) = kept.and_then(|v| v.parse().ok()) {
            return Ok(id);
        }
        let id = self.account()?.map_or_else(Uuid::new_v4, |a| a.device_id);
        self.db
            .execute(
                "INSERT INTO meta (key, value) VALUES ('device', ?1) ON CONFLICT (key) DO UPDATE SET value = ?1",
                [id.to_string()],
            )
            .map_err(|_| StoreError::Write)?;
        Ok(id)
    }

    /// Stores one folder as the server returned it.
    pub fn put_folder(&self, folder: &Folder) -> Result<()> {
        self.db
            .execute(
                "INSERT INTO object (kind, id, json) VALUES ('folder', ?1, ?2)
                 ON CONFLICT (kind, id) DO UPDATE SET json = ?2",
                params![folder.id.to_string(), to_json(folder)?],
            )
            .map(|_| ())
            .map_err(|_| StoreError::Write)
    }

    pub fn remove_folder(&self, id: Uuid) -> Result<()> {
        self.db
            .execute("DELETE FROM object WHERE kind = 'folder' AND id = ?1", [id.to_string()])
            .map(|_| ())
            .map_err(|_| StoreError::Write)
    }

    /// Signing out: removes the account, the snapshot and browser pairings, and
    /// compacts the file so the old pages are gone too.
    pub fn clear(&self) -> Result<()> {
        self.db
            .execute_batch(
                "DELETE FROM object; DELETE FROM account; DELETE FROM pairing;
                 PRAGMA wal_checkpoint(TRUNCATE); VACUUM;",
            )
            .map_err(|_| StoreError::Write)
    }

    pub fn put_pairing(&self, pairing: &Pairing) -> Result<()> {
        self.db
            .execute(
                "INSERT INTO pairing (id, json) VALUES (?1, ?2) ON CONFLICT (id) DO UPDATE SET json = ?2",
                params![pairing.id, to_json(pairing)?],
            )
            .map(|_| ())
            .map_err(|_| StoreError::Write)
    }

    pub fn pairings(&self) -> Result<Vec<Pairing>> {
        let mut q = self.db.prepare("SELECT json FROM pairing ORDER BY id").map_err(|_| StoreError::Read)?;
        let rows = q.query_map([], |r| r.get::<_, String>(0)).map_err(|_| StoreError::Read)?;
        rows.map(|r| serde_json::from_str(&r.map_err(|_| StoreError::Read)?).map_err(|_| StoreError::Corrupt)).collect()
    }

    pub fn remove_pairing(&self, id: &str) -> Result<()> {
        self.db.execute("DELETE FROM pairing WHERE id = ?1", [id]).map(|_| ()).map_err(|_| StoreError::Write)
    }

    fn one(&self, kind: &str, id: &str) -> Result<Option<String>> {
        self.db
            .query_row("SELECT json FROM object WHERE kind = ?1 AND id = ?2", [kind, id], |r| r.get(0))
            .optional()
            .map_err(|_| StoreError::Read)
    }

    fn all<T: serde::de::DeserializeOwned>(&self, kind: &str) -> Result<Vec<T>> {
        let mut q = self.db.prepare("SELECT json FROM object WHERE kind = ?1 ORDER BY id").map_err(|_| StoreError::Read)?;
        let rows = q.query_map([kind], |r| r.get::<_, String>(0)).map_err(|_| StoreError::Read)?;
        rows.map(|r| {
            let json = r.map_err(|_| StoreError::Read)?;
            serde_json::from_str(&json).map_err(|_| StoreError::Corrupt)
        })
        .collect()
    }
}

fn to_json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| StoreError::Write)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    fn account() -> Account {
        Account {
            server: "https://127.0.0.1:8087".into(),
            email: "spike@example.com".into(),
            kdf: Kdf::Pbkdf2 { iterations: 600_000 },
            device_id: Uuid::new_v4(),
            user_id: None,
            last_sync: None,
        }
    }

    #[test]
    fn snapshot_round_trips_and_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault/vault.sqlite");
        let mut store = Store::open(&path).unwrap();
        assert_eq!(store.snapshot().unwrap(), None);
        store.set_account(&account()).unwrap();
        let sync: Sync = serde_json::from_str(&fixture("pbkdf2-sync.json")).unwrap();
        store.replace_snapshot(&sync, Kdf::Pbkdf2 { iterations: 700_000 }, 1_792_000_000).unwrap();

        let back = store.snapshot().unwrap().unwrap();
        let mut want = sync.clone();
        want.ciphers.sort_by_key(|c| c.id.to_string());
        want.folders.sort_by_key(|f| f.id.to_string());
        want.collections.sort_by_key(|c| c.id.to_string());
        assert_eq!(back, want);
        let acct = store.account().unwrap().unwrap();
        assert_eq!(acct.user_id, Some(sync.profile.id));
        assert_eq!(acct.last_sync, Some(1_792_000_000));
        assert_eq!(acct.kdf, Kdf::Pbkdf2 { iterations: 700_000 });

        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        for side in ["vault.sqlite-wal", "vault.sqlite-shm"] {
            let p = path.parent().unwrap().join(side);
            if p.exists() {
                assert_eq!(mode(&p), 0o600, "{side}");
            }
        }
    }

    #[test]
    fn no_plaintext_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.sqlite");
        let mut store = Store::open(&path).unwrap();
        store.set_account(&account()).unwrap();
        let sync: Sync = serde_json::from_str(&fixture("pbkdf2-sync.json")).unwrap();
        store.replace_snapshot(&sync, account().kdf, 1).unwrap();
        store.put_cipher(&sync.ciphers[0]).unwrap();
        drop(store);

        // Every plaintext value bw decrypted from this vault, and the master password.
        let bw: serde_json::Value = serde_json::from_str(&fixture("pbkdf2-bw.json")).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&fixture("pbkdf2-account.json")).unwrap();
        let mut canaries = vec![meta["password"].as_str().unwrap().to_string()];
        for item in bw.as_array().unwrap() {
            for v in [
                &item["name"],
                &item["notes"],
                &item["login"]["password"],
                &item["login"]["username"],
                &item["login"]["totp"],
                &item["card"]["number"],
                &item["fields"][0]["value"],
            ] {
                if let Some(s) = v.as_str() {
                    canaries.push(s.to_string());
                }
            }
        }
        assert!(canaries.len() > 15);
        for entry in fs::read_dir(dir.path()).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            for c in &canaries {
                assert!(!text.contains(c.as_str()), "plaintext {c:?} on disk");
            }
        }
    }

    #[test]
    fn failed_replace_keeps_last_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
        store.set_account(&account()).unwrap();
        let sync: Sync = serde_json::from_str(&fixture("pbkdf2-sync.json")).unwrap();
        store.replace_snapshot(&sync, account().kdf, 1).unwrap();
        // Two ciphers with one id break the primary key half-way through.
        let mut bad = sync.clone();
        bad.ciphers.push(bad.ciphers[0].clone());
        assert_eq!(store.replace_snapshot(&bad, account().kdf, 2), Err(StoreError::Write));
        assert_eq!(store.snapshot().unwrap().unwrap().ciphers.len(), sync.ciphers.len());
    }

    #[test]
    fn clear_signs_out() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
        store.set_account(&account()).unwrap();
        let sync: Sync = serde_json::from_str(&fixture("pbkdf2-sync.json")).unwrap();
        store.replace_snapshot(&sync, account().kdf, 1).unwrap();
        store.clear().unwrap();
        assert_eq!(store.account().unwrap(), None);
        assert_eq!(store.snapshot().unwrap(), None);
    }

    #[test]
    fn pairings_are_kept_and_go_with_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
        let p =
            Pairing { id: "p1".into(), extension: "ext@x".into(), browser: "Firefox".into(), key: "2.a|b|c".into(), created: 1 };
        store.put_pairing(&p).unwrap();
        assert_eq!(store.pairings().unwrap(), vec![p.clone()]);
        store.remove_pairing("p1").unwrap();
        assert!(store.pairings().unwrap().is_empty());
        store.put_pairing(&p).unwrap();
        store.clear().unwrap();
        assert!(store.pairings().unwrap().is_empty());
    }

    #[test]
    fn newer_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.sqlite");
        drop(Store::open(&path).unwrap());
        Connection::open(&path).unwrap().execute("UPDATE meta SET value = '99' WHERE key = 'schema'", []).unwrap();
        assert_eq!(Store::open(&path).err(), Some(StoreError::TooNew));
    }
}
