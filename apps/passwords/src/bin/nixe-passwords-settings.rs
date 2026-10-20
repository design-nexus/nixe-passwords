//! The Settings extension helper: a Passwords page in Settings (pages, describe, set;
//! see extensions/README.md). It edits `~/.config/nixe-passwords/settings.toml`, the
//! same file the window writes and the daemon reads, and asks the daemon for its state.
//! The daemon lets it see the status, lock and sync, nothing more.

use std::path::PathBuf;
use std::time::Duration;

use nixe_core::{app, paths};
use nixe_passwords::daemon::settings::Settings;
use nixe_passwords_proto as proto;
use serde_json::{Value, json};

fn main() {
    app::init(nixe_passwords::daemon::APP);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["pages"] => Ok(pages()),
        ["describe", _] => Ok(describe()),
        ["set", _, key, value] => set(key, value),
        ["theme-changed"] => Ok(Value::Null),
        _ => Err("usage: nixe-passwords-settings pages | describe PAGE | set PAGE KEY VALUE".to_string()),
    };
    match result {
        Ok(Value::Null) => {}
        Ok(v) => println!("{v}"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn pages() -> Value {
    json!([{
        "id": "passwords", "title": "Passwords", "icon": "dialog-password-symbolic",
        "description": "Vault locking, clipboard and Glimpse",
        "keywords": "passwords vault vaultwarden bitwarden lock clipboard glimpse",
    }])
}

fn file() -> PathBuf {
    paths::prefs_file()
}

fn current() -> Settings {
    std::fs::read_to_string(file()).ok().and_then(|t| toml::from_str(&t).ok()).unwrap_or_default()
}

fn opts(pairs: &[(u64, &str)]) -> Value {
    Value::Array(pairs.iter().map(|(v, l)| json!([v.to_string(), l])).collect())
}

fn describe() -> Value {
    let s = current();
    let (state, host) = daemon_status();
    let status = match state.as_deref() {
        Some(proto::state::UNLOCKED) => format!("Open · {host}"),
        Some(proto::state::LOCKED) => format!("Locked · {host}"),
        Some(_) => "Not signed in".to_string(),
        None => "Not running; it starts when Passwords or Glimpse needs it".to_string(),
    };
    let mut vault = vec![json!({"kind": "info", "key": "status", "title": "Vault", "value": status})];
    if state.as_deref() == Some(proto::state::UNLOCKED) {
        vault.push(json!({"kind": "button", "key": "lock", "title": "Lock now", "label": "Lock", "refresh": true}));
        vault.push(json!({"kind": "button", "key": "sync", "title": "Sync now", "desc": "Fetch changes from the server.", "label": "Sync", "refresh": true}));
    }
    vault.push(json!({"kind": "button", "key": "open", "title": "Open Passwords", "label": "Open"}));
    let minutes = &[
        (1, "1 minute"),
        (5, "5 minutes"),
        (15, "15 minutes"),
        (30, "30 minutes"),
        (60, "1 hour"),
        (240, "4 hours"),
        (0, "Never"),
    ];
    let seconds = &[
        (10, "After 10 seconds"),
        (20, "After 20 seconds"),
        (30, "After 30 seconds"),
        (60, "After 1 minute"),
        (120, "After 2 minutes"),
        (0, "Never"),
    ];
    let syncs = &[
        (5, "Every 5 minutes"),
        (15, "Every 15 minutes"),
        (30, "Every 30 minutes"),
        (60, "Every hour"),
        (0, "Only when unlocking"),
    ];
    json!({
        "poll": 10,
        "groups": [
            {"title": "Vault", "rows": vault},
            {"title": "Locking", "rows": [
                {"kind": "choice", "key": "lock_minutes", "title": "Lock after", "desc": "Lock the vault when it hasn't been used for this long.", "value": s.lock_minutes.to_string(), "options": opts(minutes)},
                {"kind": "switch", "key": "lock_on_screen_lock", "title": "Lock when the screen locks", "value": s.lock_on_screen_lock},
                {"kind": "switch", "key": "lock_on_sleep", "title": "Lock on sleep", "value": s.lock_on_sleep},
            ]},
            {"title": "Clipboard", "rows": [
                {"kind": "choice", "key": "clipboard_seconds", "title": "Clear copied values", "desc": "Empty the clipboard this long after copying, if it still holds the copy.", "value": s.clipboard_seconds.to_string(), "options": opts(seconds)},
                {"kind": "switch", "key": "paste_once", "title": "Paste once", "desc": "Clear the clipboard after the first paste.", "value": s.paste_once},
                {"kind": "switch", "key": "notify_copies", "title": "Notify on copy", "desc": "Name what was copied, never the value.", "value": s.notify_copies},
            ]},
            {"title": "Sync", "rows": [
                {"kind": "choice", "key": "sync_minutes", "title": "Sync", "desc": "Fetch changes from the server while the vault is open.", "value": s.sync_minutes.to_string(), "options": opts(syncs)},
            ]},
            {"title": "Glimpse", "rows": [
                {"kind": "switch", "key": "glimpse", "title": "Find logins in Glimpse", "desc": "Type “pw” and a name. Passwords are never shown there.", "value": s.glimpse},
            ]},
        ]
    })
}

fn set(key: &str, value: &str) -> Result<Value, String> {
    match key {
        "lock" | "sync" => {
            let method = if key == "lock" { "Lock" } else { "Sync" };
            return match daemon_call(method) {
                Ok(()) => Ok(json!({"toast": if key == "lock" { "Vault locked." } else { "Synced." }, "refresh": true})),
                Err(e) => Err(e),
            };
        }
        "open" => {
            std::process::Command::new("nixe-passwords").spawn().map_err(|_| "Couldn't open Passwords".to_string())?;
            return Ok(Value::Null);
        }
        _ => {}
    }
    let new = match key {
        "lock_minutes" | "clipboard_seconds" | "sync_minutes" => {
            toml::Value::Integer(value.parse::<i64>().map_err(|_| "not a number".to_string())?)
        }
        "lock_on_screen_lock" | "lock_on_sleep" | "paste_once" | "notify_copies" | "glimpse" => {
            toml::Value::Boolean(value == "true")
        }
        _ => return Err(format!("unknown setting {key}")),
    };
    // Edit only this key, keeping the window's own settings as they are.
    let path = file();
    let mut table: toml::Table = std::fs::read_to_string(&path)
        .ok()
        .map(|t| toml::from_str(&t).map_err(|_| "settings.toml couldn't be read; fix or remove it".to_string()))
        .transpose()?
        .unwrap_or_default();
    table.insert(key.to_string(), new);
    let text = toml::to_string(&table).map_err(|e| e.to_string())?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    nixe_core::cmd::atomic_write(&path, text).map_err(|e| e.to_string())?;
    Ok(Value::Null)
}

/// `(state, server host)`, or `(None, _)` when the daemon isn't running. Never starts it.
fn daemon_status() -> (Option<String>, String) {
    let reply = with_daemon(|conn| async move {
        let msg = conn
            .call_method(None::<&str>, proto::OBJECT_PATH, Some(proto::INTERFACE), "Status", &())
            .await
            .map_err(|e| e.to_string())?;
        msg.body().deserialize::<(String, String, u32)>().map_err(|e| e.to_string())
    });
    match reply {
        Ok((state, host, _)) => (Some(state), host),
        Err(_) => (None, String::new()),
    }
}

fn daemon_call(method: &'static str) -> Result<(), String> {
    with_daemon(move |conn| async move {
        match conn.call_method(None::<&str>, proto::OBJECT_PATH, Some(proto::INTERFACE), method, &()).await {
            Ok(_) => Ok(()),
            Err(zbus::Error::MethodError(_, Some(text), _)) => Err(text),
            Err(e) => Err(e.to_string()),
        }
    })
}

fn with_daemon<T, F, Fut>(run: F) -> Result<T, String>
where
    F: FnOnce(zbus::Connection) -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let socket = proto::socket_path().ok_or("XDG_RUNTIME_DIR isn't set")?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let stream = tokio::net::UnixStream::connect(&socket).await.map_err(|_| "Passwords isn't running".to_string())?;
        let build = zbus::connection::Builder::unix_stream(stream).p2p().build();
        let conn = tokio::time::timeout(Duration::from_secs(5), build)
            .await
            .map_err(|_| "Passwords didn't answer".to_string())?
            .map_err(|e| e.to_string())?;
        tokio::time::timeout(Duration::from_secs(25), run(conn)).await.map_err(|_| "Passwords didn't answer".to_string())?
    })
}
