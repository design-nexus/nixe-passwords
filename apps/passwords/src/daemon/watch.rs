//! What locks the vault besides the user: the idle timer, the screen locking, the
//! machine going to sleep. And the periodic sync.
//!
//! Omarchy locks the screen through its shell, not logind, so the lock is read from
//! Hyprland: a session lock shows as `LOCK` in a monitor's `solitaryBlockedBy`. logind's
//! `Lock` (e.g. `loginctl lock-session`) and `PrepareForSleep` are watched as well.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::peer::Scope;
use super::vault::Vault;

pub fn spawn_all(vault: &Arc<Vault>) {
    tokio::spawn(idle(vault.clone()));
    tokio::spawn(screen(vault.clone()));
    tokio::spawn(logind(vault.clone()));
    tokio::spawn(periodic_sync(vault.clone()));
}

async fn idle(vault: Arc<Vault>) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        vault.lock_if_idle().await;
    }
}

async fn screen(vault: Arc<Vault>) {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if vault.is_unlocked().await && vault.settings().await.lock_on_screen_lock && hyprland_locked().await == Some(true) {
            vault.lock().await;
        }
    }
}

/// `Some(true)` while Hyprland holds a session lock; `None` outside Hyprland.
async fn hyprland_locked() -> Option<bool> {
    let runtime = std::env::var("XDG_RUNTIME_DIR").ok()?;
    let signature = std::env::var("HYPRLAND_INSTANCE_SIGNATURE").ok()?;
    let path = format!("{runtime}/hypr/{signature}/.socket.sock");
    let ask = async {
        let mut sock = tokio::net::UnixStream::connect(&path).await.ok()?;
        sock.write_all(b"j/monitors").await.ok()?;
        let mut reply = Vec::new();
        sock.take(4 << 20).read_to_end(&mut reply).await.ok()?;
        Some(reply)
    };
    let reply = tokio::time::timeout(Duration::from_secs(2), ask).await.ok()??;
    let monitors: serde_json::Value = serde_json::from_slice(&reply).ok()?;
    Some(
        monitors
            .as_array()?
            .iter()
            .any(|m| m["solitaryBlockedBy"].as_array().is_some_and(|reasons| reasons.iter().any(|r| r == "LOCK"))),
    )
}

async fn logind(vault: Arc<Vault>) {
    let Ok(system) = zbus::Connection::system().await else { return };
    let rules = [
        "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'",
        "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Session',member='Lock'",
    ];
    let mut streams = Vec::new();
    for rule in rules {
        let Ok(rule) = zbus::MatchRule::try_from(rule) else { continue };
        if let Ok(s) = zbus::MessageStream::for_match_rule(rule, &system, None).await {
            streams.push(s);
        }
    }
    let mut all = futures_util::stream::select_all(streams);
    while let Some(Ok(msg)) = all.next().await {
        let member = msg.header().member().map(|m| m.to_string()).unwrap_or_default();
        let settings = vault.settings().await;
        let lock = match member.as_str() {
            // PrepareForSleep(true) before sleeping, (false) after waking.
            "PrepareForSleep" => settings.lock_on_sleep && msg.body().deserialize::<bool>().unwrap_or(false),
            "Lock" => settings.lock_on_screen_lock,
            _ => false,
        };
        if lock {
            vault.lock().await;
        }
    }
}

async fn periodic_sync(vault: Arc<Vault>) {
    loop {
        let minutes = vault.settings().await.sync_minutes;
        tokio::time::sleep(Duration::from_secs(60 * minutes.max(1))).await;
        if minutes > 0 && vault.is_unlocked().await {
            let _ = vault.sync(Scope::App).await;
        }
    }
}
