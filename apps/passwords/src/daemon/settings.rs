//! The daemon's view of `~/.config/nixe-passwords/settings.toml`. The app writes the file;
//! the daemon reads only the keys below (ignoring the window's) and reloads when the
//! file changes.

use std::path::PathBuf;
use std::time::SystemTime;

use nixe_passwords_core::generate::{PassphraseRules, PasswordRules};
use serde::{Deserialize, Serialize};

/// Also the vault part of the window's preferences (`#[serde(flatten)]` there), so the
/// two never disagree about a default.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Lock after this many minutes without use; 0 never locks on a timer.
    pub lock_minutes: u64,
    pub lock_on_screen_lock: bool,
    pub lock_on_sleep: bool,
    /// Clear a copied value after this many seconds; 0 leaves it.
    pub clipboard_seconds: u64,
    /// Serve a copy to a single paste, then clear it.
    pub paste_once: bool,
    pub notify_copies: bool,
    /// Sync every this many minutes while unlocked; 0 only on unlock and on demand.
    pub sync_minutes: u64,
    /// Whether Glimpse may search the vault and copy from it.
    pub glimpse: bool,
    /// Whether Nixe Assistant may find logins and copy from them (each call still needs
    /// a key press there). Off until turned on.
    pub assistant: bool,
    /// A PEM file of extra certificate authorities, for a server with its own CA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_ca: Option<PathBuf>,
    /// What `pw generate` makes.
    pub generate_passphrase: bool,
    pub password_rules: PasswordRules,
    pub passphrase_rules: PassphraseRules,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lock_minutes: 15,
            lock_on_screen_lock: true,
            lock_on_sleep: true,
            clipboard_seconds: 30,
            paste_once: false,
            notify_copies: true,
            sync_minutes: 30,
            glimpse: true,
            assistant: false,
            extra_ca: None,
            generate_passphrase: false,
            password_rules: PasswordRules::default(),
            passphrase_rules: PassphraseRules::default(),
        }
    }
}

/// Settings, re-read when the file's modification time changes.
pub struct Watched {
    path: PathBuf,
    seen: Option<SystemTime>,
    pub current: Settings,
}

impl Watched {
    pub fn new(path: PathBuf) -> Self {
        let mut w = Watched { path, seen: None, current: Settings::default() };
        w.refresh();
        w
    }

    /// Re-reads the file if it changed. A file that doesn't parse keeps the last good
    /// settings (the app keeps a backup of a broken file).
    pub fn refresh(&mut self) -> &Settings {
        let modified = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        if modified != self.seen {
            self.seen = modified;
            match std::fs::read_to_string(&self.path) {
                Ok(text) => {
                    if let Ok(s) = toml::from_str(&text) {
                        self.current = s;
                    }
                }
                Err(_) => self.current = Settings::default(),
            }
        }
        &self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_its_keys_and_ignores_others() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.toml");
        std::fs::write(&path, "theme = \"nord\"\nlock_minutes = 5\nclipboard_seconds = 0\n").unwrap();
        let mut w = Watched::new(path.clone());
        assert_eq!((w.current.lock_minutes, w.current.clipboard_seconds, w.current.glimpse), (5, 0, true));
        // A broken edit keeps the last good settings.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&path, "lock_minutes = \"soon\"").unwrap();
        assert_eq!(w.refresh().lock_minutes, 5);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(w.refresh(), &Settings::default());
    }
}
