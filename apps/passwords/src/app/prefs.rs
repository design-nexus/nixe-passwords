//! The window's preferences and the vault settings the daemon reads, in one file
//! (`~/.config/nixe-passwords/settings.toml`).

pub use nixe_theme::ThemeMode;
use serde::{Deserialize, Serialize};

pub use nixe_passwords::daemon::settings::Settings as Vault;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    pub mode: ThemeMode,
    pub theme: String,
    pub glow: bool,
    pub reduce_motion: bool,
    pub sidebar_collapsed: bool,
    pub last_section: String,
    /// The server address last signed in to, offered again on the sign-in page.
    pub last_server: String,
    pub last_email: String,
    #[serde(flatten)]
    pub vault: Vault,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            mode: ThemeMode::Omarchy,
            theme: "tokyo-night".into(),
            glow: true,
            reduce_motion: false,
            sidebar_collapsed: false,
            last_section: "all".into(),
            last_server: String::new(),
            last_email: String::new(),
            vault: Vault::default(),
        }
    }
}

nixe_core::prefs_store!(Prefs);
