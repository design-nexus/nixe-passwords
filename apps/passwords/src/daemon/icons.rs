//! Website icons, when the user turns them on: fetched through the server's icon
//! service and kept in memory while the vault is open. Nothing is written to disk: the
//! hosts would show which sites the vault has logins for. Only the host goes to the
//! server.

use std::collections::HashMap;

use nyx_passwords_core::api::Server;
use nyx_passwords_proto::Error as Code;
use tokio::sync::{Mutex, Semaphore};

use super::vault::{Failure, Result};

/// Icons fetched at once.
const AT_ONCE: usize = 4;
/// Icons kept; past this the oldest answers go first.
const KEEP: usize = 2000;

pub struct Icons {
    permits: Semaphore,
    /// Each host's icon, or `None` when it has none.
    known: Mutex<HashMap<String, Option<Vec<u8>>>>,
    /// The server's answer for a site without an icon, to tell real icons from it.
    generic: Mutex<Option<Vec<u8>>>,
}

impl Default for Icons {
    fn default() -> Self {
        Icons { permits: Semaphore::new(AT_ONCE), known: Mutex::new(HashMap::new()), generic: Mutex::new(None) }
    }
}

/// A host name to ask for: letters, digits, dots and hyphens, with a dot, and not an
/// address.
fn valid(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && host.parse::<std::net::IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

impl Icons {
    /// `host`'s icon (PNG or whatever the site has), fetching it the first time.
    /// `NoField` when the site has none.
    pub async fn get(&self, server: &Server, host: &str) -> Result<Vec<u8>> {
        let host = host.trim().trim_start_matches("www.").to_ascii_lowercase();
        if !valid(&host) {
            return Err(Failure::new(Code::NoUrl, "not a site name"));
        }
        let none = || Failure::new(Code::NoField, "no icon");
        if let Some(known) = self.known.lock().await.get(&host) {
            return known.clone().ok_or_else(none);
        }
        let _permit = self.permits.acquire().await.map_err(|_| Failure::new(Code::Failed, "busy"))?;
        let generic = {
            let mut generic = self.generic.lock().await;
            if generic.is_none() {
                *generic = server.icon("icon.invalid").await.ok();
            }
            generic.clone()
        };
        let icon = match server.icon(&host).await {
            Ok(bytes) if generic.as_ref() != Some(&bytes) => Some(bytes),
            // A failed fetch isn't remembered: it may work next time.
            Err(_) => return Err(none()),
            Ok(_) => None,
        };
        let mut known = self.known.lock().await;
        if known.len() >= KEEP {
            known.clear();
        }
        known.insert(host, icon.clone());
        icon.ok_or_else(none)
    }

    /// Locking: the icons, and with them the sites, are forgotten.
    pub async fn forget(&self) {
        self.known.lock().await.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names() {
        assert!(valid("github.com") && valid("login.example.co.uk") && valid("a-b.example"));
        for bad in ["", "localhost", "192.168.1.1", "../etc", "a..b", "exa mple.com", "Ex.com", "x/y.com", "é.com"] {
            assert!(!valid(bad), "{bad}");
        }
    }
}
