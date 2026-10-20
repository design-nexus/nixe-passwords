//! The security report: weak, reused and old passwords, worked out in memory from the
//! unlocked vault; and, only when the user asks, which passwords appear in known data
//! breaches (Have I Been Pwned's k-anonymity range API: only the first five characters
//! of each password's SHA-1 hash leave the device).

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha1::{Digest, Sha1};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::Keys;
use crate::model::{Cipher, Kind, Sync};
use crate::secret::Secret;

/// Have I Been Pwned's password range API.
pub const BREACH_API: &str = "https://api.pwnedpasswords.com";
/// A password unchanged for longer than this is reported as old.
pub const OLD_DAYS: u64 = 365;
/// zxcvbn scores below this (0 to 4) are weak, as in the official clients.
const STRONG_ENOUGH: u8 = 3;

/// What the report says about one login. Only logins with something to say are listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: Uuid,
    /// How many other logins use the same password.
    pub reused: usize,
    pub weak: bool,
    /// Days since the password last changed, when that's over `OLD_DAYS`.
    pub age_days: Option<u64>,
}

/// Strength results kept between reports: an item is scored again only when its
/// revision changes. Holds no passwords.
pub type StrengthCache = HashMap<Uuid, (String, bool)>;

/// The logins the report covers: live, readable, with a password this account may see.
fn audited<'a>(keys: &'a Keys, sync: &'a Sync) -> impl Iterator<Item = (&'a Cipher, Secret)> + 'a {
    sync.ciphers.iter().filter(|c| c.kind() == Kind::Login && !c.is_deleted() && c.can_view_password()).filter_map(move |c| {
        let password = c.login.as_ref()?.password.as_deref()?;
        let mut key = keys.item(c.organization_id, c.key.as_deref()).ok()?;
        let plain = key.decrypt(password).ok()?;
        (!plain.is_empty()).then_some((c, plain))
    })
}

pub fn audit(keys: &Keys, sync: &Sync, now: SystemTime, cache: &mut StrengthCache) -> Vec<Finding> {
    let today = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() / 86_400);
    // Digests, not passwords, and only for the length of the report.
    let mut by_password: HashMap<[u8; 32], usize> = HashMap::new();
    let mut rows = Vec::new();
    for (c, password) in audited(keys, sync) {
        let digest: [u8; 32] = sha2::Sha256::digest(password.expose().as_bytes()).into();
        *by_password.entry(digest).or_default() += 1;
        let weak = match cache.get(&c.id) {
            Some((revision, weak)) if *revision == c.revision_date => *weak,
            _ => {
                let weak = is_weak(keys, c, &password);
                cache.insert(c.id, (c.revision_date.clone(), weak));
                weak
            }
        };
        let changed = c.login.as_ref().and_then(|l| l.extra.get("passwordRevisionDate")).and_then(|v| v.as_str());
        let changed = changed.or(c.extra.get("creationDate").and_then(|v| v.as_str())).and_then(days_since_epoch);
        let age = changed.map(|d| today.saturating_sub(d)).filter(|&a| a > OLD_DAYS);
        rows.push((c.id, digest, weak, age));
    }
    rows.into_iter()
        .map(|(id, digest, weak, age_days)| Finding { id, reused: by_password[&digest] - 1, weak, age_days })
        .filter(|f| f.reused > 0 || f.weak || f.age_days.is_some())
        .collect()
}

/// zxcvbn's estimate, counting the item's own name and username against the password.
fn is_weak(keys: &Keys, c: &Cipher, password: &Secret) -> bool {
    let mut inputs = Vec::new();
    if let Ok(mut key) = keys.item(c.organization_id, c.key.as_deref()) {
        inputs.extend(key.decrypt(&c.name).ok());
        inputs.extend(c.login.as_ref().and_then(|l| key.decrypt_opt(l.username.as_deref()).ok().flatten()));
    }
    let inputs: Vec<&str> = inputs.iter().map(|s| s.expose()).collect();
    u8::from(zxcvbn::zxcvbn(password.expose(), &inputs).score()) < STRONG_ENOUGH
}

/// `2026-10-20T04:13:05.099Z` as whole days since the epoch.
fn days_since_epoch(date: &str) -> Option<u64> {
    let year: i64 = date.get(0..4)?.parse().ok()?;
    let month: i64 = date.get(5..7)?.parse().ok()?;
    let day: i64 = date.get(8..10)?.parse().ok()?;
    // Howard Hinnant's days-from-civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    u64::try_from(era * 146_097 + doe - 719_468).ok()
}

/// Each audited login's password as an upper-case SHA-1 hex digest, for the breach
/// check. Worked out under the vault lock; the lookups happen after it's released.
pub fn breach_hashes(keys: &Keys, sync: &Sync) -> Vec<(Uuid, Zeroizing<String>)> {
    audited(keys, sync)
        .map(|(c, password)| {
            let digest = Sha1::digest(password.expose().as_bytes());
            (c.id, Zeroizing::new(digest.iter().map(|b| format!("{b:02X}")).collect()))
        })
        .collect()
}

/// How often each password appears in Have I Been Pwned's breach data (`base` is
/// `BREACH_API`). Asks once per distinct five-character hash prefix, with padding on, so
/// neither the passwords nor their full hashes are sent. Logins with no breaches are
/// left out.
pub async fn breaches(base: &str, hashes: &[(Uuid, Zeroizing<String>)]) -> Result<Vec<(Uuid, u64)>, reqwest::Error> {
    let http = reqwest::Client::builder().user_agent("nixe-passwords").timeout(Duration::from_secs(30)).build()?;
    let mut by_prefix: HashMap<&str, Vec<(Uuid, &str)>> = HashMap::new();
    for (id, hash) in hashes {
        let (prefix, suffix) = hash.split_at(5);
        by_prefix.entry(prefix).or_default().push((*id, suffix));
    }
    let mut found = Vec::new();
    for (prefix, wanted) in by_prefix {
        let body = http
            .get(format!("{base}/range/{prefix}"))
            .header("Add-Padding", "true")
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let counts: HashMap<&str, u64> = body
            .lines()
            .filter_map(|line| line.trim().split_once(':'))
            .filter_map(|(suffix, count)| Some((suffix, count.trim().parse().ok()?)))
            .collect();
        for (id, suffix) in wanted {
            // Padding lines carry a count of 0.
            if let Some(&n) = counts.get(suffix).filter(|n| **n > 0) {
                found.push((id, n));
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(days_since_epoch("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(days_since_epoch("2000-03-01T12:00:00.5Z"), Some(11_017));
        assert_eq!(days_since_epoch("2026-10-20T04:13:05.099157Z"), Some(20_746));
        assert_eq!(days_since_epoch("soon"), None);
    }
}
