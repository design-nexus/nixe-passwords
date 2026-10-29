//! Password and passphrase generation. Characters and words are picked uniformly with
//! the thread CSPRNG (ChaCha, seeded by the OS); passphrases use the EFF long word list
//! that bitwarden-crypto ships, so they match what Bitwarden's own generator draws from.

use rand::seq::{IndexedRandom, SliceRandom};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::secret::Secret;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// Bitwarden's set: the symbols most sites accept.
const SYMBOLS: &str = "!@#$%^&*";
const AMBIGUOUS: &str = "IOl01";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadRules;

impl std::fmt::Display for BadRules {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("those generator settings can't make a password")
    }
}

impl std::error::Error for BadRules {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordRules {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordRules {
    fn default() -> Self {
        Self { length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, avoid_ambiguous: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PassphraseRules {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub number: bool,
}

impl Default for PassphraseRules {
    fn default() -> Self {
        Self { words: 5, separator: "-".into(), capitalize: true, number: true }
    }
}

/// A password with at least one character from every chosen set.
pub fn password(rules: &PasswordRules) -> Result<Secret, BadRules> {
    let sets: Vec<Vec<char>> =
        [(rules.lowercase, LOWER), (rules.uppercase, UPPER), (rules.digits, DIGITS), (rules.symbols, SYMBOLS)]
            .into_iter()
            .filter(|(on, _)| *on)
            .map(|(_, set)| set.chars().filter(|c| !(rules.avoid_ambiguous && AMBIGUOUS.contains(*c))).collect())
            .collect();
    if sets.is_empty() || !(sets.len().max(5)..=128).contains(&rules.length) {
        return Err(BadRules);
    }
    let all: Vec<char> = sets.iter().flatten().copied().collect();
    let mut rng = rand::rng();
    let mut out = Zeroizing::new(Vec::with_capacity(rules.length));
    for set in &sets {
        out.push(*set.choose(&mut rng).ok_or(BadRules)?);
    }
    while out.len() < rules.length {
        out.push(*all.choose(&mut rng).ok_or(BadRules)?);
    }
    out.shuffle(&mut rng);
    Ok(Secret::new(out.iter().collect::<String>()))
}

/// The secret code of a sign-in request (25 letters and digits, as the official clients
/// make): it stands in for the password when the approved request signs in.
pub fn access_code() -> String {
    let set: Vec<char> = LOWER.chars().chain(UPPER.chars()).chain(DIGITS.chars()).collect();
    let mut rng = rand::rng();
    (0..25).map(|_| *set.choose(&mut rng).expect("set isn't empty")).collect()
}

/// Words from the EFF long list, optionally capitalized, one of them with a digit.
pub fn passphrase(rules: &PassphraseRules) -> Result<Secret, BadRules> {
    if !(3..=20).contains(&rules.words) || rules.separator.chars().count() > 3 {
        return Err(BadRules);
    }
    let list = bitwarden_crypto::EFF_LONG_WORD_LIST;
    let mut rng = rand::rng();
    let mut words: Vec<Zeroizing<String>> = (0..rules.words)
        .map(|_| {
            let word = *list.choose(&mut rng).expect("word list isn't empty");
            let mut w = Zeroizing::new(word.to_string());
            if rules.capitalize
                && let Some(first) = w.get_mut(0..1)
            {
                first.make_ascii_uppercase();
            }
            w
        })
        .collect();
    if rules.number {
        let digit = *DIGITS.as_bytes().choose(&mut rng).expect("digits") as char;
        let at = rand::RngExt::random_range(&mut rng, 0..words.len());
        words[at].push(digit);
    }
    let joined = Zeroizing::new(words.iter().map(|w| w.as_str()).collect::<Vec<_>>().join(&rules.separator));
    Ok(Secret::new(joined.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_follow_rules() {
        for _ in 0..200 {
            let p = password(&PasswordRules::default()).unwrap();
            let p = p.expose();
            assert_eq!(p.chars().count(), 20);
            for set in [LOWER, UPPER, DIGITS, SYMBOLS] {
                assert!(p.chars().any(|c| set.contains(c)), "{set} missing");
            }
        }
        let digits = PasswordRules { lowercase: false, uppercase: false, symbols: false, length: 8, ..Default::default() };
        assert!(password(&digits).unwrap().expose().chars().all(|c| c.is_ascii_digit()));
        let clear = PasswordRules { avoid_ambiguous: true, length: 128, ..Default::default() };
        for _ in 0..50 {
            assert!(!password(&clear).unwrap().expose().chars().any(|c| AMBIGUOUS.contains(c)));
        }
        assert_eq!(password(&PasswordRules { length: 4, ..Default::default() }).err(), Some(BadRules));
        assert_eq!(password(&PasswordRules { length: 129, ..Default::default() }).err(), Some(BadRules));
        let none = PasswordRules { lowercase: false, uppercase: false, digits: false, symbols: false, ..Default::default() };
        assert_eq!(password(&none).err(), Some(BadRules));
    }

    #[test]
    fn passwords_differ() {
        let a = password(&PasswordRules::default()).unwrap();
        let b = password(&PasswordRules::default()).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn passphrases_follow_rules() {
        let p = passphrase(&PassphraseRules::default()).unwrap();
        let words: Vec<&str> = p.expose().split('-').collect();
        assert_eq!(words.len(), 5);
        assert!(words.iter().all(|w| w.chars().next().unwrap().is_ascii_uppercase()));
        assert_eq!(words.iter().filter(|w| w.chars().any(|c| c.is_ascii_digit())).count(), 1);
        let plain = PassphraseRules { words: 3, separator: " ".into(), capitalize: false, number: false };
        let p = passphrase(&plain).unwrap();
        assert!(p.expose().split(' ').all(|w| bitwarden_crypto::EFF_LONG_WORD_LIST.contains(&w)));
        assert_eq!(passphrase(&PassphraseRules { words: 2, ..Default::default() }).err(), Some(BadRules));
    }
}
