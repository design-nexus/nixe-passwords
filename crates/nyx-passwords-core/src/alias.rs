//! Usernames for the generator: a random word, your address with a tag
//! (`you+tag@example.com`), an address at a catch-all domain, or a new alias from an
//! email forwarding service (SimpleLogin, addy.io, Firefox Relay, DuckDuckGo, Fastmail,
//! Forward Email), as the official clients offer. Forwarding services are asked with
//! the user's own API token; only the site's name goes with the request.

use std::time::Duration;

use rand::seq::IndexedRandom;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::secret::Secret;

/// The forwarding services: id and name.
pub const SERVICES: &[(&str, &str)] = &[
    ("simplelogin", "SimpleLogin"),
    ("addy", "addy.io"),
    ("relay", "Firefox Relay"),
    ("duckduckgo", "DuckDuckGo"),
    ("fastmail", "Fastmail"),
    ("forwardemail", "Forward Email"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UsernameKind {
    #[default]
    Word,
    /// `you+tag@example.com`.
    Plus,
    /// `tag@your-catch-all.example`.
    CatchAll,
    /// An alias from a forwarding service.
    Forwarded,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UsernameRules {
    pub kind: UsernameKind,
    /// Random word: capitalized, with a number.
    pub capitalize: bool,
    pub number: bool,
    /// Plus addressing: your address.
    pub email: String,
    /// Catch-all: your domain.
    pub domain: String,
    /// Plus and catch-all: the tag is the site's name rather than random letters.
    pub by_site: bool,
    /// Forwarding: the service's id (`SERVICES`).
    pub service: String,
    /// addy.io and Forward Email: the domain to make the alias at.
    pub service_domain: String,
    /// SimpleLogin and addy.io run on your own server: its address.
    pub service_url: String,
}

impl Default for UsernameRules {
    fn default() -> Self {
        UsernameRules {
            kind: UsernameKind::Word,
            capitalize: false,
            number: true,
            email: String::new(),
            domain: String::new(),
            by_site: false,
            service: "simplelogin".into(),
            service_domain: String::new(),
            service_url: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsernameError {
    /// The settings lack what this kind needs (an address, a domain, a service).
    Incomplete(&'static str),
    /// The service has no token saved.
    NoToken,
    /// The service refused or couldn't be reached; its own words when it gave some.
    Service(String),
}

impl std::fmt::Display for UsernameError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Incomplete(what) => write!(f, "set {what} in Passwords' generator settings first"),
            Self::NoToken => f.write_str("save the service's API token in Passwords' generator settings first"),
            Self::Service(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for UsernameError {}

/// Eight random lowercase letters and digits, for tags.
fn tag() -> String {
    let set: Vec<char> = ('a'..='z').chain('0'..='9').collect();
    let mut rng = rand::rng();
    (0..8).map(|_| *set.choose(&mut rng).expect("set isn't empty")).collect()
}

/// The site's name for a tag: its base domain (`github.com`), from a page address or host.
fn site_name(site: &str) -> Option<String> {
    let host = crate::vault::host_of(site)?;
    Some(crate::matching::base_domain(&host))
}

/// A username that doesn't need a service: a word, a tagged address or a catch-all one.
/// `site` is the login's address, for tags made from it.
pub fn local(rules: &UsernameRules, site: Option<&str>) -> Result<Secret, UsernameError> {
    let tag_for = |by_site: bool| site.filter(|_| by_site).and_then(site_name).unwrap_or_else(tag);
    match rules.kind {
        UsernameKind::Word => {
            let list = bitwarden_crypto::EFF_LONG_WORD_LIST;
            let mut rng = rand::rng();
            let mut word = list.choose(&mut rng).expect("word list isn't empty").to_string();
            if rules.capitalize
                && let Some(first) = word.get_mut(0..1)
            {
                first.make_ascii_uppercase();
            }
            if rules.number {
                word.push_str(&format!("{:04}", rand::random_range(0..10_000)));
            }
            Ok(Secret::new(word))
        }
        UsernameKind::Plus => {
            let (user, domain) = rules.email.trim().split_once('@').ok_or(UsernameError::Incomplete("your email address"))?;
            if user.is_empty() || domain.is_empty() {
                return Err(UsernameError::Incomplete("your email address"));
            }
            let user = user.split('+').next().unwrap_or(user);
            Ok(Secret::new(format!("{user}+{}@{domain}", tag_for(rules.by_site))))
        }
        UsernameKind::CatchAll => {
            let domain = rules.domain.trim().trim_start_matches('@');
            if domain.is_empty() {
                return Err(UsernameError::Incomplete("your catch-all domain"));
            }
            Ok(Secret::new(format!("{}@{domain}", tag_for(rules.by_site))))
        }
        UsernameKind::Forwarded => Err(UsernameError::Incomplete("a username kind")),
    }
}

/// A new alias from the configured forwarding service. `base` replaces the service's
/// public address (for tests); `rules.service_url` does for self-hosted ones.
pub async fn forwarded(
    rules: &UsernameRules,
    token: &Secret,
    site: Option<&str>,
    base: Option<&str>,
) -> Result<Secret, UsernameError> {
    let service = rules.service.as_str();
    if !SERVICES.iter().any(|(id, _)| *id == service) {
        return Err(UsernameError::Incomplete("an email alias service"));
    }
    if token.is_empty() {
        return Err(UsernameError::NoToken);
    }
    let own = Some(rules.service_url.trim().trim_end_matches('/')).filter(|u| !u.is_empty());
    let at = |public: &str| base.or(own).unwrap_or(public).trim_end_matches('/').to_string();
    let site = site.and_then(site_name).unwrap_or_default();
    let note = if site.is_empty() { "Made by Nyx Passwords".to_string() } else { format!("Made by Nyx Passwords for {site}") };
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("nyx-passwords/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| UsernameError::Service(e.to_string()))?;
    let t = token.expose();
    let (request, read): (reqwest::RequestBuilder, fn(&Value) -> Option<String>) = match service {
        "simplelogin" => {
            let mut url = format!("{}/api/alias/random/new", at("https://app.simplelogin.io"));
            if !site.is_empty() {
                url = format!("{url}?hostname={}", url::form_urlencoded::byte_serialize(site.as_bytes()).collect::<String>());
            }
            (http.post(url).header("Authentication", t).json(&json!({"note": note})), |v| v["alias"].as_str().map(str::to_string))
        }
        "addy" => {
            let domain = rules.service_domain.trim();
            if domain.is_empty() {
                return Err(UsernameError::Incomplete("the addy.io domain"));
            }
            let url = format!("{}/api/v1/aliases", at("https://app.addy.io"));
            (
                http.post(url)
                    .bearer_auth(t)
                    .header("X-Requested-With", "XMLHttpRequest")
                    .json(&json!({"domain": domain, "description": note})),
                |v| v["data"]["email"].as_str().map(str::to_string),
            )
        }
        "relay" => {
            let url = format!("{}/api/v1/relayaddresses/", at("https://relay.firefox.com"));
            (
                http.post(url)
                    .header("Authorization", format!("Token {t}"))
                    .json(&json!({"enabled": true, "generated_for": site, "description": note})),
                |v| v["full_address"].as_str().map(str::to_string),
            )
        }
        "duckduckgo" => {
            let url = format!("{}/api/email/addresses", at("https://quack.duckduckgo.com"));
            (http.post(url).bearer_auth(t), |v| v["address"].as_str().map(|a| format!("{a}@duck.com")))
        }
        "fastmail" => return fastmail(&http, &at("https://api.fastmail.com"), t, &site, &note).await,
        _ => {
            let domain = rules.service_domain.trim();
            if domain.is_empty() {
                return Err(UsernameError::Incomplete("the Forward Email domain"));
            }
            let url = format!("{}/v1/domains/{domain}/aliases", at("https://api.forwardemail.net"));
            (http.post(url).basic_auth(t, Some("")).json(&json!({"labels": site, "description": note})), |v| {
                Some(format!("{}@{}", v["name"].as_str()?, v["domain"]["name"].as_str().or(v["domain"].as_str())?))
            })
        }
    };
    let v = send(request).await?;
    read(&v).map(Secret::new).ok_or_else(|| UsernameError::Service("the service's answer wasn't understood".into()))
}

/// Sends a request; a refusal comes back with the service's own message if it has one.
async fn send(request: reqwest::RequestBuilder) -> Result<Value, UsernameError> {
    let resp = request.send().await.map_err(|_| UsernameError::Service("the service couldn't be reached".into()))?;
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let said = ["error", "message", "detail"].iter().find_map(|k| v[*k].as_str()).map(str::to_string);
        return Err(UsernameError::Service(match (status.as_u16(), said) {
            (401 | 403, _) => "the service refused the token".into(),
            (_, Some(said)) => format!("the service refused: {said}"),
            (code, None) => format!("the service refused (HTTP {code})"),
        }));
    }
    Ok(v)
}

/// Fastmail's masked email over JMAP: find the account, then create one.
async fn fastmail(http: &reqwest::Client, base: &str, token: &str, site: &str, note: &str) -> Result<Secret, UsernameError> {
    const MASKED: &str = "https://www.fastmail.com/dev/maskedemail";
    let session = send(http.get(format!("{base}/jmap/session")).bearer_auth(token)).await?;
    let account = session["primaryAccounts"][MASKED]
        .as_str()
        .ok_or_else(|| UsernameError::Service("this Fastmail token can't make masked email addresses".into()))?;
    let call = json!({
        "using": ["urn:ietf:params:jmap:core", MASKED],
        "methodCalls": [["MaskedEmail/set", {
            "accountId": account,
            "create": {"new": {"state": "enabled", "description": note, "forDomain": site}},
        }, "0"]],
    });
    let v = send(http.post(format!("{base}/jmap/api/")).bearer_auth(token).json(&call)).await?;
    let created = &v["methodResponses"][0][1]["created"]["new"]["email"];
    created.as_str().map(Secret::new).ok_or_else(|| UsernameError::Service("Fastmail didn't make the address".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_usernames() {
        let mut rules = UsernameRules { number: false, ..UsernameRules::default() };
        let word = local(&rules, None).unwrap();
        assert!(word.expose().chars().all(|c| c.is_ascii_lowercase() || c == '-'), "{}", word.expose());
        rules.number = true;
        rules.capitalize = true;
        let word = local(&rules, None).unwrap();
        assert!(
            word.expose().chars().next().unwrap().is_ascii_uppercase() && word.expose().ends_with(|c: char| c.is_ascii_digit())
        );

        rules.kind = UsernameKind::Plus;
        assert_eq!(local(&rules, None).err(), Some(UsernameError::Incomplete("your email address")));
        rules.email = "me+old@example.com".into();
        let tagged = local(&rules, None).unwrap();
        assert!(
            tagged.expose().starts_with("me+")
                && tagged.expose().ends_with("@example.com")
                && tagged.expose().len() == "me+12345678@example.com".len()
        );
        rules.by_site = true;
        assert_eq!(local(&rules, Some("https://login.github.com/x")).unwrap().expose(), "me+github.com@example.com");

        rules.kind = UsernameKind::CatchAll;
        rules.domain = "@catch.example".into();
        assert_eq!(local(&rules, Some("github.com")).unwrap().expose(), "github.com@catch.example");
        rules.by_site = false;
        assert!(local(&rules, Some("github.com")).unwrap().expose().ends_with("@catch.example"));
    }
}
