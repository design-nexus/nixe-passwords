//! Whether an item's web address belongs to a page, under Bitwarden's match rules
//! (each address may carry its own): base domain (the default), host, starts with,
//! exact, regular expression, never.
//!
//! One rule is stricter than Bitwarden's: a page served over plain `http://` matches
//! only addresses written with `http://`, so a downgraded or intercepted page doesn't
//! get credentials saved for the secure site.

use url::Url;

/// Bitwarden's `UriMatchType` numbers.
pub const DOMAIN: i64 = 0;
pub const HOST: i64 = 1;
pub const STARTS_WITH: i64 = 2;
pub const EXACT: i64 = 3;
pub const REGEX: i64 = 4;
pub const NEVER: i64 = 5;

/// Regular expressions from the vault are compiled with these limits.
const REGEX_SIZE: usize = 1 << 16;

/// Whether `item_uri` (as saved, under `rule`; `None` is the default, base domain)
/// matches the page at `page`.
pub fn matches(rule: Option<i64>, item_uri: &str, page: &Url) -> bool {
    let item_uri = item_uri.trim();
    if item_uri.is_empty() || !matches!(page.scheme(), "http" | "https") {
        return false;
    }
    if page.scheme() == "http" && !item_uri.to_ascii_lowercase().starts_with("http://") {
        return false;
    }
    match rule.unwrap_or(DOMAIN) {
        DOMAIN => match (web_url(item_uri), page.host_str()) {
            (Some(item), Some(page_host)) => item.host_str().is_some_and(|h| base_domain(h) == base_domain(page_host)),
            _ => false,
        },
        HOST => match web_url(item_uri) {
            Some(item) => {
                item.host_str().is_some()
                    && item.host_str().map(str::to_ascii_lowercase) == page.host_str().map(str::to_ascii_lowercase)
                    && item.port_or_known_default() == page.port_or_known_default()
            }
            None => false,
        },
        STARTS_WITH => page.as_str().starts_with(item_uri),
        EXACT => page.as_str() == item_uri || web_url(item_uri).is_some_and(|i| i.as_str() == page.as_str()),
        REGEX => regex::RegexBuilder::new(item_uri)
            .size_limit(REGEX_SIZE)
            .dfa_size_limit(REGEX_SIZE)
            .build()
            .is_ok_and(|re| re.is_match(page.as_str())),
        // NEVER, and rules this client doesn't know.
        _ => false,
    }
}

/// An item address as a web URL: a missing scheme means https; other schemes
/// (`androidapp://`, `iosapp://`) aren't web addresses.
fn web_url(uri: &str) -> Option<Url> {
    let parsed = Url::parse(uri).ok().filter(|u| u.has_host()).or_else(|| Url::parse(&format!("https://{uri}")).ok())?;
    matches!(parsed.scheme(), "http" | "https").then_some(parsed)
}

/// The registrable domain ("example.co.uk" for "login.example.co.uk"), lowercase. An
/// IP address, `localhost` or a name without a public suffix is its own base domain.
pub fn base_domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return host;
    }
    match psl::domain_str(&host) {
        Some(d) => d.to_string(),
        None => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(u: &str) -> Url {
        Url::parse(u).unwrap()
    }

    #[test]
    fn base_domains() {
        assert_eq!(base_domain("login.github.com"), "github.com");
        assert_eq!(base_domain("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(base_domain("user.github.io"), "user.github.io");
        assert_eq!(base_domain("192.168.1.1"), "192.168.1.1");
        assert_eq!(base_domain("localhost"), "localhost");
        assert_eq!(base_domain("GitHub.COM."), "github.com");
    }

    #[test]
    fn domain_rule() {
        let p = page("https://github.com/login?return=/x");
        assert!(matches(None, "https://github.com/session", &p));
        assert!(matches(None, "github.com", &p));
        assert!(matches(Some(DOMAIN), "https://gist.github.com", &p));
        assert!(!matches(None, "https://github.io", &p));
        assert!(!matches(None, "https://evil-github.com", &p));
        assert!(!matches(None, "https://github.com.evil.com", &p));
        // One GitHub Pages site doesn't match another: github.io is a public suffix.
        assert!(!matches(None, "https://alice.github.io", &page("https://mallory.github.io/")));
        assert!(!matches(None, "androidapp://com.github.android", &p));
        assert!(!matches(None, "", &p));
    }

    #[test]
    fn plain_http_pages() {
        let p = page("http://github.com/login");
        assert!(!matches(None, "https://github.com", &p));
        assert!(!matches(None, "github.com", &p));
        assert!(matches(None, "http://github.com", &p));
        assert!(matches(None, "http://192.168.1.1", &page("http://192.168.1.1/admin")));
        assert!(!matches(None, "https://github.com", &page("ftp://github.com/")));
        assert!(!matches(None, "https://github.com", &page("file:///etc/passwd")));
    }

    #[test]
    fn other_rules() {
        let p = page("https://login.example.com:8443/app/sign-in");
        assert!(matches(Some(HOST), "https://login.example.com:8443", &p));
        assert!(!matches(Some(HOST), "https://login.example.com", &p));
        assert!(!matches(Some(HOST), "https://example.com:8443", &p));
        assert!(matches(Some(STARTS_WITH), "https://login.example.com:8443/app/", &p));
        assert!(!matches(Some(STARTS_WITH), "https://login.example.com:8443/admin", &p));
        assert!(matches(Some(EXACT), "https://login.example.com:8443/app/sign-in", &p));
        assert!(!matches(Some(EXACT), "https://login.example.com:8443/app", &p));
        assert!(matches(Some(REGEX), r"^https://login\.example\.com(:\d+)?/app/", &p));
        assert!(!matches(Some(REGEX), r"^https://other\.", &p));
        assert!(!matches(Some(REGEX), "(unclosed", &p));
        assert!(!matches(Some(NEVER), "https://login.example.com:8443", &p));
        assert!(!matches(Some(42), "https://login.example.com:8443", &p));
    }

    #[test]
    fn huge_regexes_are_refused() {
        let p = page("https://example.com/");
        assert!(!matches(Some(REGEX), &format!("({}){{500}}", "a|".repeat(200) + "b"), &p));
    }
}
