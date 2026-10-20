//! The Bitwarden client API as Vaultwarden serves it: prelogin, the token endpoint
//! (password and refresh grants, two-step login), sync and cipher changes.
//!
//! Only `https://` servers are accepted, except `http://` on loopback. Errors carry a
//! kind and at most a short, cleaned server message; never a request body.

use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use uuid::Uuid;

use crate::crypto::{CryptoError, Kdf};
use crate::model::{Cipher, Sync};
use crate::secret::Secret;

/// Linux desktop, in Bitwarden's device-type list.
const DEVICE_TYPE: &str = "8";
/// The identity server's client id for desktop apps.
const CLIENT_ID: &str = "desktop";
const MAX_BODY: usize = 64 << 20;
const MAX_ERROR_TEXT: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// Not an https URL (or http on loopback), or it carries a user name, query or fragment.
    BadServerUrl,
    Unreachable,
    /// The server's certificate wasn't accepted.
    Certificate,
    Timeout,
    /// Wrong email or master password.
    Credentials,
    /// The two-step login code was wrong or expired.
    TwoFactorCode,
    /// The server wants a new-device check this client can't do yet.
    DeviceVerification,
    RateLimited,
    /// The token was refused: sign in again.
    Unauthorized,
    /// The item changed on the server since it was last synced.
    Conflict,
    NotFound,
    TooLarge,
    /// The server answered with something this client doesn't understand.
    Protocol,
    /// The server refused for another reason; `message` is its own short explanation.
    Server {
        status: u16,
        message: String,
    },
    Crypto(CryptoError),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BadServerUrl => f.write_str("the server address must start with https://"),
            Self::Unreachable => f.write_str("couldn't reach the server"),
            Self::Certificate => f.write_str("the server's certificate isn't trusted"),
            Self::Timeout => f.write_str("the server took too long to answer"),
            Self::Credentials => f.write_str("wrong email or master password"),
            Self::TwoFactorCode => f.write_str("that two-step login code didn't work"),
            Self::DeviceVerification => f.write_str("the server asks to verify this device, which isn't supported yet"),
            Self::RateLimited => f.write_str("too many attempts; wait a minute and try again"),
            Self::Unauthorized => f.write_str("the session has ended; sign in again"),
            Self::Conflict => f.write_str("the item was changed elsewhere"),
            Self::NotFound => f.write_str("not found on the server"),
            Self::TooLarge => f.write_str("the server's answer was too large"),
            Self::Protocol => f.write_str("the server's answer wasn't understood"),
            Self::Server { status, message } if message.is_empty() => write!(f, "the server refused (HTTP {status})"),
            Self::Server { message, .. } => f.write_str(message),
            Self::Crypto(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ApiError {}

impl From<CryptoError> for ApiError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;

/// Two-step login methods, by Bitwarden's numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwoFactor {
    Authenticator,
    /// `hint` is the server's masked address, like `o***@example.com`.
    Email {
        hint: Option<String>,
    },
    Duo,
    YubiKey,
    WebAuthn,
    OrganizationDuo,
    Other(u8),
}

impl TwoFactor {
    fn of(number: u8, data: &Value) -> TwoFactor {
        match number {
            0 => TwoFactor::Authenticator,
            1 => TwoFactor::Email { hint: field(data, "email").as_str().map(clean) },
            2 => TwoFactor::Duo,
            3 => TwoFactor::YubiKey,
            6 => TwoFactor::OrganizationDuo,
            7 => TwoFactor::WebAuthn,
            n => TwoFactor::Other(n),
        }
    }

    pub fn number(&self) -> u8 {
        match self {
            TwoFactor::Authenticator => 0,
            TwoFactor::Email { .. } => 1,
            TwoFactor::Duo => 2,
            TwoFactor::YubiKey => 3,
            TwoFactor::OrganizationDuo => 6,
            TwoFactor::WebAuthn => 7,
            TwoFactor::Other(n) => *n,
        }
    }

    /// Whether this client can complete it (a typed code).
    pub fn supported(&self) -> bool {
        matches!(self, TwoFactor::Authenticator | TwoFactor::Email { .. })
    }
}

/// A two-step login answer for a retried token request.
pub struct TwoFactorAnswer {
    pub method: u8,
    pub code: Secret,
}

/// This install, as the server sees it.
#[derive(Debug, Clone)]
pub struct Device {
    pub id: Uuid,
    pub name: String,
}

pub struct Tokens {
    pub access: Secret,
    pub refresh: Secret,
    pub expires: Instant,
}

impl Tokens {
    /// True a minute before the access token runs out.
    pub fn stale(&self) -> bool {
        Instant::now() + Duration::from_secs(60) >= self.expires
    }
}

impl fmt::Debug for Tokens {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Tokens([redacted])")
    }
}

pub enum Login {
    Done(Tokens),
    /// The account has two-step login; the user picks one of these and the login is
    /// retried with its code.
    TwoFactor(Vec<TwoFactor>),
}

#[derive(Clone)]
pub struct Server {
    base: String,
    http: reqwest::Client,
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Server({})", self.base)
    }
}

impl Server {
    /// A server at `url` (Vaultwarden's root, like `https://vault.example.com`), trusting
    /// the system's certificates plus `extra_roots` (PEM), for servers with their own CA.
    pub fn new(url: &str, extra_roots: &[Vec<u8>]) -> Result<Server> {
        let base = normalize(url)?;
        let mut roots = Vec::new();
        for pem in extra_roots {
            roots.push(reqwest::Certificate::from_pem(pem).map_err(|_| ApiError::Certificate)?);
        }
        let http = reqwest::Client::builder()
            .https_only(!base.starts_with("http://"))
            .tls_certs_merge(roots)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("nixe-passwords/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| ApiError::Protocol)?;
        Ok(Server { base, http })
    }

    pub fn url(&self) -> &str {
        &self.base
    }

    pub async fn prelogin(&self, email: &str) -> Result<Kdf> {
        let resp = self.send(self.http.post(self.at("/identity/accounts/prelogin")).json(&json!({"email": email}))).await?;
        let body = read_json(resp).await?;
        kdf_of(&body)
    }

    /// The password grant. `hash` is `MasterKey::server_hash`; `answer` the two-step
    /// code when retrying after `Login::TwoFactor`.
    pub async fn login(&self, email: &str, hash: &Secret, device: &Device, answer: Option<&TwoFactorAnswer>) -> Result<Login> {
        let method;
        let mut form = vec![
            ("grant_type", "password"),
            ("username", email),
            ("password", hash.expose()),
            ("scope", "api offline_access"),
            ("client_id", CLIENT_ID),
            ("deviceType", DEVICE_TYPE),
            ("deviceName", &device.name),
        ];
        let device_id = device.id.to_string();
        form.push(("deviceIdentifier", &device_id));
        if let Some(a) = answer {
            method = a.method.to_string();
            form.extend([
                ("twoFactorProvider", method.as_str()),
                ("twoFactorToken", a.code.expose()),
                ("twoFactorRemember", "0"),
            ]);
        }
        let resp = self.send(self.http.post(self.at("/identity/connect/token")).form(&form)).await?;
        if resp.status().is_success() {
            return tokens_of(&read_json(resp).await?).map(Login::Done);
        }
        let status = resp.status().as_u16();
        let body = read_json_any(resp).await;
        match two_factor_methods(&body) {
            // Asked again after an answer: the code was wrong.
            Some(_) if answer.is_some() => return Err(ApiError::TwoFactorCode),
            Some(methods) => return Ok(Login::TwoFactor(methods)),
            None => {}
        }
        Err(login_error(status, &body, answer.is_some()))
    }

    /// Exchanges a refresh token for new tokens.
    pub async fn refresh(&self, refresh: &Secret) -> Result<Tokens> {
        let form = [("grant_type", "refresh_token"), ("client_id", CLIENT_ID), ("refresh_token", refresh.expose())];
        let resp = self.send(self.http.post(self.at("/identity/connect/token")).form(&form)).await?;
        if resp.status().is_success() {
            let mut tokens = tokens_of(&read_json(resp).await?)?;
            if tokens.refresh.is_empty() {
                tokens.refresh = Secret::new(refresh.expose());
            }
            return Ok(tokens);
        }
        let status = resp.status().as_u16();
        // An expired or revoked refresh token: the session is over.
        match status {
            400 | 401 => Err(ApiError::Unauthorized),
            _ => Err(status_error(status, &read_json_any(resp).await)),
        }
    }

    /// Asks the server to mail a two-step login code.
    pub async fn send_email_code(&self, email: &str, hash: &Secret) -> Result<()> {
        let body = json!({"email": email, "masterPasswordHash": hash.expose()});
        let resp = self.send(self.http.post(self.at("/api/two-factor/send-email-login")).json(&body)).await?;
        expect_ok(resp).await.map(|_| ())
    }

    pub async fn sync(&self, access: &Secret) -> Result<Sync> {
        let req = self
            .http
            .get(self.at("/api/sync?excludeDomains=true"))
            .bearer_auth(access.expose())
            .timeout(Duration::from_secs(180));
        let body = expect_ok(self.send(req).await?).await?;
        serde_json::from_value(body).map_err(|_| ApiError::Protocol)
    }

    pub async fn get_cipher(&self, access: &Secret, id: Uuid) -> Result<Cipher> {
        let req = self.http.get(self.at(&format!("/api/ciphers/{id}"))).bearer_auth(access.expose());
        let value = expect_ok(self.send(req).await?).await?;
        serde_json::from_value(value).map_err(|_| ApiError::Protocol)
    }

    pub async fn create_cipher(&self, access: &Secret, body: &Value) -> Result<Cipher> {
        let req = self.http.post(self.at("/api/ciphers")).bearer_auth(access.expose()).json(body);
        let value = expect_ok(self.send(req).await?).await?;
        serde_json::from_value(value).map_err(|_| ApiError::Protocol)
    }

    /// Fails with `Conflict` when the server's copy is newer than `lastKnownRevisionDate`.
    pub async fn update_cipher(&self, access: &Secret, id: Uuid, body: &Value) -> Result<Cipher> {
        let req = self.http.put(self.at(&format!("/api/ciphers/{id}"))).bearer_auth(access.expose()).json(body);
        let value = expect_ok(self.send(req).await?).await?;
        serde_json::from_value(value).map_err(|_| ApiError::Protocol)
    }

    /// Moves an item to the trash.
    pub async fn trash_cipher(&self, access: &Secret, id: Uuid) -> Result<()> {
        let req = self.http.put(self.at(&format!("/api/ciphers/{id}/delete"))).bearer_auth(access.expose());
        expect_ok(self.send(req).await?).await.map(|_| ())
    }

    pub async fn restore_cipher(&self, access: &Secret, id: Uuid) -> Result<Cipher> {
        let req = self.http.put(self.at(&format!("/api/ciphers/{id}/restore"))).bearer_auth(access.expose());
        let value = expect_ok(self.send(req).await?).await?;
        serde_json::from_value(value).map_err(|_| ApiError::Protocol)
    }

    fn at(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// Sends a request; transport failures become errors, every HTTP status is returned.
    async fn send(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        req.send().await.map_err(transport_error)
    }
}

/// Checks and tidies a server address: https (http only on loopback), no user name,
/// password, query or fragment, no trailing slash.
pub fn normalize(url: &str) -> Result<String> {
    let parsed = url::Url::parse(url.trim()).map_err(|_| ApiError::BadServerUrl)?;
    let loopback = match parsed.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => return Err(ApiError::BadServerUrl),
    };
    let scheme_ok = parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback);
    if !scheme_ok
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ApiError::BadServerUrl);
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

/// A field that Vaultwarden may send in camelCase or PascalCase.
fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    if let Some(found) = v.get(key).filter(|f| !f.is_null()) {
        return found;
    }
    let mut pascal = key.to_string();
    pascal[..1].make_ascii_uppercase();
    v.get(&pascal).unwrap_or(&Value::Null)
}

fn kdf_of(v: &Value) -> Result<Kdf> {
    let n = |k: &str| field(v, k).as_u64();
    let kind = n("kdf").or_else(|| n("kdfType")).ok_or(ApiError::Protocol)?;
    let iterations = n("kdfIterations").or_else(|| n("iterations")).ok_or(ApiError::Protocol)?;
    let memory = n("kdfMemory").or_else(|| n("memory"));
    let parallelism = n("kdfParallelism").or_else(|| n("parallelism"));
    Ok(Kdf::from_server(kind, iterations, memory, parallelism)?)
}

/// The KDF a sync reports (`userDecryption.masterPasswordUnlock.kdf`), if it has one.
pub fn sync_kdf(sync: &Sync) -> Option<Result<Kdf>> {
    let unlock = field(field(sync.extra.get("userDecryption").unwrap_or(&Value::Null), "masterPasswordUnlock"), "kdf");
    (!unlock.is_null()).then(|| kdf_of(unlock))
}

fn tokens_of(v: &Value) -> Result<Tokens> {
    let access = field(v, "access_token").as_str().ok_or(ApiError::Protocol)?;
    let refresh = field(v, "refresh_token").as_str().unwrap_or_default();
    let expires_in = field(v, "expires_in").as_u64().unwrap_or(3600);
    Ok(Tokens {
        access: Secret::new(access),
        refresh: Secret::new(refresh),
        expires: Instant::now() + Duration::from_secs(expires_in),
    })
}

fn two_factor_methods(body: &Value) -> Option<Vec<TwoFactor>> {
    let map = field(body, "twoFactorProviders2").as_object()?;
    let mut methods: Vec<TwoFactor> =
        map.iter().filter_map(|(k, data)| k.parse::<u8>().ok().map(|n| TwoFactor::of(n, data))).collect();
    methods.sort_by_key(TwoFactor::number);
    Some(methods)
}

fn login_error(status: u16, body: &Value, answered: bool) -> ApiError {
    let message = server_message(body).to_lowercase();
    match status {
        429 => ApiError::RateLimited,
        400 | 401 if message.contains("device") && message.contains("verif") => ApiError::DeviceVerification,
        400 if answered && (message.contains("two") || message.contains("token") || message.contains("code")) => {
            ApiError::TwoFactorCode
        }
        400 if field(body, "error").as_str() == Some("invalid_grant") || message.contains("password") => ApiError::Credentials,
        _ => status_error(status, body),
    }
}

fn status_error(status: u16, body: &Value) -> ApiError {
    let message = server_message(body);
    match status {
        400 if message.to_lowercase().contains("out of date") => ApiError::Conflict,
        401 | 403 => ApiError::Unauthorized,
        404 => ApiError::NotFound,
        429 => ApiError::RateLimited,
        _ => ApiError::Server { status, message: clean(&message) },
    }
}

/// The human message in a Bitwarden or Vaultwarden error body.
fn server_message(body: &Value) -> String {
    for key in ["message", "error_description", "errorModel"] {
        let v = field(body, key);
        if let Some(s) = v.as_str() {
            return s.to_string();
        }
        if let Some(s) = field(v, "message").as_str() {
            return s.to_string();
        }
    }
    String::new()
}

/// Server text shown to the user: printable, single line, short.
fn clean(text: &str) -> String {
    let flat: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let flat = flat.trim();
    match flat.char_indices().nth(MAX_ERROR_TEXT) {
        Some((i, _)) => format!("{}…", &flat[..i]),
        None => flat.to_string(),
    }
}

fn transport_error(e: reqwest::Error) -> ApiError {
    if e.is_timeout() {
        return ApiError::Timeout;
    }
    let mut source: Option<&dyn std::error::Error> = Some(&e);
    while let Some(s) = source {
        if s.to_string().to_lowercase().contains("certificate") {
            return ApiError::Certificate;
        }
        source = s.source();
    }
    if e.is_builder() { ApiError::BadServerUrl } else { ApiError::Unreachable }
}

async fn read_body(mut resp: reqwest::Response) -> Result<Vec<u8>> {
    if resp.content_length().is_some_and(|n| n > MAX_BODY as u64) {
        return Err(ApiError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(transport_error)? {
        if body.len() + chunk.len() > MAX_BODY {
            return Err(ApiError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn read_json(resp: reqwest::Response) -> Result<Value> {
    let body = read_body(resp).await?;
    if body.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&body).map_err(|_| ApiError::Protocol)
}

/// An error body, which may be JSON, HTML or empty.
async fn read_json_any(resp: reqwest::Response) -> Value {
    read_json(resp).await.unwrap_or(Value::Null)
}

async fn expect_ok(resp: reqwest::Response) -> Result<Value> {
    let status = resp.status().as_u16();
    if (200..300).contains(&status) {
        return read_json(resp).await;
    }
    Err(status_error(status, &read_json_any(resp).await))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls() {
        assert_eq!(normalize("https://vault.example.com/").unwrap(), "https://vault.example.com");
        assert_eq!(normalize(" https://example.com/vw ").unwrap(), "https://example.com/vw");
        assert_eq!(normalize("http://127.0.0.1:8087").unwrap(), "http://127.0.0.1:8087");
        assert_eq!(normalize("http://localhost:8080/").unwrap(), "http://localhost:8080");
        assert_eq!(normalize("http://[::1]:80").unwrap(), "http://[::1]");
        for bad in [
            "http://vault.example.com",
            "http://192.168.1.2",
            "https://user:pw@vault.example.com",
            "https://vault.example.com/?x=1",
            "https://vault.example.com/#frag",
            "ftp://vault.example.com",
            "vault.example.com",
            "",
        ] {
            assert_eq!(normalize(bad), Err(ApiError::BadServerUrl), "{bad}");
        }
    }

    #[test]
    fn two_factor_answer_parsing() {
        let body = json!({
            "error": "invalid_grant", "error_description": "Two factor required.",
            "TwoFactorProviders": ["1", "0"],
            "TwoFactorProviders2": {"1": {"Email": "o***@example.com"}, "0": null, "7": {"challenge": "x"}},
        });
        let methods = two_factor_methods(&body).unwrap();
        assert_eq!(
            methods,
            vec![TwoFactor::Authenticator, TwoFactor::Email { hint: Some("o***@example.com".into()) }, TwoFactor::WebAuthn]
        );
        assert!(methods[0].supported() && methods[1].supported() && !methods[2].supported());
        assert!(two_factor_methods(&json!({"error": "invalid_grant"})).is_none());
    }

    #[test]
    fn login_errors() {
        let wrong = json!({"error": "invalid_grant", "error_description": "Username or password is incorrect. Try again"});
        assert_eq!(login_error(400, &wrong, false), ApiError::Credentials);
        assert_eq!(login_error(429, &Value::Null, false), ApiError::RateLimited);
        let device = json!({"error": "device_error", "error_description": "New device verification required"});
        assert_eq!(login_error(400, &device, false), ApiError::DeviceVerification);
        let code = json!({"error": "invalid_grant", "error_description": "Invalid TOTP code"});
        assert_eq!(login_error(400, &code, true), ApiError::TwoFactorCode);
    }

    #[test]
    fn status_errors() {
        let stale = json!({"message": "The client copy of this cipher is out of date. Resync the client and try again."});
        assert_eq!(status_error(400, &stale), ApiError::Conflict);
        assert_eq!(status_error(401, &Value::Null), ApiError::Unauthorized);
        assert_eq!(status_error(404, &Value::Null), ApiError::NotFound);
        let long = json!({"message": format!("bad\n{}", "x".repeat(500))});
        let ApiError::Server { status: 500, message } = status_error(500, &long) else { panic!() };
        assert!(!message.contains('\n') && message.chars().count() <= MAX_ERROR_TEXT + 1);
    }

    #[test]
    fn prelogin_and_sync_kdf() {
        assert_eq!(kdf_of(&json!({"kdf": 0, "kdfIterations": 600000})).unwrap(), Kdf::Pbkdf2 { iterations: 600_000 });
        assert_eq!(
            kdf_of(&json!({"Kdf": 1, "KdfIterations": 3, "KdfMemory": 64, "KdfParallelism": 4})).unwrap(),
            Kdf::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 }
        );
        let path = format!("{}/tests/fixtures/argon2-sync.json", env!("CARGO_MANIFEST_DIR"));
        let sync: Sync = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(sync_kdf(&sync).unwrap().unwrap(), Kdf::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 });
    }
}
