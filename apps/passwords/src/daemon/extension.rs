//! The paired extension's requests beyond filling a login (docs/NATIVE_MESSAGING.md):
//! the popup's search and item view, cards and identities for checkout and address
//! forms, the save prompt's check and the never-save list, adding the page to an item,
//! security flags, universal sign-on, and passkeys.
//!
//! What a request may get is decided here, not in the extension: names and usernames
//! from across the vault (search), secret fields only for the page's own items or an
//! item the user confirmed for the page, nothing for plain-http pages but addresses
//! saved with `http://`.

use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nyx_passwords_core::edit::{CustomDraft, LoginDraft, Place};
use nyx_passwords_core::matching;
use nyx_passwords_core::model::Kind;
use nyx_passwords_core::passkey::{self, NewPasskey};
use nyx_passwords_core::secret::Secret;
use nyx_passwords_core::session::Session;
use nyx_passwords_core::vault::{Entry, Field, reveal_for_use, specs};
use nyx_passwords_proto::Error as Code;
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

use super::vault::{Failure, State, online, parse_id};

pub use nyx_passwords_proto::custom::{NO_FILL_ON_LOAD, PROVIDERS, SIGN_IN_WITH};
const SEARCH_MAX: usize = 50;
/// The popup's list of the whole vault (names and usernames only).
const LIST_MAX: usize = 1000;
const NEVER_SAVE: &str = "never_save";

pub(super) fn error(code: Code) -> Value {
    json!({"error": code.short()})
}

/// The request's page: http or https only.
pub(super) fn page(request: &Value) -> Option<Url> {
    request["url"].as_str().and_then(|u| Url::parse(u).ok()).filter(|u| matches!(u.scheme(), "http" | "https"))
}

/// The value of an item's custom field `name`, if it has one.
pub(super) fn custom(session: &Session, id: Uuid, name: &str) -> Option<String> {
    let c = session.snapshot.ciphers.iter().find(|c| c.id == id)?;
    let mut key = session.keys.item(c.organization_id, c.key.as_deref()).ok()?;
    let n = c
        .fields
        .iter()
        .flatten()
        .position(|f| key.decrypt_opt(f.name.as_deref()).ok().flatten().is_some_and(|v| v.expose() == name))?;
    reveal_for_use(&session.keys, &session.snapshot, id, Field::Custom(n)).ok().map(|v| v.expose().to_string())
}

fn summary(session: &Session, e: &Entry) -> Value {
    json!({
        "id": e.id, "name": e.name.expose(), "username": e.username.as_ref().map_or("", |u| u.expose()),
        "host": e.host, "kind": kind_name(e.kind), "has_totp": e.has_totp, "favorite": e.favorite, "reprompt": e.reprompt,
        "sub": sub_line(session, e),
    })
}

/// What a card or identity shows under its name: the brand and last four digits, or
/// the person's name.
fn sub_line(session: &Session, e: &Entry) -> String {
    let get = |name: &str| {
        nyx_passwords_core::vault::sub_field(name)
            .and_then(|f| reveal_for_use(&session.keys, &session.snapshot, e.id, f).ok())
            .map(|v| v.expose().to_string())
            .unwrap_or_default()
    };
    match e.kind {
        Kind::Card => {
            let number = get("card.number");
            let last = number.get(number.len().saturating_sub(4)..).unwrap_or_default().to_string();
            format!("{} •••• {last}", get("card.brand")).trim().to_string()
        }
        Kind::Identity => format!("{} {}", get("identity.firstName"), get("identity.lastName")).trim().to_string(),
        _ => String::new(),
    }
}

/// The suite's theme as Passwords shows it, so the extension's pages look like the app.
pub fn theme() -> Value {
    let t = nyx_theme::suite_theme("passwords");
    let (p, l) = (&t.palette, &t.look);
    let suite = nyx_theme::read_suite().unwrap_or_default();
    json!({
        "light": p.light, "bg": p.bg, "panel": l.panel, "card": l.card, "raised": l.raised, "popover": l.popover,
        "surface": p.surface, "text": p.text, "dim": p.dim_text, "tertiary": l.text_tertiary, "accent": p.accent,
        "border": p.border, "divider": l.divider, "danger": p.danger, "warning": l.warning, "success": l.success,
        "hover": l.hover, "selection": l.selection, "font_ui": l.font.ui, "font_mono": l.font.mono,
        "radius_small": l.shape.radius_small, "radius_card": l.shape.radius_card, "radius_dialog": l.shape.radius_dialog,
        "swatches": l.swatches.iter().map(|(_, c)| c.clone()).collect::<Vec<_>>(), "text_scale": suite.text_scale,
    })
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Login => "login",
        Kind::Note => "note",
        Kind::Card => "card",
        Kind::Identity => "identity",
        Kind::SshKey => "ssh",
        Kind::Other(_) => "other",
    }
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64url(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok()
}

/// The never-save list: hosts the user said not to offer saving for. Kept encrypted
/// with the user key beside the vault, like everything else that names sites.
pub(super) fn never_save(st: &State) -> Vec<String> {
    let Some(session) = st.session.as_ref() else { return Vec::new() };
    let Some(stored) = st.store.setting(NEVER_SAVE).ok().flatten() else { return Vec::new() };
    let plain = session.keys.item(None, None).and_then(|mut k| k.decrypt(&stored));
    plain.ok().and_then(|p| serde_json::from_str(p.expose()).ok()).unwrap_or_default()
}

fn add_never_save(st: &mut State, host: &str) -> Result<(), Failure> {
    let mut hosts = never_save(st);
    if !hosts.iter().any(|h| h == host) {
        hosts.push(host.to_string());
    }
    let session = st.session.as_ref().ok_or_else(super::vault::locked)?;
    let encrypted = session
        .keys
        .item(None, None)
        .and_then(|mut k| k.encrypt(&serde_json::to_string(&hosts).unwrap_or_default()))
        .map_err(|e| Failure::new(Code::Failed, e.to_string()))?;
    st.store.set_setting(NEVER_SAVE, &encrypted).map_err(|e| Failure::new(Code::Failed, e.to_string()))
}

fn same_site(frame: Option<&str>, page: &Url) -> bool {
    let Some(frame) = frame.filter(|f| !f.is_empty()) else { return true };
    Url::parse(frame).ok().is_some_and(|f| {
        matches!(f.scheme(), "http" | "https")
            && f.host_str().zip(page.host_str()).is_some_and(|(a, b)| matching::base_domain(a) == matching::base_domain(b))
    })
}

/// Whether a login may be filled as `page` loads: it's https, the login isn't marked
/// against it, and one of its addresses names this very host (a base-domain match alone
/// isn't enough) or matches under an explicit rule.
pub(super) fn fill_on_load_ok(session: &Session, e: &Entry, page: &Url) -> bool {
    if page.scheme() != "https" || e.reprompt {
        return false;
    }
    let host = page.host_str().unwrap_or_default().to_ascii_lowercase();
    let exact = e.uris.iter().zip(&e.uri_rules).any(|(u, rule)| match rule.unwrap_or(matching::DOMAIN) {
        matching::DOMAIN => nyx_passwords_core::vault::host_of(u.expose()).is_some_and(|h| h == host.trim_start_matches("www.")),
        _ => matching::matches(*rule, u.expose(), page),
    });
    exact && custom(session, e.id, NO_FILL_ON_LOAD).as_deref() != Some("true")
}

/// Requests answered from the vault as it is, under the lock.
pub(super) fn read(st: &mut State, pairing: &str, request: &Value) -> Value {
    let r = request["r"].as_str().unwrap_or_default();
    let fills_ok = |st: &mut State| st.browser.fills_left(pairing);
    match r {
        "settings" => {
            let s = st.settings.refresh();
            json!({"fill_on_load": s.fill_on_load, "passkeys": s.browser_passkeys, "icons": s.icons, "theme": theme()})
        }
        "search" => {
            let Some(session) = st.session.as_ref() else { return error(Code::Locked) };
            let query: String = request["q"].as_str().unwrap_or_default().chars().take(256).collect();
            let hits: Vec<&Entry> = if query.trim().is_empty() {
                let mut all: Vec<&Entry> = session.view.entries.iter().filter(|e| !e.deleted && e.readable).collect();
                all.sort_by_key(|e| !e.favorite);
                all.into_iter().take(LIST_MAX).collect()
            } else {
                session.view.search(&query, SEARCH_MAX)
            };
            json!({"items": hits.into_iter().map(|e| summary(session, e)).collect::<Vec<_>>()})
        }
        "item" => {
            let Some(session) = st.session.as_ref() else { return error(Code::Locked) };
            let Some(e) = request["id"].as_str().and_then(|i| parse_id(i).ok()).and_then(|id| session.view.get(id)) else {
                return error(Code::NotFound);
            };
            let mut v = summary(session, e);
            v["has_passkey"] = session.passkeys(e.id).is_ok_and(|p| !p.is_empty()).into();
            v["uris"] = e.uris.iter().map(|u| u.expose()).collect::<Vec<_>>().into();
            v["has_password"] = e.has_password.into();
            v["editable"] = e.editable.into();
            v["sign_in_with"] = custom(session, e.id, SIGN_IN_WITH).into();
            v
        }
        "cards" | "identities" => {
            let Some(page) = page(request) else { return error(Code::NoUrl) };
            if r == "cards" && page.scheme() != "https" {
                return json!({"items": []});
            }
            let Some(session) = st.session.as_ref() else { return error(Code::Locked) };
            let kind = if r == "cards" { Kind::Card } else { Kind::Identity };
            let items: Vec<Value> = session
                .view
                .entries
                .iter()
                .filter(|e| e.kind == kind && !e.deleted && e.readable)
                .map(|e| json!({"id": e.id, "name": e.name.expose(), "sub": sub_line(session, e), "reprompt": e.reprompt}))
                .collect();
            json!({"items": items})
        }
        "fill_card" | "fill_identity" => {
            let Some(page) = page(request) else { return error(Code::NoUrl) };
            if r == "fill_card" && page.scheme() != "https" {
                return error(Code::Denied);
            }
            if !same_site(request["frame"].as_str(), &page) {
                return error(Code::Denied);
            }
            let kind = if r == "fill_card" { Kind::Card } else { Kind::Identity };
            let Some(id) = request["id"].as_str().and_then(|i| parse_id(i).ok()) else { return error(Code::NotFound) };
            let Some(session) = st.session.as_ref() else { return error(Code::Locked) };
            let Some(e) = session.view.get(id).filter(|e| e.kind == kind && !e.deleted) else { return error(Code::NotFound) };
            if e.reprompt {
                return error(Code::Reprompt);
            }
            let mut fields = serde_json::Map::new();
            for spec in specs(kind) {
                if let Ok(v) = reveal_for_use(&session.keys, &session.snapshot, id, Field::Sub(spec)) {
                    fields.insert(spec.key.to_string(), Value::String(v.expose().to_string()));
                }
            }
            if !fills_ok(st) {
                return error(Code::RateLimited);
            }
            Value::Object(fields)
        }
        "check" => {
            let Some(page) = page(request) else { return error(Code::NoUrl) };
            let host = page.host_str().unwrap_or_default().trim_start_matches("www.").to_string();
            if never_save(st).contains(&host) {
                return json!({"state": "excluded"});
            }
            let Some(session) = st.session.as_ref() else { return error(Code::Locked) };
            let username = request["username"].as_str().unwrap_or_default().trim();
            let password = request["password"].as_str().unwrap_or_default();
            let found =
                session.view.matching(&page).into_iter().find(|e| e.username.as_ref().map_or("", |u| u.expose()) == username);
            match found {
                None => json!({"state": "new"}),
                Some(e) => {
                    let current = reveal_for_use(&session.keys, &session.snapshot, e.id, Field::Password).ok();
                    if current.is_some_and(|c| c.expose() == password) {
                        json!({"state": "same"})
                    } else if e.reprompt || !e.editable || !e.view_password {
                        json!({"state": "locked"})
                    } else {
                        json!({"state": "changed", "id": e.id})
                    }
                }
            }
        }
        "exclude" => {
            let Some(page) = page(request) else { return error(Code::NoUrl) };
            let host = page.host_str().unwrap_or_default().trim_start_matches("www.").to_string();
            match add_never_save(st, &host) {
                Ok(()) => json!({}),
                Err(f) => error(f.kind),
            }
        }
        "security" => {
            let ids: Vec<Uuid> = request["ids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|i| i.as_str()?.parse().ok())
                .take(SEARCH_MAX)
                .collect();
            let st = &mut *st;
            let Some(session) = st.session.as_ref() else { return error(Code::Locked) };
            let found = nyx_passwords_core::audit::audit(
                &session.keys,
                &session.snapshot,
                std::time::SystemTime::now(),
                &mut st.strength,
            );
            let flags: Vec<Value> = found
                .iter()
                .filter(|f| ids.contains(&f.id))
                .map(|f| json!({"id": f.id, "weak": f.weak, "reused": f.reused, "old": f.age_days.is_some()}))
                .collect();
            json!({"items": flags})
        }
        "passkey.list" => {
            if !st.settings.refresh().browser_passkeys {
                return error(Code::Denied);
            }
            let Some(page) = page(request) else { return error(Code::NoUrl) };
            let rp_id = request["rp_id"].as_str().unwrap_or_default().to_ascii_lowercase();
            if !matching::valid_rp_id(&rp_id, &page) {
                return error(Code::Denied);
            }
            let allow: Vec<Vec<u8>> =
                request["allow"].as_array().into_iter().flatten().filter_map(|a| unb64url(a.as_str()?)).collect();
            let Some(session) = st.session.as_ref() else { return error(Code::Locked) };
            let mut out = Vec::new();
            for e in session.view.entries.iter().filter(|e| e.kind == Kind::Login && !e.deleted && e.readable) {
                for p in session.passkeys(e.id).unwrap_or_default() {
                    let Some(bytes) = passkey::credential_bytes(&p.credential_id) else { continue };
                    if p.rp_id != rp_id || (!allow.is_empty() && !allow.contains(&bytes)) {
                        continue;
                    }
                    out.push(json!({"id": e.id, "name": e.name.expose(), "credential_id": b64url(&bytes), "user_name": p.user_name, "reprompt": e.reprompt}));
                }
            }
            json!({"items": out})
        }
        "passkey.get" => passkey_get(st, pairing, request),
        _ => error(Code::Failed),
    }
}

fn passkey_get(st: &mut State, pairing: &str, request: &Value) -> Value {
    if !st.settings.refresh().browser_passkeys {
        return error(Code::Denied);
    }
    let Some(page) = page(request) else { return error(Code::NoUrl) };
    let rp_id = request["rp_id"].as_str().unwrap_or_default().to_ascii_lowercase();
    if !matching::valid_rp_id(&rp_id, &page) || request["confirmed"] != true {
        return error(Code::Denied);
    }
    let (Some(id), Some(credential), Some(hash)) = (
        request["id"].as_str().and_then(|i| parse_id(i).ok()),
        request["credential_id"].as_str().and_then(unb64url),
        request["client_data_hash"].as_str().and_then(unb64url),
    ) else {
        return error(Code::NotFound);
    };
    if hash.len() != 32 {
        return error(Code::Failed);
    }
    if !st.browser.fills_left(pairing) {
        return error(Code::RateLimited);
    }
    let Some(session) = st.session.as_ref() else { return error(Code::Locked) };
    if session.view.get(id).is_some_and(|e| e.reprompt) {
        return error(Code::Reprompt);
    }
    let Some(c) = session.snapshot.ciphers.iter().find(|c| c.id == id && !c.is_deleted()) else { return error(Code::NotFound) };
    let Ok(mut key) = session.keys.item(c.organization_id, c.key.as_deref()) else { return error(Code::Failed) };
    // An unlocked vault is the user verification, as the official clients count it.
    match passkey::assert(&mut key, c, &passkey::credential_text(&credential), &rp_id, &hash, true) {
        Ok(a) => json!({
            "credential_id": b64url(&a.credential_id), "authenticator_data": b64url(&a.authenticator_data),
            "signature": b64url(&a.signature), "user_handle": b64url(&a.user_handle),
        }),
        Err(passkey::PasskeyError::WrongSite) => error(Code::Denied),
        Err(_) => error(Code::Failed),
    }
}

/// Requests that change the vault: they wait for the server.
pub(super) async fn edit(st: &mut State, pairing: &str, request: &Value) -> Value {
    let r = request["r"].as_str().unwrap_or_default();
    let Some(page) = page(request) else { return error(Code::NoUrl) };
    if !st.browser.fills_left(pairing) {
        return error(Code::RateLimited);
    }
    let Ok((server, refresh)) = online(st) else { return error(Code::Failed) };
    st.edits += 1;
    let Some(session) = st.session.as_mut() else { return error(Code::Locked) };
    let result = match r {
        "add_uri" => {
            let Some(id) = request["id"].as_str().and_then(|i| parse_id(i).ok()) else { return error(Code::NotFound) };
            let Some(e) = session.view.get(id).filter(|e| e.kind == Kind::Login) else { return error(Code::NotFound) };
            if !e.editable {
                return error(Code::Denied);
            }
            let get = |field| reveal_for_use(&session.keys, &session.snapshot, id, field).ok();
            let mut uris: Vec<Secret> = e.uris.iter().map(|u| Secret::new(u.expose())).collect();
            uris.push(Secret::new(page.origin().ascii_serialization()));
            let draft = LoginDraft {
                name: Secret::new(e.name.expose()),
                username: e.username.as_ref().map(|u| Secret::new(u.expose())),
                password: get(Field::Password),
                totp: get(Field::TotpSeed),
                uris,
                notes: get(Field::Notes),
                folder: e.folder,
                favorite: e.favorite,
                reprompt: e.reprompt,
                place: Place { organization: e.organization, collections: e.collections.clone() },
                custom: None,
            };
            session.update_login(&mut st.store, &server, &refresh, id, &draft).await.map(|()| json!({"id": id}))
        }
        "signin.save" => {
            let provider = request["provider"].as_str().unwrap_or_default();
            if !PROVIDERS.iter().any(|(id, _)| *id == provider) {
                return error(Code::Failed);
            }
            let known = session
                .view
                .matching(&page)
                .into_iter()
                .any(|e| custom(session, e.id, SIGN_IN_WITH).as_deref() == Some(provider));
            if known {
                return json!({"saved": "same"});
            }
            let username = request["username"].as_str().unwrap_or_default().trim();
            let host = page.host_str().unwrap_or_default().trim_start_matches("www.").to_string();
            let draft = LoginDraft {
                name: Secret::new(host),
                username: (!username.is_empty()).then(|| Secret::new(username)),
                password: None,
                totp: None,
                uris: vec![Secret::new(page.origin().ascii_serialization())],
                notes: None,
                folder: None,
                favorite: false,
                reprompt: false,
                place: Place::default(),
                custom: Some(vec![CustomDraft {
                    name: Secret::new(SIGN_IN_WITH),
                    value: Some(Secret::new(provider)),
                    kind: 0,
                    from: None,
                }]),
            };
            session.create_login(&mut st.store, &server, &refresh, &draft).await.map(|id| json!({"saved": "created", "id": id}))
        }
        "passkey.create" => {
            let settings = st.settings.refresh().clone();
            if !settings.browser_passkeys || request["confirmed"] != true {
                return error(Code::Denied);
            }
            let rp_id = request["rp_id"].as_str().unwrap_or_default().to_ascii_lowercase();
            if !matching::valid_rp_id(&rp_id, &page) {
                return error(Code::Denied);
            }
            let (Some(user_id), Some(hash)) =
                (request["user_id"].as_str().and_then(unb64url), request["client_data_hash"].as_str().and_then(unb64url))
            else {
                return error(Code::Failed);
            };
            if hash.len() != 32 || user_id.len() > 64 {
                return error(Code::Failed);
            }
            // A passkey the site already has for this account: it asked not to make another.
            let exclude: Vec<Vec<u8>> =
                request["exclude"].as_array().into_iter().flatten().filter_map(|a| unb64url(a.as_str()?)).collect();
            let existing = session.view.entries.iter().filter(|e| e.kind == Kind::Login && !e.deleted).any(|e| {
                session.passkeys(e.id).unwrap_or_default().iter().any(|p| {
                    p.rp_id == rp_id && passkey::credential_bytes(&p.credential_id).is_some_and(|b| exclude.contains(&b))
                })
            });
            if existing {
                return json!({"error": "Excluded"});
            }
            let into = request["into"].as_str().and_then(|i| parse_id(i).ok());
            if into.is_some_and(|id| !session.view.matching(&page).iter().any(|e| e.id == id)) {
                return error(Code::Denied);
            }
            let s = |k: &str| request[k].as_str().unwrap_or_default().chars().take(256).collect::<String>();
            let (rp_name, user_name, display) = (s("rp_name"), s("user_name"), s("user_display_name"));
            let new = NewPasskey {
                rp_id: &rp_id,
                rp_name: &rp_name,
                user_handle: &user_id,
                user_name: &user_name,
                user_display_name: &display,
                discoverable: request["rk"] != false,
                verified: true,
            };
            let made = match passkey::create(&new, &nyx_passwords_core::edit::timestamp()) {
                Ok(m) => m,
                Err(_) => return error(Code::Failed),
            };
            session.save_passkey(&mut st.store, &server, &refresh, into, &page, &made).await.map(|id| {
                json!({
                    "id": id, "credential_id": b64url(&made.credential_id), "attestation_object": b64url(&made.attestation_object),
                    "authenticator_data": b64url(&made.authenticator_data), "public_key": b64url(&made.public_key), "algorithm": -7,
                })
            })
        }
        _ => return error(Code::Failed),
    };
    st.last_used = Instant::now();
    match result {
        Ok(v) => v,
        Err(e) => error(Failure::from(e).kind),
    }
}
