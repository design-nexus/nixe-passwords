//! The notification hub on the throwaway Vaultwarden: a change made in `bw` arrives as
//! an event; this client's own change doesn't.
//!
//!   apps/passwords/scripts/test-server.sh start
//!   NYX_PW_TEST_SERVER=https://127.0.0.1:8087 NYX_PW_TEST_CA=$PWD/target/vaultwarden-test/ca.pem \
//!     cargo test -p nyx-passwords-core --test live -- --ignored

mod common;

use std::num::NonZeroU32;
use std::time::Duration;

use nyx_passwords_core::api::Server;
use nyx_passwords_core::edit::{LoginDraft, Place};
use nyx_passwords_core::live::Event;
use nyx_passwords_core::secret::Secret;
use nyx_passwords_core::session::{self, SignIn};
use nyx_passwords_core::store::Store;
use serde_json::json;

#[tokio::test]
#[ignore = "needs NYX_PW_TEST_SERVER"]
async fn hub_reports_changes_made_elsewhere() {
    let email = common::fresh_email("live");
    let password = "correct horse live battery";
    common::register(&email, password, &bitwarden_crypto::Kdf::PBKDF2 { iterations: NonZeroU32::new(600_000).unwrap() }).await;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
    let server = Server::new(&common::server_url(), &[common::ca_pem()]).unwrap();
    let SignIn::Done(mut s) =
        session::sign_in(&mut store, &server, &email, &Secret::new(password), "nyx test", None).await.unwrap()
    else {
        panic!("two-step login")
    };
    let refresh = Secret::new(s.refresh_token().unwrap().expose());
    let access = Secret::new(s.access(&server, &refresh).await.unwrap().expose());
    let mut hub = server.connect_hub(&access, s.account.device_id).await.unwrap();

    // Our own edit: the hub stays quiet about it.
    let draft = LoginDraft {
        name: Secret::new("Mine"),
        username: None,
        password: Some(Secret::new("canary-live-Pw!9")),
        totp: None,
        uris: vec![],
        notes: None,
        folder: None,
        favorite: false,
        reprompt: false,
        place: Place::default(),
        custom: None,
    };
    s.create_login(&mut store, &server, &refresh, &draft).await.unwrap();
    let quiet = tokio::time::timeout(Duration::from_secs(3), hub.next()).await;
    assert!(quiet.is_err() || quiet == Ok(Some(Event::Idle)), "{quiet:?}");

    // bw's edit: an event.
    let bw = common::Bw::login(&email, password);
    bw.create(&json!({"type": 2, "name": "From bw", "notes": "x", "secureNote": {"type": 0}, "favorite": false, "reprompt": 0}));
    let heard = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match hub.next().await {
                Some(Event::Idle) => continue,
                other => return other,
            }
        }
    })
    .await
    .expect("an event within 10 s");
    assert_eq!(heard, Some(Event::Changed));
}

/// Equivalent domains come with the sync: the server's global groups, less the ones the
/// account turned off, plus its own.
#[tokio::test]
#[ignore = "needs NYX_PW_TEST_SERVER"]
async fn equivalent_domains_from_the_server() {
    let email = common::fresh_email("domains");
    let password = "correct horse domains battery";
    common::register(&email, password, &bitwarden_crypto::Kdf::PBKDF2 { iterations: NonZeroU32::new(600_000).unwrap() }).await;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
    let server = Server::new(&common::server_url(), &[common::ca_pem()]).unwrap();
    let SignIn::Done(mut s) =
        session::sign_in(&mut store, &server, &email, &Secret::new(password), "nyx test", None).await.unwrap()
    else {
        panic!("two-step login")
    };
    let refresh = Secret::new(s.refresh_token().unwrap().expose());
    let apple = |s: &session::Session| {
        s.view.equivalents.iter().any(|g| g.contains(&"apple.com".into()) && g.contains(&"icloud.com".into()))
    };
    assert!(apple(&s), "the global apple.com / icloud.com group");
    let mut draft = LoginDraft {
        name: Secret::new("Apple"),
        username: None,
        password: Some(Secret::new("canary-apple-Pw!9")),
        totp: None,
        uris: vec![Secret::new("https://appleid.apple.com")],
        notes: None,
        folder: None,
        favorite: false,
        reprompt: false,
        place: Place::default(),
        custom: None,
    };
    s.create_login(&mut store, &server, &refresh, &draft).await.unwrap();
    let icloud = url::Url::parse("https://www.icloud.com/").unwrap();
    assert_eq!(s.view.matching(&icloud).len(), 1);

    // Turn the global group off and add one of our own.
    let raw: serde_json::Value = common::http()
        .get(format!("{}/api/settings/domains", common::server_url()))
        .bearer_auth(s.access(&server, &refresh).await.unwrap().expose())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let globals = raw.get("globalEquivalentDomains").or_else(|| raw.get("GlobalEquivalentDomains")).unwrap();
    let kind = globals
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["domains"].as_array().or_else(|| g["Domains"].as_array()).unwrap().iter().any(|d| d == "icloud.com"))
        .map(|g| g.get("type").or_else(|| g.get("Type")).unwrap().clone())
        .unwrap();
    let access = Secret::new(s.access(&server, &refresh).await.unwrap().expose());
    let resp = common::http()
        .put(format!("{}/api/settings/domains", common::server_url()))
        .bearer_auth(access.expose())
        .json(&json!({"equivalentDomains": [["example.com", "example.net"]], "excludedGlobalEquivalentDomains": [kind]}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    s.sync(&mut store, &server, &refresh).await.unwrap();
    assert!(!apple(&s));
    assert!(s.view.matching(&icloud).is_empty());
    draft.name = Secret::new("Example");
    draft.uris = vec![Secret::new("https://login.example.com")];
    s.create_login(&mut store, &server, &refresh, &draft).await.unwrap();
    assert_eq!(s.view.matching(&url::Url::parse("https://example.net/").unwrap()).len(), 1);
}

#[tokio::test]
#[ignore = "needs NYX_PW_TEST_SERVER"]
async fn hub_refuses_a_bad_token() {
    let server = Server::new(&common::server_url(), &[common::ca_pem()]).unwrap();
    assert!(server.connect_hub(&Secret::new("not-a-token"), uuid::Uuid::new_v4()).await.is_err());
}
