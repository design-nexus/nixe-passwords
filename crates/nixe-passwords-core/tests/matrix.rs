//! When the server and this copy disagree: an item trashed or deleted elsewhere, edited
//! elsewhere at the same time, an organization that took the account's access away, and
//! a server that can't be reached. Against the throwaway Vaultwarden, with `bw` or the
//! API as the other side:
//!
//!   apps/passwords/scripts/test-server.sh start
//!   NIXE_PW_TEST_SERVER=https://127.0.0.1:8087 NIXE_PW_TEST_CA=$PWD/target/vaultwarden-test/ca.pem \
//!     cargo test -p nixe-passwords-core --test matrix -- --ignored

mod common;

use std::num::NonZeroU32;

use nixe_passwords_core::api::{ApiError, Server};
use nixe_passwords_core::edit::{ItemDraft, LoginDraft, Place};
use nixe_passwords_core::model::Kind;
use nixe_passwords_core::secret::Secret;
use nixe_passwords_core::session::{self, Session, SessionError, SignIn};
use nixe_passwords_core::store::Store;
use uuid::Uuid;

fn kdf() -> bitwarden_crypto::Kdf {
    bitwarden_crypto::Kdf::PBKDF2 { iterations: NonZeroU32::new(600_000).unwrap() }
}

async fn signed_in(store: &mut Store, server: &Server, email: &str, password: &str) -> (Box<Session>, Secret) {
    let SignIn::Done(s) = session::sign_in(store, server, email, &Secret::new(password), "nixe test", None).await.unwrap()
    else {
        panic!("two-step login")
    };
    let refresh = Secret::new(s.refresh_token().unwrap().expose());
    (s, refresh)
}

fn login(name: &str) -> LoginDraft {
    LoginDraft {
        name: Secret::new(name),
        username: Some(Secret::new("octo")),
        password: Some(Secret::new(format!("canary-{name}-Pw!9"))),
        totp: None,
        uris: vec![Secret::new("https://example.com")],
        notes: None,
        folder: None,
        favorite: false,
        reprompt: false,
        place: Place::default(),
    }
}

fn card(name: &str) -> ItemDraft {
    ItemDraft {
        kind: Kind::Card,
        name: Secret::new(name),
        fields: vec![("card.number".into(), Secret::new("4111111111111111"))],
        notes: None,
        folder: None,
        favorite: false,
        reprompt: false,
        place: Place::default(),
    }
}

fn gone(s: &Session, id: Uuid) -> bool {
    s.view.get(id).is_none() && !s.snapshot.ciphers.iter().any(|c| c.id == id)
}

/// Trashed elsewhere: an edit from the stale copy is refused as a conflict and the
/// trashed state comes in. Deleted for good elsewhere: edits, trash and attachments are
/// refused, and the item leaves this copy (store included) at once, not at the next sync.
/// Edited elsewhere at the same time: a card's edit is refused as a conflict too.
#[tokio::test]
#[ignore = "needs NIXE_PW_TEST_SERVER"]
async fn changed_elsewhere() {
    let email = common::fresh_email("matrix");
    let password = "correct horse matrix battery";
    common::register(&email, password, &kdf()).await;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
    let server = Server::new(&common::server_url(), &[common::ca_pem()]).unwrap();
    let (mut s, refresh) = signed_in(&mut store, &server, &email, password).await;
    let trashed = s.create_login(&mut store, &server, &refresh, &login("Trashed")).await.unwrap();
    let deleted = s.create_login(&mut store, &server, &refresh, &login("Deleted")).await.unwrap();
    let edited = s.create_item(&mut store, &server, &refresh, &card("Edited")).await.unwrap();
    let bw = common::Bw::login(&email, password);
    std::thread::sleep(std::time::Duration::from_millis(1100));

    bw.run(&["delete", "item", &trashed.to_string()]);
    let refused = s.update_login(&mut store, &server, &refresh, trashed, &login("Trashed, edited")).await;
    assert_eq!(refused.err(), Some(SessionError::Api(ApiError::Conflict)));
    assert!(s.view.get(trashed).unwrap().deleted, "the trash came in");

    bw.run(&["delete", "item", &deleted.to_string(), "--permanent"]);
    let refused = s.update_login(&mut store, &server, &refresh, deleted, &login("Deleted, edited")).await;
    assert_eq!(refused.err(), Some(SessionError::Api(ApiError::NotFound)), "an edit");
    assert!(gone(&s, deleted), "the item left this copy");
    let stored = store.snapshot().unwrap().unwrap();
    assert!(!stored.ciphers.iter().any(|c| c.id == deleted), "and the stored copy");
    // Every other kind of change, on an item already gone, is refused the same way.
    assert_eq!(s.trash(&mut store, &server, &refresh, deleted).await.err(), Some(SessionError::Api(ApiError::NotFound)));

    let mut theirs = bw.item(&edited.to_string());
    theirs["name"] = "Edited in bw".into();
    bw.edit(&edited.to_string(), &theirs);
    let refused = s.update_item(&mut store, &server, &refresh, edited, &card("Edited here")).await;
    assert_eq!(refused.err(), Some(SessionError::Api(ApiError::Conflict)));
    assert_eq!(s.view.get(edited).unwrap().name.expose(), "Edited in bw");

    // A sync agrees with all of it.
    s.sync(&mut store, &server, &refresh).await.unwrap();
    assert!(s.view.get(trashed).unwrap().deleted && gone(&s, deleted));
}

/// Removed from an organization: its items and collections leave the view at the next
/// sync, and an edit from the stale copy before that is refused without leaving the item
/// behind.
#[tokio::test]
#[ignore = "needs NIXE_PW_TEST_SERVER"]
async fn organization_access_removed() {
    let (owner_email, member_email) = (common::fresh_email("owner"), common::fresh_email("member"));
    let password = "correct horse removed battery";
    let owner_public = common::register(&owner_email, password, &kdf()).await;
    let member_public = common::register(&member_email, password, &kdf()).await;
    let dir = tempfile::tempdir().unwrap();
    let server = Server::new(&common::server_url(), &[common::ca_pem()]).unwrap();
    let mut owner_store = Store::open(&dir.path().join("owner.sqlite")).unwrap();
    let (mut owner, owner_refresh) = signed_in(&mut owner_store, &server, &owner_email, password).await;
    let access = Secret::new(owner.access(&server, &owner_refresh).await.unwrap().expose());
    let org = common::create_org(access.expose(), &owner_email, &owner_public).await;
    common::add_member(access.expose(), &org, &member_email, &member_public, &[(org.collection.as_str(), false, false)]).await;
    owner.sync(&mut owner_store, &server, &owner_refresh).await.unwrap();
    let org_id: Uuid = org.id.parse().unwrap();
    let mut shared = login("Shared");
    shared.place = Place { organization: Some(org_id), collections: vec![org.collection.parse().unwrap()] };
    let item = owner.create_login(&mut owner_store, &server, &owner_refresh, &shared).await.unwrap();

    let mut store = Store::open(&dir.path().join("member.sqlite")).unwrap();
    let (mut s, refresh) = signed_in(&mut store, &server, &member_email, password).await;
    assert!(s.view.get(item).is_some() && !s.view.collections.is_empty());

    common::remove_member(access.expose(), &org, &member_email).await;
    let refused = s.update_login(&mut store, &server, &refresh, item, &shared).await;
    assert!(refused.is_err(), "{refused:?}");
    assert!(gone(&s, item), "the item left this copy");

    s.sync(&mut store, &server, &refresh).await.unwrap();
    assert!(gone(&s, item) && s.view.collections.is_empty() && s.view.organizations.is_empty());
    // The local copy agrees, offline.
    s.lock();
    let s = session::unlock(&mut store, &Secret::new(password)).await.unwrap();
    assert!(gone(&s, item));
}

/// The server can't be reached: edits fail as `Unreachable` and change nothing here; the
/// local copy still unlocks and reads.
#[tokio::test]
#[ignore = "needs NIXE_PW_TEST_SERVER"]
async fn server_unreachable() {
    let email = common::fresh_email("offline");
    let password = "correct horse offline battery";
    common::register(&email, password, &kdf()).await;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
    let server = Server::new(&common::server_url(), &[common::ca_pem()]).unwrap();
    let (mut s, refresh) = signed_in(&mut store, &server, &email, password).await;
    let id = s.create_login(&mut store, &server, &refresh, &login("Kept")).await.unwrap();
    // A fresh token is forgotten too, so every call has to reach the server.
    s.tokens = None;

    // Nothing listens on port 9 on this machine.
    let offline = Server::new("https://127.0.0.1:9", &[common::ca_pem()]).unwrap();
    let before = (s.snapshot.ciphers.len(), s.view.get(id).unwrap().revision.clone());
    let unreachable = Some(SessionError::Api(ApiError::Unreachable));
    assert_eq!(s.create_login(&mut store, &offline, &refresh, &login("New")).await.err(), unreachable);
    assert_eq!(s.update_login(&mut store, &offline, &refresh, id, &login("Kept, edited")).await.err(), unreachable);
    assert_eq!(s.trash(&mut store, &offline, &refresh, id).await.err(), unreachable);
    assert_eq!(s.sync(&mut store, &offline, &refresh).await.err(), unreachable);
    assert_eq!((s.snapshot.ciphers.len(), s.view.get(id).unwrap().revision.clone()), before);

    s.lock();
    let s = session::unlock(&mut store, &Secret::new(password)).await.unwrap();
    assert_eq!(s.view.get(id).unwrap().name.expose(), "Kept");
}
