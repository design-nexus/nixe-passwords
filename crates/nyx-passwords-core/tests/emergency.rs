//! Emergency access between two accounts on the throwaway Vaultwarden: inviting,
//! confirming after comparing fingerprints, asking, approving and viewing; rejecting
//! and removing.
//!
//!   apps/passwords/scripts/test-server.sh start
//!   NYX_PW_TEST_SERVER=https://127.0.0.1:8087 NYX_PW_TEST_CA=$PWD/target/vaultwarden-test/ca.pem \
//!     cargo test -p nyx-passwords-core --test emergency -- --ignored

mod common;

use std::num::NonZeroU32;

use nyx_passwords_core::api::Server;
use nyx_passwords_core::edit::{LoginDraft, Place};
use nyx_passwords_core::emergency::{Status, Step};
use nyx_passwords_core::secret::Secret;
use nyx_passwords_core::session::{self, Session, SignIn};
use nyx_passwords_core::store::Store;
use nyx_passwords_core::vault::{Field, reveal_in};

fn server() -> Server {
    Server::new(&common::server_url(), &[common::ca_pem()]).unwrap()
}

async fn account(tag: &str) -> (String, Session, Store, Secret, tempfile::TempDir) {
    let email = common::fresh_email(tag);
    let password = format!("correct horse {tag} battery");
    common::register(&email, &password, &bitwarden_crypto::Kdf::PBKDF2 { iterations: NonZeroU32::new(600_000).unwrap() }).await;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
    let SignIn::Done(s) =
        session::sign_in(&mut store, &server(), &email, &Secret::new(password.as_str()), "nyx", None).await.unwrap()
    else {
        panic!("two-step login")
    };
    let refresh = Secret::new(s.refresh_token().unwrap().expose());
    (email, *s, store, refresh, dir)
}

#[tokio::test]
#[ignore = "needs NYX_PW_TEST_SERVER"]
async fn trusted_contact_views_the_vault() {
    let (_, mut grantor, mut gstore, grefresh, _d1) = account("grantor").await;
    let (grantee_email, mut grantee, _gs, erefresh, _d2) = account("grantee").await;
    let draft = LoginDraft {
        name: Secret::new("Bank"),
        username: Some(Secret::new("me")),
        password: Some(Secret::new("canary-bank-Pw!9")),
        totp: None,
        uris: vec![],
        notes: None,
        folder: None,
        favorite: false,
        reprompt: false,
        place: Place::default(),
        custom: None,
    };
    let bank = grantor.create_login(&mut gstore, &server(), &grefresh, &draft).await.unwrap();

    // Invited (accepted at once: the test server sends no mail), then confirmed once the
    // phrases match.
    assert!(grantor.invite_emergency(&server(), &grefresh, &grantee_email, 0).await.is_err(), "a wait of a day or more");
    grantor.invite_emergency(&server(), &grefresh, &grantee_email, 7).await.unwrap();
    let (trusted, _) = grantor.emergency_contacts(&server(), &grefresh).await.unwrap();
    assert_eq!(trusted.len(), 1);
    assert_eq!((trusted[0].email.as_str(), trusted[0].wait_days), (grantee_email.as_str(), 7));
    assert_eq!(trusted[0].status, Status::Accepted, "{:?}", trusted[0]);
    let id = trusted[0].id.clone();
    let seen = grantor.emergency_fingerprint(&server(), &grefresh, &id).await.unwrap();
    assert_eq!(seen, grantee.my_fingerprint(&server(), &erefresh).await.unwrap());
    grantor.confirm_emergency(&server(), &grefresh, &id).await.unwrap();

    // The contact asks; nothing to see until the grantor approves.
    let (_, granted) = grantee.emergency_contacts(&server(), &erefresh).await.unwrap();
    assert_eq!((granted.len(), granted[0].status), (1, Status::Confirmed));
    grantee.emergency_step(&server(), &erefresh, &id, Step::Request).await.unwrap();
    assert!(grantee.view_emergency(&server(), &erefresh, &id).await.is_err());
    let (trusted, _) = grantor.emergency_contacts(&server(), &grefresh).await.unwrap();
    assert_eq!(trusted[0].status, Status::RecoveryInitiated);
    grantor.emergency_step(&server(), &grefresh, &id, Step::Approve).await.unwrap();
    let opened = grantee.view_emergency(&server(), &erefresh, &id).await.unwrap();
    assert_eq!(opened.view.entries.len(), 1);
    assert_eq!(opened.view.entries[0].name.expose(), "Bank");
    assert_eq!(reveal_in(&opened.keys, &opened.ciphers, bank, Field::Password).unwrap().expose(), "canary-bank-Pw!9");

    // Ask again, turned down; then removed.
    grantee.emergency_step(&server(), &erefresh, &id, Step::Request).await.ok();
    grantor.emergency_step(&server(), &grefresh, &id, Step::Reject).await.ok();
    grantor.emergency_step(&server(), &grefresh, &id, Step::Remove).await.unwrap();
    assert!(grantor.emergency_contacts(&server(), &grefresh).await.unwrap().0.is_empty());
    assert!(grantee.emergency_contacts(&server(), &erefresh).await.unwrap().1.is_empty());
}
