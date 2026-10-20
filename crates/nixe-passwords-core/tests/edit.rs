//! Creating, editing, trashing and restoring logins against the throwaway Vaultwarden,
//! with the official `bw` CLI as the other client:
//!
//!   apps/passwords/scripts/test-server.sh start
//!   NIXE_PW_TEST_SERVER=https://127.0.0.1:8087 NIXE_PW_TEST_CA=$PWD/target/vaultwarden-test/ca.pem \
//!     cargo test -p nixe-passwords-core --test edit -- --ignored

mod common;

use std::num::NonZeroU32;

use nixe_passwords_core::api::{ApiError, Server};
use nixe_passwords_core::edit::LoginDraft;
use nixe_passwords_core::secret::Secret;
use nixe_passwords_core::session::{self, SessionError, SignIn};
use nixe_passwords_core::store::Store;
use nixe_passwords_core::vault::{Field, reveal};

fn draft(name: &str, password: &str) -> LoginDraft {
    LoginDraft {
        name: Secret::new(name),
        username: Some(Secret::new("octo")),
        password: Some(Secret::new(password)),
        totp: Some(Secret::new("JBSWY3DPEHPK3PXP")),
        uris: vec![Secret::new("https://github.com/login"), Secret::new("github.com")],
        notes: Some(Secret::new("written by nixe")),
        folder: None,
        favorite: true,
        reprompt: false,
    }
}

#[tokio::test]
#[ignore = "needs NIXE_PW_TEST_SERVER"]
async fn logins_round_trip_with_bw() {
    let email = common::fresh_email("edit");
    let password = "correct horse edit battery";
    common::register(&email, password, &bitwarden_crypto::Kdf::PBKDF2 { iterations: NonZeroU32::new(600_000).unwrap() }).await;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
    let server = Server::new(&common::server_url(), &[common::ca_pem()]).unwrap();
    let SignIn::Done(mut s) =
        session::sign_in(&mut store, &server, &email, &Secret::new(password), "nixe test", None).await.unwrap()
    else {
        panic!("two-step login")
    };
    let refresh = Secret::new(s.refresh_token().unwrap().expose());

    // Create: bw reads every field, including both web addresses.
    let id = s.create_login(&mut store, &server, &refresh, &draft("GitHub", "canary-one-Pw!9")).await.unwrap();
    let bw = common::Bw::login(&email, password);
    let item = bw.item(&id.to_string());
    assert_eq!(item["name"], "GitHub");
    assert_eq!(item["login"]["username"], "octo");
    assert_eq!(item["login"]["password"], "canary-one-Pw!9");
    assert_eq!(item["login"]["totp"], "JBSWY3DPEHPK3PXP");
    assert_eq!(item["login"]["uris"][0]["uri"], "https://github.com/login");
    assert_eq!(item["login"]["uris"][1]["uri"], "github.com");
    assert_eq!(item["notes"], "written by nixe");
    assert_eq!(item["favorite"], true);
    assert_eq!(s.view.search("github", 5).len(), 1);

    // Edit: the new password shows in bw, the old one in its history.
    s.update_login(&mut store, &server, &refresh, id, &draft("GitHub", "canary-two-Pw!9")).await.unwrap();
    let item = bw.item(&id.to_string());
    assert_eq!(item["login"]["password"], "canary-two-Pw!9");
    assert_eq!(item["passwordHistory"][0]["password"], "canary-one-Pw!9");
    assert_eq!(reveal(&s.keys, &s.snapshot, id, Field::Password).unwrap().expose(), "canary-two-Pw!9");

    // An edit made elsewhere since our copy: ours is refused and theirs comes in.
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let mut theirs = item.clone();
    theirs["name"] = "GitHub (renamed in bw)".into();
    bw.edit(&id.to_string(), &theirs);
    let refused = s.update_login(&mut store, &server, &refresh, id, &draft("GitHub mine", "canary-three-Pw!9")).await;
    assert_eq!(refused.err(), Some(SessionError::Api(ApiError::Conflict)));
    assert_eq!(s.view.get(id).unwrap().name.expose(), "GitHub (renamed in bw)");
    assert_eq!(bw.item(&id.to_string())["login"]["password"], "canary-two-Pw!9");
    // Based on the fresh copy, the edit goes through.
    s.update_login(&mut store, &server, &refresh, id, &draft("GitHub mine", "canary-three-Pw!9")).await.unwrap();
    assert_eq!(bw.item(&id.to_string())["name"], "GitHub mine");

    // Trash and restore.
    s.trash(&mut store, &server, &refresh, id).await.unwrap();
    assert!(s.view.get(id).unwrap().deleted && s.view.search("github", 5).is_empty());
    assert!(bw.item(&id.to_string())["deletedDate"].is_string());
    s.restore(&mut store, &server, &refresh, id).await.unwrap();
    assert!(!s.view.get(id).unwrap().deleted);

    // The local copy has every change: unlock offline and look.
    s.lock();
    let s = session::unlock(&mut store, &Secret::new(password)).await.unwrap();
    assert_eq!(s.view.get(id).unwrap().name.expose(), "GitHub mine");
    assert_eq!(reveal(&s.keys, &s.snapshot, id, Field::Password).unwrap().expose(), "canary-three-Pw!9");
}
