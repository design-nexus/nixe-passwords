//! Other ways to sign in, against the throwaway Vaultwarden: with another device's
//! approval (both sides), with a recovery code, and with the account's API key.
//!
//!   apps/passwords/scripts/test-server.sh start
//!   NYX_PW_TEST_SERVER=https://127.0.0.1:8087 NYX_PW_TEST_CA=$PWD/target/vaultwarden-test/ca.pem \
//!     cargo test -p nyx-passwords-core --test signin -- --ignored

mod common;

use std::num::NonZeroU32;

use nyx_passwords_core::api::{RECOVERY_CODE, Server, TwoFactor, TwoFactorAnswer};
use nyx_passwords_core::crypto::{Kdf, MasterKey};
use nyx_passwords_core::secret::Secret;
use nyx_passwords_core::session::{self, Session, SessionError, SignIn};
use nyx_passwords_core::store::Store;
use serde_json::{Value, json};

fn server() -> Server {
    Server::new(&common::server_url(), &[common::ca_pem()]).unwrap()
}

async fn fresh(tag: &str) -> (String, Secret, Store, Session, tempfile::TempDir) {
    let email = common::fresh_email(tag);
    let password = Secret::new(format!("correct horse {tag} battery"));
    common::register(&email, password.expose(), &bitwarden_crypto::Kdf::PBKDF2 { iterations: NonZeroU32::new(600_000).unwrap() })
        .await;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
    let SignIn::Done(s) = session::sign_in(&mut store, &server(), &email, &password, "first device", None).await.unwrap() else {
        panic!("two-step login")
    };
    (email, password, store, *s, dir)
}

fn hash(email: &str, password: &Secret) -> String {
    let master = MasterKey::derive(password, email, &Kdf::Pbkdf2 { iterations: 600_000 }).unwrap();
    master.server_hash(password).expose().to_string()
}

#[tokio::test]
#[ignore = "needs NYX_PW_TEST_SERVER"]
async fn sign_in_with_another_device() {
    let (email, password, _store, mut first, _dir) = fresh("device").await;
    let refresh = Secret::new(first.refresh_token().unwrap().expose());
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
    // Vaultwarden takes requests only from a device that signed in to the account
    // before: this one did, then signed out. Its device id outlives the sign-out.
    let device = store.device_id().unwrap();
    assert!(matches!(
        session::request_device_sign_in(&mut store, &server(), &email, "second device").await,
        Err(SessionError::Api(_))
    ));
    let SignIn::Done(once) = session::sign_in(&mut store, &server(), &email, &password, "second device", None).await.unwrap()
    else {
        panic!("two-step login")
    };
    once.lock();
    store.clear().unwrap();
    assert_eq!(store.device_id().unwrap(), device);

    // Approved: both sides show the same words, and the new device opens the vault.
    let mut asking = session::request_device_sign_in(&mut store, &server(), &email, "second device").await.unwrap();
    assert!(asking.poll(&mut store, &server()).await.unwrap().is_none(), "no answer yet");
    let requests = first.sign_in_requests(&server(), &refresh).await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].fingerprint, asking.fingerprint);
    first.answer_sign_in(&server(), &refresh, &requests[0].id, true).await.unwrap();
    let second = asking.poll(&mut store, &server()).await.unwrap().expect("approved");
    assert_eq!(second.account.email, email);
    assert_eq!(second.snapshot.profile.id, first.snapshot.profile.id);
    assert!(second.keys.is_unlocked());
    // Its local copy unlocks later with the master password, like any other sign-in.
    second.lock();

    // Declined.
    let mut asking = session::request_device_sign_in(&mut store, &server(), &email, "second device").await.unwrap();
    let requests = first.sign_in_requests(&server(), &refresh).await.unwrap();
    first.answer_sign_in(&server(), &refresh, &requests[0].id, false).await.unwrap();
    assert!(matches!(asking.poll(&mut store, &server()).await, Err(SessionError::NotAllowed(_))));
    assert!(first.sign_in_requests(&server(), &refresh).await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "needs NYX_PW_TEST_SERVER"]
async fn recovery_code_turns_two_step_login_off() {
    let (email, password, mut store, s, _dir) = fresh("recover").await;
    let access = s.tokens.as_ref().unwrap().access.expose().to_string();
    common::enable_authenticator(&access, &hash(&email, &password)).await;
    let got: Value = common::http()
        .post(format!("{}/api/two-factor/get-recover", common::server_url()))
        .bearer_auth(&access)
        .json(&json!({"masterPasswordHash": hash(&email, &password)}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = got["code"].as_str().unwrap().to_string();
    let SignIn::TwoFactor(methods) = session::sign_in(&mut store, &server(), &email, &password, "nyx", None).await.unwrap()
    else {
        panic!("two-step login not asked for")
    };
    assert!(methods.contains(&TwoFactor::Authenticator));
    // The recovery code answers the two-step prompt itself (method 8), once, and turns
    // two-step login off.
    let wrong = TwoFactorAnswer { method: RECOVERY_CODE, code: Secret::new("not the code") };
    assert!(session::sign_in(&mut store, &server(), &email, &password, "nyx", Some(&wrong)).await.is_err());
    let right = TwoFactorAnswer { method: RECOVERY_CODE, code: Secret::new(code.as_str()) };
    let signed = session::sign_in(&mut store, &server(), &email, &password, "nyx", Some(&right)).await.unwrap();
    assert!(matches!(signed, SignIn::Done(_)));
    assert!(matches!(session::sign_in(&mut store, &server(), &email, &password, "nyx", None).await.unwrap(), SignIn::Done(_)));
}

#[tokio::test]
#[ignore = "needs NYX_PW_TEST_SERVER"]
async fn sign_in_with_api_key() {
    let (email, password, _store, s, _dir) = fresh("apikey").await;
    let access = s.tokens.as_ref().unwrap().access.expose().to_string();
    let got: Value = common::http()
        .post(format!("{}/api/accounts/api-key", common::server_url()))
        .bearer_auth(&access)
        .json(&json!({"masterPasswordHash": hash(&email, &password)}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let secret = Secret::new(got["apiKey"].as_str().unwrap());
    let client_id = format!("user.{}", s.snapshot.profile.id);
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
    let wrong = session::sign_in_with_api_key(&mut store, &server(), &client_id, &secret, &Secret::new("wrong"), "nyx").await;
    assert!(wrong.is_err(), "the master password still opens the vault");
    let mut s = session::sign_in_with_api_key(&mut store, &server(), &client_id, &secret, &password, "nyx").await.unwrap();
    assert_eq!(s.account.email, email);
    // No refresh token: the key gets new tokens.
    let refresh = Secret::new(s.refresh_token().unwrap().expose());
    s.tokens = None;
    s.sync(&mut store, &server(), &refresh).await.unwrap();
    assert!(s.tokens.is_some());
}
