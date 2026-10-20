//! Signing in, unlocking and syncing against the throwaway Vaultwarden:
//!
//!   apps/passwords/scripts/test-server.sh start
//!   NIXE_PW_TEST_SERVER=https://127.0.0.1:8087 NIXE_PW_TEST_CA=$PWD/target/vaultwarden-test/ca.pem \
//!     cargo test -p nixe-passwords-core --test session -- --ignored

mod common;

use std::num::NonZeroU32;

use nixe_passwords_core::api::{ApiError, Server, TwoFactor, TwoFactorAnswer};
use nixe_passwords_core::crypto::{CryptoError, Kdf, MasterKey};
use nixe_passwords_core::secret::Secret;
use nixe_passwords_core::session::{self, SessionError, SignIn};
use nixe_passwords_core::store::Store;

fn pbkdf2() -> bitwarden_crypto::Kdf {
    bitwarden_crypto::Kdf::PBKDF2 { iterations: NonZeroU32::new(600_000).unwrap() }
}

fn server() -> Server {
    Server::new(&common::server_url(), &[common::ca_pem()]).unwrap()
}

async fn signed_in(store: &mut Store, email: &str, password: &Secret) -> Box<session::Session> {
    match session::sign_in(store, &server(), email, password, "nixe test", None).await.unwrap() {
        SignIn::Done(s) => s,
        SignIn::TwoFactor(_) => panic!("unexpected two-step login"),
    }
}

#[tokio::test]
#[ignore = "needs NIXE_PW_TEST_SERVER"]
async fn sign_in_unlock_sync() {
    let email = common::fresh_email("session");
    let password = Secret::new("correct horse session battery");
    common::register(&email, password.expose(), &pbkdf2()).await;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();

    let wrong = session::sign_in(&mut store, &server(), &email, &Secret::new("nope"), "nixe test", None).await;
    assert_eq!(wrong.err(), Some(SessionError::Api(ApiError::Credentials)));

    let s = signed_in(&mut store, &email, &password).await;
    let refresh = Secret::new(s.refresh_token().expect("refresh token").expose());
    let account = store.account().unwrap().unwrap();
    assert_eq!(account.kdf, Kdf::Pbkdf2 { iterations: 600_000 });
    assert!(account.last_sync.is_some() && account.user_id.is_some());
    s.lock();

    // Offline: no server involved.
    assert_eq!(
        session::unlock(&mut store, &Secret::new("nope")).await.err(),
        Some(SessionError::Crypto(CryptoError::WrongPassword))
    );
    let mut s = session::unlock(&mut store, &password).await.unwrap();
    assert!(s.tokens.is_none() && s.keys.is_unlocked());

    // Online again with only the refresh token.
    s.sync(&mut store, &server(), &refresh).await.unwrap();
    assert!(s.tokens.is_some());
}

#[tokio::test]
#[ignore = "needs NIXE_PW_TEST_SERVER"]
async fn two_step_login() {
    let email = common::fresh_email("twofactor");
    let password = Secret::new("correct horse twofactor battery");
    common::register(&email, password.expose(), &pbkdf2()).await;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
    let s = signed_in(&mut store, &email, &password).await;
    let master = MasterKey::derive(&password, &email, &Kdf::Pbkdf2 { iterations: 600_000 }).unwrap();
    let key =
        common::enable_authenticator(s.tokens.as_ref().unwrap().access.expose(), master.server_hash(&password).expose()).await;

    let methods = match session::sign_in(&mut store, &server(), &email, &password, "nixe test", None).await.unwrap() {
        SignIn::TwoFactor(m) => m,
        SignIn::Done(_) => panic!("two-step login not asked for"),
    };
    assert!(methods.contains(&TwoFactor::Authenticator), "{methods:?}");

    let bad = TwoFactorAnswer { method: 0, code: Secret::new("000000") };
    let wrong = session::sign_in(&mut store, &server(), &email, &password, "nixe test", Some(&bad)).await;
    assert_eq!(wrong.err(), Some(SessionError::Api(ApiError::TwoFactorCode)));

    // Vaultwarden refuses a code it has seen; wait for the next period if needed.
    let mut code = common::totp(&key);
    let answer = loop {
        let a = TwoFactorAnswer { method: 0, code: Secret::new(code.clone()) };
        match session::sign_in(&mut store, &server(), &email, &password, "nixe test", Some(&a)).await {
            Ok(SignIn::Done(s)) => break s,
            Err(SessionError::Api(ApiError::TwoFactorCode)) => {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                code = common::totp(&key);
            }
            other => panic!("two-step login: {:?}", other.err()),
        }
    };
    assert!(answer.keys.is_unlocked());
}

#[tokio::test]
#[ignore = "needs NIXE_PW_TEST_SERVER"]
async fn weaker_kdf_is_refused() {
    let email = common::fresh_email("downgrade");
    let password = Secret::new("correct horse downgrade battery");
    common::register(&email, password.expose(), &pbkdf2()).await;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
    signed_in(&mut store, &email, &password).await.lock();
    // Pretend this device knew a stronger setting; the server's 600 000 is now weaker.
    let mut account = store.account().unwrap().unwrap();
    account.kdf = Kdf::Pbkdf2 { iterations: 900_000 };
    store.set_account(&account).unwrap();
    let again = session::sign_in(&mut store, &server(), &email, &password, "nixe test", None).await;
    assert_eq!(again.err(), Some(SessionError::KdfDowngrade));
}

#[tokio::test]
#[ignore = "needs NIXE_PW_TEST_SERVER"]
async fn untrusted_certificate() {
    let plain = Server::new(&common::server_url(), &[]).unwrap();
    assert_eq!(plain.prelogin("x@example.com").await.err(), Some(ApiError::Certificate));
    assert_eq!(Server::new("http://example.com", &[]).err(), Some(ApiError::BadServerUrl));
}

/// For trying the window by hand: NIXE_PW_MAKE_ACCOUNT="email|password" registers that
/// account on the test server.
#[tokio::test]
#[ignore = "a tool for manual runs"]
async fn make_account() {
    let Ok(spec) = std::env::var("NIXE_PW_MAKE_ACCOUNT") else { return };
    let (email, password) = spec.split_once('|').expect("email|password");
    common::register(email, password, &pbkdf2()).await;
}
