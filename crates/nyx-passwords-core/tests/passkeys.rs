//! Passkeys made here, stored through the throwaway Vaultwarden: `bw` reads every
//! field as the official clients store them, signing in with it checks out, and
//! deleting it removes it.
//!
//!   apps/passwords/scripts/test-server.sh start
//!   NYX_PW_TEST_SERVER=https://127.0.0.1:8087 NYX_PW_TEST_CA=$PWD/target/vaultwarden-test/ca.pem \
//!     cargo test -p nyx-passwords-core --test passkeys -- --ignored

mod common;

use std::num::NonZeroU32;

use nyx_passwords_core::api::Server;
use nyx_passwords_core::crypto::sha256;
use nyx_passwords_core::passkey::{self, NewPasskey};
use nyx_passwords_core::secret::Secret;
use nyx_passwords_core::session::{self, SignIn};
use nyx_passwords_core::store::Store;
use p256::ecdsa::signature::Verifier;

#[tokio::test]
#[ignore = "needs NYX_PW_TEST_SERVER"]
async fn passkeys_round_trip_with_bw() {
    let email = common::fresh_email("passkey");
    let password = "correct horse passkey battery";
    common::register(&email, password, &bitwarden_crypto::Kdf::PBKDF2 { iterations: NonZeroU32::new(600_000).unwrap() }).await;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
    let server = Server::new(&common::server_url(), &[common::ca_pem()]).unwrap();
    let SignIn::Done(mut s) = session::sign_in(&mut store, &server, &email, &Secret::new(password), "nyx", None).await.unwrap()
    else {
        panic!("two-step login")
    };
    let refresh = Secret::new(s.refresh_token().unwrap().expose());

    let new = NewPasskey {
        rp_id: "webauthn.example",
        rp_name: "WebAuthn Example",
        user_handle: b"user-1234",
        user_name: "octo",
        user_display_name: "Octo Cat",
        discoverable: true,
        verified: true,
    };
    let made = passkey::create(&new, &nyx_passwords_core::edit::timestamp()).unwrap();
    let page = url::Url::parse("https://webauthn.example/register").unwrap();
    let id = s.save_passkey(&mut store, &server, &refresh, None, &page, &made).await.unwrap();

    // bw sees it as the official clients store passkeys.
    let bw = common::Bw::login(&email, password);
    let item = bw.item(&id.to_string());
    let stored = &item["login"]["fido2Credentials"][0];
    assert_eq!(item["name"], "webauthn.example");
    assert_eq!(item["login"]["username"], "octo");
    for (field, value) in [
        ("rpId", "webauthn.example"),
        ("rpName", "WebAuthn Example"),
        ("userName", "octo"),
        ("userDisplayName", "Octo Cat"),
        ("keyType", "public-key"),
        ("keyAlgorithm", "ECDSA"),
        ("keyCurve", "P-256"),
        ("counter", "0"),
        ("discoverable", "true"),
    ] {
        assert_eq!(stored[field], value, "{field}");
    }
    assert_eq!(stored["credentialId"], made.fields["credentialId"]);
    assert_eq!(stored["keyValue"], made.fields["keyValue"]);
    assert_eq!(stored["userHandle"], "dXNlci0xMjM0");

    // Listed, and signing in with it checks out against the public key the site keeps.
    let listed = s.passkeys(id).unwrap();
    assert_eq!((listed.len(), listed[0].rp_id.as_str(), listed[0].user_name.as_str()), (1, "webauthn.example", "octo"));
    let c = s.snapshot.ciphers.iter().find(|c| c.id == id).unwrap().clone();
    let mut key = s.keys.item(None, c.key.as_deref()).unwrap();
    let client = sha256(br#"{"type":"webauthn.get","challenge":"abc","origin":"https://webauthn.example"}"#);
    let credential = listed[0].credential_id.clone();
    assert!(matches!(
        passkey::assert(&mut key, &c, &credential, "evil.example", &client, false),
        Err(passkey::PasskeyError::WrongSite)
    ));
    let signed_in = passkey::assert(&mut key, &c, &credential, "webauthn.example", &client, false).unwrap();
    assert_eq!(signed_in.user_handle, b"user-1234");
    assert_eq!(signed_in.credential_id, made.credential_id);
    let cose: ciborium::value::Value = ciborium::from_reader(made.public_key.as_slice()).unwrap();
    let map = cose.as_map().unwrap();
    let get = |k: i64| map.iter().find(|(n, _)| n.as_integer() == Some(k.into())).unwrap().1.as_bytes().unwrap().clone();
    let mut sec1 = vec![4u8];
    sec1.extend(get(-2));
    sec1.extend(get(-3));
    let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let mut data = signed_in.authenticator_data.clone();
    data.extend(client);
    verifying.verify(&data, &p256::ecdsa::Signature::from_der(&signed_in.signature).unwrap()).unwrap();
    drop(key);

    // Deleted.
    s.delete_passkey(&mut store, &server, &refresh, id, &credential).await.unwrap();
    assert!(s.passkeys(id).unwrap().is_empty());
    let item = bw.item(&id.to_string());
    assert!(item["login"]["fido2Credentials"].as_array().is_none_or(|l| l.is_empty()), "{}", item["login"]);
}
