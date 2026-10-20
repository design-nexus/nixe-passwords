//! Creating, editing, trashing and restoring logins against the throwaway Vaultwarden,
//! with the official `bw` CLI as the other client:
//!
//!   apps/passwords/scripts/test-server.sh start
//!   NIXE_PW_TEST_SERVER=https://127.0.0.1:8087 NIXE_PW_TEST_CA=$PWD/target/vaultwarden-test/ca.pem \
//!     cargo test -p nixe-passwords-core --test edit -- --ignored

mod common;

use std::num::NonZeroU32;

use nixe_passwords_core::api::{ApiError, Server};
use nixe_passwords_core::edit::{ItemDraft, LoginDraft};
use nixe_passwords_core::model::Kind;
use nixe_passwords_core::secret::Secret;
use nixe_passwords_core::session::{self, Session, SessionError, SignIn};
use nixe_passwords_core::store::Store;
use nixe_passwords_core::vault::{Field, reveal};
use serde_json::{Value, json};
use uuid::Uuid;

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

/// A draft that changes nothing: the item as `bw` shows it.
fn draft_of(item: &Value) -> LoginDraft {
    let text = |v: &Value| v.as_str().map(Secret::new);
    let login = &item["login"];
    LoginDraft {
        name: Secret::new(item["name"].as_str().unwrap()),
        username: text(&login["username"]),
        password: text(&login["password"]),
        totp: text(&login["totp"]),
        uris: login["uris"].as_array().into_iter().flatten().filter_map(|u| text(&u["uri"])).collect(),
        notes: text(&item["notes"]),
        folder: item["folderId"].as_str().map(|f| f.parse().unwrap()),
        favorite: item["favorite"].as_bool().unwrap(),
        reprompt: item["reprompt"] == 1,
    }
}

/// `bw`'s view without what changes on every save: the revision date, and attachment
/// links (signed per request).
fn settled(mut item: Value) -> Value {
    item.as_object_mut().unwrap().remove("revisionDate");
    for a in item["attachments"].as_array_mut().into_iter().flatten() {
        a.as_object_mut().unwrap().remove("url");
    }
    item
}

/// Renames the item here, then changes its password. After each edit `bw` must see that
/// change and nothing else: whatever this client doesn't edit comes back as it was.
async fn edits_keep_the_rest(s: &mut Session, store: &mut Store, server: &Server, refresh: &Secret, bw: &common::Bw, id: Uuid) {
    let before = bw.item(&id.to_string());
    let mut draft = draft_of(&before);
    let name = format!("{} renamed", before["name"].as_str().unwrap());
    draft.name = Secret::new(name.as_str());
    s.update_login(store, server, refresh, id, &draft).await.unwrap();
    let after = bw.item(&id.to_string());
    let mut expected = before.clone();
    expected["name"] = name.into();
    assert_eq!(settled(after.clone()), settled(expected), "a rename changes only the name");

    let before = after;
    draft.password = Some(Secret::new("canary-changed-Pw!9"));
    s.update_login(store, server, refresh, id, &draft).await.unwrap();
    let after = bw.item(&id.to_string());
    assert_eq!(after["login"]["password"], "canary-changed-Pw!9");
    let history = after["passwordHistory"].as_array().unwrap();
    assert_eq!(history[0]["password"], before["login"]["password"]);
    assert_eq!(history[1..], before["passwordHistory"].as_array().cloned().unwrap_or_default()[..]);
    assert_ne!(after["login"]["passwordRevisionDate"], before["login"]["passwordRevisionDate"]);
    let mut expected = before.clone();
    for path in [&["login", "password"][..], &["login", "passwordRevisionDate"], &["passwordHistory"]] {
        let (mut from, mut to) = (&after, &mut expected);
        for key in path {
            from = &from[*key];
            to = &mut to[*key];
        }
        *to = from.clone();
    }
    assert_eq!(settled(after), settled(expected), "a new password changes only the password and its history");
}

/// Items written by the official clients keep what this client doesn't edit: every kind
/// of custom field, match rules, a passkey, older password history and an attachment; an
/// item with its own key keeps that key; an organization item keeps its collection.
#[tokio::test]
#[ignore = "needs NIXE_PW_TEST_SERVER"]
async fn edits_keep_what_other_clients_wrote() {
    let email = common::fresh_email("compat");
    let password = "correct horse compat battery";
    let public =
        common::register(&email, password, &bitwarden_crypto::Kdf::PBKDF2 { iterations: NonZeroU32::new(600_000).unwrap() })
            .await;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
    let server = Server::new(&common::server_url(), &[common::ca_pem()]).unwrap();
    let SignIn::Done(mut s) =
        session::sign_in(&mut store, &server, &email, &Secret::new(password), "nixe test", None).await.unwrap()
    else {
        panic!("two-step login")
    };
    let refresh = Secret::new(s.refresh_token().unwrap().expose());
    let access = Secret::new(s.access(&server, &refresh).await.unwrap().expose());
    let (org, collection) = common::create_org(access.expose(), &email, &public).await;
    let bw = common::Bw::login(&email, password);

    // Written by bw: the parts this client leaves alone.
    let rich = bw.create(&json!({
        "type": 1, "name": "Rich", "notes": "kept notes", "favorite": false, "reprompt": 0, "folderId": null,
        "fields": [
            {"name": "text", "value": "plain value", "type": 0},
            {"name": "hidden", "value": "hidden value", "type": 1},
            {"name": "flag", "value": "true", "type": 2},
            {"name": "linked", "value": null, "type": 3, "linkedId": 100},
        ],
        "login": {
            "username": "rich", "password": "canary-rich-Pw!9", "totp": "JBSWY3DPEHPK3PXP",
            "uris": [{"match": 1, "uri": "https://a.example.com"}, {"match": 3, "uri": "https://b.example.com/x"}],
            "fido2Credentials": [{
                "credentialId": "b64.AAECAwQFBgcICQoLDA0ODw", "keyType": "public-key", "keyAlgorithm": "ECDSA",
                "keyCurve": "P-256", "keyValue": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEH", "rpId": "example.com",
                "userHandle": "dXNlcg", "userName": "rich", "counter": "0", "rpName": "Example",
                "userDisplayName": "Rich", "discoverable": "true", "creationDate": "2026-10-01T00:00:00.000Z",
            }],
        },
        "passwordHistory": [{"lastUsedDate": "2026-01-01T00:00:00.000Z", "password": "canary-older-Pw!9"}],
    }));
    let rich: Uuid = rich["id"].as_str().unwrap().parse().unwrap();
    let file = dir.path().join("recovery-codes.txt");
    std::fs::write(&file, "canary attachment contents\n").unwrap();
    bw.attach(&rich.to_string(), &file);
    let shared = bw.create(&json!({
        "type": 1, "name": "Shared", "notes": null, "favorite": false, "reprompt": 0, "folderId": null,
        "organizationId": org, "collectionIds": [collection],
        "login": {"username": "team", "password": "canary-team-Pw!9", "uris": [{"match": null, "uri": "https://team.example.com"}]},
    }));
    let shared: Uuid = shared["id"].as_str().unwrap().parse().unwrap();

    // Written as newer clients do: the item has its own key.
    let wrapped = {
        let (mut key, wrapped) = s.keys.new_item(None).unwrap();
        let body = json!({
            "type": 1, "name": key.encrypt("Own key").unwrap(), "notes": null, "folderId": null,
            "organizationId": null, "key": wrapped, "favorite": false, "reprompt": 0, "passwordHistory": null,
            "fields": [{"name": key.encrypt("pin").unwrap(), "value": key.encrypt("4321").unwrap(), "type": 1}],
            "login": {
                "username": key.encrypt("own").unwrap(), "password": key.encrypt("canary-own-Pw!9").unwrap(),
                "totp": null, "uris": [{"uri": key.encrypt("https://own.example.com").unwrap(), "match": null}],
            },
            "encryptedFor": s.snapshot.profile.id,
        });
        drop(key);
        (server.create_cipher(&access, &body).await.unwrap().id, wrapped)
    };
    let (own, wrapped) = wrapped;
    assert_eq!(bw.item(&own.to_string())["fields"][0]["value"], "4321", "bw reads an item with its own key");

    s.sync(&mut store, &server, &refresh).await.unwrap();
    for id in [rich, shared, own] {
        edits_keep_the_rest(&mut s, &mut store, &server, &refresh, &bw, id).await;
    }
    assert_eq!(s.snapshot.ciphers.iter().find(|c| c.id == own).unwrap().key.as_deref(), Some(wrapped.as_str()));
    assert_eq!(bw.attachment(&rich.to_string(), "recovery-codes.txt"), b"canary attachment contents\n");
}

fn item_draft(kind: Kind, name: &str, fields: &[(&str, &str)]) -> ItemDraft {
    ItemDraft {
        kind,
        name: Secret::new(name),
        fields: fields.iter().map(|(n, v)| (n.to_string(), Secret::new(*v))).collect(),
        notes: Some(Secret::new(format!("{name} notes"))),
        folder: None,
        favorite: false,
        reprompt: false,
    }
}

/// Notes, cards and identities made here read back in `bw` field by field; editing one
/// `bw` made changes only what was edited.
#[tokio::test]
#[ignore = "needs NIXE_PW_TEST_SERVER"]
async fn notes_cards_and_identities_round_trip_with_bw() {
    let email = common::fresh_email("items");
    let password = "correct horse items battery";
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
    let bw = common::Bw::login(&email, password);

    let card = [
        ("card.cardholderName", "Octo Cat"),
        ("card.brand", "Visa"),
        ("card.number", "4111111111111111"),
        ("card.expMonth", "12"),
        ("card.expYear", "2030"),
        ("card.code", "123"),
    ];
    let identity = [
        ("identity.title", "Dr"),
        ("identity.firstName", "Octo"),
        ("identity.lastName", "Cat"),
        ("identity.email", "octo@example.com"),
        ("identity.city", "Springfield"),
        ("identity.ssn", "078-05-1120"),
    ];
    for (draft, section) in [
        (item_draft(Kind::Note, "Note here", &[]), "secureNote"),
        (item_draft(Kind::Card, "Card here", &card), "card"),
        (item_draft(Kind::Identity, "Identity here", &identity), "identity"),
    ] {
        let id = s.create_item(&mut store, &server, &refresh, &draft).await.unwrap();
        let item = bw.item(&id.to_string());
        assert_eq!(item["name"], draft.name.expose());
        assert_eq!(item["notes"], format!("{} notes", draft.name.expose()));
        assert_eq!(item["type"], draft.kind.number());
        for (name, value) in &draft.fields {
            let key = name.split_once('.').unwrap().1;
            assert_eq!(item[section][key], value.expose(), "{name}");
        }
        if draft.kind == Kind::Note {
            assert_eq!(item["secureNote"]["type"], 0);
        }
    }

    // A card bw made, with a custom field and an attachment: a new expiry year changes
    // only that, and clearing the code clears only that.
    let made = bw.create(&json!({
        "type": 3, "name": "Card from bw", "notes": null, "favorite": true, "reprompt": 0, "folderId": null,
        "fields": [{"name": "pin", "value": "4321", "type": 1}],
        "card": {"cardholderName": "Octo Cat", "brand": "Mastercard", "number": "5555555555554444",
                 "expMonth": "3", "expYear": "2027", "code": "456"},
    }));
    let id: Uuid = made["id"].as_str().unwrap().parse().unwrap();
    let file = dir.path().join("card-terms.txt");
    std::fs::write(&file, "canary card attachment\n").unwrap();
    bw.attach(&id.to_string(), &file);
    s.sync(&mut store, &server, &refresh).await.unwrap();
    let before = bw.item(&id.to_string());
    let mut fields: Vec<(&str, &str)> =
        nixe_passwords_core::vault::CARD.iter().map(|spec| (spec.name, before["card"][spec.key].as_str().unwrap())).collect();
    for f in &mut fields {
        match f.0 {
            "card.expYear" => f.1 = "2031",
            "card.code" => f.1 = "",
            _ => {}
        }
    }
    let mut draft = item_draft(Kind::Card, "Card from bw", &fields);
    draft.notes = None;
    draft.favorite = true;
    s.update_item(&mut store, &server, &refresh, id, &draft).await.unwrap();
    let after = bw.item(&id.to_string());
    let mut expected = before.clone();
    expected["card"]["expYear"] = "2031".into();
    expected["card"]["code"] = Value::Null;
    assert_eq!(settled(after), settled(expected));
    assert_eq!(bw.attachment(&id.to_string(), "card-terms.txt"), b"canary card attachment\n");

    // A card isn't saved as an identity.
    let wrong = item_draft(Kind::Identity, "Card from bw", &[]);
    assert!(s.update_item(&mut store, &server, &refresh, id, &wrong).await.is_err());
}

/// An SSH key made here reads back in `bw` with the public key and fingerprint worked
/// out from its private key, whatever the draft said; a new key replaces all three; a
/// key that can't be read is refused.
#[tokio::test]
#[ignore = "needs NIXE_PW_TEST_SERVER"]
async fn ssh_keys_round_trip_with_bw() {
    let email = common::fresh_email("ssh");
    let password = "correct horse ssh battery";
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
    let bw = common::Bw::login(&email, password);
    let fixture = |name: &str| std::fs::read_to_string(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();

    let private = fixture("ssh-ed25519");
    let draft = item_draft(
        Kind::SshKey,
        "Deploy key",
        &[
            ("ssh.privateKey", private.as_str()),
            ("ssh.publicKey", "ssh-ed25519 not-this-one"),
            ("ssh.keyFingerprint", "SHA256:nope"),
        ],
    );
    let id = s.create_item(&mut store, &server, &refresh, &draft).await.unwrap();
    let item = bw.item(&id.to_string());
    assert_eq!(item["type"], 5);
    assert_eq!(item["sshKey"]["publicKey"], fixture("ssh-ed25519.pub").trim());
    assert_eq!(item["sshKey"]["keyFingerprint"], fixture("ssh-ed25519.fp").trim());
    assert_eq!(item["sshKey"]["privateKey"].as_str().unwrap().trim(), private.trim());

    let made = nixe_passwords_core::ssh::generate();
    let draft = item_draft(Kind::SshKey, "Deploy key", &[("ssh.privateKey", made.private.expose())]);
    s.update_item(&mut store, &server, &refresh, id, &draft).await.unwrap();
    let item = bw.item(&id.to_string());
    assert_eq!(item["sshKey"]["publicKey"], made.public.as_str());
    assert_eq!(item["sshKey"]["keyFingerprint"], made.fingerprint.as_str());

    let bad = item_draft(Kind::SshKey, "Deploy key", &[("ssh.privateKey", "not a key")]);
    assert!(matches!(
        s.update_item(&mut store, &server, &refresh, id, &bad).await,
        Err(SessionError::BadSshKey(nixe_passwords_core::ssh::SshError::Unreadable))
    ));
    assert_eq!(bw.item(&id.to_string())["sshKey"]["keyFingerprint"], made.fingerprint.as_str());
}
