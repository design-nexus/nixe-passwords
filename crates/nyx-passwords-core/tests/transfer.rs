//! Exports and imports against the throwaway Vaultwarden, with the official `bw` CLI
//! as the other side: what bw exports reads here, and what's exported here bw imports.
//!
//!   apps/passwords/scripts/test-server.sh start
//!   NYX_PW_TEST_SERVER=https://127.0.0.1:8087 NYX_PW_TEST_CA=$PWD/target/vaultwarden-test/ca.pem \
//!     cargo test -p nyx-passwords-core --test transfer -- --ignored

mod common;

use std::num::NonZeroU32;

use nyx_passwords_core::api::Server;
use nyx_passwords_core::secret::Secret;
use nyx_passwords_core::session::{self, Session, SignIn};
use nyx_passwords_core::store::Store;
use nyx_passwords_core::transfer::{self, ExportFormat, TransferError};
use nyx_passwords_core::vault::{Field, reveal};
use serde_json::{Value, json};

struct Account {
    email: String,
    password: String,
    s: Session,
    store: Store,
    server: Server,
    refresh: Secret,
    _dir: tempfile::TempDir,
}

async fn account(tag: &str) -> Account {
    let email = common::fresh_email(tag);
    let password = format!("correct horse {tag} battery");
    common::register(&email, &password, &bitwarden_crypto::Kdf::PBKDF2 { iterations: NonZeroU32::new(600_000).unwrap() }).await;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("vault.sqlite")).unwrap();
    let server = Server::new(&common::server_url(), &[common::ca_pem()]).unwrap();
    let SignIn::Done(s) =
        session::sign_in(&mut store, &server, &email, &Secret::new(password.as_str()), "nyx test", None).await.unwrap()
    else {
        panic!("two-step login")
    };
    let refresh = Secret::new(s.refresh_token().unwrap().expose());
    Account { email, password, s: *s, store, server, refresh, _dir: dir }
}

fn names(bw: &common::Bw) -> Vec<String> {
    bw.run(&["sync"]);
    let items: Value = serde_json::from_str(&bw.run(&["list", "items"])).unwrap();
    let mut names: Vec<String> = items.as_array().unwrap().iter().map(|i| i["name"].as_str().unwrap().to_string()).collect();
    names.sort();
    names
}

#[tokio::test]
#[ignore = "needs NYX_PW_TEST_SERVER"]
async fn exports_and_imports_round_trip_with_bw() {
    let mut a = account("export").await;
    let bw_a = common::Bw::login(&a.email, &a.password);
    let folder = bw_a.run(&["get", "template", "folder"]);
    let mut folder: Value = serde_json::from_str(&folder).unwrap();
    folder["name"] = "Work".into();
    let encoded = bitwarden_encoding::B64::from(serde_json::to_vec(&folder).unwrap()).to_string();
    let folder: Value = serde_json::from_str(&bw_a.run(&["create", "folder", &encoded])).unwrap();
    bw_a.create(&json!({
        "type": 1, "name": "GitHub", "notes": "kept", "favorite": true, "reprompt": 0, "folderId": folder["id"],
        "fields": [{"name": "pin", "value": "1234", "type": 1}],
        "login": {"username": "octo", "password": "canary-gh-Pw!9", "totp": "JBSWY3DPEHPK3PXP",
                  "uris": [{"uri": "https://github.com/login", "match": null}]},
    }));
    bw_a.create(
        &json!({"type": 2, "name": "Memo", "notes": "remember", "secureNote": {"type": 0}, "favorite": false, "reprompt": 0}),
    );
    bw_a.create(&json!({"type": 3, "name": "Visa", "notes": null, "favorite": false, "reprompt": 0,
                         "card": {"cardholderName": "O. Cat", "number": "4111111111111111", "code": "123", "brand": "Visa", "expMonth": "9", "expYear": "2027"}}));
    a.s.sync(&mut a.store, &a.server, &a.refresh).await.unwrap();
    let dir = tempfile::tempdir().unwrap();

    // bw's exports read here: plain JSON, password-protected, this account's, and CSV.
    for (args, password) in [
        (vec!["--format", "json"], None),
        (vec!["--format", "encrypted_json", "--password", "export pw"], Some("export pw")),
        (vec!["--format", "encrypted_json"], None),
        (vec!["--format", "csv"], None),
    ] {
        let out = dir.path().join(format!("bw-{}", args.join("-")));
        let mut cmd = vec!["export", "--output", out.to_str().unwrap()];
        cmd.extend(args.iter().copied());
        bw_a.run(&cmd);
        let data = std::fs::read(&out).unwrap();
        if password.is_some() {
            assert_eq!(transfer::parse(&data, None, &a.s.keys).err(), Some(TransferError::NeedsPassword));
            assert_eq!(transfer::parse(&data, Some(&Secret::new("nope")), &a.s.keys).err(), Some(TransferError::WrongPassword));
        }
        let parsed = transfer::parse(&data, password.map(Secret::new).as_ref(), &a.s.keys).unwrap();
        let expected = if args.contains(&"csv") { 2 } else { 3 };
        assert_eq!(parsed.items.len(), expected, "{args:?}: {}", parsed.format);
        let github = parsed.items.iter().find(|(i, _)| i["name"] == "GitHub").unwrap();
        assert_eq!(github.0["login"]["password"], "canary-gh-Pw!9", "{args:?}");
        assert_eq!(parsed.folders, vec!["Work".to_string()], "{args:?}");
    }

    // Exports made here, imported by bw into another account.
    let b = account("import-bw").await;
    let bw_b = common::Bw::login(&b.email, &b.password);
    for (format, bw_format) in [(ExportFormat::Json, "bitwardenjson"), (ExportFormat::Csv, "bitwardencsv")] {
        let made = transfer::export(&a.s.keys, &a.s.snapshot, format, None).unwrap();
        let file = dir.path().join(format!("nyx-{bw_format}"));
        std::fs::write(&file, made.expose()).unwrap();
        bw_b.run(&["import", bw_format, file.to_str().unwrap()]);
    }
    // JSON gives three, CSV the login and note again. (bw asks for an export's password
    // only interactively; the protected format is checked below, and above from bw's side.)
    assert_eq!(names(&bw_b).len(), 5, "{:?}", names(&bw_b));

    // And imports here: an export made here goes into a fresh account, every field intact.
    let mut c = account("import-nyx").await;
    let made = transfer::export(&a.s.keys, &a.s.snapshot, ExportFormat::PasswordJson, Some(&Secret::new("our pw"))).unwrap();
    let parsed = transfer::parse(made.expose().as_bytes(), Some(&Secret::new("our pw")), &c.s.keys).unwrap();
    c.s.import(&mut c.store, &c.server, &c.refresh, &parsed).await.unwrap();
    let github = c.s.view.search("github", 5)[0].id;
    assert_eq!(reveal(&c.s.keys, &c.s.snapshot, github, Field::Password).unwrap().expose(), "canary-gh-Pw!9");
    assert_eq!(reveal(&c.s.keys, &c.s.snapshot, github, Field::Custom(0)).unwrap().expose(), "1234");
    assert_eq!(c.s.view.get(github).unwrap().folder.and_then(|f| c.s.view.folder_name(f)), Some("Work"));
    let bw_c = common::Bw::login(&c.email, &c.password);
    assert_eq!(names(&bw_c), vec!["GitHub", "Memo", "Visa"]);
    let item = bw_c.item(&github.to_string());
    assert_eq!(item["login"]["uris"][0]["uri"], "https://github.com/login", "bw trusts the address (checksum)");
    // This account's encrypted export doesn't open in another account.
    let mine = transfer::export(&a.s.keys, &a.s.snapshot, ExportFormat::AccountJson, None).unwrap();
    assert_eq!(transfer::parse(mine.expose().as_bytes(), None, &c.s.keys).err(), Some(TransferError::OtherAccount));
    assert_eq!(transfer::parse(mine.expose().as_bytes(), None, &a.s.keys).unwrap().items.len(), 3);
}
