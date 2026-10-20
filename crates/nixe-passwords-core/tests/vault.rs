//! Offline: the decrypted view of a recorded vault (tests/fixtures), its search, and
//! revealing single fields, checked against what the official `bw` CLI decrypted.

use nixe_passwords_core::crypto::{CryptoError, Kdf, Keys, MasterKey};
use nixe_passwords_core::model::{Kind, Sync};
use nixe_passwords_core::secret::Secret;
use nixe_passwords_core::vault::{Field, RevealError, View, reveal};
use serde_json::Value;

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn open() -> (Keys, Sync, Vec<Value>) {
    let meta = fixture("pbkdf2-account.json");
    let sync: Sync = serde_json::from_value(fixture("pbkdf2-sync.json")).unwrap();
    let password = Secret::new(meta["password"].as_str().unwrap());
    let master = MasterKey::derive(&password, meta["email"].as_str().unwrap(), &Kdf::Pbkdf2 { iterations: 600_000 }).unwrap();
    let keys = Keys::unlock(&master, &sync.profile.key).unwrap();
    keys.add_private_key(sync.profile.private_key.as_deref().unwrap()).unwrap();
    for org in &sync.profile.organizations {
        keys.add_organization(org.id, org.key.as_deref().unwrap()).unwrap();
    }
    (keys, sync, serde_json::from_value(fixture("pbkdf2-bw.json")).unwrap())
}

fn names(hits: &[&nixe_passwords_core::vault::Entry]) -> Vec<String> {
    hits.iter().map(|e| e.name.expose().to_string()).collect()
}

#[test]
fn view_lists_everything_readable() {
    let (keys, sync, bw) = open();
    let view = View::build(&keys, &sync);
    assert_eq!(view.entries.len(), bw.len());
    assert!(view.entries.iter().all(|e| e.readable));
    for e in &view.entries {
        let b = bw.iter().find(|b| b["id"] == e.id.to_string()).unwrap();
        assert_eq!(e.name.expose(), b["name"]);
        assert_eq!(e.username.as_ref().map(|u| u.expose().to_string()), b["login"]["username"].as_str().map(str::to_string));
        assert_eq!(e.has_totp, b["login"]["totp"].is_string());
    }
    let github = view.entries.iter().find(|e| e.name.expose() == "GitHub pbkdf2").unwrap();
    assert_eq!((github.kind, github.host.as_deref()), (Kind::Login, Some("github.com")));
    assert_eq!(view.folder_name(github.folder.unwrap()), Some("Work pbkdf2"));
    assert_eq!(view.collections.len(), 1);
    assert_eq!(view.collections[0].name.expose(), "Shared");
    assert_eq!(view.organizations[0].1, "Spike Org");
}

#[test]
fn search_ranks_and_filters() {
    let (keys, sync, _) = open();
    let view = View::build(&keys, &sync);
    // Name matches first; both logins are GitHub, the personal one sorts first by name.
    assert_eq!(names(&view.search("github", 10)), ["GitHub pbkdf2", "GitHub pbkdf2-org"]);
    // Every word must match.
    assert_eq!(names(&view.search("github org", 10)), ["GitHub pbkdf2-org"]);
    // By username, host, folder and collection.
    assert_eq!(names(&view.search("octo-pbkdf2-org", 10)), ["GitHub pbkdf2-org"]);
    assert_eq!(view.search("github.com", 10).len(), 2);
    assert!(names(&view.search("work", 10)).contains(&"Card pbkdf2".to_string()));
    assert_eq!(names(&view.search("shared", 10)), ["GitHub pbkdf2-org"]);
    assert!(view.search("nothing-like-this", 10).is_empty());
    assert_eq!(view.search("pbkdf2", 2).len(), 2);
    // Never by secret fields.
    assert!(view.search("canary", 10).is_empty());
}

#[test]
fn reveal_matches_bw() {
    let (keys, sync, bw) = open();
    let view = View::build(&keys, &sync);
    for e in &view.entries {
        let b = bw.iter().find(|b| b["id"] == e.id.to_string()).unwrap();
        match reveal(&keys, &sync, e.id, Field::Password) {
            Ok(p) => assert_eq!(p.expose(), b["login"]["password"]),
            Err(err) => assert_eq!((err, &b["login"]["password"]), (RevealError::Empty, &Value::Null)),
        }
        assert_eq!(reveal(&keys, &sync, e.id, Field::Notes).unwrap().expose(), b["notes"]);
        assert_eq!(reveal(&keys, &sync, e.id, Field::Custom(0)).unwrap().expose(), b["fields"][0]["value"]);
        if e.has_totp {
            let code = reveal(&keys, &sync, e.id, Field::Totp).unwrap();
            assert!(code.expose().len() == 6 && code.expose().chars().all(|c| c.is_ascii_digit()));
        }
    }
    assert_eq!(reveal(&keys, &sync, uuid::Uuid::nil(), Field::Password).err(), Some(RevealError::NotFound));
}

#[test]
fn nothing_after_lock() {
    let (keys, sync, _) = open();
    let id = sync.ciphers[0].id;
    keys.lock();
    assert_eq!(reveal(&keys, &sync, id, Field::Password).err(), Some(RevealError::Crypto(CryptoError::MissingKey)));
    let view = View::build(&keys, &sync);
    assert!(view.entries.iter().all(|e| !e.readable && e.name.is_empty()));
    assert!(view.folders.is_empty() && view.collections.is_empty());
    assert!(view.search("github", 10).is_empty());
}

#[test]
fn entries_never_print_their_contents() {
    let (keys, sync, _) = open();
    let view = View::build(&keys, &sync);
    let e = view.entries.iter().find(|e| e.username.is_some()).unwrap();
    let printed = format!("{:?} {:?}", e.name, e.username);
    assert!(!printed.contains("GitHub") && !printed.contains("octo"), "{printed}");
}

#[test]
fn matching_pages() {
    let (keys, sync, _) = open();
    let view = View::build(&keys, &sync);
    let page = |u: &str| url::Url::parse(u).unwrap();
    // Both GitHub logins (one personal, one in the organization) saved https://github.com/login.
    assert_eq!(view.matching(&page("https://github.com/settings")).len(), 2);
    assert_eq!(view.matching(&page("https://gist.github.com/")).len(), 2);
    assert!(view.matching(&page("http://github.com/")).is_empty());
    assert!(view.matching(&page("https://github.io/")).is_empty());
    assert!(view.matching(&page("https://example.com/")).is_empty());
}

#[test]
fn every_field_of_every_kind() {
    use nixe_passwords_core::vault::{fields, sub_field};
    let (keys, sync, bw) = open();
    let view = View::build(&keys, &sync);
    let card = view.entries.iter().find(|e| e.kind == Kind::Card).unwrap();
    let shown = fields(&keys, &sync, card.id).unwrap();
    let get = |name: &str| shown.iter().find(|f| f.name == name).unwrap();
    assert_eq!(get("card.cardholderName").value.as_ref().unwrap().expose(), "Octo Cat");
    assert_eq!(get("card.brand").value.as_ref().unwrap().expose(), "Visa");
    // Secret fields are listed but withheld until asked for.
    assert!(get("card.number").secret && get("card.number").value.is_none());
    let b = bw.iter().find(|b| b["id"] == card.id.to_string()).unwrap();
    assert_eq!(reveal(&keys, &sync, card.id, sub_field("card.number").unwrap()).unwrap().expose(), b["card"]["number"]);
    assert_eq!(reveal(&keys, &sync, card.id, sub_field("card.code").unwrap()).unwrap().expose(), b["card"]["code"]);
    // Custom fields: "recovery" was saved as hidden (type 1).
    let custom = shown.iter().find(|f| f.name == "custom:0").unwrap();
    assert_eq!((custom.label.as_str(), custom.secret, custom.value.is_none()), ("recovery", true, true));

    let ident = view.entries.iter().find(|e| e.kind == Kind::Identity).unwrap();
    let shown = fields(&keys, &sync, ident.id).unwrap();
    assert!(shown.iter().any(|f| f.name == "identity.firstName" && f.value.as_ref().unwrap().expose() == "Octo"));
    assert!(shown.iter().any(|f| f.name == "identity.email" && f.value.as_ref().unwrap().expose() == "octo@example.com"));
    // Only fields the item has are listed.
    assert!(!shown.iter().any(|f| f.name == "identity.ssn"));
    assert!(sub_field("card.nope").is_none() && sub_field("identity.ssn").is_some());
}
