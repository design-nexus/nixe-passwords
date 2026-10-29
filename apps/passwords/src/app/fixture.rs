//! Debug builds only: set a test copy up for layout checks (signed in to a throwaway
//! account, items made, a section, item or card open). The window is captured from
//! outside (`grim`), on a virtual monitor of its own.
//!
//!   PASSWORDS_TEST_SIGNIN=URL|EMAIL|PASSWORD   a throwaway test account to sign in to
//!   PASSWORDS_TEST_ITEMS=JSON         an array of drafts to create first (logins, or
//!                                     notes, cards and identities with a `kind`)
//!   PASSWORDS_TEST_SELECT=NAME[|NAME…] the item to select, or several
//!   PASSWORDS_TEST_SETTINGS=1         open the settings card
//!   PASSWORDS_TEST_EMERGENCY=1        open the emergency access dialog
//!   PASSWORDS_TEST_SECTION=ID         the sidebar section
//!   PASSWORDS_TEST_EDIT=1             open the editor on the selection
//!   PASSWORDS_TEST_UNLOCK=PASSWORD    unlock a locked vault first

use std::time::Duration;

use gtk::{glib, prelude::*};
use nyx_passwords_proto::state;

use super::client;
use super::ui::{self, Ui};

pub fn maybe(ui: &Ui) {
    let set_up = ["SIGNIN", "UNLOCK", "SECTION", "SELECT", "SETTINGS", "EDIT"]
        .iter()
        .any(|k| std::env::var_os(format!("PASSWORDS_TEST_{k}")).is_some());
    if !set_up {
        return;
    }
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        if let Ok(account) = std::env::var("PASSWORDS_TEST_SIGNIN") {
            let parts: Vec<&str> = account.splitn(3, '|').collect();
            if let [server, email, password] = parts[..]
                && client::status().await.is_ok_and(|(s, _, _)| s != state::UNLOCKED)
            {
                let args = (server, email, password, 255u8, "");
                if let Err(e) = client::call("SignIn", Some(args.to_variant())).await {
                    eprintln!("test: sign in: {e}");
                }
                if let Ok(items) = std::env::var("PASSWORDS_TEST_ITEMS")
                    && let Ok(serde_json::Value::Array(items)) = serde_json::from_str(&items)
                {
                    for item in items {
                        let method = if item.get("kind").is_some() { "CreateItem" } else { "CreateLogin" };
                        let _ = client::call(method, Some((item.to_string(),).to_variant())).await;
                    }
                }
            }
        }
        if let Ok(password) = std::env::var("PASSWORDS_TEST_UNLOCK")
            && client::status().await.is_ok_and(|(s, _, _)| s == state::LOCKED)
            && let Err(e) = client::call("Unlock", Some((password.as_str(),).to_variant())).await
        {
            eprintln!("test: unlock: {e}");
        }
        ui::refresh_state(&ui);
        glib::timeout_future(Duration::from_millis(900)).await;
        if let Ok(section) = std::env::var("PASSWORDS_TEST_SECTION") {
            ui::navigate(&ui, &section);
        }
        let names = std::env::var("PASSWORDS_TEST_SELECT").unwrap_or_default();
        for name in names.split('|').filter(|n| !n.is_empty()) {
            let id = ui.listing.borrow().entries.iter().find(|e| e.name == name).map(|e| e.id.clone());
            if let Some(id) = id {
                let mut row = ui.list.first_child();
                while let Some(r) = row {
                    if r.widget_name() == id
                        && let Some(r) = r.downcast_ref::<gtk::ListBoxRow>()
                    {
                        ui.list.select_row(Some(r));
                    }
                    row = r.next_sibling();
                }
            }
        }
        if std::env::var_os("PASSWORDS_TEST_SETTINGS").is_some() {
            ui::open_settings();
        }
        if std::env::var_os("PASSWORDS_TEST_EMERGENCY").is_some() {
            super::emergency::open(&ui);
        }
        if std::env::var_os("PASSWORDS_TEST_EDIT").is_some() {
            let id = ui.selected.borrow().clone();
            let entry = id.and_then(|id| ui.listing.borrow().entries.iter().find(|e| e.id == id).cloned());
            super::editor::open(&ui, entry);
        }
    });
}
