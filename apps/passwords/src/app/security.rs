//! The Security section: logins with a weak, reused or old password, from the daemon's
//! report, and, when asked, those whose password appears in known breaches.

use std::collections::HashMap;

use gtk::{glib, prelude::*};
use nyx_ui::widgets as w;

use super::client;
use super::data::Entry;
use super::ui::{self, Ui};

#[derive(Debug, Clone, serde::Deserialize)]
struct Finding {
    id: String,
    reused: usize,
    weak: bool,
    age_days: Option<u64>,
}

#[derive(serde::Deserialize)]
struct Exposed {
    id: String,
    count: u64,
}

/// The latest report, and the breach check's results once one has run. Dropped on lock.
#[derive(Default)]
pub struct Report {
    findings: HashMap<String, Finding>,
    breaches: Option<HashMap<String, u64>>,
}

impl Report {
    fn exposed(&self, id: &str) -> Option<u64> {
        self.breaches.as_ref().and_then(|b| b.get(id).copied())
    }

    pub fn flags(&self, e: &Entry) -> bool {
        !e.deleted && (self.findings.contains_key(&e.id) || self.exposed(&e.id).is_some())
    }

    /// What's wrong with an entry's password, most serious first.
    pub fn describe(&self, e: &Entry) -> String {
        let mut parts = Vec::new();
        if let Some(n) = self.exposed(&e.id) {
            parts.push(format!("exposed in {} breaches", thousands(n)));
        }
        if let Some(f) = self.findings.get(&e.id) {
            match f.reused {
                0 => {}
                1 => parts.push("used by one other login".into()),
                n => parts.push(format!("used by {n} other logins")),
            }
            if f.weak {
                parts.push("weak".into());
            }
            if let Some(days) = f.age_days {
                parts.push(match days / 365 {
                    1 => "over a year old".into(),
                    n => format!("over {n} years old"),
                });
            }
        }
        let text = parts.join(" · ");
        let mut chars = text.chars();
        chars.next().map(|c| c.to_uppercase().chain(chars).collect()).unwrap_or_default()
    }
}

fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Asks the daemon for a fresh report, then updates the sidebar count and, in the
/// Security section, the list.
pub fn refresh(ui: &Ui) {
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let Ok(json) = client::text("Report", None).await else { return };
        let Ok(list) = serde_json::from_str::<Vec<Finding>>(&json) else { return };
        ui.security.borrow_mut().findings = list.into_iter().map(|f| (f.id.clone(), f)).collect();
        ui::nav(&ui);
        if *ui.section.borrow() == "security" {
            ui::refresh_list(&ui);
        }
    });
}

/// The toolbar's part in the Security section: the breach check.
pub fn toolbar(ui: &Ui) -> gtk::Box {
    let bar = w::hbox(0);
    let check = gtk::Button::from_icon_name("security-high-symbolic");
    check.set_tooltip_text(Some("Check for breaches: look up your passwords in Have I Been Pwned's breach data"));
    let u = ui.clone();
    check.connect_clicked(move |b| ask_and_check(&u, b));
    bar.append(&check);
    bar
}

fn ask_and_check(ui: &Ui, button: &gtk::Button) {
    let window = button.root().and_downcast::<gtk::Window>();
    let ask = gtk::AlertDialog::builder()
        .modal(true)
        .message("Check your passwords against known breaches?")
        .detail(
            "Have I Been Pwned (api.pwnedpasswords.com) gets the first five characters of each password's SHA-1 \
             hash and answers with every breached hash that starts the same way; the match is made here. Your \
             passwords and their full hashes never leave this device.",
        )
        .buttons(["Cancel", "Check"])
        .cancel_button(0)
        .default_button(1)
        .build();
    let (ui, button) = (ui.clone(), button.clone());
    glib::spawn_future_local(async move {
        if ask.choose_future(window.as_ref()).await != Ok(1) {
            return;
        }
        button.set_sensitive(false);
        ui::toast(&ui, "Checking…");
        let reply = client::text("CheckBreaches", None).await;
        button.set_sensitive(true);
        match reply.map(|json| serde_json::from_str::<Vec<Exposed>>(&json).unwrap_or_default()) {
            // Locked while it ran: nothing of the vault goes back into the window.
            Ok(_) if *ui.state.borrow() != nyx_passwords_proto::state::UNLOCKED => {}
            Ok(found) => {
                let n = found.len();
                ui.security.borrow_mut().breaches = Some(found.into_iter().map(|e| (e.id, e.count)).collect());
                ui::nav(&ui);
                ui::refresh_list(&ui);
                ui::toast(
                    &ui,
                    &match n {
                        0 => "None of your passwords are in known breaches.".to_string(),
                        1 => "One password is in known breaches: change it.".to_string(),
                        n => format!("{n} passwords are in known breaches: change them."),
                    },
                );
            }
            Err(e) => ui::toast(&ui, &e.to_string()),
        }
    });
}
