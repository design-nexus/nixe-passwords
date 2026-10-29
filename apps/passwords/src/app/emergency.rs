//! Emergency access, from the settings card: the people you trust with your vault
//! (invite, confirm, approve or reject their requests) and the people who trust you
//! (ask for access, then view their vault). Everything goes through the daemon.

use std::rc::Rc;

use gtk::{glib, prelude::*};
use nyx_ui::widgets as w;
use serde::Deserialize;

use super::client;
use super::ui::{self, Ui, label};

#[derive(Deserialize, Clone)]
struct Contact {
    id: String,
    name: String,
    email: String,
    status: String,
    wait_days: i64,
}

#[derive(Deserialize)]
struct Contacts {
    trusted: Vec<Contact>,
    granted: Vec<Contact>,
}

async fn act(action: &str, arg: &str, days: u32) -> client::Result<String> {
    let v = client::call("Emergency", Some((action, arg, days).to_variant())).await?;
    Ok(v.get::<(String,)>().map(|(s,)| s).unwrap_or_default())
}

pub fn open(ui: &Ui) {
    let (dialog, card) = w::dialog("Emergency access", 580);
    dialog.set_transient_for(Some(&ui.window));
    card.append(&label(
        "People you trust can ask to see your vault. They get in when you approve, or when the wait you set runs out without you turning them down. They can only view it.",
        "dim",
    ));
    let body = w::vbox(12);
    let scroll = ui::scroll(&body);
    scroll.set_min_content_height(420);
    card.append(&scroll);
    let page = Rc::new(Page { ui: ui.clone(), body });
    page.refresh();
    dialog.present();
}

struct Page {
    ui: Ui,
    body: gtk::Box,
}

impl Page {
    fn refresh(self: &Rc<Self>) {
        let page = self.clone();
        glib::spawn_future_local(async move {
            let contacts = match client::text("EmergencyContacts", None).await {
                Ok(json) => serde_json::from_str::<Contacts>(&json).ok(),
                Err(e) => return ui::toast(&page.ui, &e.to_string()),
            };
            let Some(contacts) = contacts else { return };
            let me = act("me", "", 0).await.unwrap_or_default();
            page.show(contacts, &me);
        });
    }

    fn group(&self, title: &str) -> gtk::Box {
        self.body.append(&label(&title.to_uppercase(), "group-title"));
        let rows = w::vbox(0);
        rows.add_css_class("group-list");
        self.body.append(&rows);
        rows
    }

    fn button(self: &Rc<Self>, text: &str, action: &'static str, id: &str, then: Option<&'static str>) -> gtk::Button {
        let b = gtk::Button::with_label(text);
        let (page, id) = (self.clone(), id.to_string());
        b.connect_clicked(move |_| {
            let (page, id) = (page.clone(), id.clone());
            glib::spawn_future_local(async move {
                match act(action, &id, 0).await {
                    Ok(_) => {
                        if let Some(done) = then {
                            ui::toast(&page.ui, done);
                        }
                        page.refresh();
                    }
                    Err(e) => ui::toast(&page.ui, &e.to_string()),
                }
            });
        });
        b
    }

    fn show(self: &Rc<Self>, contacts: Contacts, me: &str) {
        ui::clear(&self.body);
        if !me.is_empty() {
            let rows = self.group("Your fingerprint phrase");
            let phrase = label(me, "");
            phrase.set_selectable(true);
            rows.append(&w::row("Read it to someone confirming you as their contact", "", Some(phrase.upcast_ref())));
        }

        let rows = self.group("People you trust");
        for c in &contacts.trusted {
            let who = if c.name.is_empty() { c.email.clone() } else { format!("{} ({})", c.name, c.email) };
            let (state, buttons): (String, Vec<gtk::Button>) = match c.status.as_str() {
                "invited" => ("Invited; waiting for them to accept".into(), vec![]),
                "accepted" => ("Accepted: confirm them to finish".into(), vec![self.confirm_button(c)]),
                "confirmed" => (format!("Can ask for access; a {}-day wait", c.wait_days), vec![]),
                "requested" => (
                    format!("Asks for access: let in after {} days unless you reject", c.wait_days),
                    vec![
                        self.button("Approve", "approve", &c.id, Some("Approved.")),
                        self.button("Reject", "reject", &c.id, Some("Rejected.")),
                    ],
                ),
                "approved" => ("Has access to view your vault".into(), vec![]),
                _ => (String::new(), vec![]),
            };
            let line = w::hbox(6);
            for b in buttons {
                line.append(&b);
            }
            let remove = self.button("Remove", "remove", &c.id, Some("Removed."));
            remove.add_css_class("destructive-action");
            line.append(&remove);
            rows.append(&w::row(&who, &glib::markup_escape_text(&state), Some(line.upcast_ref())));
        }
        // Inviting: their account's email and the wait.
        let line = w::hbox(6);
        let email = gtk::Entry::new();
        email.set_placeholder_text(Some("Their account's email"));
        email.set_hexpand(true);
        let days = gtk::SpinButton::with_range(1.0, 90.0, 1.0);
        days.set_value(7.0);
        days.set_tooltip_text(Some("Days to wait before they get in, unless you turn them down"));
        let invite = gtk::Button::with_label("Invite");
        line.append(&email);
        line.append(&days);
        line.append(&invite);
        rows.append(&w::row("Add someone", "They need an account on this server.", None));
        rows.append(&line);
        let page = self.clone();
        invite.connect_clicked(move |_| {
            let (page, address, wait) = (page.clone(), email.text().trim().to_string(), days.value() as u32);
            if address.is_empty() {
                return;
            }
            glib::spawn_future_local(async move {
                match act("invite", &address, wait).await {
                    Ok(_) => page.refresh(),
                    Err(e) => ui::toast(&page.ui, &e.to_string()),
                }
            });
        });

        let rows = self.group("People who trust you");
        if contacts.granted.is_empty() {
            rows.append(&w::row("No one yet", "", None));
        }
        for c in &contacts.granted {
            let who = if c.name.is_empty() { c.email.clone() } else { format!("{} ({})", c.name, c.email) };
            let (state, buttons): (String, Vec<gtk::Button>) = match c.status.as_str() {
                "invited" | "accepted" => ("Waiting for them to confirm you".into(), vec![]),
                "confirmed" => (
                    format!("You can ask for access; they have {} days to turn you down", c.wait_days),
                    vec![self.button("Ask for access", "request", &c.id, Some("Asked. They've been told."))],
                ),
                "requested" => (format!("Asked; you get in after {} days unless they reject", c.wait_days), vec![]),
                "approved" => ("You can view their vault".into(), vec![self.view_button(c)]),
                _ => (String::new(), vec![]),
            };
            let line = w::hbox(6);
            for b in buttons {
                line.append(&b);
            }
            line.append(&self.button("Remove", "remove", &c.id, Some("Removed.")));
            rows.append(&w::row(&who, &glib::markup_escape_text(&state), Some(line.upcast_ref())));
        }
    }

    /// Confirming sends them your vault's key: first compare their phrase with theirs.
    fn confirm_button(self: &Rc<Self>, c: &Contact) -> gtk::Button {
        let b = gtk::Button::with_label("Confirm…");
        b.add_css_class("suggested-action");
        let (page, c) = (self.clone(), c.clone());
        b.connect_clicked(move |_| {
            let (page, c) = (page.clone(), c.clone());
            glib::spawn_future_local(async move {
                let phrase = match act("fingerprint", &c.id, 0).await {
                    Ok(p) => p,
                    Err(e) => return ui::toast(&page.ui, &e.to_string()),
                };
                let detail = format!(
                    "Ask {} to read their fingerprint phrase (Settings → Emergency access in Passwords, or Account settings in the web vault). Confirm only if it's:\n\n{phrase}",
                    c.email
                );
                if !ui::confirm(&page.ui, "Confirm this contact?", &detail, "Confirm").await {
                    return;
                }
                match act("confirm", &c.id, 0).await {
                    Ok(_) => page.refresh(),
                    Err(e) => ui::toast(&page.ui, &e.to_string()),
                }
            });
        });
        b
    }

    fn view_button(self: &Rc<Self>, c: &Contact) -> gtk::Button {
        let b = gtk::Button::with_label("View vault");
        b.add_css_class("suggested-action");
        let (ui, c) = (self.ui.clone(), c.clone());
        b.connect_clicked(move |_| view(&ui, &c));
        b
    }
}

/// A grantor's vault, read-only: each item's name and username, with its password and
/// notes shown on request.
fn view(ui: &Ui, c: &Contact) {
    #[derive(Deserialize)]
    struct Entry {
        id: String,
        name: String,
        username: Option<String>,
        has_password: bool,
    }
    let (ui, c) = (ui.clone(), c.clone());
    glib::spawn_future_local(async move {
        let entries = match client::text("ViewEmergency", Some((c.id.as_str(),).to_variant())).await {
            Ok(json) => serde_json::from_str::<Vec<Entry>>(&json).unwrap_or_default(),
            Err(e) => return ui::toast(&ui, &e.to_string()),
        };
        let (dialog, card) = w::dialog(&format!("{}'s vault", if c.name.is_empty() { &c.email } else { &c.name }), 560);
        dialog.set_transient_for(Some(&ui.window));
        card.append(&label("Read-only. It's closed again when your vault locks.", "dim"));
        let rows = w::vbox(0);
        rows.add_css_class("group-list");
        for e in entries {
            let line = w::hbox(6);
            let shown = label("", "secret-value");
            shown.set_selectable(true);
            line.append(&shown);
            for (field, text) in [("password", "Password"), ("notes", "Notes")] {
                if field == "password" && !e.has_password {
                    continue;
                }
                let b = gtk::Button::with_label(text);
                b.add_css_class("flat");
                let (ui, id, shown) = (ui.clone(), e.id.clone(), shown.clone());
                b.connect_clicked(move |_| {
                    let (ui, id, shown) = (ui.clone(), id.clone(), shown.clone());
                    glib::spawn_future_local(async move {
                        match client::text("EmergencyReveal", Some((id.as_str(), field).to_variant())).await {
                            Ok(v) => shown.set_text(&v),
                            Err(e) => ui::toast(&ui, &e.to_string()),
                        }
                    });
                });
                line.append(&b);
            }
            let sub = glib::markup_escape_text(e.username.as_deref().unwrap_or(""));
            rows.append(&w::row(&e.name, &sub, Some(line.upcast_ref())));
        }
        let scroll = ui::scroll(&rows);
        scroll.set_min_content_height(360);
        card.append(&scroll);
        dialog.present();
    });
}
