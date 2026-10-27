//! Browser pairing in the window: the request a browser extension makes shows here
//! with its code, and paired browsers are listed in the settings card.

use std::cell::Cell;

use gtk::{glib, prelude::*};
use nyx_ui::widgets as w;
use serde::Deserialize;

use super::client;
use super::ui::{self, Ui, label};

#[derive(Deserialize, Default)]
struct Listing {
    pending: Vec<Request>,
    paired: Vec<Paired>,
}

#[derive(Deserialize, Clone)]
struct Request {
    id: String,
    browser: String,
    code: String,
}

#[derive(Deserialize, Clone)]
struct Paired {
    id: String,
    browser: String,
    created: u64,
}

thread_local! { static ASKING: Cell<bool> = const { Cell::new(false) }; }

async fn listing() -> Option<Listing> {
    let json = client::text("Pairings", None).await.ok()?;
    serde_json::from_str(&json).ok()
}

/// Shows a waiting pairing request, if there is one and none is showing.
pub fn check(ui: &Ui) {
    if ASKING.with(Cell::get) {
        return;
    }
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let Some(request) = listing().await.and_then(|l| l.pending.into_iter().next()) else { return };
        if ASKING.with(|a| a.replace(true)) {
            return;
        }
        ask(&ui, request);
    });
}

fn ask(ui: &Ui, request: Request) {
    let (dialog, card) = w::dialog(&format!("Pair {}?", request.browser), 440);
    dialog.set_transient_for(Some(&ui.window));
    card.append(&label(
        &format!("{} asks to fill logins from this vault. Pair it only if the extension shows this code:", request.browser),
        "dim",
    ));
    let code = label(&format!("{} {}", &request.code[..3], &request.code[3..]), "pairing-code");
    card.append(&code);
    let not_now = gtk::Button::with_label("Not now");
    let pair = gtk::Button::with_label("Pair");
    pair.add_css_class("suggested-action");
    let actions = w::hbox(8);
    actions.set_halign(gtk::Align::End);
    actions.append(&not_now);
    actions.append(&pair);
    card.append(&actions);
    dialog.connect_destroy(|_| ASKING.with(|a| a.set(false)));
    let (d, id) = (dialog.clone(), request.id.clone());
    not_now.connect_clicked(move |_| {
        let id = id.clone();
        glib::spawn_future_local(async move {
            let _ = client::call("RemovePairing", Some((id.as_str(),).to_variant())).await;
        });
        d.close();
    });
    let (d, u) = (dialog.clone(), ui.clone());
    pair.connect_clicked(move |_| {
        let (d, u, request) = (d.clone(), u.clone(), request.clone());
        glib::spawn_future_local(async move {
            match client::call("ConfirmPairing", Some((request.id.as_str(),).to_variant())).await {
                Ok(_) => ui::toast(&u, &format!("{} is paired.", request.browser)),
                Err(e) => ui::toast(&u, &e.to_string()),
            }
            d.close();
        });
    });
    dialog.present();
}

/// The settings card's Browsers group: paired browsers, each with Remove.
pub fn fill_group(rows: &gtk::Box) {
    let rows = rows.clone();
    glib::spawn_future_local(async move {
        let paired = listing().await.map(|l| l.paired).unwrap_or_default();
        if paired.is_empty() {
            rows.append(&w::row("No browsers paired", "Pair from the extension's button in the browser.", None));
        }
        for p in paired {
            let when = super::data::ago(p.created);
            let row_box = w::vbox(0);
            let id = p.id.clone();
            let remove = w::two_click("Remove", "Click again to remove", {
                let row_box = row_box.clone();
                move || {
                    let id = id.clone();
                    let row_box = row_box.clone();
                    glib::spawn_future_local(async move {
                        if client::call("RemovePairing", Some((id.as_str(),).to_variant())).await.is_ok() {
                            row_box.set_visible(false);
                        }
                    });
                }
            });
            row_box.append(&w::row(&p.browser, &format!("Paired {when}"), Some(remove.upcast_ref())));
            rows.append(&row_box);
        }
    });
}
