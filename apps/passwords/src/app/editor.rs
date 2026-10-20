//! Creating and editing logins. An existing login's secret fields are fetched one by
//! one when the editor opens; the draft goes to the daemon as JSON when saved.

use std::rc::Rc;

use gtk::{gdk, glib, prelude::*};
use nixe_passwords_proto::Error as Code;
use nixe_ui::widgets as w;
use serde_json::json;

use super::client;
use super::data::Entry;
use super::detail;
use super::prefs;
use super::ui::{self, Ui, label};

struct Form {
    name: gtk::Entry,
    username: gtk::Entry,
    password: gtk::PasswordEntry,
    totp: gtk::Entry,
    uris: gtk::TextView,
    notes: gtk::TextView,
    folder: gtk::DropDown,
    folder_ids: Vec<Option<String>>,
    favorite: gtk::Switch,
    reprompt: gtk::Switch,
    banner: gtk::Box,
}

pub fn open(ui: &Ui, entry: Option<Entry>) {
    if let Some(e) = ui.editor.borrow().as_ref() {
        e.present();
        return;
    }
    let (dialog, card) = w::dialog(if entry.is_some() { "Edit login" } else { "New login" }, 560);
    dialog.set_default_height(720);
    dialog.set_transient_for(Some(&ui.window));
    dialog.set_application(ui.window.application().as_ref());
    *ui.editor.borrow_mut() = Some(dialog.clone());
    let u = ui.clone();
    dialog.connect_destroy(move |_| *u.editor.borrow_mut() = None);

    let body = w::vbox(8);
    let scroll = ui::scroll(&body);
    scroll.set_min_content_height(360);
    card.append(&scroll);
    let banner = w::vbox(0);
    body.append(&banner);

    let name = gtk::Entry::new();
    let username = gtk::Entry::new();
    let password = gtk::PasswordEntry::new();
    password.set_show_peek_icon(true);
    password.set_hexpand(true);
    let totp = gtk::Entry::new();
    totp.set_placeholder_text(Some("otpauth://… or the setup key"));
    let uris = text_view(3);
    let notes = text_view(4);
    let listing = ui.listing.borrow();
    let mut folder_ids = vec![None];
    let mut folder_names = vec![("".to_string(), "No folder".to_string())];
    for f in &listing.folders {
        folder_ids.push(Some(f.id.clone()));
        folder_names.push((f.id.clone(), f.name.clone()));
    }
    drop(listing);
    let current_folder = entry.as_ref().and_then(|e| e.folder.clone()).unwrap_or_default();
    let folder = w::dropdown(&folder_names, &current_folder);
    let favorite = gtk::Switch::new();
    let reprompt = gtk::Switch::new();

    field(&body, "Name", &name);
    field(&body, "Username", &username);
    let pw_line = w::hbox(6);
    pw_line.append(&password);
    let generate = w::bar_button("media-playlist-shuffle-symbolic", "Generate a password");
    pw_line.append(&generate);
    field(&body, "Password", &pw_line);
    field(&body, "One-time code key", &totp);
    field(&body, "Web addresses, one per line", &frame(&uris));
    field(&body, "Folder", &folder);
    let rows = w::vbox(0);
    rows.add_css_class("group-list");
    rows.append(&w::row("Favorite", "Show it under Favorites.", Some(favorite.upcast_ref())));
    rows.append(&w::row(
        "Ask for master password",
        "Ask for it again before showing or copying this login's secrets.",
        Some(reprompt.upcast_ref()),
    ));
    body.append(&rows);
    field(&body, "Notes", &frame(&notes));

    let form = Rc::new(Form { name, username, password, totp, uris, notes, folder, folder_ids, favorite, reprompt, banner });
    let id = entry.as_ref().map(|e| e.id.clone());
    if let Some(e) = &entry {
        form.name.set_text(&e.name);
        form.username.set_text(e.username.as_deref().unwrap_or(""));
        form.uris.buffer().set_text(&e.uris.join("\n"));
        form.favorite.set_active(e.favorite);
        form.reprompt.set_active(e.reprompt);
        fill_secrets(ui, &e.id, &form, &dialog);
    }

    let (u, f) = (ui.clone(), form.clone());
    generate.connect_clicked(move |_| {
        let (u, f) = (u.clone(), f.clone());
        glib::spawn_future_local(async move {
            let p = prefs::get().vault;
            let rules = if p.generate_passphrase {
                let mut v = serde_json::to_value(&p.passphrase_rules).unwrap_or_default();
                v["kind"] = "passphrase".into();
                v
            } else {
                let mut v = serde_json::to_value(&p.password_rules).unwrap_or_default();
                v["kind"] = "password".into();
                v
            };
            match client::text("GeneratePassword", Some((rules.to_string(),).to_variant())).await {
                Ok(made) => {
                    f.password.set_text(&made);
                    f.password.set_show_peek_icon(true);
                }
                Err(e) => ui::toast(&u, &e.to_string()),
            }
        });
    });

    let cancel = gtk::Button::with_label("Cancel");
    let save = gtk::Button::with_label("Save");
    save.add_css_class("suggested-action");
    save.set_tooltip_text(Some("Save (Ctrl+S)"));
    let actions = w::hbox(8);
    actions.set_halign(gtk::Align::End);
    actions.append(&cancel);
    actions.append(&save);
    card.append(&actions);
    let d = dialog.clone();
    cancel.connect_clicked(move |_| d.close());
    let submit = {
        let (u, f, d, save) = (ui.clone(), form.clone(), dialog.clone(), save.clone());
        Rc::new(move || submit(&u, &f, id.clone(), &d, &save))
    };
    let s = submit.clone();
    save.connect_clicked(move |_| s());
    let keys = gtk::EventControllerKey::new();
    let (s, d) = (submit.clone(), dialog.clone());
    keys.connect_key_pressed(move |_, key, _, mods| {
        if mods.contains(gdk::ModifierType::CONTROL_MASK) && matches!(key, gdk::Key::s | gdk::Key::S) {
            s();
            return glib::Propagation::Stop;
        }
        if key == gdk::Key::Escape {
            d.close();
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });
    dialog.add_controller(keys);
    dialog.present();
    form.name.grab_focus();
}

fn field(body: &gtk::Box, title: &str, control: &impl IsA<gtk::Widget>) {
    body.append(&label(title, "account-field"));
    body.append(control);
}

fn text_view(lines: i32) -> gtk::TextView {
    let t = gtk::TextView::new();
    t.set_wrap_mode(gtk::WrapMode::WordChar);
    t.set_accepts_tab(false);
    t.set_size_request(-1, lines * 22);
    t.add_css_class("editor-text");
    t
}

fn frame(view: &gtk::TextView) -> gtk::Box {
    let b = w::vbox(0);
    b.add_css_class("editor-frame");
    b.append(view);
    b
}

fn text_of(view: &gtk::TextView) -> String {
    let buf = view.buffer();
    buf.text(&buf.start_iter(), &buf.end_iter(), false).to_string()
}

/// Fetches the password, one-time code key and notes into the form.
fn fill_secrets(ui: &Ui, id: &str, form: &Rc<Form>, dialog: &gtk::Window) {
    let (ui, id, form, dialog) = (ui.clone(), id.to_string(), form.clone(), dialog.clone());
    glib::spawn_future_local(async move {
        let entry = ui.listing.borrow().entries.iter().find(|e| e.id == id).cloned();
        let wanted: Vec<(&str, bool)> = vec![
            ("password", entry.as_ref().is_some_and(|e| e.has_password)),
            ("totp_seed", entry.as_ref().is_some_and(|e| e.has_totp)),
            ("notes", true),
        ];
        for (field, present) in wanted {
            if !present {
                continue;
            }
            match client::reveal(&id, field).await {
                Ok(v) => match field {
                    "password" => form.password.set_text(&v),
                    "totp_seed" => form.totp.set_text(&v),
                    _ => form.notes.buffer().set_text(&v),
                },
                Err(e) if e.is(Code::NoField) => {}
                Err(e) if e.is(Code::Reprompt) => {
                    let (u, i, f, d) = (ui.clone(), id.clone(), form.clone(), dialog.clone());
                    super::account::confirm(&ui, move || fill_secrets(&u, &i, &f, &d));
                    return;
                }
                Err(e) => {
                    ui::toast(&ui, &e.to_string());
                    dialog.close();
                    return;
                }
            }
        }
    });
}

fn submit(ui: &Ui, form: &Rc<Form>, id: Option<String>, dialog: &gtk::Window, save: &gtk::Button) {
    let name = form.name.text().trim().to_string();
    if name.is_empty() {
        ui::toast(ui, "Give the login a name.");
        form.name.grab_focus();
        return;
    }
    let uris: Vec<String> = text_of(&form.uris).lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect();
    let folder = form.folder_ids.get(form.folder.selected() as usize).cloned().flatten();
    let draft = json!({
        "name": name,
        "username": form.username.text().to_string(),
        "password": form.password.text().to_string(),
        "totp": form.totp.text().trim().to_string(),
        "uris": uris,
        "notes": text_of(&form.notes),
        "folder": folder,
        "favorite": form.favorite.is_active(),
        "reprompt": form.reprompt.is_active(),
    })
    .to_string();
    save.set_sensitive(false);
    let (ui, form, dialog, save) = (ui.clone(), form.clone(), dialog.clone(), save.clone());
    glib::spawn_future_local(async move {
        let reply = match &id {
            Some(id) => client::call("UpdateLogin", Some((id.as_str(), draft.as_str()).to_variant())).await.map(|_| id.clone()),
            None => client::text("CreateLogin", Some((draft.as_str(),).to_variant())).await,
        };
        save.set_sensitive(true);
        match reply {
            Ok(saved) => {
                dialog.close();
                *ui.selected.borrow_mut() = Some(saved);
                ui.showing_detail.set(true);
                ui::reload(&ui);
                ui::toast(&ui, "Saved.");
            }
            Err(e) if e.is(Code::Conflict) => {
                // The daemon now has the server's copy; saving again replaces it with this draft.
                ui::clear(&form.banner);
                form.banner.append(&w::banner(
                    "This login was changed in another app since you opened it. Your edit wasn't saved; save again to replace the other change with yours.",
                    true,
                ));
                ui::reload(&ui);
            }
            Err(e) => detail::handle(&ui, e, || {}),
        }
    });
}
