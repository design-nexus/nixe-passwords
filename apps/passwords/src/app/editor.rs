//! Creating and editing logins, notes, cards and identities. An existing item's secret
//! fields are fetched one by one when the editor opens; the draft goes to the daemon as
//! JSON when saved.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use gtk::{gdk, glib, prelude::*};
use nixe_passwords_proto::Error as Code;
use nixe_passwords_proto::fields::{self, Spec};
use nixe_ui::widgets as w;
use serde_json::json;

use super::client;
use super::data::{self, Entry};
use super::detail::{self, FieldRow};
use super::prefs;
use super::ui::{self, Ui, label};

/// The kinds the editor makes; SSH keys are edited in the web vault for now.
pub const KINDS: &[&str] = &["login", "note", "card", "identity"];

/// Fields with fixed choices, as the official clients offer them: `(value, label)`.
fn choices(name: &str) -> Option<&'static [(&'static str, &'static str)]> {
    match name {
        "card.brand" => Some(&[
            ("Visa", "Visa"),
            ("Mastercard", "Mastercard"),
            ("Amex", "American Express"),
            ("Discover", "Discover"),
            ("Diners Club", "Diners Club"),
            ("JCB", "JCB"),
            ("Maestro", "Maestro"),
            ("UnionPay", "UnionPay"),
            ("RuPay", "RuPay"),
            ("Other", "Other"),
        ]),
        "card.expMonth" => Some(&[
            ("1", "01 · January"),
            ("2", "02 · February"),
            ("3", "03 · March"),
            ("4", "04 · April"),
            ("5", "05 · May"),
            ("6", "06 · June"),
            ("7", "07 · July"),
            ("8", "08 · August"),
            ("9", "09 · September"),
            ("10", "10 · October"),
            ("11", "11 · November"),
            ("12", "12 · December"),
        ]),
        "identity.title" => Some(&[("Mr", "Mr"), ("Mrs", "Mrs"), ("Ms", "Ms"), ("Mx", "Mx"), ("Dr", "Dr")]),
        _ => None,
    }
}

/// One field of a note, card or identity.
enum Control {
    Text(gtk::Entry),
    Secret(gtk::PasswordEntry),
    /// The values behind the drop-down's rows; the first row is "none".
    Choice(gtk::DropDown, RefCell<Vec<String>>),
}

impl Control {
    fn new(spec: &Spec) -> Control {
        if let Some(options) = choices(spec.name) {
            let mut rows = vec![(String::new(), "—".to_string())];
            rows.extend(options.iter().map(|(v, l)| (v.to_string(), l.to_string())));
            let values = rows.iter().map(|(v, _)| v.clone()).collect();
            return Control::Choice(w::dropdown(&rows, ""), RefCell::new(values));
        }
        if spec.secret {
            let p = gtk::PasswordEntry::new();
            p.set_show_peek_icon(true);
            return Control::Secret(p);
        }
        Control::Text(gtk::Entry::new())
    }

    fn widget(&self) -> gtk::Widget {
        match self {
            Control::Text(e) => e.clone().upcast(),
            Control::Secret(p) => p.clone().upcast(),
            Control::Choice(d, _) => d.clone().upcast(),
        }
    }

    fn text(&self) -> String {
        match self {
            Control::Text(e) => e.text().trim().to_string(),
            Control::Secret(p) => p.text().trim().to_string(),
            Control::Choice(d, values) => values.borrow().get(d.selected() as usize).cloned().unwrap_or_default(),
        }
    }

    /// A value another client saved that isn't one of the choices is added as its own row.
    fn set(&self, value: &str) {
        match self {
            Control::Text(e) => e.set_text(value),
            Control::Secret(p) => p.set_text(value),
            Control::Choice(d, values) => {
                let at = values.borrow().iter().position(|v| v == value);
                let at = at.unwrap_or_else(|| {
                    if let Some(list) = d.model().and_downcast::<gtk::StringList>() {
                        list.append(value);
                    }
                    values.borrow_mut().push(value.to_string());
                    values.borrow().len() - 1
                });
                d.set_selected(at as u32);
            }
        }
    }
}

struct Form {
    kind: Cell<&'static str>,
    name: gtk::Entry,
    login: gtk::Box,
    username: gtk::Entry,
    password: gtk::PasswordEntry,
    totp: gtk::Entry,
    uris: gtk::TextView,
    /// A note's, card's or identity's own fields, rebuilt when the kind changes.
    others: gtk::Box,
    fields: RefCell<Vec<(&'static str, Control)>>,
    notes: gtk::TextView,
    folder: gtk::DropDown,
    folder_ids: Vec<Option<String>>,
    favorite: gtk::Switch,
    reprompt: gtk::Switch,
    banner: gtk::Box,
}

impl Form {
    /// Shows the fields of `kind`: the login form, or the kind's own fields.
    fn show_kind(&self, kind: &'static str) {
        self.kind.set(kind);
        self.login.set_visible(kind == "login");
        ui::clear(&self.others);
        let mut controls = Vec::new();
        for spec in fields::of_kind(kind) {
            let control = Control::new(spec);
            field(&self.others, spec.label, &control.widget());
            controls.push((spec.name, control));
        }
        self.others.set_visible(!controls.is_empty());
        *self.fields.borrow_mut() = controls;
    }
}

/// The kind a new item starts as: the sidebar's kind when one is open, else a login.
fn starting_kind(ui: &Ui) -> &'static str {
    let section = ui.section.borrow();
    KINDS.iter().copied().find(|k| *k == section.as_str()).unwrap_or("login")
}

pub fn open(ui: &Ui, entry: Option<Entry>) {
    if let Some(e) = ui.editor.borrow().as_ref() {
        e.present();
        return;
    }
    let kind = match &entry {
        Some(e) => match KINDS.iter().copied().find(|k| *k == e.kind) {
            Some(k) => k,
            None => return,
        },
        None => starting_kind(ui),
    };
    let title = match &entry {
        Some(_) => format!("Edit {}", data::kind_name(kind).to_lowercase()),
        None => "New item".to_string(),
    };
    let (dialog, card) = w::dialog(&title, 560);
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

    let kind_rows: Vec<(String, String)> = KINDS.iter().map(|k| (k.to_string(), data::kind_name(k).to_string())).collect();
    let kind_choice = w::dropdown(&kind_rows, kind);
    if entry.is_none() {
        field(&body, "Type", &kind_choice);
    }

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
    let login = w::vbox(8);
    field(&login, "Username", &username);
    let pw_line = w::hbox(6);
    pw_line.append(&password);
    let generate = w::bar_button("media-playlist-shuffle-symbolic", "Generate a password");
    pw_line.append(&generate);
    field(&login, "Password", &pw_line);
    field(&login, "One-time code key", &totp);
    field(&login, "Web addresses, one per line", &frame(&uris));
    body.append(&login);
    let others = w::vbox(8);
    body.append(&others);
    field(&body, "Folder", &folder);
    let rows = w::vbox(0);
    rows.add_css_class("group-list");
    rows.append(&w::row("Favorite", "Show it under Favorites.", Some(favorite.upcast_ref())));
    rows.append(&w::row(
        "Ask for master password",
        "Ask for it again before showing or copying this item's secrets.",
        Some(reprompt.upcast_ref()),
    ));
    body.append(&rows);
    field(&body, "Notes", &frame(&notes));

    let form = Rc::new(Form {
        kind: Cell::new(kind),
        name,
        login,
        username,
        password,
        totp,
        uris,
        others,
        fields: RefCell::new(Vec::new()),
        notes,
        folder,
        folder_ids,
        favorite,
        reprompt,
        banner,
    });
    form.show_kind(kind);
    let f = form.clone();
    kind_choice.connect_selected_notify(move |d| {
        if let Some(k) = KINDS.get(d.selected() as usize) {
            f.show_kind(k);
        }
    });
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

/// Fetches the item's fields into the form: a login's password and one-time code key,
/// or a note's, card's or identity's own fields; then the notes.
fn fill_secrets(ui: &Ui, id: &str, form: &Rc<Form>, dialog: &gtk::Window) {
    let (ui, id, form, dialog) = (ui.clone(), id.to_string(), form.clone(), dialog.clone());
    glib::spawn_future_local(async move {
        let entry = ui.listing.borrow().entries.iter().find(|e| e.id == id).cloned();
        let mut wanted: Vec<String> = Vec::new();
        if form.kind.get() == "login" {
            if entry.as_ref().is_some_and(|e| e.has_password) {
                wanted.push("password".into());
            }
            if entry.as_ref().is_some_and(|e| e.has_totp) {
                wanted.push("totp_seed".into());
            }
        } else {
            let listed = match client::text("Fields", Some((id.as_str(),).to_variant())).await {
                Ok(json) => serde_json::from_str::<Vec<FieldRow>>(&json).unwrap_or_default(),
                Err(e) => {
                    ui::toast(&ui, &e.to_string());
                    dialog.close();
                    return;
                }
            };
            for row in listed.into_iter().filter(|r| !r.name.starts_with("custom:")) {
                match row.value {
                    Some(value) => set_field(&form, &row.name, &value),
                    None if row.secret => wanted.push(row.name),
                    None => {}
                }
            }
        }
        wanted.push("notes".into());
        for field in wanted {
            match client::reveal(&id, &field).await {
                Ok(v) => match field.as_str() {
                    "password" => form.password.set_text(&v),
                    "totp_seed" => form.totp.set_text(&v),
                    "notes" => form.notes.buffer().set_text(&v),
                    other => set_field(&form, other, &v),
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

fn set_field(form: &Form, name: &str, value: &str) {
    if let Some((_, control)) = form.fields.borrow().iter().find(|(n, _)| *n == name) {
        control.set(value);
    }
}

fn submit(ui: &Ui, form: &Rc<Form>, id: Option<String>, dialog: &gtk::Window, save: &gtk::Button) {
    let name = form.name.text().trim().to_string();
    let kind = form.kind.get();
    if name.is_empty() {
        ui::toast(ui, &format!("Give the {} a name.", data::kind_name(kind).to_lowercase()));
        form.name.grab_focus();
        return;
    }
    let folder = form.folder_ids.get(form.folder.selected() as usize).cloned().flatten();
    let draft = if kind == "login" {
        let uris: Vec<String> =
            text_of(&form.uris).lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect();
        json!({
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
    } else {
        let fields: serde_json::Map<String, serde_json::Value> =
            form.fields.borrow().iter().map(|(n, c)| (n.to_string(), c.text().into())).collect();
        json!({
            "kind": kind,
            "name": name,
            "fields": fields,
            "notes": text_of(&form.notes),
            "folder": folder,
            "favorite": form.favorite.is_active(),
            "reprompt": form.reprompt.is_active(),
        })
    }
    .to_string();
    let (create, update) = if kind == "login" { ("CreateLogin", "UpdateLogin") } else { ("CreateItem", "UpdateItem") };
    save.set_sensitive(false);
    let (ui, form, dialog, save) = (ui.clone(), form.clone(), dialog.clone(), save.clone());
    glib::spawn_future_local(async move {
        let reply = match &id {
            Some(id) => client::call(update, Some((id.as_str(), draft.as_str()).to_variant())).await.map(|_| id.clone()),
            None => client::text(create, Some((draft.as_str(),).to_variant())).await,
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
                    "This item was changed in another app since you opened it. Your edit wasn't saved; save again to replace the other change with yours.",
                    true,
                ));
                ui::reload(&ui);
            }
            Err(e) => detail::handle(&ui, e, || {}),
        }
    });
}
