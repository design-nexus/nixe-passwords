//! The selected item. Secret fields stay masked until asked for (`Reveal`), and hide
//! again after 30 s; copies go through the daemon, which clears the clipboard later.

use std::time::Duration;

use gtk::{glib, prelude::*};
use nixe_passwords_proto::Error as Code;
use nixe_ui::widgets as w;

use super::client::{self, Fail};
use super::data::{self, Entry};
use super::ui::{self, Ui, clear, label};
use super::{account, editor};

const MASK: &str = "••••••••••••";
const SHOWN_FOR: Duration = Duration::from_secs(30);

fn selected_entry(ui: &Ui) -> Option<Entry> {
    let id = ui.selected.borrow().clone()?;
    ui.listing.borrow().entries.iter().find(|e| e.id == id).cloned()
}

pub fn show(ui: &Ui) {
    ui.detail_serial.set(ui.detail_serial.get() + 1);
    clear(&ui.details);
    let back = gtk::Button::from_icon_name("go-previous-symbolic");
    back.set_tooltip_text(Some("Back to the list (Esc)"));
    back.set_halign(gtk::Align::Start);
    back.set_visible(ui.narrow.get());
    let u = ui.clone();
    back.connect_clicked(move |_| {
        u.showing_detail.set(false);
        ui::layout(&u);
    });
    ui.details.append(&back);
    let Some(e) = selected_entry(ui) else {
        let empty = w::vbox(12);
        empty.add_css_class("item-empty");
        empty.set_valign(gtk::Align::Center);
        empty.set_halign(gtk::Align::Center);
        empty.set_vexpand(true);
        let icon = gtk::Image::from_icon_name("dialog-password-symbolic");
        icon.set_pixel_size(40);
        icon.add_css_class("dim");
        empty.append(&icon);
        empty.append(&label("Select an item to see its details.", "dim"));
        ui.details.append(&empty);
        return;
    };

    let header = w::hbox(14);
    let icon = gtk::Image::from_icon_name(data::kind_icon(&e.kind));
    icon.set_pixel_size(32);
    icon.add_css_class("accent");
    header.append(&icon);
    let title = w::vbox(4);
    title.set_hexpand(true);
    let name_line = w::hbox(8);
    let name = label(if e.readable { &e.name } else { "Unreadable item" }, "item-name");
    name.set_selectable(true);
    name_line.append(&name);
    if e.deleted {
        name_line.append(&w::tag("In trash", "danger"));
    }
    if e.reprompt {
        name_line.append(&w::tag("Asks for master password", ""));
    }
    title.append(&name_line);
    title.append(&label(&describe(ui, &e), "dim"));
    header.append(&title);
    ui.details.append(&header);

    if !e.readable {
        ui.details.append(&w::banner(
            "This item's key isn't available on this device: its organization's key couldn't be opened.",
            true,
        ));
        return;
    }

    let bar = w::hbox(6);
    if e.deleted {
        let restore = gtk::Button::from_icon_name("edit-undo-symbolic");
        restore.add_css_class("suggested-action");
        allow(&restore, e.restorable, "Restore this item", "Its organization doesn't let you restore it");
        let (u, id) = (ui.clone(), e.id.clone());
        restore.connect_clicked(move |_| set_trashed(&u, &id, false));
        bar.append(&restore);
    } else {
        let edit = gtk::Button::from_icon_name("document-edit-symbolic");
        if !editor::KINDS.contains(&e.kind.as_str()) {
            allow(&edit, false, "", "This kind of item can't be edited here yet; use the web vault");
        } else {
            allow(&edit, e.editable, "Edit this item", "Read-only for you: its collection doesn't allow changes");
        }
        let (u, entry) = (ui.clone(), e.clone());
        edit.connect_clicked(move |_| editor::open(&u, Some(entry.clone())));
        bar.append(&edit);
        let trash = gtk::Button::from_icon_name("user-trash-symbolic");
        allow(&trash, e.deletable, "Move this item to the trash", "Its organization doesn't let you delete it");
        let (u, id) = (ui.clone(), e.id.clone());
        trash.connect_clicked(move |_| set_trashed(&u, &id, true));
        bar.append(&trash);
    }
    ui.details.append(&bar);

    if e.kind == "login" {
        let rows = group(ui, "Login");
        if let Some(user) = &e.username {
            rows.append(&w::row(
                user,
                "Username",
                Some(copy_button(ui, &e.id, "username", "Copy username (Ctrl+Shift+U)").upcast_ref()),
            ));
        }
        if e.has_password && !e.view_password {
            rows.append(&hidden_row("Password"));
        } else if e.has_password {
            rows.append(&secret_row(ui, &e, "password", "Password", "Copy password (Ctrl+Shift+C)"));
        }
        if e.has_totp {
            rows.append(&secret_row(ui, &e, "totp", "One-time code", "Copy one-time code (Ctrl+Shift+O)"));
        }
        if e.username.is_none() && !e.has_password && !e.has_totp {
            rows.append(&w::row("No username or password", "", None));
        }
        if !e.uris.is_empty() {
            let rows = group(ui, "Web addresses");
            for uri in &e.uris {
                let actions = w::hbox(4);
                let copy = w::bar_button("edit-copy-symbolic", "Copy address");
                let (win, value) = (ui.window.clone(), uri.clone());
                copy.connect_clicked(move |_| win.clipboard().set_text(&value));
                actions.append(&copy);
                if let Some(link) = web_link(uri) {
                    let open = w::bar_button("web-browser-symbolic", "Open in the browser");
                    open.connect_clicked(move |_| {
                        let _ = gtk::gio::AppInfo::launch_default_for_uri(&link, None::<&gtk::gio::AppLaunchContext>);
                    });
                    actions.append(&open);
                }
                rows.append(&w::row(uri, "", Some(actions.upcast_ref())));
            }
        }
    }
    // A card's, identity's or SSH key's fields, and custom fields, arrive from the daemon;
    // this keeps their place above the notes.
    // Both stay hidden until they have something, so an empty one adds no gap.
    let more = w::vbox(12);
    more.set_visible(false);
    ui.details.append(&more);
    show_fields(ui, &e, &more);
    let files = w::vbox(12);
    files.set_visible(false);
    ui.details.append(&files);
    super::attachments::show(ui, &e, &files);
    let rows = group(ui, "Notes");
    rows.append(&secret_row(ui, &e, "notes", "Notes", ""));
}

fn describe(ui: &Ui, e: &Entry) -> String {
    let listing = ui.listing.borrow();
    let mut parts = vec![data::kind_name(&e.kind).to_string()];
    if let Some(f) = e.folder.as_ref().and_then(|id| listing.folders.iter().find(|f| f.id == *id)) {
        parts.push(f.name.clone());
    }
    if let Some(o) = e.organization.as_ref().and_then(|id| listing.organizations.iter().find(|o| o.id == *id)) {
        parts.push(o.name.clone());
    }
    for c in listing.collections.iter().filter(|c| e.collections.contains(&c.id)) {
        parts.push(c.name.clone());
    }
    parts.join(" · ")
}

#[derive(serde::Deserialize)]
pub(super) struct FieldRow {
    pub name: String,
    pub label: String,
    pub value: Option<String>,
    pub secret: bool,
}

fn show_fields(ui: &Ui, e: &Entry, into: &gtk::Box) {
    let (ui, e, into) = (ui.clone(), e.clone(), into.clone());
    let serial = ui.detail_serial.get();
    glib::spawn_future_local(async move {
        let Ok(json) = client::text("Fields", Some((e.id.as_str(),).to_variant())).await else { return };
        let Ok(list) = serde_json::from_str::<Vec<FieldRow>>(&json) else { return };
        if ui.detail_serial.get() != serial {
            return;
        }
        let (own, custom): (Vec<_>, Vec<_>) = list.into_iter().partition(|f| !f.name.starts_with("custom:"));
        for (title, fields) in [(data::kind_name(&e.kind), own), ("Custom fields", custom)] {
            if fields.is_empty() {
                continue;
            }
            into.set_visible(true);
            into.append(&label(&title.to_uppercase(), "group-title"));
            let rows = w::vbox(0);
            rows.add_css_class("group-list");
            into.append(&rows);
            for f in fields {
                if f.secret && !e.view_password {
                    rows.append(&hidden_row(&f.label));
                } else if f.secret {
                    rows.append(&secret_row(&ui, &e, &f.name, &f.label, &format!("Copy {}", f.label.to_lowercase())));
                } else {
                    let value = f.value.unwrap_or_default();
                    let button = w::bar_button("edit-copy-symbolic", &format!("Copy {}", f.label.to_lowercase()));
                    let (u, id, name) = (ui.clone(), e.id.clone(), f.name.clone());
                    button.connect_clicked(move |_| copy(&u, &id, &name));
                    let row = w::row(&value, &glib::markup_escape_text(&f.label), Some(button.upcast_ref()));
                    wrap_anywhere(&row);
                    rows.append(&row);
                }
            }
        }
    });
}

/// Lets a row's value break anywhere, without added hyphens: a public key or fingerprint
/// is one long word and would otherwise widen the window.
fn wrap_anywhere(row: &gtk::Box) {
    let value = row.first_child().and_then(|text| text.first_child()).and_downcast::<gtk::Label>();
    if let Some(value) = value {
        let unhyphenated = gtk::pango::AttrList::new();
        unhyphenated.insert(gtk::pango::AttrInt::new_insert_hyphens(false));
        value.set_wrap_mode(gtk::pango::WrapMode::WordChar);
        value.set_attributes(Some(&unhyphenated));
    }
}

/// Enables a button with its tooltip, or disables it saying why.
fn allow(button: &gtk::Button, allowed: bool, tip: &str, why_not: &str) {
    button.set_sensitive(allowed);
    button.set_tooltip_text(Some(if allowed { tip } else { why_not }));
}

/// A field the item's organization hides from this account: no reveal, no copy.
fn hidden_row(title: &str) -> gtk::Box {
    let row = w::row("Hidden by its organization", &glib::markup_escape_text(title), None);
    row.add_css_class("dim");
    row
}

fn group(ui: &Ui, title: &str) -> gtk::Box {
    ui.details.append(&label(&title.to_uppercase(), "group-title"));
    let rows = w::vbox(0);
    rows.add_css_class("group-list");
    ui.details.append(&rows);
    rows
}

fn copy_button(ui: &Ui, id: &str, field: &str, tip: &str) -> gtk::Button {
    let b = w::bar_button("edit-copy-symbolic", tip);
    let (u, id, field) = (ui.clone(), id.to_string(), field.to_string());
    b.connect_clicked(move |_| copy(&u, &id, &field));
    b
}

/// A masked value with Show and Copy, laid out like `widgets::row`. Notes show below
/// the row's title instead of in it.
fn secret_row(ui: &Ui, e: &Entry, field: &str, title: &str, copy_tip: &str) -> gtk::Box {
    let notes = field == "notes";
    let row = w::hbox(14);
    row.add_css_class("settings-option");
    let text = w::vbox(2);
    text.set_valign(gtk::Align::Center);
    text.set_hexpand(true);
    let value = label(MASK, "settings-option-title");
    value.add_css_class("secret-value");
    value.set_selectable(true);
    let hint =
        label(if notes { "Hidden" } else { title }, if notes { "settings-option-title" } else { "settings-option-description" });
    if notes {
        hint.add_css_class("dim");
        text.append(&hint);
        value.remove_css_class("settings-option-title");
        value.add_css_class("secret-text");
        value.set_visible(false);
        text.append(&value);
    } else {
        text.append(&value);
        text.append(&hint);
    }
    row.append(&text);
    let actions = w::hbox(4);
    actions.set_valign(gtk::Align::Center);
    let show = w::bar_button("view-reveal-symbolic", "Show");
    actions.append(&show);
    if !copy_tip.is_empty() {
        actions.append(&copy_button(ui, &e.id, field, copy_tip));
    }
    row.append(&actions);
    let hint: Option<gtk::Widget> = notes.then(|| hint.upcast());
    let (u, id, field, value_l) = (ui.clone(), e.id.clone(), field.to_string(), value.clone());
    show.connect_clicked(move |b| {
        if value_l.text() != MASK && value_l.is_visible() {
            hide(&value_l, &field, hint.as_ref(), b);
            return;
        }
        reveal_into(&u, &id, &field, &value_l, hint.clone(), b.clone());
    });
    row
}

fn hide(value: &gtk::Label, field: &str, hint: Option<&gtk::Widget>, button: &gtk::Button) {
    value.set_text(MASK);
    if field == "notes" {
        value.set_visible(false);
        if let Some(h) = hint {
            h.set_visible(true);
        }
    }
    button.set_icon_name("view-reveal-symbolic");
    button.set_tooltip_text(Some("Show"));
}

fn reveal_into(ui: &Ui, id: &str, field: &str, value: &gtk::Label, hint: Option<gtk::Widget>, button: gtk::Button) {
    let (ui, id, field, value) = (ui.clone(), id.to_string(), field.to_string(), value.clone());
    let serial = ui.detail_serial.get();
    glib::spawn_future_local(async move {
        match client::reveal(&id, &field).await {
            Ok(text) => {
                if ui.detail_serial.get() != serial {
                    return;
                }
                value.set_text(if text.is_empty() { "(empty)" } else { &text });
                value.set_visible(true);
                if field == "notes"
                    && let Some(h) = &hint
                {
                    h.set_visible(false);
                }
                button.set_icon_name("view-conceal-symbolic");
                button.set_tooltip_text(Some("Hide"));
                if field == "totp" {
                    follow_code(&ui, &id, &value, serial);
                }
                let (u, v, b, f) = (ui.clone(), value.clone(), button.clone(), field.clone());
                glib::timeout_add_local_once(SHOWN_FOR, move || {
                    if u.detail_serial.get() == serial {
                        hide(&v, &f, hint.as_ref(), &b);
                    }
                });
            }
            Err(e) => handle(&ui, e, {
                let (ui, id, field, value, button) = (ui.clone(), id.clone(), field.clone(), value.clone(), button.clone());
                move || reveal_into(&ui, &id, &field, &value, hint.clone(), button.clone())
            }),
        }
    });
}

/// Fetches the next one-time code at each 30-second boundary while it's shown.
fn follow_code(ui: &Ui, id: &str, value: &gtk::Label, serial: u64) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let wait = Duration::from_secs(30) - Duration::from_millis((now.as_millis() % 30_000) as u64) + Duration::from_millis(200);
    let (ui, id, value) = (ui.clone(), id.to_string(), value.clone());
    glib::timeout_add_local_once(wait, move || {
        if ui.detail_serial.get() != serial || value.text() == MASK {
            return;
        }
        glib::spawn_future_local(async move {
            if let Ok(code) = client::reveal(&id, "totp").await
                && ui.detail_serial.get() == serial
                && value.text() != MASK
            {
                value.set_text(&code);
                follow_code(&ui, &id, &value, serial);
            }
        });
    });
}

/// Copies through the daemon, which clears the clipboard after the set time.
pub fn copy(ui: &Ui, id: &str, field: &str) {
    let (ui, id, field) = (ui.clone(), id.to_string(), field.to_string());
    glib::spawn_future_local(async move {
        match client::copy(&id, &field).await {
            Ok(seconds) => {
                let what = match field.as_str() {
                    "username" => "Username",
                    "password" => "Password",
                    "totp" => "One-time code",
                    _ => "Value",
                };
                let when = if seconds > 0 { format!(" · clears in {seconds} s") } else { String::new() };
                ui::toast(&ui, &format!("{what} copied{when}"));
            }
            Err(e) => handle(&ui, e, {
                let (ui, id, field) = (ui.clone(), id.clone(), field.clone());
                move || copy(&ui, &id, &field)
            }),
        }
    });
}

pub fn copy_selected(ui: &Ui, field: &str) {
    if let Some(e) = selected_entry(ui) {
        copy(ui, &e.id, field);
    }
}

/// Shows an error; a re-prompting item asks for the master password and then retries.
pub fn handle(ui: &Ui, e: Fail, retry: impl Fn() + 'static) {
    if e.is(Code::Reprompt) {
        account::confirm(ui, retry);
    } else if e.is(Code::NotFound) {
        // Deleted elsewhere, or no longer shared with this account: the daemon has
        // dropped it, so the list catches up.
        ui::reload(ui);
        ui::toast(ui, "That item is gone: deleted elsewhere, or no longer shared with you.");
    } else if e.is(Code::Locked) {
        ui::set_state(ui, nixe_passwords_proto::state::LOCKED);
    } else {
        ui::toast(ui, &e.to_string());
    }
}

fn set_trashed(ui: &Ui, id: &str, trash: bool) {
    let (ui, id) = (ui.clone(), id.to_string());
    glib::spawn_future_local(async move {
        let method = if trash { "Trash" } else { "Restore" };
        match client::call(method, Some((id.as_str(),).to_variant())).await {
            Ok(_) => {
                ui::reload(&ui);
                if trash {
                    let (u, id) = (ui.clone(), id.clone());
                    ui::toast_action(&ui, "Moved to the trash.", Some(("Undo", Box::new(move || set_trashed(&u, &id, false)))));
                } else {
                    ui::toast(&ui, "Restored.");
                }
            }
            Err(e) => handle(&ui, e, || {}),
        }
    });
}

/// An address as something to open: http(s), with https assumed when there's no scheme.
fn web_link(uri: &str) -> Option<String> {
    let uri = uri.trim();
    if uri.starts_with("https://") || uri.starts_with("http://") {
        return Some(uri.to_string());
    }
    (!uri.contains("://") && uri.contains('.')).then(|| format!("https://{uri}"))
}
