//! The selected item. Secret fields stay masked until asked for (`Reveal`), and hide
//! again after 30 s; copies go through the daemon, which clears the clipboard later.
//! The one-time code is the exception: it shows at once and follows each new code.

use std::cell::Cell;
use std::f64::consts::{FRAC_PI_2, TAU};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gtk::{glib, prelude::*};
use nyx_passwords_proto::Error as Code;
use nyx_ui::widgets as w;

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
    if ui.multi.borrow().len() > 1 {
        show_many(ui);
        return;
    }
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
    super::icons::show(&icon, e.host.as_deref(), 32);
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
        let forever = gtk::Button::from_icon_name("edit-delete-symbolic");
        forever.add_css_class("destructive-action");
        allow(&forever, e.deletable, "Delete for good", "Its organization doesn't let you delete it");
        let (u, id) = (ui.clone(), e.id.clone());
        forever.connect_clicked(move |_| delete_forever(&u, vec![id.clone()]));
        bar.append(&forever);
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
        let clone = gtk::Button::from_icon_name("nyx-duplicate-symbolic");
        if !editor::KINDS.contains(&e.kind.as_str()) {
            allow(&clone, false, "", "This kind of item can't be copied here yet");
        } else {
            allow(
                &clone,
                e.view_password,
                "Make a copy of this item",
                "Its organization hides its secrets, so it can't be copied",
            );
        }
        let (u, entry) = (ui.clone(), e.clone());
        clone.connect_clicked(move |_| editor::open_copy(&u, entry.clone()));
        bar.append(&clone);
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
            rows.append(&code_row(ui, &e));
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
    if e.kind == "login" {
        let passkeys = w::vbox(12);
        passkeys.set_visible(false);
        ui.details.append(&passkeys);
        show_passkeys(ui, &e, &passkeys);
    }
    if e.kind == "login" && e.view_password {
        let history = w::vbox(12);
        history.set_visible(false);
        ui.details.append(&history);
        show_history(ui, &e, &history);
    }
}

/// The login's passkeys: the site and account each signs in to, when it was made, and
/// deleting one. The browser extension signs in with them.
fn show_passkeys(ui: &Ui, e: &Entry, into: &gtk::Box) {
    #[derive(serde::Deserialize)]
    struct Passkey {
        credential_id: String,
        rp_id: String,
        user_name: String,
        created: String,
    }
    let (ui, e, into) = (ui.clone(), e.clone(), into.clone());
    let serial = ui.detail_serial.get();
    glib::spawn_future_local(async move {
        let Ok(json) = client::text("Passkeys", Some((e.id.as_str(),).to_variant())).await else { return };
        let Ok(list) = serde_json::from_str::<Vec<Passkey>>(&json) else { return };
        if ui.detail_serial.get() != serial || list.is_empty() {
            return;
        }
        into.set_visible(true);
        into.append(&label("PASSKEYS", "group-title"));
        let rows = w::vbox(0);
        rows.add_css_class("group-list");
        into.append(&rows);
        for p in list {
            let when = data::date(&p.created).map(|d| format!(" · made {d}")).unwrap_or_default();
            let who = if p.user_name.is_empty() { p.rp_id.clone() } else { format!("{} on {}", p.user_name, p.rp_id) };
            let delete = w::bar_button("user-trash-symbolic", "Delete this passkey");
            delete.set_sensitive(e.editable && !e.deleted);
            let (u, id, credential) = (ui.clone(), e.id.clone(), p.credential_id.clone());
            delete.connect_clicked(move |_| {
                let (u, id, credential) = (u.clone(), id.clone(), credential.clone());
                glib::spawn_future_local(async move {
                    if !ui::confirm(
                        &u,
                        "Delete this passkey?",
                        "You won't be able to sign in to the site with it any more.",
                        "Delete",
                    )
                    .await
                    {
                        return;
                    }
                    match client::call("DeletePasskey", Some((id.as_str(), credential.as_str()).to_variant())).await {
                        Ok(_) => {
                            ui::reload(&u);
                            ui::toast(&u, "Passkey deleted.");
                        }
                        Err(e) => handle(&u, e, || {}),
                    }
                });
            });
            rows.append(&w::row(&who, &glib::markup_escape_text(&format!("Passkey{when}")), Some(delete.upcast_ref())));
        }
    });
}

/// The login's old passwords, newest first, each hidden until shown.
fn show_history(ui: &Ui, e: &Entry, into: &gtk::Box) {
    #[derive(serde::Deserialize)]
    struct Old {
        index: usize,
        date: String,
    }
    let (ui, e, into) = (ui.clone(), e.clone(), into.clone());
    let serial = ui.detail_serial.get();
    glib::spawn_future_local(async move {
        let Ok(json) = client::text("History", Some((e.id.as_str(),).to_variant())).await else { return };
        let Ok(list) = serde_json::from_str::<Vec<Old>>(&json) else { return };
        if ui.detail_serial.get() != serial || list.is_empty() {
            return;
        }
        into.set_visible(true);
        into.append(&label("PASSWORD HISTORY", "group-title"));
        let rows = w::vbox(0);
        rows.add_css_class("group-list");
        into.append(&rows);
        for old in list {
            let when = data::date(&old.date).map(|d| format!("Used until {d}")).unwrap_or_else(|| "Old password".into());
            rows.append(&secret_row(&ui, &e, &format!("history:{}", old.index), &when, "Copy this old password"));
        }
    });
}

/// Several items picked at once: what can be done to all of them.
fn show_many(ui: &Ui) {
    let ids = ui.multi.borrow().clone();
    let listing = ui.listing.borrow();
    let picked: Vec<Entry> = listing.entries.iter().filter(|e| ids.contains(&e.id)).cloned().collect();
    let folders: Vec<(String, String)> = std::iter::once((String::new(), "No folder".to_string()))
        .chain(listing.folders.iter().map(|f| (f.id.clone(), f.name.clone())))
        .collect();
    drop(listing);
    let header = w::hbox(14);
    let icon = gtk::Image::from_icon_name("edit-select-all-symbolic");
    icon.set_pixel_size(32);
    icon.add_css_class("accent");
    header.append(&icon);
    let title = w::vbox(4);
    title.append(&label(&format!("{} items selected", picked.len()), "item-name"));
    title.append(&label("Ctrl-click or Shift-click in the list to change the selection.", "dim"));
    header.append(&title);
    ui.details.append(&header);

    let in_trash = picked.iter().all(|e| e.deleted);
    let rows = group(ui, "With all of them");
    if in_trash {
        let restore = gtk::Button::with_label("Restore");
        restore.set_sensitive(picked.iter().all(|e| e.restorable));
        let (u, chosen) = (ui.clone(), ids.clone());
        restore.connect_clicked(move |_| act_on_many(&u, "RestoreItems", &chosen, "Restored."));
        rows.append(&w::row("Restore", "Put them back in the vault.", Some(restore.upcast_ref())));
        let forever = gtk::Button::with_label("Delete…");
        forever.add_css_class("destructive-action");
        forever.set_sensitive(picked.iter().all(|e| e.deletable));
        let (u, chosen) = (ui.clone(), ids.clone());
        forever.connect_clicked(move |_| delete_forever(&u, chosen.clone()));
        rows.append(&w::row("Delete for good", "They can't be brought back.", Some(forever.upcast_ref())));
    } else {
        let line = w::hbox(6);
        let choice = w::dropdown(&folders, "");
        line.append(&choice);
        let go = gtk::Button::with_label("Move");
        line.append(&go);
        let (u, chosen, folder_ids) = (ui.clone(), ids.clone(), folders.clone());
        go.connect_clicked(move |_| {
            let folder = folder_ids.get(choice.selected() as usize).map(|(id, _)| id.clone()).unwrap_or_default();
            let (u, ids) = (u.clone(), chosen.clone());
            glib::spawn_future_local(async move {
                let args = (serde_json::to_string(&ids).unwrap_or_default(), folder);
                match client::call("MoveItems", Some(args.to_variant())).await {
                    Ok(_) => {
                        ui::reload(&u);
                        ui::toast(&u, "Moved.");
                    }
                    Err(e) => handle(&u, e, || {}),
                }
            });
        });
        rows.append(&w::row("Move to a folder", "Folders are yours alone, even for shared items.", Some(line.upcast_ref())));
        let trash = gtk::Button::with_label("Move to trash");
        trash.set_sensitive(picked.iter().all(|e| e.deletable));
        if !trash.is_sensitive() {
            trash.set_tooltip_text(Some("An organization doesn't let you delete one of them"));
        }
        let (u, chosen) = (ui.clone(), ids.clone());
        trash.connect_clicked(move |_| act_on_many(&u, "TrashItems", &chosen, "Moved to the trash."));
        rows.append(&w::row("Move to the trash", "You can restore them from the trash.", Some(trash.upcast_ref())));
    }
}

/// `TrashItems` or `RestoreItems` on several items, then the list catches up.
fn act_on_many(ui: &Ui, method: &'static str, ids: &[String], done: &'static str) {
    let (ui, ids) = (ui.clone(), serde_json::to_string(ids).unwrap_or_default());
    glib::spawn_future_local(async move {
        match client::call(method, Some((ids.as_str(),).to_variant())).await {
            Ok(_) => {
                ui.multi.borrow_mut().clear();
                ui::reload(&ui);
                ui::toast(&ui, done);
            }
            Err(e) => handle(&ui, e, || {}),
        }
    });
}

/// Deletes items in the trash for good, after asking.
fn delete_forever(ui: &Ui, ids: Vec<String>) {
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let message = if ids.len() == 1 {
            "Delete this item for good?".to_string()
        } else {
            format!("Delete {} items for good?", ids.len())
        };
        if !ui::confirm(&ui, &message, "It can't be brought back, and its attachments go with it.", "Delete").await {
            return;
        }
        let json = serde_json::to_string(&ids).unwrap_or_default();
        match client::call("DeleteForever", Some((json.as_str(),).to_variant())).await {
            Ok(_) => {
                ui.multi.borrow_mut().clear();
                *ui.selected.borrow_mut() = None;
                ui::reload(&ui);
                ui::toast(&ui, "Deleted.");
            }
            Err(e) => handle(&ui, e, || {}),
        }
    });
}

/// Deletes everything in the trash that this account may delete, after asking.
pub fn empty_trash(ui: &Ui) {
    let ids: Vec<String> =
        ui.listing.borrow().entries.iter().filter(|e| e.deleted && e.deletable).map(|e| e.id.clone()).collect();
    if ids.is_empty() {
        ui::toast(ui, "Nothing in the trash can be deleted by you.");
        return;
    }
    delete_forever(ui, ids);
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
    /// A custom field's type: 0 text, 1 hidden, 2 true or false.
    #[serde(default)]
    pub kind: i64,
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
        let (own, mut custom): (Vec<_>, Vec<_>) = list.into_iter().partition(|f| !f.name.starts_with("custom:"));
        // Passwords' own fields read as what they mean.
        let mut browser_lines = Vec::new();
        custom.retain(|f| {
            let line = match f.label.as_str() {
                nyx_passwords_proto::custom::SIGN_IN_WITH => {
                    let id = f.value.clone().unwrap_or_default();
                    let name =
                        nyx_passwords_proto::custom::PROVIDERS.iter().find(|(p, _)| *p == id).map_or(id.as_str(), |(_, n)| n);
                    format!("Signs in with {name}")
                }
                nyx_passwords_proto::custom::NO_FILL_ON_LOAD if f.value.as_deref() == Some("true") => {
                    "Not filled as its page loads".to_string()
                }
                nyx_passwords_proto::custom::NO_FILL_ON_LOAD => return false,
                _ => return true,
            };
            browser_lines.push(line);
            false
        });
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
                    let value = match (f.kind, value.as_str()) {
                        (2, "true") => "Yes".to_string(),
                        (2, _) => "No".to_string(),
                        _ => value,
                    };
                    let button = w::bar_button("edit-copy-symbolic", &format!("Copy {}", f.label.to_lowercase()));
                    let (u, id, name) = (ui.clone(), e.id.clone(), f.name.clone());
                    button.connect_clicked(move |_| copy(&u, &id, &name));
                    let row = w::row(&value, &glib::markup_escape_text(&f.label), Some(button.upcast_ref()));
                    wrap_anywhere(&row);
                    rows.append(&row);
                }
            }
        }
        if !browser_lines.is_empty() {
            into.set_visible(true);
            into.append(&label("IN BROWSERS", "group-title"));
            let rows = w::vbox(0);
            rows.add_css_class("group-list");
            for line in browser_lines {
                rows.append(&w::row(&line, "", None));
            }
            into.append(&rows);
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

/// The one-time code row: the code, a ring that fills until the next code replaces it
/// (with the seconds left inside), and Copy. Items that ask for the master password
/// show it after Show; others at once. It never hides again on its own.
fn code_row(ui: &Ui, e: &Entry) -> gtk::Box {
    let row = w::hbox(14);
    row.add_css_class("settings-option");
    let text = w::vbox(2);
    text.set_valign(gtk::Align::Center);
    text.set_hexpand(true);
    let value = label(MASK, "settings-option-title");
    value.add_css_class("secret-value");
    value.set_selectable(true);
    text.append(&value);
    text.append(&label("One-time code", "settings-option-description"));
    row.append(&text);

    let ring = gtk::DrawingArea::new();
    ring.set_content_width(28);
    ring.set_content_height(28);
    ring.add_css_class("code-ring");
    let seconds = label("", "code-seconds");
    seconds.set_halign(gtk::Align::Center);
    seconds.set_valign(gtk::Align::Center);
    let dial = gtk::Overlay::new();
    dial.set_child(Some(&ring));
    dial.add_overlay(&seconds);
    dial.set_valign(gtk::Align::Center);
    dial.set_tooltip_text(Some("Seconds until the next code"));
    dial.set_visible(false);

    let actions = w::hbox(4);
    actions.set_valign(gtk::Align::Center);
    let show = w::bar_button("view-reveal-symbolic", "Show");
    show.set_visible(e.reprompt);
    actions.append(&dial);
    actions.append(&show);
    actions.append(&copy_button(ui, &e.id, "totp", "Copy one-time code (Ctrl+Shift+O)"));
    row.append(&actions);

    let view = CodeView {
        ui: ui.clone(),
        id: e.id.clone(),
        serial: ui.detail_serial.get(),
        value,
        dial,
        ring: ring.clone(),
        seconds,
        show: show.clone(),
        period: Rc::new(Cell::new(30)),
        step: Rc::new(Cell::new(0)),
        busy: Rc::new(Cell::new(false)),
        ticking: Rc::new(Cell::new(false)),
    };
    let period = view.period.clone();
    ring.set_draw_func(move |area, cr, w, h| draw_ring(area, cr, w, h, period.get()));
    let v = view.clone();
    show.connect_clicked(move |_| v.fetch(true));
    if !e.reprompt {
        view.fetch(true);
    }
    row
}

#[derive(Clone)]
struct CodeView {
    ui: Ui,
    id: String,
    serial: u64,
    value: gtk::Label,
    dial: gtk::Overlay,
    ring: gtk::DrawingArea,
    seconds: gtk::Label,
    show: gtk::Button,
    period: Rc<Cell<u32>>,
    /// The period the shown code belongs to (`time / period`).
    step: Rc<Cell<u64>>,
    busy: Rc<Cell<bool>>,
    ticking: Rc<Cell<bool>>,
}

impl CodeView {
    fn current(&self) -> bool {
        self.ui.detail_serial.get() == self.serial
    }

    /// Asks the daemon for the code in effect. The first ask reports a failure (and asks
    /// for the master password when the item wants it); a later one masks the code again.
    fn fetch(&self, first: bool) {
        if self.busy.replace(true) {
            return;
        }
        let v = self.clone();
        glib::spawn_future_local(async move {
            let answer = client::totp(&v.id).await;
            v.busy.set(false);
            if !v.current() {
                return;
            }
            match answer {
                Ok((code, period, _)) => {
                    v.period.set(period.max(1));
                    v.step.set(code_clock(period).0);
                    v.value.set_text(&spaced(&code));
                    v.show.set_visible(false);
                    v.dial.set_visible(true);
                    v.tick();
                    if !v.ticking.replace(true) {
                        let t = v.clone();
                        glib::timeout_add_local(Duration::from_millis(100), move || {
                            if !t.current() || !t.ticking.get() || t.ring.root().is_none() {
                                t.ticking.set(false);
                                return glib::ControlFlow::Break;
                            }
                            t.tick();
                            glib::ControlFlow::Continue
                        });
                    }
                }
                Err(e) => {
                    v.ticking.set(false);
                    v.value.set_text(MASK);
                    v.dial.set_visible(false);
                    v.show.set_visible(true);
                    if first {
                        let retry = v.clone();
                        handle(&v.ui, e, move || retry.fetch(true));
                    }
                }
            }
        });
    }

    fn tick(&self) {
        let period = self.period.get();
        let (step, done) = code_clock(period);
        let left = ((1.0 - done) * f64::from(period)).ceil().max(1.0);
        self.seconds.set_text(&format!("{left}"));
        if left <= 5.0 {
            self.ring.add_css_class("ending");
            self.seconds.add_css_class("ending");
        } else {
            self.ring.remove_css_class("ending");
            self.seconds.remove_css_class("ending");
        }
        self.ring.queue_draw();
        if step != self.step.get() {
            self.fetch(false);
        }
    }
}

/// Which period the clock is in (`time / period`) and how far through it, 0 to 1. Codes
/// change on whole multiples of the period, so the ring follows the clock.
fn code_clock(period: u32) -> (u64, f64) {
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    let length = u64::from(period.max(1)) * 1000;
    (ms / length, (ms % length) as f64 / length as f64)
}

/// A faint full circle, and over it an arc from the top that closes as the code's
/// time runs out; both in the widget's color (accent, or warning near the end).
fn draw_ring(area: &gtk::DrawingArea, cr: &gtk::cairo::Context, width: i32, height: i32, period: u32) {
    let (_, done) = code_clock(period);
    let color = area.color();
    let (r, g, b, a) = (f64::from(color.red()), f64::from(color.green()), f64::from(color.blue()), f64::from(color.alpha()));
    let (cx, cy) = (f64::from(width) / 2.0, f64::from(height) / 2.0);
    let line = 2.5;
    let radius = cx.min(cy) - line;
    cr.set_line_width(line);
    cr.set_source_rgba(r, g, b, a * 0.2);
    cr.arc(cx, cy, radius, 0.0, TAU);
    let _ = cr.stroke();
    cr.set_source_rgba(r, g, b, a);
    cr.set_line_cap(gtk::cairo::LineCap::Round);
    cr.arc(cx, cy, radius, -FRAC_PI_2, -FRAC_PI_2 + TAU * done);
    let _ = cr.stroke();
}

/// A code split in two for reading ("123 456"); Copy still copies it whole.
fn spaced(code: &str) -> String {
    let n = code.chars().count();
    if n < 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return code.to_string();
    }
    let (a, b) = code.split_at(n / 2);
    format!("{a} {b}")
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
                    f if f.starts_with("history:") => "Old password",
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
        ui::set_state(ui, nyx_passwords_proto::state::LOCKED);
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
