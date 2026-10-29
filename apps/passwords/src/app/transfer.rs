//! Importing and exporting, from the settings card. The daemon reads and writes the
//! files through handles opened here, so nothing decrypted passes through the window.

use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::rc::Rc;

use gtk::{gio, glib, prelude::*};
use nyx_passwords_proto::Error as Code;
use nyx_ui::widgets as w;

use super::client;
use super::ui::{self, Ui, label};

const FORMATS: &[(&str, &str, &str)] = &[
    ("password_json", "Bitwarden JSON with a password", "nyx-passwords-export.json"),
    ("json", "Bitwarden JSON, not encrypted", "nyx-passwords-export.json"),
    ("csv", "CSV (logins and notes), not encrypted", "nyx-passwords-export.csv"),
    ("account_json", "Bitwarden JSON for this account only", "nyx-passwords-export.json"),
];

/// Export: the format (and its password), the master password, then where to save.
pub fn export(ui: &Ui) {
    let (dialog, card) = w::dialog("Export the vault", 480);
    card.append(&label(
        "Your own items, without attachments or the trash, in a format the Bitwarden apps import too. \
         Organization items are exported by the organization's admins.",
        "dim",
    ));
    let rows: Vec<(String, String)> = FORMATS.iter().map(|(id, name, _)| (id.to_string(), name.to_string())).collect();
    let format = w::dropdown(&rows, "password_json");
    card.append(&format);
    let first = gtk::PasswordEntry::new();
    first.set_show_peek_icon(true);
    first.set_placeholder_text(Some("A password for the file"));
    let again = gtk::PasswordEntry::new();
    again.set_show_peek_icon(true);
    again.set_placeholder_text(Some("The same password again"));
    let passwords = w::vbox(6);
    passwords.append(&first);
    passwords.append(&again);
    card.append(&passwords);
    let note = label("", "dim");
    card.append(&note);
    let explain = {
        let (passwords, note) = (passwords.clone(), note.clone());
        move |id: &str| {
            passwords.set_visible(id == "password_json");
            note.set_text(match id {
                "password_json" => "Anyone with the file and this password can read it. It isn't your master password.",
                "account_json" => "Only this account can import it: not for moving to another account or another app.",
                _ => "Anyone who gets this file can read every password in it.",
            });
        }
    };
    explain("password_json");
    let e = explain.clone();
    format.connect_selected_notify(move |d| e(FORMATS.get(d.selected() as usize).map_or("", |f| f.0)));
    let buttons = w::hbox(8);
    buttons.set_halign(gtk::Align::End);
    let cancel = gtk::Button::with_label("Cancel");
    let go = gtk::Button::with_label("Export…");
    go.add_css_class("suggested-action");
    buttons.append(&cancel);
    buttons.append(&go);
    card.append(&buttons);
    let d = dialog.clone();
    cancel.connect_clicked(move |_| d.close());
    let (u, d) = (ui.clone(), dialog.clone());
    go.connect_clicked(move |_| {
        let Some(&(id, _, file_name)) = FORMATS.get(format.selected() as usize) else { return };
        let password = first.text().to_string();
        if id == "password_json" && (password.is_empty() || password != again.text().as_str()) {
            again.add_css_class("error");
            ui::toast(&u, "Enter the same password twice.");
            return;
        }
        d.close();
        let (u2, password) = (u.clone(), Rc::new(password));
        super::account::confirm_for(&u, "Exporting needs your master password.", move || {
            choose_and_export(&u2, id, file_name, password.clone());
        });
    });
    dialog.present();
}

fn choose_and_export(ui: &Ui, format: &'static str, file_name: &str, password: Rc<String>) {
    let dialog = gtk::FileDialog::builder().title("Save the export").initial_name(file_name).modal(true).build();
    let ui = ui.clone();
    dialog.save(Some(&ui.window.clone()), gio::Cancellable::NONE, move |picked| {
        let Some(path) = picked.ok().and_then(|f| f.path()) else { return };
        let file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path);
        let file = file.and_then(|f| f.set_permissions(std::fs::Permissions::from_mode(0o600)).map(|()| f));
        let file = match file {
            Ok(f) => f,
            Err(e) => return ui::toast(&ui, &format!("The file couldn't be created: {e}")),
        };
        let ui = ui.clone();
        glib::spawn_future_local(async move {
            match client::call_with_file("Export", &[format, password.as_str()], file.into()).await {
                Ok(_) => ui::toast(&ui, "Exported."),
                Err(e) => {
                    let _ = std::fs::remove_file(&path);
                    ui::toast(&ui, &e.to_string());
                }
            }
        });
    });
}

/// Import: pick a file, see what's in it (asking for its password if it has one), then
/// confirm.
pub fn import(ui: &Ui) {
    let dialog = gtk::FileDialog::builder().title("Import into the vault").modal(true).build();
    let ui = ui.clone();
    dialog.open(Some(&ui.window.clone()), gio::Cancellable::NONE, move |picked| {
        if let Some(path) = picked.ok().and_then(|f| f.path()) {
            preview(&ui, path, String::new());
        }
    });
}

fn open(ui: &Ui, path: &std::path::Path) -> Option<std::fs::File> {
    match std::fs::File::open(path) {
        Ok(f) => Some(f),
        Err(e) => {
            ui::toast(ui, &format!("The file couldn't be opened: {e}"));
            None
        }
    }
}

fn preview(ui: &Ui, path: std::path::PathBuf, password: String) {
    #[derive(serde::Deserialize)]
    struct Preview {
        format: String,
        items: u64,
        folders: u64,
        counts: std::collections::BTreeMap<String, u64>,
    }
    let Some(file) = open(ui, &path) else { return };
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let answer = client::call_with_file("ImportPreview", &[password.as_str()], file.into()).await;
        let found = match answer {
            Ok(v) => v.get::<(String,)>().and_then(|(json,)| serde_json::from_str::<Preview>(&json).ok()),
            Err(e) if e.is(Code::NeedsPassword) => {
                let (u, p) = (ui.clone(), path.clone());
                w::ask_text("This export has a password", "Enter the password it was exported with.", "", "Open", move |pw| {
                    preview(&u, p.clone(), pw)
                });
                return;
            }
            Err(e) => return ui::toast(&ui, &e.to_string()),
        };
        let Some(found) = found else { return ui::toast(&ui, "The file couldn't be read.") };
        let kinds: Vec<String> = found
            .counts
            .iter()
            .map(|(kind, n)| {
                let name = match kind.as_str() {
                    "login" => "logins",
                    "note" => "notes",
                    "card" => "cards",
                    "identity" => "identities",
                    "ssh" => "SSH keys",
                    _ => "other items",
                };
                format!("{n} {name}")
            })
            .collect();
        let folders = match found.folders {
            0 => String::new(),
            1 => " and 1 folder".into(),
            n => format!(" and {n} folders"),
        };
        let detail = format!(
            "{} ({}){folders}, from a {} file. They're added to your vault as your own items; nothing in it is replaced.",
            kinds.join(", "),
            found.items,
            found.format
        );
        if !ui::confirm(&ui, &format!("Import {} items?", found.items), &detail, "Import").await {
            return;
        }
        let Some(file) = open(&ui, &path) else { return };
        ui::toast(&ui, "Importing…");
        match client::call_with_file("Import", &[password.as_str()], file.into()).await {
            Ok(v) => {
                let n = v.get::<(u32,)>().map_or(0, |(n,)| n);
                ui::reload(&ui);
                ui::toast(&ui, &format!("Imported {n} items."));
            }
            Err(e) => ui::toast(&ui, &e.to_string()),
        }
    });
}
