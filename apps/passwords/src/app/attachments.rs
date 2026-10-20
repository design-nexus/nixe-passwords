//! An item's attachments in the item view: save one to a file you choose, attach a file,
//! delete one. The window opens the file and hands it to the daemon, which decrypts into
//! it (or encrypts from it); the contents never pass through here.

use std::os::unix::fs::OpenOptionsExt;

use gtk::{gio, glib, prelude::*};
use nixe_ui::widgets as w;

use super::client;
use super::data::Entry;
use super::detail;
use super::ui::{self, Ui, label};

#[derive(serde::Deserialize)]
struct Listed {
    id: String,
    name: String,
    size: u64,
}

/// Fills `into` with the item's attachments, once the daemon has listed them.
pub fn show(ui: &Ui, e: &Entry, into: &gtk::Box) {
    let (ui, e, into) = (ui.clone(), e.clone(), into.clone());
    let serial = ui.detail_serial.get();
    glib::spawn_future_local(async move {
        let Ok(json) = client::text("Attachments", Some((e.id.as_str(),).to_variant())).await else { return };
        let Ok(list) = serde_json::from_str::<Vec<Listed>>(&json) else { return };
        if ui.detail_serial.get() != serial || list.is_empty() && (!e.editable || e.deleted) {
            return;
        }
        into.set_visible(true);
        into.append(&label("ATTACHMENTS", "group-title"));
        let rows = w::vbox(0);
        rows.add_css_class("group-list");
        into.append(&rows);
        for a in list {
            let actions = w::hbox(4);
            let save = w::bar_button("document-save-symbolic", "Save to a file…");
            let (u, id, file) = (ui.clone(), e.id.clone(), (a.id.clone(), a.name.clone()));
            save.connect_clicked(move |b| save_as(&u, b, &id, &file.0, &file.1));
            actions.append(&save);
            if e.editable && !e.deleted {
                let remove = w::bar_button("user-trash-symbolic", "Delete this attachment");
                let (u, id, file) = (ui.clone(), e.id.clone(), (a.id.clone(), a.name.clone()));
                remove.connect_clicked(move |b| delete(&u, b, &id, &file.0, &file.1));
                actions.append(&remove);
            }
            rows.append(&w::row(&a.name, &size(a.size), Some(actions.upcast_ref())));
        }
        if e.editable && !e.deleted {
            let attach = w::labeled_button("mail-attachment-symbolic", "Attach file…");
            attach.set_halign(gtk::Align::Start);
            let (u, id) = (ui.clone(), e.id.clone());
            attach.connect_clicked(move |b| attach_file(&u, b, &id));
            into.append(&attach);
        }
    });
}

fn size(bytes: u64) -> String {
    match bytes {
        b if b < 1024 => format!("{b} bytes"),
        b if b < 1024 * 1024 => format!("{:.0} KB", b as f64 / 1024.0),
        b => format!("{:.1} MB", b as f64 / (1024.0 * 1024.0)),
    }
}

fn parent(widget: &impl IsA<gtk::Widget>) -> Option<gtk::Window> {
    widget.root().and_downcast::<gtk::Window>()
}

fn save_as(ui: &Ui, button: &gtk::Button, id: &str, attachment: &str, name: &str) {
    let (ui, id, attachment) = (ui.clone(), id.to_string(), attachment.to_string());
    let dialog = gtk::FileDialog::builder().title("Save attachment").initial_name(name).modal(true).build();
    dialog.save(parent(button).as_ref(), gio::Cancellable::NONE, move |picked| {
        let Some(path) = picked.ok().and_then(|f| f.path()) else { return };
        save_to(&ui, &id, &attachment, path);
    });
}

/// Writes the attachment into `path`, readable by you alone. A failed save doesn't
/// leave a partial file behind.
fn save_to(ui: &Ui, id: &str, attachment: &str, path: std::path::PathBuf) {
    let file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path);
    let file = match file {
        Ok(f) => f,
        Err(e) => return ui::toast(ui, &format!("The file couldn't be created: {e}")),
    };
    let (ui, id, attachment) = (ui.clone(), id.to_string(), attachment.to_string());
    glib::spawn_future_local(async move {
        match client::call_with_file("SaveAttachment", &[&id, &attachment], file.into()).await {
            Ok(_) => ui::toast(&ui, "Saved."),
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                let (u, i, a) = (ui.clone(), id.clone(), attachment.clone());
                detail::handle(&ui, e, move || save_to(&u, &i, &a, path.clone()));
            }
        }
    });
}

fn attach_file(ui: &Ui, button: &gtk::Button, id: &str) {
    let (ui, id) = (ui.clone(), id.to_string());
    let dialog = gtk::FileDialog::builder().title("Attach a file").modal(true).build();
    dialog.open(parent(button).as_ref(), gio::Cancellable::NONE, move |picked| {
        let Some(path) = picked.ok().and_then(|f| f.path()) else { return };
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => return ui::toast(&ui, &format!("The file couldn't be opened: {e}")),
        };
        let (ui, id) = (ui.clone(), id.clone());
        glib::spawn_future_local(async move {
            ui::toast(&ui, "Attaching…");
            match client::call_with_file("AddAttachment", &[&id, &name], file.into()).await {
                Ok(_) => {
                    ui::reload(&ui);
                    ui::toast(&ui, "Attached.");
                }
                Err(e) => detail::handle(&ui, e, || {}),
            }
        });
    });
}

fn delete(ui: &Ui, button: &gtk::Button, id: &str, attachment: &str, name: &str) {
    let (ui, id, attachment, window) = (ui.clone(), id.to_string(), attachment.to_string(), parent(button));
    let ask = gtk::AlertDialog::builder()
        .modal(true)
        .message(format!("Delete {name}?"))
        .detail("Attachments don't go to the trash: it can't be restored.")
        .buttons(["Cancel", "Delete"])
        .cancel_button(0)
        .default_button(0)
        .build();
    glib::spawn_future_local(async move {
        if ask.choose_future(window.as_ref()).await != Ok(1) {
            return;
        }
        match client::call("DeleteAttachment", Some((id.as_str(), attachment.as_str()).to_variant())).await {
            Ok(_) => {
                ui::reload(&ui);
                ui::toast(&ui, "Deleted.");
            }
            Err(e) => detail::handle(&ui, e, || {}),
        }
    });
}
