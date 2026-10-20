//! Debug builds only: render the window to a PNG and quit, for checking layouts.
//!
//!   PASSWORDS_SNAPSHOT=out.png            where to write
//!   PASSWORDS_SNAPSHOT_SIGNIN=URL|EMAIL|PASSWORD   a throwaway test account to sign in to
//!   PASSWORDS_SNAPSHOT_ITEMS=JSON         an array of login drafts to create first
//!   PASSWORDS_SNAPSHOT_SELECT=NAME        the item to select
//!   PASSWORDS_SNAPSHOT_SETTINGS=1         open the settings card
//!   PASSWORDS_SNAPSHOT_SECTION=ID         the sidebar section
//!   PASSWORDS_SNAPSHOT_EDIT=1             open the editor on the selection and render it
//!   PASSWORDS_SNAPSHOT_UNLOCK=PASSWORD    unlock a locked vault first
//!   PASSWORDS_SNAPSHOT_COPY=FIELD         copy a field of the selection (through the daemon)

use std::time::Duration;

use gtk::{gdk, glib, prelude::*};
use nixe_passwords_proto::state;

use super::client;
use super::ui::{self, Ui};

pub fn maybe(ui: &Ui, app: &gtk::Application) {
    let Some(path) = std::env::var_os("PASSWORDS_SNAPSHOT") else { return };
    let (ui, app) = (ui.clone(), app.clone());
    glib::spawn_future_local(async move {
        if let Ok(account) = std::env::var("PASSWORDS_SNAPSHOT_SIGNIN") {
            let parts: Vec<&str> = account.splitn(3, '|').collect();
            if let [server, email, password] = parts[..]
                && client::status().await.is_ok_and(|(s, _, _)| s != state::UNLOCKED)
            {
                let args = (server, email, password, 255u8, "");
                if let Err(e) = client::call("SignIn", Some(args.to_variant())).await {
                    eprintln!("snapshot: sign in: {e}");
                }
                if let Ok(items) = std::env::var("PASSWORDS_SNAPSHOT_ITEMS")
                    && let Ok(serde_json::Value::Array(items)) = serde_json::from_str(&items)
                {
                    for item in items {
                        let _ = client::call("CreateLogin", Some((item.to_string(),).to_variant())).await;
                    }
                }
            }
        }
        if let Ok(password) = std::env::var("PASSWORDS_SNAPSHOT_UNLOCK")
            && client::status().await.is_ok_and(|(s, _, _)| s == state::LOCKED)
            && let Err(e) = client::call("Unlock", Some((password.as_str(),).to_variant())).await
        {
            eprintln!("snapshot: unlock: {e}");
        }
        ui::refresh_state(&ui);
        glib::timeout_future(Duration::from_millis(900)).await;
        if let Ok(section) = std::env::var("PASSWORDS_SNAPSHOT_SECTION") {
            ui::navigate(&ui, &section);
        }
        if let Ok(name) = std::env::var("PASSWORDS_SNAPSHOT_SELECT") {
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
        if let Ok(field) = std::env::var("PASSWORDS_SNAPSHOT_COPY") {
            let id = ui.selected.borrow().clone().unwrap_or_default();
            match client::copy(&id, &field).await {
                Ok(seconds) => println!("snapshot: copied {field}, clears in {seconds} s"),
                Err(e) => eprintln!("snapshot: copy: {e}"),
            }
        }
        if std::env::var_os("PASSWORDS_SNAPSHOT_SETTINGS").is_some() {
            ui::open_settings();
        }
        if std::env::var_os("PASSWORDS_SNAPSHOT_EDIT").is_some() {
            let id = ui.selected.borrow().clone();
            let entry = id.and_then(|id| ui.listing.borrow().entries.iter().find(|e| e.id == id).cloned());
            super::editor::open(&ui, entry);
        }
        glib::timeout_future(Duration::from_millis(700)).await;
        let editor = ui.editor.borrow().clone();
        match editor {
            Some(e) => render(&e, std::path::Path::new(&path)),
            None => render(ui.window.upcast_ref(), std::path::Path::new(&path)),
        }
        app.quit();
    });
}

fn render(window: &gtk::Window, path: &std::path::Path) {
    let Some(child) = window.child() else { return };
    let paintable = gtk::WidgetPaintable::new(Some(&child));
    let (width, height) = (child.width(), child.height());
    let snapshot = gtk::Snapshot::new();
    if let Ok(bg) = gdk::RGBA::parse(super::theme::current_palette().bg.as_str()) {
        snapshot.append_color(&bg, &gtk::graphene::Rect::new(0.0, 0.0, width as f32, height as f32));
    }
    paintable.snapshot(&snapshot, width as f64, height as f64);
    if let (Some(node), Some(renderer)) = (snapshot.to_node(), window.renderer()) {
        let texture = renderer.render_texture(node, None);
        match texture.save_to_png(path) {
            Ok(()) => println!("snapshot: {width} × {height}"),
            Err(e) => eprintln!("snapshot: {e}"),
        }
    }
}
