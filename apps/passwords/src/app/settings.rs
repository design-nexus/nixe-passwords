//! The settings card. Vault, clipboard and generator settings are read by the daemon
//! from the same file, within a second of a change.

use std::cell::Cell;
use std::rc::Rc;

use gtk::{glib, prelude::*};
use nixe_ui::widgets as w;

use super::client;
use super::prefs;
use super::theme;
use super::ui::{self, Ui, label};

fn group(body: &gtk::Box, name: &str) -> gtk::Box {
    let outer = w::vbox(0);
    outer.add_css_class("settings-group");
    outer.set_widget_name(name);
    outer.append(&label(&name.to_uppercase(), "group-title"));
    let rows = w::vbox(0);
    rows.add_css_class("group-list");
    outer.append(&rows);
    body.append(&outer);
    rows
}

/// A dropdown row over `choices` of (value, label), storing the value with `set`.
fn choice(
    rows: &gtk::Box,
    title: &str,
    desc: &str,
    choices: &[(u64, &str)],
    current: u64,
    set: impl Fn(&mut prefs::Prefs, u64) + 'static,
) {
    let opts: Vec<(String, String)> = choices.iter().map(|(v, l)| (v.to_string(), l.to_string())).collect();
    let values: Vec<u64> = choices.iter().map(|(v, _)| *v).collect();
    let current = if values.contains(&current) { current } else { values[0] };
    let (row, _) = w::choice_row(title, desc, opts, &current.to_string(), move |id| {
        if let Ok(v) = id.parse::<u64>() {
            prefs::update(|p| set(p, v));
        }
    });
    rows.append(&row);
}

fn switch(rows: &gtk::Box, title: &str, desc: &str, on: bool, set: impl Fn(&mut prefs::Prefs, bool) + 'static) {
    let (row, _) = w::switch_row(title, desc, on, move |v| prefs::update(|p| set(p, v)));
    rows.append(&row);
}

/// "Unlock with the keyring". Not a preference: the daemon saves the vault's key in the
/// desktop keyring or removes it, and the switch shows which is the case.
fn keyring_row(ui: &Ui) -> gtk::Box {
    let (row, sw) = w::switch_row(
        "Unlock with the keyring",
        "Keep the vault's key in your desktop keyring, which opens when you log in, and unlock without the master password. \
         Anyone using your session, and any program running as you, can then open the vault too: leave it off on shared \
         or unattended computers.",
        false,
        |_| {},
    );
    // Set while the switch is moved from here rather than by the user.
    let quiet = Rc::new(Cell::new(true));
    let (s, q) = (sw.clone(), quiet.clone());
    glib::spawn_future_local(async move {
        let on = client::call("KeyringUnlock", None).await.ok().and_then(|v| v.get::<(bool,)>()).is_some_and(|(on,)| on);
        s.set_active(on);
        q.set(false);
    });
    let u = ui.clone();
    sw.connect_active_notify(move |s| {
        if quiet.get() {
            return;
        }
        let (ui, s, quiet, on) = (u.clone(), s.clone(), quiet.clone(), s.is_active());
        glib::spawn_future_local(async move {
            match client::call("SetKeyringUnlock", Some((on,).to_variant())).await {
                Ok(_) => {
                    ui::toast(&ui, if on { "The keyring can unlock the vault now." } else { "The key is gone from the keyring." })
                }
                Err(e) => {
                    ui::toast(&ui, &e.to_string());
                    quiet.set(true);
                    s.set_active(!on);
                    quiet.set(false);
                }
            }
        });
    });
    row
}

pub fn open(ui: &Ui) {
    let p = prefs::get();
    let v = p.vault.clone();
    let body = w::vbox(0);
    body.add_css_class("settings-page");
    body.set_hexpand(true);
    let root = ui::scroll(&body);

    let g = group(&body, "Vault");
    let account = ui.listing.borrow().account.clone();
    if !account.email.is_empty() {
        g.append(&w::row(&account.email, &glib::markup_escape_text(&account.server), None));
    }
    choice(
        &g,
        "Lock after",
        "Lock the vault when it hasn't been used for this long.",
        &[
            (1, "1 minute"),
            (5, "5 minutes"),
            (15, "15 minutes"),
            (30, "30 minutes"),
            (60, "1 hour"),
            (240, "4 hours"),
            (0, "Never"),
        ],
        v.lock_minutes,
        |p, x| p.vault.lock_minutes = x,
    );
    switch(&g, "Lock when the screen locks", "Lock the vault as soon as the desktop locks.", v.lock_on_screen_lock, |p, x| {
        p.vault.lock_on_screen_lock = x
    });
    switch(&g, "Lock on sleep", "Lock the vault before the computer suspends.", v.lock_on_sleep, |p, x| {
        p.vault.lock_on_sleep = x
    });
    g.append(&keyring_row(ui));
    choice(
        &g,
        "Sync",
        "Fetch changes from the server while the vault is open.",
        &[
            (5, "Every 5 minutes"),
            (15, "Every 15 minutes"),
            (30, "Every 30 minutes"),
            (60, "Every hour"),
            (0, "Only when unlocking"),
        ],
        v.sync_minutes,
        |p, x| p.vault.sync_minutes = x,
    );
    let ca_desc = v
        .extra_ca
        .as_ref()
        .map(|c| glib::markup_escape_text(&c.display().to_string()).to_string())
        .unwrap_or_else(|| "For a server whose certificate comes from your own authority.".into());
    let (row, button) = w::button_row("Extra certificate", &ca_desc, "", |_| {});
    // One button: choose a file, or remove the one chosen.
    let shows = |b: &gtk::Button, chosen: bool| {
        b.set_icon_name(if chosen { "edit-delete-symbolic" } else { "document-open-symbolic" });
        b.set_tooltip_text(Some(if chosen { "Remove the certificate" } else { "Choose a certificate file…" }));
    };
    shows(&button, v.extra_ca.is_some());
    let u = ui.clone();
    button.connect_clicked(move |b| {
        if prefs::get().vault.extra_ca.is_some() {
            prefs::update(|p| p.vault.extra_ca = None);
            shows(b, false);
            return;
        }
        let dialog = gtk::FileDialog::builder().title("Certificate authority (PEM)").build();
        let b = b.clone();
        dialog.open(Some(&u.window), gtk::gio::Cancellable::NONE, move |file| {
            if let Some(path) = file.ok().and_then(|f| f.path()) {
                prefs::update(|p| p.vault.extra_ca = Some(path));
                shows(&b, true);
            }
        });
    });
    g.append(&row);

    let g = group(&body, "Clipboard");
    choice(
        &g,
        "Clear copied values",
        "Empty the clipboard this long after copying, if it still holds the copy.",
        &[
            (10, "After 10 seconds"),
            (20, "After 20 seconds"),
            (30, "After 30 seconds"),
            (60, "After 1 minute"),
            (120, "After 2 minutes"),
            (0, "Never"),
        ],
        v.clipboard_seconds,
        |p, x| p.vault.clipboard_seconds = x,
    );
    switch(
        &g,
        "Paste once",
        "Clear the clipboard after the first paste. Some apps paste twice and get nothing.",
        v.paste_once,
        |p, x| p.vault.paste_once = x,
    );
    switch(&g, "Notify on copy", "Show a notification naming what was copied (never the value).", v.notify_copies, |p, x| {
        p.vault.notify_copies = x
    });
    g.append(&w::row(
        "Clipboard history",
        "Copies are marked as passwords. Clipboard managers that honor the mark keep them out of history; others may store them.",
        None,
    ));

    let g = group(&body, "Generator");
    let kinds = w::opts(&[("password", "Password"), ("passphrase", "Passphrase")]);
    let (row, _) = w::choice_row(
        "Generate",
        "What the editor and Glimpse's “pw generate” make.",
        kinds,
        if v.generate_passphrase { "passphrase" } else { "password" },
        |id| prefs::update(|p| p.vault.generate_passphrase = id == "passphrase"),
    );
    g.append(&row);
    let length = gtk::SpinButton::with_range(8.0, 128.0, 1.0);
    length.set_value(v.password_rules.length as f64);
    length.connect_value_changed(|s| prefs::update(|p| p.vault.password_rules.length = s.value() as usize));
    g.append(&w::row("Password length", "Characters in a generated password.", Some(length.upcast_ref())));
    for (title, which) in
        [("Uppercase letters", 0), ("Lowercase letters", 1), ("Digits", 2), ("Symbols", 3), ("Avoid look-alikes", 4)]
    {
        let r = &v.password_rules;
        let on = [r.uppercase, r.lowercase, r.digits, r.symbols, r.avoid_ambiguous][which];
        let desc = if which == 4 { "Leave out I, O, l, 0 and 1." } else { "" };
        switch(&g, title, desc, on, move |p, x| {
            let r = &mut p.vault.password_rules;
            match which {
                0 => r.uppercase = x,
                1 => r.lowercase = x,
                2 => r.digits = x,
                3 => r.symbols = x,
                _ => r.avoid_ambiguous = x,
            }
        });
    }
    let words = gtk::SpinButton::with_range(3.0, 20.0, 1.0);
    words.set_value(v.passphrase_rules.words as f64);
    words.connect_value_changed(|s| prefs::update(|p| p.vault.passphrase_rules.words = s.value() as usize));
    g.append(&w::row("Passphrase words", "Words in a generated passphrase.", Some(words.upcast_ref())));

    let g = group(&body, "Integrations");
    switch(
        &g,
        "Glimpse",
        "Find logins with “pw” in Glimpse and copy from them. Passwords are never shown there.",
        v.glimpse,
        |p, x| p.vault.glimpse = x,
    );
    switch(
        &g,
        "Nixe Assistant",
        "Let the Assistant find logins and copy them to the clipboard. It asks for a key press each time and never sees a password.",
        v.assistant,
        |p, x| p.vault.assistant = x,
    );

    let g = group(&body, "Browsers");
    g.append(&w::row(
        "Browser extension",
        &glib::markup_escape_text(&format!(
            "Install it from {}: “Load unpacked” in Chromium and Brave; “Install Add-on From File” in Firefox and Zen. Then pair from its button.",
            nixe_core::paths::pretty(&nixe_core::paths::data_dir().join("browser"))
        )),
        None,
    ));
    super::pairing::fill_group(&g);

    let g = group(&body, "Passwords window");
    g.append(&w::start_row());
    let (row, dd) = w::choice_row(
        "Theme",
        "Choose a bundled or user theme.",
        theme::all().into_iter().map(|t| (t.id, t.name)).collect(),
        &p.theme,
        |id| {
            prefs::update(|p| {
                p.mode = prefs::ThemeMode::Theme;
                p.theme = id;
            });
            theme::apply();
        },
    );
    dd.set_sensitive(p.mode == prefs::ThemeMode::Theme || !theme::omarchy_available());
    if theme::omarchy_available() {
        let (r, _) = w::switch_row(
            "Follow Omarchy theme",
            "Match the desktop colors and update live.",
            p.mode == prefs::ThemeMode::Omarchy,
            move |on| {
                prefs::update(|p| p.mode = if on { prefs::ThemeMode::Omarchy } else { prefs::ThemeMode::Theme });
                dd.set_sensitive(!on);
                theme::apply();
            },
        );
        g.append(&r);
    }
    g.append(&row);
    let swatches = w::hbox(4);
    let repaint = {
        let s = swatches.clone();
        move || {
            ui::clear(&s);
            let p = theme::current_palette();
            for color in [&p.bg, &p.surface, &p.muted, &p.text, &p.accent, &p.danger] {
                let b = w::hbox(0);
                b.set_size_request(24, 24);
                b.add_css_class("swatch");
                w::paint(&b, color);
                s.append(&b);
            }
        }
    };
    repaint();
    let weak = swatches.downgrade();
    glib::timeout_add_seconds_local(1, move || {
        if weak.upgrade().is_none() {
            return glib::ControlFlow::Break;
        }
        repaint();
        glib::ControlFlow::Continue
    });
    g.append(&w::row("Current colors", "", Some(swatches.upcast_ref())));
    for (name, on, motion) in [("Glow", p.glow, false), ("Reduce motion", p.reduce_motion, true)] {
        let (r, _) = w::switch_row(name, "", on, move |on| {
            prefs::update(|p| if motion { p.reduce_motion = on } else { p.glow = on });
            theme::apply();
        });
        g.append(&r);
    }

    let g = group(&body, "Keyboard");
    for (keys, action) in ui::SHORTCUTS {
        g.append(&w::row(action, "", Some(w::key_caps(keys).upcast_ref())));
    }

    nixe_ui::settings_card::open_page(
        &ui.overlay,
        &ui.window,
        nixe_ui::settings_card::Spec {
            groups: &[
                ("Vault", "dialog-password-symbolic", "Locking, sync, server"),
                ("Clipboard", "edit-paste-symbolic", "Clearing, notifications"),
                ("Generator", "media-playlist-shuffle-symbolic", "Passwords and passphrases"),
                ("Integrations", "system-search-symbolic", "Glimpse, Nixe Assistant"),
                ("Browsers", "web-browser-symbolic", "Paired browsers, the extension"),
                ("Passwords window", "applications-graphics-symbolic", "Theme and motion"),
                ("Keyboard", "input-keyboard-symbolic", "Shortcuts"),
            ],
            search_text: None,
        },
        root.upcast_ref(),
        &body,
    );
}
