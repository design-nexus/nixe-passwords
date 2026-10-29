//! The page shown while the vault isn't open: signing in (with two-step login), or
//! unlocking with the master password. The password goes straight to the daemon and
//! the entry is cleared.

use gtk::{glib, prelude::*};
use nyx_passwords_proto::{Error as Code, state};
use nyx_ui::widgets as w;

use super::client;
use super::prefs;
use super::ui::{self, Ui, clear, label};

/// Two-step methods this client completes: authenticator (0), email (1) and YubiKey
/// OTP (3). A recovery code (8) answers any of them.
const SUPPORTED: [u8; 3] = [0, 1, 3];
const RECOVERY_CODE: u8 = 8;

pub fn show(ui: &Ui, st: &str) {
    match st {
        state::LOCKED => unlock_page(ui),
        state::LOGGED_OUT => sign_in_page(ui, None),
        _ => {}
    }
}

/// The daemon couldn't be reached.
pub fn unavailable(ui: &Ui, message: &str) {
    let card = page(ui, "Passwords isn't available", message);
    let retry = gtk::Button::with_label("Try again");
    retry.add_css_class("suggested-action");
    let u = ui.clone();
    retry.connect_clicked(move |_| ui::refresh_state(&u));
    card.append(&buttons(&[&retry]));
}

/// A centered card with a heading and a line of help; returns the card to fill.
fn page(ui: &Ui, title: &str, note: &str) -> gtk::Box {
    clear(&ui.account);
    let outer = w::vbox(0);
    outer.set_valign(gtk::Align::Center);
    outer.set_vexpand(true);
    let card = w::vbox(14);
    card.add_css_class("account-card");
    card.set_halign(gtk::Align::Center);
    card.set_width_request(420);
    let icon = gtk::Image::from_icon_name("dialog-password-symbolic");
    icon.set_pixel_size(40);
    icon.add_css_class("accent");
    icon.set_halign(gtk::Align::Start);
    card.append(&icon);
    card.append(&label(title, "account-title"));
    if !note.is_empty() {
        card.append(&label(note, "dim"));
    }
    outer.append(&card);
    ui.account.append(&outer);
    card
}

fn field(card: &gtk::Box, title: &str, entry: &impl IsA<gtk::Widget>) {
    let l = label(title, "account-field");
    card.append(&l);
    card.append(entry);
}

fn buttons(items: &[&gtk::Button]) -> gtk::Box {
    let row = w::hbox(8);
    row.set_halign(gtk::Align::End);
    for b in items {
        row.append(*b);
    }
    row
}

fn error_label() -> gtk::Label {
    let l = label("", "account-error");
    l.set_visible(false);
    l
}

fn show_error(l: &gtk::Label, text: &str) {
    l.set_text(text);
    l.set_visible(!text.is_empty());
}

/// What a two-step retry needs to resend.
#[derive(Clone)]
struct Pending {
    server: String,
    email: String,
    /// Kept only for the length of the two-step prompt.
    password: String,
    methods: Vec<(u8, String)>,
}

fn sign_in_page(ui: &Ui, error: Option<&str>) {
    let card = page(ui, "Sign in to Vaultwarden", "Use the account you have on your own server.");
    let p = prefs::get();
    let server = gtk::Entry::new();
    server.set_placeholder_text(Some("https://vault.example.com"));
    server.set_text(&p.last_server);
    server.set_input_purpose(gtk::InputPurpose::Url);
    field(&card, "Server address", &server);
    let email = gtk::Entry::new();
    email.set_placeholder_text(Some("you@example.com"));
    email.set_text(&p.last_email);
    email.set_input_purpose(gtk::InputPurpose::Email);
    field(&card, "Email", &email);
    let password = gtk::PasswordEntry::new();
    password.set_show_peek_icon(true);
    field(&card, "Master password", &password);
    let err = error_label();
    card.append(&err);
    if let Some(e) = error {
        show_error(&err, e);
    }
    let go = gtk::Button::with_label("Sign in");
    go.add_css_class("suggested-action");
    card.append(&buttons(&[&go]));
    let others = w::hbox(8);
    let device = gtk::Button::with_label("Sign in with another device");
    let api_key = gtk::Button::with_label("Use an API key");
    for b in [&device, &api_key] {
        b.add_css_class("flat");
        others.append(b);
    }
    card.append(&others);
    let (u, s, e, er) = (ui.clone(), server.clone(), email.clone(), err.clone());
    device.connect_clicked(move |_| {
        let (server, email) = (s.text().trim().to_string(), e.text().trim().to_string());
        if server.is_empty() || email.is_empty() {
            show_error(&er, "Fill in the server and email first.");
            return;
        }
        prefs::update(|p| {
            p.last_server = server.clone();
            p.last_email = email.clone();
        });
        device_page(&u, server, email);
    });
    let (u, s) = (ui.clone(), server.clone());
    api_key.connect_clicked(move |_| api_key_page(&u, s.text().trim().to_string()));

    let submit = {
        let (ui, server, email, password, err, go) =
            (ui.clone(), server.clone(), email.clone(), password.clone(), err.clone(), go.clone());
        move || {
            let pending = Pending {
                server: server.text().trim().to_string(),
                email: email.text().trim().to_string(),
                password: password.text().to_string(),
                methods: Vec::new(),
            };
            password.set_text("");
            if pending.server.is_empty() || pending.email.is_empty() || pending.password.is_empty() {
                show_error(&err, "Fill in the server, email and master password.");
                return;
            }
            prefs::update(|p| {
                p.last_server = pending.server.clone();
                p.last_email = pending.email.clone();
            });
            sign_in(&ui, pending, None, &go, &err);
        }
    };
    let s = submit.clone();
    go.connect_clicked(move |_| s());
    let s = submit.clone();
    password.connect_activate(move |_| s());
    if p.last_server.is_empty() {
        server.grab_focus();
    } else {
        password.grab_focus();
    }
}

/// Signing in with another device's approval: the words to compare, while it waits.
fn device_page(ui: &Ui, server: String, email: String) {
    let card = page(ui, "Sign in with another device", "Asking your other devices…");
    let err = error_label();
    card.append(&err);
    let back = gtk::Button::with_label("Cancel");
    card.append(&buttons(&[&back]));
    let waiting = std::rc::Rc::new(std::cell::Cell::new(true));
    let (u, w2) = (ui.clone(), waiting.clone());
    back.connect_clicked(move |_| {
        w2.set(false);
        let u = u.clone();
        glib::spawn_future_local(async move {
            let _ = client::call("CancelDeviceSignIn", None).await;
            sign_in_page(&u, None);
        });
    });
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let fingerprint = match client::text("RequestDeviceSignIn", Some((server.as_str(), email.as_str()).to_variant())).await {
            Ok(f) => f,
            Err(e) => return sign_in_page(&ui, Some(&e.to_string())),
        };
        let note = label(
            "Approve the request on a device where you're signed in (the web vault, a Bitwarden app, or Passwords on another computer), if it shows these words:",
            "dim",
        );
        let phrase = label(&fingerprint, "pairing-code");
        phrase.set_selectable(true);
        card.insert_child_after(&note, card.first_child().and_then(|c| c.next_sibling()).as_ref());
        card.insert_child_after(&phrase, Some(&note));
        while waiting.get() {
            glib::timeout_future(std::time::Duration::from_secs(3)).await;
            // Cancelled, or the page was replaced.
            if !waiting.get() || card.root().is_none() {
                return;
            }
            match client::call("PollDeviceSignIn", None).await.map(|v| v.get::<(bool,)>()) {
                Ok(Some((true,))) => return ui::set_state(&ui, state::UNLOCKED),
                Ok(_) => {}
                Err(e) => return sign_in_page(&ui, Some(&e.to_string())),
            }
        }
    });
}

/// Signing in with the account's API key, which skips two-step login and new-device
/// checks; the master password still opens the vault.
fn api_key_page(ui: &Ui, server_text: String) {
    let card = page(
        ui,
        "Sign in with an API key",
        "Find the key in the web vault: Settings → Security → Keys → View API key. Two-step login isn't asked for.",
    );
    let server = gtk::Entry::new();
    server.set_text(&server_text);
    server.set_placeholder_text(Some("https://vault.example.com"));
    field(&card, "Server address", &server);
    let client_id = gtk::Entry::new();
    client_id.set_placeholder_text(Some("user.…"));
    field(&card, "client_id", &client_id);
    let secret = gtk::PasswordEntry::new();
    secret.set_show_peek_icon(true);
    field(&card, "client_secret", &secret);
    let password = gtk::PasswordEntry::new();
    password.set_show_peek_icon(true);
    field(&card, "Master password", &password);
    let err = error_label();
    card.append(&err);
    let back = gtk::Button::with_label("Back");
    let go = gtk::Button::with_label("Sign in");
    go.add_css_class("suggested-action");
    card.append(&buttons(&[&back, &go]));
    let u = ui.clone();
    back.connect_clicked(move |_| sign_in_page(&u, None));
    let submit = {
        let (ui, err, go, password) = (ui.clone(), err.clone(), go.clone(), password.clone());
        move || {
            let fields = (server.text().trim().to_string(), client_id.text().trim().to_string(), secret.text().to_string());
            let pw = password.text().to_string();
            password.set_text("");
            if fields.0.is_empty() || fields.1.is_empty() || fields.2.is_empty() || pw.is_empty() {
                show_error(&err, "Fill in every field.");
                return;
            }
            prefs::update(|p| p.last_server = fields.0.clone());
            busy(&go, "Signing in…");
            let (ui, err, go) = (ui.clone(), err.clone(), go.clone());
            glib::spawn_future_local(async move {
                let args = (fields.0.as_str(), fields.1.as_str(), fields.2.as_str(), pw.as_str());
                let reply = client::call("SignInWithApiKey", Some(args.to_variant())).await;
                go.set_sensitive(true);
                go.set_label("Sign in");
                match reply {
                    Ok(_) => ui::set_state(&ui, state::UNLOCKED),
                    Err(e) => show_error(&err, &e.to_string()),
                }
            });
        }
    };
    let s = submit.clone();
    go.connect_clicked(move |_| s());
    password.connect_activate(move |_| submit());
}

fn busy(button: &gtk::Button, text: &str) {
    button.set_sensitive(false);
    button.set_label(text);
}

fn sign_in(ui: &Ui, pending: Pending, answer: Option<(u8, String)>, button: &gtk::Button, err: &gtk::Label) {
    let label_before = button.label().map(|l| l.to_string()).unwrap_or_default();
    busy(button, "Signing in…");
    show_error(err, "");
    let (ui, button, err) = (ui.clone(), button.clone(), err.clone());
    glib::spawn_future_local(async move {
        let (method, code) = answer.unwrap_or((255, String::new()));
        let args = (pending.server.as_str(), pending.email.as_str(), pending.password.as_str(), method, code.as_str());
        let reply = client::call("SignIn", Some(args.to_variant())).await;
        button.set_sensitive(true);
        button.set_label(&label_before);
        match reply.map(|v| v.get::<(bool, Vec<(u8, String)>)>()) {
            Ok(Some((true, _))) => ui::set_state(&ui, state::UNLOCKED),
            Ok(Some((false, methods))) => two_step(&ui, Pending { methods, ..pending }),
            Ok(None) => show_error(&err, "The service gave an unexpected answer."),
            Err(e) => {
                if method != 255 {
                    show_error(&err, &e.to_string());
                } else {
                    sign_in_page(&ui, Some(&e.to_string()));
                }
            }
        }
    });
}

fn method_name(number: u8, hint: &str) -> String {
    match number {
        0 => "Authenticator app".into(),
        1 if hint.is_empty() => "Email".into(),
        1 => format!("Email to {hint}"),
        2 | 6 => "Duo".into(),
        3 => "YubiKey".into(),
        7 => "Passkey or security key".into(),
        n => format!("Method {n}"),
    }
}

fn two_step(ui: &Ui, pending: Pending) {
    let usable: Vec<(u8, String)> = pending.methods.iter().filter(|(n, _)| SUPPORTED.contains(n)).cloned().collect();
    if usable.is_empty() {
        let names: Vec<String> = pending.methods.iter().map(|(n, h)| method_name(*n, h)).collect();
        let card = page(
            ui,
            "Two-step login",
            &format!(
                "This account uses {}, which Passwords can't do yet. Add an authenticator app or email login in the web vault.",
                names.join(", ")
            ),
        );
        let back = gtk::Button::with_label("Back");
        let u = ui.clone();
        back.connect_clicked(move |_| sign_in_page(&u, None));
        card.append(&buttons(&[&back]));
        return;
    }
    let card = page(ui, "Two-step login", "Enter the code for this sign-in.");
    let options: Vec<(String, String)> = usable.iter().map(|(n, h)| (n.to_string(), method_name(*n, h))).collect();
    let chooser = w::dropdown(&options, &options[0].0);
    if usable.len() > 1 {
        field(&card, "Method", &chooser);
    }
    let code = gtk::Entry::new();
    code.set_max_length(64);
    field(&card, "Code", &code);
    let err = error_label();
    card.append(&err);
    let back = gtk::Button::with_label("Back");
    let send = gtk::Button::with_label("Email me a code");
    let go = gtk::Button::with_label("Continue");
    go.add_css_class("suggested-action");
    card.append(&buttons(&[&back, &send, &go]));
    let recover = gtk::Button::with_label("Use a recovery code");
    recover.add_css_class("flat");
    recover.set_halign(gtk::Align::Start);
    card.append(&recover);
    let chosen = {
        let usable = usable.clone();
        let chooser = chooser.clone();
        move || usable.get(chooser.selected() as usize).map(|(n, _)| *n).unwrap_or(0)
    };
    let c = chosen.clone();
    let (s, entry) = (send.clone(), code.clone());
    let update_send = move || {
        s.set_visible(c() == 1);
        let yubikey = c() == 3;
        entry.set_placeholder_text(Some(if yubikey { "Touch your YubiKey" } else { "" }));
        entry.set_input_purpose(if yubikey { gtk::InputPurpose::FreeForm } else { gtk::InputPurpose::Digits });
    };
    update_send();
    chooser.connect_selected_notify(move |_| update_send());
    let (u, p, g, e) = (ui.clone(), pending.clone(), go.clone(), err.clone());
    recover.connect_clicked(move |_| {
        let (u, p, g, e) = (u.clone(), p.clone(), g.clone(), e.clone());
        w::ask_text(
            "Recovery code",
            "The code you saved when you set up two-step login. Using it signs you in and turns two-step login off for the account; set it up again in the web vault afterwards.",
            "",
            "Sign in",
            move |text| {
                let code: String = text.chars().filter(|c| !c.is_whitespace()).collect();
                sign_in(&u, p.clone(), Some((RECOVERY_CODE, code)), &g, &e);
            },
        );
    });

    let u = ui.clone();
    back.connect_clicked(move |_| sign_in_page(&u, None));
    let p = pending.clone();
    let e = err.clone();
    send.connect_clicked(move |b| {
        let (p, e, b) = (p.clone(), e.clone(), b.clone());
        b.set_sensitive(false);
        glib::spawn_future_local(async move {
            let args = (p.server.as_str(), p.email.as_str(), p.password.as_str());
            match client::call("SendEmailCode", Some(args.to_variant())).await {
                Ok(_) => show_error(&e, "A code is on its way."),
                Err(f) => show_error(&e, &f.to_string()),
            }
            b.set_sensitive(true);
        });
    });
    let submit = {
        let (ui, code, err, go) = (ui.clone(), code.clone(), err.clone(), go.clone());
        move || {
            let text: String = code.text().chars().filter(|c| !c.is_whitespace()).collect();
            if text.is_empty() {
                show_error(&err, "Enter the code.");
                return;
            }
            sign_in(&ui, pending.clone(), Some((chosen(), text)), &go, &err);
        }
    };
    let s = submit.clone();
    go.connect_clicked(move |_| s());
    code.connect_activate(move |_| submit());
    code.grab_focus();
}

fn unlock_page(ui: &Ui) {
    let p = prefs::get();
    let who = if p.last_email.is_empty() { String::new() } else { format!("{} on {}", p.last_email, host(&p.last_server)) };
    let card = page(ui, "Vault locked", &who);
    let password = gtk::PasswordEntry::new();
    password.set_show_peek_icon(true);
    field(&card, "Master password", &password);
    let err = error_label();
    card.append(&err);
    let u = ui.clone();
    let sign_out = w::two_click("Sign out", "Click again to sign out", move || {
        let u = u.clone();
        glib::spawn_future_local(async move {
            let _ = client::call("SignOut", None).await;
            ui::set_state(&u, state::LOGGED_OUT);
        });
    });
    sign_out.set_tooltip_text(Some("Remove this account and its local copy from this device"));
    let go = gtk::Button::with_label("Unlock");
    go.add_css_class("suggested-action");
    // Shown when a key is saved in the keyring (Settings, "Unlock with the keyring").
    let keyring = gtk::Button::from_icon_name("changes-allow-symbolic");
    keyring.set_tooltip_text(Some("Unlock with the key saved in your desktop keyring"));
    keyring.set_visible(false);
    card.append(&buttons(&[&sign_out, &keyring, &go]));
    let k = keyring.clone();
    glib::spawn_future_local(async move {
        if let Ok(v) = client::call("KeyringUnlock", None).await {
            k.set_visible(v.get::<(bool,)>().is_some_and(|(on,)| on));
        }
    });
    let (u, e) = (ui.clone(), err.clone());
    keyring.connect_clicked(move |b| {
        b.set_sensitive(false);
        show_error(&e, "");
        let (ui, err, b) = (u.clone(), e.clone(), b.clone());
        glib::spawn_future_local(async move {
            let reply = client::call("UnlockWithKeyring", None).await;
            b.set_sensitive(true);
            match reply {
                Ok(_) => {
                    ui::set_state(&ui, state::UNLOCKED);
                    ui::sync(&ui);
                }
                Err(e) if e.is(Code::LoggedOut) => ui::set_state(&ui, state::LOGGED_OUT),
                Err(e) => {
                    show_error(&err, &e.to_string());
                    b.set_visible(false);
                }
            }
        });
    });
    let submit = {
        let (ui, password, err, go) = (ui.clone(), password.clone(), err.clone(), go.clone());
        move || {
            let text = password.text().to_string();
            password.set_text("");
            if text.is_empty() {
                return;
            }
            busy(&go, "Unlocking…");
            show_error(&err, "");
            let (ui, err, go) = (ui.clone(), err.clone(), go.clone());
            glib::spawn_future_local(async move {
                let reply = client::call("Unlock", Some((text.as_str(),).to_variant())).await;
                go.set_sensitive(true);
                go.set_label("Unlock");
                match reply {
                    Ok(_) => {
                        ui::set_state(&ui, state::UNLOCKED);
                        // Show the local copy now, the server's when the sync is in.
                        ui::sync(&ui);
                    }
                    Err(e) if e.is(Code::LoggedOut) => ui::set_state(&ui, state::LOGGED_OUT),
                    Err(e) => show_error(&err, &e.to_string()),
                }
            });
        }
    };
    let s = submit.clone();
    go.connect_clicked(move |_| s());
    password.connect_activate(move |_| submit());
    password.grab_focus();
}

thread_local! {
    /// Sign-in requests already put in front of the user.
    static ASKED: std::cell::RefCell<std::collections::HashSet<String>> = Default::default();
}

/// Another device asking to sign in with this account: ask the user, once per request.
pub fn check_sign_in_requests(ui: &Ui) {
    #[derive(serde::Deserialize)]
    struct Request {
        id: String,
        device: String,
        ip: String,
        fingerprint: String,
    }
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let Ok(json) = client::text("SignInRequests", None).await else { return };
        let Ok(list) = serde_json::from_str::<Vec<Request>>(&json) else { return };
        for r in list {
            if !ASKED.with(|a| a.borrow_mut().insert(r.id.clone())) {
                continue;
            }
            let (dialog, card) = w::dialog("Approve a sign-in?", 460);
            dialog.set_transient_for(Some(&ui.window));
            let from = if r.ip.is_empty() { device_name(&r.device) } else { format!("{} at {}", device_name(&r.device), r.ip) };
            card.append(&label(
                &format!(
                    "{from} asks to sign in to your account. Approve it only if you started it there and it shows these words:"
                ),
                "dim",
            ));
            let phrase = label(&r.fingerprint, "pairing-code");
            phrase.set_selectable(true);
            card.append(&phrase);
            let decline = gtk::Button::with_label("Decline");
            let approve = gtk::Button::with_label("Approve");
            approve.add_css_class("suggested-action");
            card.append(&buttons(&[&decline, &approve]));
            for (button, yes) in [(&decline, false), (&approve, true)] {
                let (u, d, id) = (ui.clone(), dialog.clone(), r.id.clone());
                button.connect_clicked(move |_| {
                    d.close();
                    let (u, id) = (u.clone(), id.clone());
                    glib::spawn_future_local(async move {
                        match client::call("AnswerSignIn", Some((id.as_str(), yes).to_variant())).await {
                            Ok(_) => ui::toast(&u, if yes { "Approved: the other device is signing in." } else { "Declined." }),
                            Err(e) => ui::toast(&u, &e.to_string()),
                        }
                    });
                });
            }
            dialog.present();
        }
    });
}

/// Bitwarden's device types, as the server may name them by number.
fn device_name(kind: &str) -> String {
    let name = match kind {
        "0" | "15" => "An Android device",
        "1" => "An iPhone or iPad",
        "2" | "3" | "4" | "5" | "19" | "20" => "A browser extension",
        "6" | "7" | "8" | "16" => "A desktop app",
        "9" | "10" | "11" | "12" | "13" | "14" | "17" | "18" => "A web browser",
        "23" | "24" | "25" => "The command line",
        "" => "A device",
        other => return other.to_string(),
    };
    name.to_string()
}

/// Asks for the master password again for an item that wants it, then runs `then`.
pub fn confirm(ui: &Ui, then: impl Fn() + 'static) {
    confirm_for(ui, "This item asks for your master password before showing its secrets.", then);
}

/// Asks for the master password, saying why, then runs `then`.
pub fn confirm_for(ui: &Ui, why: &str, then: impl Fn() + 'static) {
    let (dialog, card) = w::dialog("Master password", 420);
    dialog.set_transient_for(Some(&ui.window));
    card.append(&label(why, "dim"));
    let password = gtk::PasswordEntry::new();
    password.set_show_peek_icon(true);
    card.append(&password);
    let err = error_label();
    card.append(&err);
    let cancel = gtk::Button::with_label("Not now");
    let go = gtk::Button::with_label("Confirm");
    go.add_css_class("suggested-action");
    card.append(&buttons(&[&cancel, &go]));
    let d = dialog.clone();
    cancel.connect_clicked(move |_| d.close());
    let then = std::rc::Rc::new(then);
    let submit = {
        let (password, err, d) = (password.clone(), err.clone(), dialog.clone());
        move || {
            let text = password.text().to_string();
            password.set_text("");
            let (err, d, then) = (err.clone(), d.clone(), then.clone());
            glib::spawn_future_local(async move {
                match client::call("VerifyPassword", Some((text.as_str(),).to_variant())).await {
                    Ok(_) => {
                        d.close();
                        then();
                    }
                    Err(e) => show_error(&err, &e.to_string()),
                }
            });
        }
    };
    let s = submit.clone();
    go.connect_clicked(move |_| s());
    password.connect_activate(move |_| submit());
    dialog.present();
    password.grab_focus();
}

fn host(url: &str) -> String {
    url.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/').to_string()
}
