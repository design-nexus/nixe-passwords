//! Creating and editing logins, notes, cards, identities and SSH keys. An existing
//! item's secret fields are fetched one by one when the editor opens; the draft goes to
//! the daemon as JSON when saved.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use gtk::{gdk, gio, glib, prelude::*};
use nyx_passwords_proto::Error as Code;
use nyx_passwords_proto::custom;
use nyx_passwords_proto::fields::{self, Spec};
use nyx_ui::widgets as w;
use serde_json::json;

use super::client;
use super::data::{self, Entry};
use super::detail::{self, FieldRow};
use super::prefs;
use super::ui::{self, Ui, label};

/// The kinds the editor makes.
pub const KINDS: &[&str] = &["login", "note", "card", "identity", "ssh"];

/// "card", "secure note", "SSH key": the kind's name inside a sentence.
fn noun(kind: &str) -> String {
    let name = data::kind_name(kind);
    if kind == "ssh" { name.to_string() } else { name.to_lowercase() }
}

/// Larger files can't be private keys.
const KEY_FILE_LIMIT: usize = 64 * 1024;

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
    /// An SSH private key: held, never shown.
    Key(Rc<KeyPicker>),
}

/// An SSH key in the editor: the private key stays out of sight; its type, fingerprint
/// and public key are shown, with buttons to generate a new key or import one.
struct KeyPicker {
    private: RefCell<String>,
    summary: gtk::Label,
    public: gtk::Label,
    buttons: gtk::Box,
    body: gtk::Box,
}

impl KeyPicker {
    fn new(ui: &Ui) -> Rc<KeyPicker> {
        let body = w::vbox(6);
        let summary = label("No key yet: generate one, or import a private key file.", "dim");
        let public = label("", "dim");
        public.set_selectable(true);
        // Keys and fingerprints wrap anywhere, without the hyphens Pango would add.
        let unhyphenated = gtk::pango::AttrList::new();
        unhyphenated.insert(gtk::pango::AttrInt::new_insert_hyphens(false));
        for l in [&summary, &public] {
            l.set_wrap_mode(gtk::pango::WrapMode::WordChar);
            l.set_attributes(Some(&unhyphenated));
        }
        public.set_visible(false);
        body.append(&summary);
        body.append(&public);
        let buttons = w::hbox(6);
        let generate = gtk::Button::from_icon_name("view-refresh-symbolic");
        generate.set_tooltip_text(Some("Generate a new Ed25519 key"));
        let import = gtk::Button::from_icon_name("document-open-symbolic");
        import.set_tooltip_text(Some("Import a private key file…"));
        buttons.append(&generate);
        buttons.append(&import);
        body.append(&buttons);
        let picker = Rc::new(KeyPicker { private: RefCell::new(String::new()), summary, public, buttons, body });
        let (u, p) = (ui.clone(), picker.clone());
        generate.connect_clicked(move |_| {
            let (u, p) = (u.clone(), p.clone());
            glib::spawn_future_local(async move {
                match client::text("GenerateSshKey", None).await {
                    Ok(json) => {
                        let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
                        *p.private.borrow_mut() = v["private"].as_str().unwrap_or_default().to_string();
                        p.show(v["public"].as_str().unwrap_or_default(), v["fingerprint"].as_str().unwrap_or_default());
                    }
                    Err(e) => ui::toast(&u, &e.to_string()),
                }
            });
        });
        let (u, p) = (ui.clone(), picker.clone());
        import.connect_clicked(move |b| p.import(&u, b));
        picker
    }

    fn show(&self, public: &str, fingerprint: &str) {
        let kind = match public.split(' ').next().unwrap_or_default() {
            "ssh-ed25519" => "Ed25519",
            "ssh-rsa" => "RSA",
            "ecdsa-sha2-nistp256" => "ECDSA P-256",
            "ecdsa-sha2-nistp384" => "ECDSA P-384",
            "ecdsa-sha2-nistp521" => "ECDSA P-521",
            other => other,
        };
        self.summary.set_text(&format!("{kind} key · {fingerprint}"));
        self.public.set_text(public);
        self.public.set_visible(true);
    }

    /// Takes a private key: asks the daemon for its public key and fingerprint, and keeps
    /// it only if the daemon can read it.
    fn take(self: &Rc<Self>, ui: Option<&Ui>, private: String) {
        let (ui, p) = (ui.cloned(), self.clone());
        glib::spawn_future_local(async move {
            match client::text("ReadSshKey", Some((private.as_str(),).to_variant())).await {
                Ok(json) => {
                    let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
                    *p.private.borrow_mut() = private;
                    p.show(v["public"].as_str().unwrap_or_default(), v["fingerprint"].as_str().unwrap_or_default());
                }
                // The daemon's words for a key with a passphrase (`ssh::SshError::Encrypted`).
                Err(e) if ui.is_some() && e.message.contains("has a passphrase") => {
                    p.ask_passphrase(ui.as_ref().expect("checked"), private);
                }
                Err(e) => match ui {
                    Some(ui) => ui::toast(&ui, &e.to_string()),
                    None => p.summary.set_text(&format!("The saved key can't be read: {e}")),
                },
            }
        });
    }

    /// Opens an imported key that has a passphrase. The item keeps the key without it,
    /// as the official clients do; the vault's encryption protects it instead.
    fn ask_passphrase(self: &Rc<Self>, ui: &Ui, private: String) {
        let (dialog, card) = w::dialog("This key has a passphrase", 420);
        card.append(&label("Enter it to import the key. It's saved without the passphrase, encrypted in your vault.", "dim"));
        let entry = gtk::PasswordEntry::new();
        entry.set_show_peek_icon(true);
        card.append(&entry);
        let buttons = w::hbox(8);
        buttons.set_halign(gtk::Align::End);
        let cancel = gtk::Button::with_label("Cancel");
        let open = gtk::Button::with_label("Import");
        open.add_css_class("suggested-action");
        buttons.append(&cancel);
        buttons.append(&open);
        card.append(&buttons);
        let d = dialog.clone();
        cancel.connect_clicked(move |_| d.close());
        let submit = {
            let (ui, p, d, e, private) = (ui.clone(), self.clone(), dialog.clone(), entry.clone(), Rc::new(private));
            Rc::new(move || {
                let (ui, p, d, e, private) = (ui.clone(), p.clone(), d.clone(), e.clone(), private.clone());
                glib::spawn_future_local(async move {
                    let args = (private.as_str(), e.text().as_str()).to_variant();
                    match client::text("OpenSshKey", Some(args)).await {
                        Ok(json) => {
                            let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
                            *p.private.borrow_mut() = v["private"].as_str().unwrap_or_default().to_string();
                            p.show(v["public"].as_str().unwrap_or_default(), v["fingerprint"].as_str().unwrap_or_default());
                            d.close();
                        }
                        Err(err) => {
                            e.add_css_class("error");
                            ui::toast(&ui, &err.to_string());
                        }
                    }
                });
            })
        };
        let s = submit.clone();
        open.connect_clicked(move |_| s());
        entry.connect_activate(move |_| submit());
        dialog.present();
        entry.grab_focus();
    }

    fn import(self: &Rc<Self>, ui: &Ui, button: &gtk::Button) {
        let parent = button.root().and_downcast::<gtk::Window>();
        let (ui, p) = (ui.clone(), self.clone());
        gtk::FileDialog::builder().title("Import a private key").modal(true).build().open(
            parent.as_ref(),
            gio::Cancellable::NONE,
            move |picked| {
                let Ok(file) = picked else { return };
                glib::spawn_future_local(async move {
                    match file.load_contents_future().await {
                        Ok((bytes, _)) if bytes.len() <= KEY_FILE_LIMIT => match String::from_utf8(bytes.to_vec()) {
                            Ok(text) => p.take(Some(&ui), text),
                            Err(_) => ui::toast(&ui, "That file isn't a private key."),
                        },
                        Ok(_) => ui::toast(&ui, "That file is too large to be a private key."),
                        Err(e) => ui::toast(&ui, &e.to_string()),
                    }
                });
            },
        );
    }
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
            Control::Key(k) => k.body.clone().upcast(),
        }
    }

    fn text(&self) -> String {
        match self {
            Control::Text(e) => e.text().trim().to_string(),
            Control::Secret(p) => p.text().trim().to_string(),
            Control::Choice(d, values) => values.borrow().get(d.selected() as usize).cloned().unwrap_or_default(),
            Control::Key(k) => k.private.borrow().clone(),
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
            Control::Key(k) => k.take(None, value.to_string()),
        }
    }
}

/// A custom field's value: text, hidden text, or true or false.
enum CustomValue {
    Text(gtk::Entry),
    Hidden(gtk::PasswordEntry),
    Flag(gtk::Switch),
}

/// The custom field types the editor makes: `(type, name)`.
const CUSTOM_KINDS: &[(i64, &str)] = &[(0, "Text"), (1, "Hidden"), (2, "True or false")];

/// One custom field in the editor. `source` is its position in the item it came from
/// (for revealing it, and, unless the item is being copied, for keeping what isn't
/// edited). A `locked` field is hidden from this account: its value stays as stored.
struct CustomRow {
    source: Option<usize>,
    keep_source: bool,
    kind: i64,
    name: gtk::Entry,
    value: CustomValue,
    locked: bool,
    root: gtk::Box,
}

impl CustomRow {
    fn json(&self) -> serde_json::Value {
        let value = match &self.value {
            _ if self.locked => None,
            CustomValue::Text(e) => Some(e.text().to_string()),
            CustomValue::Hidden(p) => Some(p.text().to_string()),
            CustomValue::Flag(s) => Some(s.is_active().to_string()),
        };
        json!({
            "name": self.name.text().trim(),
            "value": value,
            "kind": self.kind,
            "from": if self.keep_source { self.source } else { None },
        })
    }

    fn set(&self, value: &str) {
        match &self.value {
            CustomValue::Text(e) => e.set_text(value),
            CustomValue::Hidden(p) => p.set_text(value),
            CustomValue::Flag(s) => s.set_active(value == "true"),
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
    /// `None` for "Me", else an organization's id; the item's own when it has one.
    owner: gtk::DropDown,
    owner_ids: Vec<Option<String>>,
    /// The chosen organization's collections, as checkboxes.
    collections: gtk::Box,
    collection_checks: RefCell<Vec<(String, gtk::CheckButton)>>,
    /// Said when a personal item is about to move into an organization.
    move_note: gtk::Label,
    custom_box: gtk::Box,
    custom: RefCell<Vec<Rc<CustomRow>>>,
    /// The item's custom fields are all in the form (an edit sends them only then, so a
    /// failed load can't wipe them).
    custom_ready: Cell<bool>,
    /// A login's "Sign in with …" provider (empty: its password), and whether it's filled
    /// as its page loads; kept as custom fields (`proto::custom`), from these positions.
    sign_in_with: gtk::DropDown,
    provider_ids: Vec<String>,
    fill_on_load: gtk::Switch,
    special_from: Cell<(Option<usize>, Option<usize>)>,
}

impl Form {
    /// Adds a custom field row; `name` and `value` for one the item already has.
    fn add_custom(
        self: &Rc<Self>,
        kind: i64,
        source: Option<usize>,
        keep_source: bool,
        name: &str,
        locked: bool,
    ) -> Rc<CustomRow> {
        let root = w::hbox(6);
        let name_entry = gtk::Entry::new();
        name_entry.set_placeholder_text(Some("Name"));
        name_entry.set_width_chars(12);
        name_entry.set_text(name);
        root.append(&name_entry);
        let value = match kind {
            1 => {
                let p = gtk::PasswordEntry::new();
                p.set_show_peek_icon(true);
                p.set_hexpand(true);
                if locked {
                    p.set_sensitive(false);
                    p.set_placeholder_text(Some("Hidden by its organization"));
                }
                root.append(&p);
                CustomValue::Hidden(p)
            }
            2 => {
                let s = gtk::Switch::new();
                s.set_valign(gtk::Align::Center);
                let spacer = w::hbox(0);
                spacer.set_hexpand(true);
                root.append(&s);
                root.append(&spacer);
                CustomValue::Flag(s)
            }
            _ => {
                let e = gtk::Entry::new();
                e.set_placeholder_text(Some("Value"));
                e.set_hexpand(true);
                root.append(&e);
                CustomValue::Text(e)
            }
        };
        let remove = w::bar_button("user-trash-symbolic", "Remove this field");
        root.append(&remove);
        let row = Rc::new(CustomRow { source, keep_source, kind, name: name_entry, value, locked, root });
        self.custom_box.append(&row.root);
        self.custom.borrow_mut().push(row.clone());
        let (f, r) = (Rc::downgrade(self), Rc::downgrade(&row));
        remove.connect_clicked(move |_| {
            if let (Some(f), Some(r)) = (f.upgrade(), r.upgrade()) {
                f.custom_box.remove(&r.root);
                f.custom.borrow_mut().retain(|x| !Rc::ptr_eq(x, &r));
            }
        });
        row
    }

    fn clear_custom(&self) {
        for row in self.custom.borrow_mut().drain(..) {
            self.custom_box.remove(&row.root);
        }
    }

    fn organization(&self) -> Option<String> {
        self.owner_ids.get(self.owner.selected() as usize).cloned().flatten()
    }

    /// Lists the chosen organization's collections; `current` are ticked. Ones this
    /// account can't write to can't be ticked or unticked.
    fn show_collections(&self, ui: &Ui, current: &[String]) {
        ui::clear(&self.collections);
        let mut checks = Vec::new();
        if let Some(org) = self.organization() {
            self.collections.append(&label("Collections", "account-field"));
            for c in ui.listing.borrow().collections.iter().filter(|c| c.organization == org) {
                let check = gtk::CheckButton::with_label(&c.name);
                check.set_active(current.contains(&c.id));
                check.set_sensitive(c.writable);
                if !c.writable {
                    check.set_tooltip_text(Some("Read-only for you"));
                }
                self.collections.append(&check);
                checks.push((c.id.clone(), check));
            }
        }
        self.collections.set_visible(!checks.is_empty());
        *self.collection_checks.borrow_mut() = checks;
    }

    /// For an item whose organization hides its secrets: those fields can't be seen or
    /// changed here, and keep their stored values when saved.
    fn hide_secrets(&self) {
        for (name, control) in self.fields.borrow().iter() {
            let secret = fields::of_kind(self.kind.get()).iter().any(|s| s.name == *name && s.secret);
            match control {
                Control::Key(k) => {
                    k.summary.set_text("Hidden by its organization; the key stays as it is.");
                    k.public.set_visible(false);
                    k.buttons.set_sensitive(false);
                }
                Control::Secret(p) if secret => {
                    p.set_sensitive(false);
                    p.set_placeholder_text(Some("Hidden by its organization"));
                }
                _ => {}
            }
        }
    }

    fn chosen_collections(&self) -> Vec<String> {
        self.collection_checks.borrow().iter().filter(|(_, c)| c.is_active()).map(|(id, _)| id.clone()).collect()
    }
    /// Shows the fields of `kind`: the login form, or the kind's own fields. An SSH key's
    /// public key and fingerprint come from its private key, so only that is edited.
    fn show_kind(&self, ui: &Ui, kind: &'static str) {
        self.kind.set(kind);
        self.login.set_visible(kind == "login");
        ui::clear(&self.others);
        let mut controls = Vec::new();
        if kind == "ssh" {
            let control = Control::Key(KeyPicker::new(ui));
            field(&self.others, "Key", &control.widget());
            controls.push(("ssh.privateKey", control));
        } else {
            for spec in fields::of_kind(kind) {
                let control = Control::new(spec);
                field(&self.others, spec.label, &control.widget());
                controls.push((spec.name, control));
            }
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

/// The editor: a card over the window rather than a window of its own, so it can't fall
/// behind the main window or keep the app from closing.
#[derive(Clone)]
pub struct Sheet {
    veil: gtk::Box,
    ui: std::rc::Weak<ui::State>,
}

impl Sheet {
    pub fn close(&self) {
        if let Some(overlay) = self.veil.parent().and_downcast::<gtk::Overlay>() {
            if let Some(child) = overlay.child() {
                child.set_sensitive(true);
            }
            overlay.remove_overlay(&self.veil);
        }
        if let Some(ui) = self.ui.upgrade()
            && let Ok(mut editor) = ui.editor.try_borrow_mut()
        {
            editor.take();
        }
    }

    pub fn present(&self) {
        self.veil.child_focus(gtk::DirectionType::TabForward);
    }
}

pub fn open(ui: &Ui, entry: Option<Entry>) {
    open_with(ui, entry, false);
}

/// A new item with another's contents: its secrets, custom fields and notes, but not
/// its attachments or passkeys.
pub fn open_copy(ui: &Ui, entry: Entry) {
    open_with(ui, Some(entry), true);
}

fn open_with(ui: &Ui, entry: Option<Entry>, copy: bool) {
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
        Some(_) if copy => format!("Copy {}", noun(kind)),
        Some(_) => format!("Edit {}", noun(kind)),
        None => "New item".to_string(),
    };
    let veil = w::vbox(0);
    veil.add_css_class("settings-veil");
    veil.set_hexpand(true);
    veil.set_vexpand(true);
    let card = w::vbox(12);
    card.add_css_class("dialog-card");
    card.add_css_class("editor-sheet");
    card.set_halign(gtk::Align::Center);
    card.set_valign(gtk::Align::Center);
    card.set_vexpand(true);
    card.set_size_request(560, -1);
    card.append(&w::label(&title, "section-title"));
    veil.append(&card);
    // The window behind can't be clicked or tabbed into while the editor is open.
    if let Some(child) = ui.overlay.child() {
        child.set_sensitive(false);
    }
    ui.overlay.add_overlay(&veil);
    ui.overlay.set_measure_overlay(&veil, false);
    ui::raise_toast(ui);
    let dialog = Sheet { veil: veil.clone(), ui: Rc::downgrade(ui) };
    *ui.editor.borrow_mut() = Some(dialog.clone());

    let body = w::vbox(8);
    let scroll = ui::scroll(&body);
    scroll.set_vexpand(false);
    scroll.set_propagate_natural_height(true);
    scroll.set_min_content_height(280);
    scroll.set_max_content_height(520);
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

    // Owner: "Me" or an organization with a collection this account can write to. An
    // organization item stays in its organization.
    let listing = ui.listing.borrow();
    // A copy is a new item: it may go anywhere a new item may, starting where the original is.
    let item_org = entry.as_ref().filter(|_| !copy).and_then(|e| e.organization.clone());
    let owner_current = entry.as_ref().and_then(|e| e.organization.clone()).unwrap_or_default();
    let mut owner_ids = vec![None];
    let mut owner_names = vec![(String::new(), "Me".to_string())];
    for o in &listing.organizations {
        let writable = listing.collections.iter().any(|c| c.organization == o.id && c.writable);
        if item_org.as_deref() == Some(o.id.as_str()) || item_org.is_none() && writable {
            owner_ids.push(Some(o.id.clone()));
            owner_names.push((o.id.clone(), o.name.clone()));
        }
    }
    drop(listing);
    if item_org.is_some() {
        owner_ids.remove(0);
        owner_names.remove(0);
    }
    let owner = w::dropdown(&owner_names, &owner_current);
    owner.set_sensitive(owner_ids.len() > 1);
    let collections = w::vbox(4);
    let move_note = label("Once it's in an organization, it can't be moved back here.", "dim");
    move_note.set_visible(false);

    field(&body, "Name", &name);
    let login = w::vbox(8);
    let user_line = w::hbox(6);
    username.set_hexpand(true);
    user_line.append(&username);
    let generate_user = w::bar_button("media-playlist-shuffle-symbolic", "Generate a username (see Settings → Generator)");
    user_line.append(&generate_user);
    field(&login, "Username", &user_line);
    let pw_line = w::hbox(6);
    pw_line.append(&password);
    let generate = w::bar_button("media-playlist-shuffle-symbolic", "Generate a password");
    pw_line.append(&generate);
    let history = w::bar_button("document-open-recent-symbolic", "What the generators made while the vault was open");
    pw_line.append(&history);
    let u = ui.clone();
    history.connect_clicked(move |_| show_history(&u));
    body.append(&login);
    let others = w::vbox(8);
    body.append(&others);
    let hidden_note = label("Its organization hides this login's password from you; it stays as it is.", "dim");
    hidden_note.set_visible(entry.as_ref().is_some_and(|e| !e.view_password));
    if !hidden_note.is_visible() {
        field(&login, "Password", &pw_line);
        field(&login, "One-time code key", &totp);
    } else {
        login.append(&hidden_note);
    }
    field(&login, "Web addresses, one per line", &frame(&uris));
    let mut provider_rows = vec![(String::new(), "Its password".to_string())];
    provider_rows.extend(custom::PROVIDERS.iter().map(|(id, name)| (id.to_string(), format!("“Sign in with {name}”"))));
    let provider_ids: Vec<String> = provider_rows.iter().map(|(id, _)| id.clone()).collect();
    let sign_in_with = w::dropdown(&provider_rows, "");
    field(&login, "Signs in with", &sign_in_with);
    let fill_on_load = gtk::Switch::new();
    fill_on_load.set_active(true);
    let load_rows = w::vbox(0);
    load_rows.add_css_class("group-list");
    load_rows.append(&w::row(
        "Fill as the page loads",
        "In paired browsers, when that's on in Settings → Browsers.",
        Some(fill_on_load.upcast_ref()),
    ));
    login.append(&load_rows);
    let custom_box = w::vbox(6);
    body.append(&label("Custom fields", "account-field"));
    body.append(&custom_box);
    let add_line = w::hbox(6);
    let custom_kinds: Vec<(String, String)> = CUSTOM_KINDS.iter().map(|(k, n)| (k.to_string(), n.to_string())).collect();
    let add_kind = w::dropdown(&custom_kinds, "0");
    let add_custom = gtk::Button::with_label("Add field");
    add_line.append(&add_kind);
    add_line.append(&add_custom);
    body.append(&add_line);
    if owner_ids.len() > 1 || item_org.is_some() {
        field(&body, "Owner", &owner);
        body.append(&move_note);
        body.append(&collections);
    }
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
        owner,
        owner_ids,
        collections,
        collection_checks: RefCell::new(Vec::new()),
        move_note,
        custom_box,
        custom: RefCell::new(Vec::new()),
        custom_ready: Cell::new(entry.is_none()),
        sign_in_with,
        provider_ids,
        fill_on_load,
        special_from: Cell::new((None, None)),
    });
    form.show_kind(ui, kind);
    form.show_collections(ui, &entry.as_ref().map(|e| e.collections.clone()).unwrap_or_default());
    let f = form.clone();
    add_custom.connect_clicked(move |_| {
        let kind = CUSTOM_KINDS.get(add_kind.selected() as usize).map_or(0, |(k, _)| *k);
        f.add_custom(kind, None, false, "", false).name.grab_focus();
    });
    let personal = !copy && entry.as_ref().is_some_and(|e| e.organization.is_none());
    let (u, f) = (ui.clone(), form.clone());
    form.owner.connect_selected_notify(move |_| {
        f.show_collections(&u, &[]);
        f.move_note.set_visible(personal && f.organization().is_some());
    });
    let (u, f) = (ui.clone(), form.clone());
    kind_choice.connect_selected_notify(move |d| {
        if let Some(k) = KINDS.get(d.selected() as usize) {
            f.show_kind(&u, k);
        }
    });
    let id = entry.as_ref().filter(|_| !copy).map(|e| e.id.clone());
    if let Some(e) = &entry {
        form.name.set_text(&if copy { format!("{} (copy)", e.name) } else { e.name.clone() });
        form.username.set_text(e.username.as_deref().unwrap_or(""));
        form.uris.buffer().set_text(&e.uris.join("\n"));
        form.favorite.set_active(e.favorite);
        form.reprompt.set_active(e.reprompt);
        fill_secrets(ui, &e.id, &form, &dialog, copy);
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

    let (u, f) = (ui.clone(), form.clone());
    generate_user.connect_clicked(move |b| {
        let site = text_of(&f.uris).lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or_default().to_string();
        let (u, f, b) = (u.clone(), f.clone(), b.clone());
        b.set_sensitive(false);
        glib::spawn_future_local(async move {
            match client::text("GenerateUsername", Some((site.as_str(),).to_variant())).await {
                Ok(made) => f.username.set_text(&made),
                Err(e) => ui::toast(&u, &e.to_string()),
            }
            b.set_sensitive(true);
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
    veil.add_controller(keys);
    form.name.grab_focus();
}

/// The generator history: what was made while the vault was open, newest first, each
/// hidden until shown. Copies go through the daemon, which clears them later.
fn show_history(ui: &Ui) {
    #[derive(serde::Deserialize)]
    struct Made {
        what: String,
        value: String,
        when: u64,
    }
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let list = match client::text("GeneratorHistory", None).await {
            Ok(json) => serde_json::from_str::<Vec<Made>>(&json).unwrap_or_default(),
            Err(e) => return ui::toast(&ui, &e.to_string()),
        };
        let (dialog, card) = w::dialog("Generator history", 480);
        dialog.set_transient_for(Some(&ui.window));
        if list.is_empty() {
            card.append(&label("Nothing generated since the vault was unlocked.", "dim"));
        }
        let rows = w::vbox(0);
        rows.add_css_class("group-list");
        for (i, m) in list.into_iter().enumerate() {
            let value = gtk::PasswordEntry::new();
            value.set_text(&m.value);
            value.set_editable(false);
            value.set_show_peek_icon(true);
            value.set_hexpand(true);
            let copy = w::bar_button("edit-copy-symbolic", "Copy");
            let u = ui.clone();
            copy.connect_clicked(move |_| {
                let u = u.clone();
                glib::spawn_future_local(async move {
                    match client::call("CopyGenerated", Some((i as u32,).to_variant())).await {
                        Ok(_) => ui::toast(&u, "Copied."),
                        Err(e) => ui::toast(&u, &e.to_string()),
                    }
                });
            });
            let line = w::hbox(6);
            line.append(&value);
            line.append(&copy);
            let what = if m.what == "username" { "Username" } else { "Password" };
            rows.append(&w::row(&format!("{what} · {}", data::ago(m.when)), "", Some(line.upcast_ref())));
        }
        card.append(&rows);
        dialog.present();
    });
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
/// or a note's, card's or identity's own fields; its custom fields; then the notes. For
/// a copy, custom fields don't point back at the original.
fn fill_secrets(ui: &Ui, id: &str, form: &Rc<Form>, dialog: &Sheet, copy: bool) {
    let (ui, id, form, dialog) = (ui.clone(), id.to_string(), form.clone(), dialog.clone());
    glib::spawn_future_local(async move {
        let entry = ui.listing.borrow().entries.iter().find(|e| e.id == id).cloned();
        let mut wanted: Vec<String> = Vec::new();
        let visible = entry.as_ref().is_none_or(|e| e.view_password);
        if form.kind.get() == "login" {
            if visible && entry.as_ref().is_some_and(|e| e.has_password) {
                wanted.push("password".into());
            }
            if visible && entry.as_ref().is_some_and(|e| e.has_totp) {
                wanted.push("totp_seed".into());
            }
        }
        let listed = match client::text("Fields", Some((id.as_str(),).to_variant())).await {
            Ok(json) => serde_json::from_str::<Vec<FieldRow>>(&json).unwrap_or_default(),
            Err(e) => {
                ui::toast(&ui, &e.to_string());
                dialog.close();
                return;
            }
        };
        form.clear_custom();
        for row in listed {
            if let Some(n) = row.name.strip_prefix("custom:").and_then(|n| n.parse::<usize>().ok()) {
                // Passwords' own fields have controls of their own.
                let keep = if copy { None } else { Some(n) };
                if row.label == custom::SIGN_IN_WITH {
                    let value = row.value.clone().unwrap_or_default();
                    if let Some(at) = form.provider_ids.iter().position(|p| *p == value) {
                        form.sign_in_with.set_selected(at as u32);
                    }
                    form.special_from.set((keep, form.special_from.get().1));
                    continue;
                }
                if row.label == custom::NO_FILL_ON_LOAD {
                    form.fill_on_load.set_active(row.value.as_deref() != Some("true"));
                    form.special_from.set((form.special_from.get().0, keep));
                    continue;
                }
                let locked = row.secret && !visible;
                let custom = form.add_custom(row.kind, Some(n), !copy, &row.label, locked);
                match row.value {
                    Some(value) => custom.set(&value),
                    None if row.secret && visible => wanted.push(row.name),
                    None => {}
                }
                continue;
            }
            match row.value {
                Some(value) => set_field(&form, &row.name, &value),
                None if row.secret && visible => wanted.push(row.name),
                None => {}
            }
        }
        if !visible && form.kind.get() != "login" {
            form.hide_secrets();
        }
        wanted.push("notes".into());
        for field in wanted {
            match client::reveal(&id, &field).await {
                Ok(v) => match field.as_str() {
                    "password" => form.password.set_text(&v),
                    "totp_seed" => form.totp.set_text(&v),
                    "notes" => form.notes.buffer().set_text(&v),
                    other => match other.strip_prefix("custom:").and_then(|n| n.parse::<usize>().ok()) {
                        Some(n) => {
                            if let Some(row) = form.custom.borrow().iter().find(|r| r.source == Some(n)) {
                                row.set(&v);
                            }
                        }
                        None => set_field(&form, other, &v),
                    },
                },
                Err(e) if e.is(Code::NoField) => {}
                Err(e) if e.is(Code::Reprompt) => {
                    let (u, i, f, d) = (ui.clone(), id.clone(), form.clone(), dialog.clone());
                    super::account::confirm(&ui, move || fill_secrets(&u, &i, &f, &d, copy));
                    return;
                }
                Err(e) => {
                    ui::toast(&ui, &e.to_string());
                    dialog.close();
                    return;
                }
            }
        }
        form.custom_ready.set(true);
    });
}

fn set_field(form: &Form, name: &str, value: &str) {
    if let Some((_, control)) = form.fields.borrow().iter().find(|(n, _)| *n == name) {
        control.set(value);
    }
}

fn submit(ui: &Ui, form: &Rc<Form>, id: Option<String>, dialog: &Sheet, save: &gtk::Button) {
    let name = form.name.text().trim().to_string();
    let kind = form.kind.get();
    if name.is_empty() {
        ui::toast(ui, &format!("Give the {} a name.", noun(kind)));
        form.name.grab_focus();
        return;
    }
    let hidden = id.as_ref().is_some_and(|id| ui.listing.borrow().entries.iter().any(|e| e.id == *id && !e.view_password));
    if kind == "ssh" && !hidden && form.fields.borrow().iter().all(|(_, c)| c.text().is_empty()) {
        ui::toast(ui, "Generate a key or import one first.");
        return;
    }
    let folder = form.folder_ids.get(form.folder.selected() as usize).cloned().flatten();
    let organization = form.organization();
    let collections = form.chosen_collections();
    if organization.is_some() && collections.is_empty() {
        ui::toast(ui, "Choose at least one collection.");
        return;
    }
    if !form.custom_ready.get() {
        ui::toast(ui, "Still loading the item; try again in a moment.");
        return;
    }
    let mut custom: Vec<serde_json::Value> = form.custom.borrow().iter().map(|r| r.json()).collect();
    if kind == "login" {
        let (provider_from, load_from) = form.special_from.get();
        let provider = form.provider_ids.get(form.sign_in_with.selected() as usize).cloned().unwrap_or_default();
        if !provider.is_empty() {
            custom.push(json!({"name": custom::SIGN_IN_WITH, "value": provider, "kind": 0, "from": provider_from}));
        }
        if !form.fill_on_load.is_active() {
            custom.push(json!({"name": custom::NO_FILL_ON_LOAD, "value": "true", "kind": 2, "from": load_from}));
        }
    }
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
            "organization": organization,
            "collections": collections,
            "custom": custom,
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
            "organization": organization,
            "collections": collections,
            "custom": custom,
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
            Err(e) => {
                if e.is(Code::NotFound) {
                    dialog.close();
                }
                detail::handle(&ui, e, || {});
            }
        }
    });
}
