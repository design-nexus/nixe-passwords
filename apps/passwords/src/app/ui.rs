//! The window: sidebar, item list and details while the vault is open; the sign-in or
//! unlock page otherwise. Built like Contacts (STYLE.md: Music's sidebar, the shared
//! settings card, status bar actions).

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use gtk::{gdk, glib, prelude::*};
use nixe_passwords_proto::state;
use nixe_ui::{chrome, widgets as w};

use super::data::{self, Listing};
use super::{account, client, detail, editor, prefs, settings, theme};

pub type Ui = Rc<State>;

pub struct State {
    pub window: gtk::ApplicationWindow,
    pub overlay: gtk::Overlay,
    nav: gtk::Box,
    head: gtk::Box,
    sidebar: gtk::Box,
    /// "account" (sign in, unlock) or "vault".
    pages: gtk::Stack,
    pub account: gtk::Box,
    toolbar: gtk::Box,
    pub list: gtk::ListBox,
    list_scroll: gtk::ScrolledWindow,
    pub details: gtk::Box,
    detail_scroll: gtk::ScrolledWindow,
    pub search: gtk::SearchEntry,
    status: gtk::Label,
    lock_button: gtk::Button,
    sync_button: gtk::Button,
    toast_box: gtk::Box,
    toast_serial: Cell<u64>,
    /// The daemon's state: logged_out, locked, unlocked; "" before the first answer.
    pub state: RefCell<String>,
    pub listing: RefCell<Listing>,
    pub section: RefCell<String>,
    pub selected: RefCell<Option<String>>,
    pub narrow: Cell<bool>,
    pub showing_detail: Cell<bool>,
    rebuilding: Cell<bool>,
    pub editor: RefCell<Option<gtk::Window>>,
    /// Bumped whenever details are rebuilt, so timers from older ones stop.
    pub detail_serial: Cell<u64>,
}

thread_local! { static UI: RefCell<Option<Ui>> = const { RefCell::new(None) }; }

pub fn current() -> Option<Ui> {
    UI.with(|u| u.borrow().clone())
}

pub fn present(app: &gtk::Application, section: Option<&str>) -> Ui {
    if let Some(ui) = current() {
        if let Some(s) = section {
            navigate(&ui, s);
        }
        ui.window.present();
        return ui;
    }
    theme::install();
    install_icons();
    let window = gtk::ApplicationWindow::builder().application(app).default_width(1120).default_height(800).build();
    window.add_css_class("passwords-window");
    window.set_icon_name(Some("io.github.design_nexus.nixe.Passwords"));
    window.set_titlebar(Some(&w::hbox(0)));
    chrome::set_title(&window, "Passwords", "");
    let overlay = gtk::Overlay::new();
    let frame = w::vbox(0);
    frame.add_css_class("window-frame");
    let body = w::hbox(0);
    body.set_vexpand(true);
    frame.append(&body);
    overlay.set_child(Some(&frame));
    window.set_child(Some(&overlay));

    let sidebar = w::vbox(0);
    sidebar.set_hexpand(false); // Required: expanding labels must not expand the sidebar.
    sidebar.add_css_class("settings-navigation");
    let head = chrome::sidebar_head("Passwords", Some("Find (Ctrl+F)"));
    sidebar.append(&head.root);
    let nav = w::vbox(0);
    nav.set_hexpand(false);
    let nav_scroll = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(false)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::External)
        .child(&nav)
        .build();
    sidebar.append(&nav_scroll);
    body.append(&sidebar);

    let content = w::vbox(0);
    content.add_css_class("settings-content");
    content.set_hexpand(true); // Only the page column receives spare horizontal space.
    body.append(&content);
    let pages = gtk::Stack::new();
    pages.set_transition_type(gtk::StackTransitionType::Crossfade);
    pages.set_transition_duration(160);
    pages.set_vexpand(true);
    content.append(&pages);

    let account = w::vbox(0);
    account.set_vexpand(true);
    pages.add_named(&scroll(&account), Some("account"));

    let vault = w::vbox(0);
    let search = gtk::SearchEntry::new();
    search.set_placeholder_text(Some("Search the vault…"));
    search.set_visible(false);
    vault.append(&chrome::search_strip(&search));
    let toolbar = w::hbox(6);
    toolbar.add_css_class("list-toolbar");
    vault.append(&toolbar);
    let new = gtk::Button::new();
    new.add_css_class("suggested-action");
    new.set_tooltip_text(Some("New login (Ctrl+N)"));
    let new_content = w::hbox(8);
    new_content.append(&gtk::Image::from_icon_name("list-add-symbolic"));
    new_content.append(&gtk::Label::new(Some("New login")));
    new.set_child(Some(&new_content));
    toolbar.append(&new);
    let panes = w::hbox(0);
    panes.set_vexpand(true);
    vault.append(&panes);
    let list = gtk::ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::Single);
    list.add_css_class("item-list");
    let list_scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::External)
        .vexpand(true)
        .child(&list)
        .build();
    list_scroll.set_width_request(300);
    panes.append(&list_scroll);
    let details = w::vbox(12);
    details.add_css_class("item-details");
    let detail_scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::External)
        .hexpand(true)
        .vexpand(true)
        .child(&nixe_ui::clamp::Clamp::new(&details, 920))
        .build();
    detail_scroll.add_css_class("item-detail-pane");
    panes.append(&detail_scroll);
    pages.add_named(&vault, Some("vault"));

    let statusbar = w::hbox(16);
    statusbar.add_css_class("status-bar");
    let shortcuts = gtk::Button::new();
    shortcuts.add_css_class("status-help");
    shortcuts.set_tooltip_text(Some("Show the keyboard shortcuts (F1)"));
    let help = w::hbox(10);
    help.append(&w::label("F1", "status-key"));
    help.append(&w::label("Shortcuts", ""));
    shortcuts.set_child(Some(&help));
    shortcuts.connect_clicked(|_| show_shortcuts());
    statusbar.append(&shortcuts);
    let status = w::label("", "status-readout");
    status.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    status.set_hexpand(true);
    status.set_xalign(1.0);
    statusbar.append(&status);
    let sync_button = chrome::status_action("view-refresh-symbolic", "Sync now (F5)", || {
        if let Some(ui) = current() {
            sync(&ui);
        }
    });
    sync_button.set_visible(false);
    statusbar.append(&sync_button);
    let lock_button = chrome::status_action("system-lock-screen-symbolic", "Lock the vault (Ctrl+L)", || {
        if let Some(ui) = current() {
            lock(&ui);
        }
    });
    lock_button.set_visible(false);
    statusbar.append(&lock_button);
    statusbar.append(&chrome::gear(open_settings));
    frame.append(&statusbar);

    let toast_box = w::hbox(10);
    toast_box.add_css_class("toast");
    toast_box.set_halign(gtk::Align::Center);
    toast_box.set_valign(gtk::Align::End);
    toast_box.set_margin_bottom(48);
    toast_box.set_visible(false);
    overlay.add_overlay(&toast_box);

    let start = section.map(str::to_string).unwrap_or_else(|| nixe_theme::start_page("all", &prefs::get().last_section));
    let ui = Rc::new(State {
        window,
        overlay,
        nav,
        head: head.root,
        sidebar,
        pages,
        account,
        toolbar,
        list,
        list_scroll,
        details,
        detail_scroll,
        search,
        status,
        lock_button,
        sync_button,
        toast_box,
        toast_serial: Cell::new(0),
        state: RefCell::new(String::new()),
        listing: RefCell::new(Listing::default()),
        section: RefCell::new(start),
        selected: RefCell::new(None),
        narrow: Cell::new(false),
        showing_detail: Cell::new(false),
        rebuilding: Cell::new(false),
        editor: RefCell::new(None),
        detail_serial: Cell::new(0),
    });
    UI.with(|u| *u.borrow_mut() = Some(ui.clone()));

    let u = ui.clone();
    new.connect_clicked(move |_| editor::open(&u, None));
    let u = ui.clone();
    head.toggle.connect_clicked(move |_| {
        prefs::update(|p| p.sidebar_collapsed = !p.sidebar_collapsed);
        layout(&u);
    });
    if let Some(b) = head.search {
        let u = ui.clone();
        b.connect_clicked(move |_| find(&u));
    }
    let u = ui.clone();
    ui.search.connect_search_changed(move |_| refresh_list(&u));
    let u = ui.clone();
    ui.list.connect_selected_rows_changed(move |list| {
        if u.rebuilding.get() {
            return;
        }
        *u.selected.borrow_mut() = list.selected_row().map(|r| r.widget_name().to_string());
        u.showing_detail.set(u.selected.borrow().is_some());
        detail::show(&u);
        layout(&u);
    });
    let u = ui.clone();
    let last_width = Cell::new(0);
    ui.window.add_tick_callback(move |win, _| {
        if last_width.replace(win.width()) != win.width() {
            layout(&u);
        }
        glib::ControlFlow::Continue
    });
    nixe_ui::keys::install(
        &ui.window,
        nixe_ui::keys::Common {
            settings: Some(open_settings),
            shortcuts: Some(show_shortcuts),
            close: true,
            ..Default::default()
        },
    );
    let keys = gtk::EventControllerKey::new();
    let u = ui.clone();
    keys.connect_key_pressed(move |_, key, _, mods| {
        let ctrl = mods.contains(gdk::ModifierType::CONTROL_MASK);
        let shift = mods.contains(gdk::ModifierType::SHIFT_MASK);
        let open = *u.state.borrow() == state::UNLOCKED;
        match key {
            gdk::Key::f | gdk::Key::F if ctrl && open => find(&u),
            gdk::Key::n | gdk::Key::N if ctrl && open => editor::open(&u, None),
            gdk::Key::l | gdk::Key::L if ctrl && open => lock(&u),
            gdk::Key::F5 if open => sync(&u),
            gdk::Key::b | gdk::Key::B if ctrl => {
                prefs::update(|p| p.sidebar_collapsed = !p.sidebar_collapsed);
                layout(&u);
            }
            gdk::Key::c | gdk::Key::C if ctrl && shift && open => detail::copy_selected(&u, "password"),
            gdk::Key::u | gdk::Key::U if ctrl && shift && open => detail::copy_selected(&u, "username"),
            gdk::Key::o | gdk::Key::O if ctrl && shift && open => detail::copy_selected(&u, "totp"),
            gdk::Key::F1 => show_shortcuts(),
            gdk::Key::Escape => {
                if nixe_ui::settings_card::is_open() {
                    nixe_ui::settings_card::escape();
                } else if u.search.is_visible() {
                    u.search.set_text("");
                    u.search.set_visible(false);
                } else {
                    u.showing_detail.set(false);
                    layout(&u);
                }
            }
            _ => return glib::Propagation::Proceed,
        }
        glib::Propagation::Stop
    });
    ui.window.add_controller(keys);
    let u = ui.clone();
    ui.window.connect_close_request(move |_| {
        if let Some(e) = u.editor.borrow().as_ref() {
            e.present();
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });

    refresh_state(&ui);
    watch_state(&ui);
    ui.window.present();
    if prefs::take_broken() {
        toast(&ui, "Settings couldn't be read. The original is kept as settings.toml.bak.");
    }
    #[cfg(debug_assertions)]
    super::snapshot::maybe(&ui, app);
    ui
}

/// Asks the daemon for its state and shows the matching page.
pub fn refresh_state(ui: &Ui) {
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        match client::status().await {
            Ok((st, _, _)) => set_state(&ui, &st),
            Err(e) => {
                set_state(&ui, "");
                account::unavailable(&ui, &e.to_string());
            }
        }
    });
}

/// Follows lock changes made elsewhere (the idle timer, `pw lock`, the screen locking).
fn watch_state(ui: &Ui) {
    let weak = Rc::downgrade(ui);
    glib::timeout_add_seconds_local(2, move || {
        let Some(ui) = weak.upgrade() else { return glib::ControlFlow::Break };
        if ui.window.is_visible() {
            glib::spawn_future_local(async move {
                if let Ok((st, _, _)) = client::status().await
                    && st != *ui.state.borrow()
                {
                    set_state(&ui, &st);
                }
            });
        }
        glib::ControlFlow::Continue
    });
}

pub fn set_state(ui: &Ui, st: &str) {
    let changed = *ui.state.borrow() != st;
    *ui.state.borrow_mut() = st.to_string();
    let open = st == state::UNLOCKED;
    // Nothing to navigate or search until the vault is open.
    ui.sidebar.set_visible(open);
    ui.lock_button.set_visible(open);
    ui.sync_button.set_visible(open);
    if open {
        ui.pages.set_visible_child_name("vault");
        reload(ui);
    } else {
        // Nothing of the vault stays in the window once it's locked.
        *ui.listing.borrow_mut() = Listing::default();
        *ui.selected.borrow_mut() = None;
        clear(&ui.details);
        clear(&ui.list);
        if let Some(e) = ui.editor.borrow_mut().take() {
            e.destroy();
        }
        ui.search.set_text("");
        ui.search.set_visible(false);
        ui.pages.set_visible_child_name("account");
        if changed || st.is_empty() {
            account::show(ui, st);
        }
        ui.status.set_text(match st {
            state::LOCKED => "Locked",
            state::LOGGED_OUT => "Not signed in",
            _ => "",
        });
        chrome::set_title(&ui.window, "Passwords", if st == state::LOCKED { "Locked" } else { "Sign in" });
    }
    nav(ui);
    layout(ui);
}

/// Fetches the listing again and redraws.
pub fn reload(ui: &Ui) {
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        match client::text("List", None).await {
            Ok(json) => {
                if let Ok(listing) = serde_json::from_str::<Listing>(&json) {
                    *ui.listing.borrow_mut() = listing;
                }
                refresh_list(&ui);
                nav(&ui);
                detail::show(&ui);
            }
            Err(e) if e.is(nixe_passwords_proto::Error::Locked) => set_state(&ui, state::LOCKED),
            Err(e) => toast(&ui, &e.to_string()),
        }
    });
}

pub fn sync(ui: &Ui) {
    let ui = ui.clone();
    ui.status.set_text("Syncing…");
    glib::spawn_future_local(async move {
        match client::call("Sync", None).await {
            Ok(_) => reload(&ui),
            Err(e) => {
                toast(&ui, &format!("Sync failed: {e}"));
                refresh_list(&ui);
            }
        }
    });
}

pub fn lock(ui: &Ui) {
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let _ = client::call("Lock", None).await;
        set_state(&ui, state::LOCKED);
    });
}

pub fn navigate(ui: &Ui, section: &str) {
    if section == "settings" {
        open_settings();
        return;
    }
    *ui.section.borrow_mut() = section.to_string();
    *ui.selected.borrow_mut() = None;
    ui.showing_detail.set(false);
    prefs::update(|p| p.last_section = section.to_string());
    refresh_list(ui);
    nav(ui);
    detail::show(ui);
}

/// The entries shown for the current section and search, in name order.
pub fn visible(ui: &Ui) -> Vec<data::Entry> {
    let section = ui.section.borrow().clone();
    let query = ui.search.text().to_string();
    ui.listing.borrow().entries.iter().filter(|e| e.in_section(&section) && e.matches(&query)).cloned().collect()
}

pub fn refresh_list(ui: &Ui) {
    ui.rebuilding.set(true);
    clear(&ui.list);
    let entries = visible(ui);
    let selected = ui.selected.borrow().clone().filter(|id| entries.iter().any(|e| e.id == *id));
    *ui.selected.borrow_mut() = selected.clone();
    for e in &entries {
        let row = gtk::ListBoxRow::new();
        row.set_widget_name(&e.id);
        let line = w::hbox(12);
        line.set_margin_top(8);
        line.set_margin_bottom(8);
        line.set_margin_start(14);
        line.set_margin_end(14);
        let icon = gtk::Image::from_icon_name(data::kind_icon(&e.kind));
        icon.add_css_class("dim");
        line.append(&icon);
        let text = w::vbox(2);
        text.set_hexpand(true);
        let name = gtk::Label::new(Some(if e.readable { &e.name } else { "Unreadable item" }));
        name.add_css_class("item-row-name");
        name.set_xalign(0.0);
        name.set_ellipsize(gtk::pango::EllipsizeMode::End);
        text.append(&name);
        let sub = gtk::Label::new(Some(&e.subtitle()));
        sub.add_css_class("dim");
        sub.add_css_class("item-row-description");
        sub.set_xalign(0.0);
        sub.set_ellipsize(gtk::pango::EllipsizeMode::End);
        text.append(&sub);
        line.append(&text);
        if e.favorite {
            let star = gtk::Image::from_icon_name("starred-symbolic");
            star.add_css_class("accent");
            line.append(&star);
        }
        row.set_child(Some(&line));
        ui.list.append(&row);
        if selected.as_deref() == Some(e.id.as_str()) {
            ui.list.select_row(Some(&row));
        }
    }
    if entries.is_empty() {
        let empty = w::vbox(12);
        empty.add_css_class("item-empty");
        empty.set_margin_top(80);
        empty.set_margin_start(20);
        empty.set_margin_end(20);
        empty.set_halign(gtk::Align::Center);
        let icon = gtk::Image::from_icon_name("dialog-password-symbolic");
        icon.set_pixel_size(32);
        icon.add_css_class("dim");
        empty.append(&icon);
        let message = if !ui.search.text().is_empty() {
            "No matching items."
        } else if *ui.section.borrow() == "trash" {
            "The trash is empty."
        } else {
            "No items here yet."
        };
        empty.append(&label(message, "dim"));
        let row = gtk::ListBoxRow::new();
        row.add_css_class("item-empty-row");
        row.set_selectable(false);
        row.set_activatable(false);
        row.set_child(Some(&empty));
        ui.list.append(&row);
    }
    ui.rebuilding.set(false);
    let listing = ui.listing.borrow();
    let count = listing.entries.iter().filter(|e| !e.deleted).count();
    let synced = listing.account.last_sync.map(|t| format!(" · synced {}", data::ago(t))).unwrap_or_default();
    if *ui.state.borrow() == state::UNLOCKED {
        ui.status.set_text(&format!("{count} items{synced}"));
    }
    drop(listing);
    layout(ui);
}

fn nav_button(icon: &str, title: &str, tooltip: &str) -> gtk::Button {
    let button = gtk::Button::new();
    button.add_css_class("nav-item");
    let content = w::hbox(12);
    content.append(&gtk::Image::from_icon_name(icon));
    let text = w::label(title, "nav-label");
    text.set_hexpand(true);
    text.set_xalign(0.0);
    text.set_ellipsize(gtk::pango::EllipsizeMode::End);
    text.add_css_class("compact-hide");
    content.append(&text);
    button.set_child(Some(&content));
    button.set_tooltip_text(Some(tooltip));
    button
}

fn nav_group(ui: &Ui, title: &str, first: bool) {
    let heading = w::label(&title.to_uppercase(), "nav-group");
    heading.add_css_class("compact-hide");
    if first {
        heading.add_css_class("first");
    }
    ui.nav.append(&heading);
}

/// A sidebar entry: section id, name, icon, item count.
type NavItem = (String, String, String, usize);

fn nav(ui: &Ui) {
    clear(&ui.nav);
    if *ui.state.borrow() != state::UNLOCKED {
        return;
    }
    let listing = ui.listing.borrow();
    let live = |f: &dyn Fn(&data::Entry) -> bool| listing.entries.iter().filter(|e| !e.deleted && f(e)).count();
    let mut groups: Vec<(&str, Vec<NavItem>)> = vec![(
        "Vault",
        vec![
            ("all".into(), "All items".into(), "view-list-symbolic".into(), live(&|_| true)),
            ("favorites".into(), "Favorites".into(), "starred-symbolic".into(), live(&|e| e.favorite)),
        ],
    )];
    let kinds: Vec<_> = data::KINDS
        .iter()
        .map(|(id, name, icon)| (id.to_string(), name.to_string(), icon.to_string(), live(&|e| e.kind == *id)))
        .filter(|(id, _, _, n)| *n > 0 || id == "login")
        .collect();
    groups.push(("Types", kinds));
    if !listing.folders.is_empty() {
        let mut folders: Vec<_> = listing
            .folders
            .iter()
            .map(|f| {
                let id = f.id.clone();
                (
                    format!("folder:{}", f.id),
                    f.name.clone(),
                    "folder-symbolic".into(),
                    live(&|e| e.folder.as_deref() == Some(&id)),
                )
            })
            .collect();
        folders.push((
            "nofolder".into(),
            "No folder".into(),
            "folder-symbolic".into(),
            live(&|e| e.folder.is_none() && e.organization.is_none()),
        ));
        groups.push(("Folders", folders));
    }
    if !listing.collections.is_empty() {
        let cols = listing
            .collections
            .iter()
            .map(|c| {
                let id = c.id.clone();
                (
                    format!("collection:{}", c.id),
                    c.name.clone(),
                    "system-users-symbolic".into(),
                    live(&|e| e.collections.contains(&id)),
                )
            })
            .collect();
        groups.push(("Collections", cols));
    }
    let trashed = listing.entries.iter().filter(|e| e.deleted).count();
    groups.push(("Other", vec![("trash".into(), "Trash".into(), "user-trash-symbolic".into(), trashed)]));
    drop(listing);
    let current = ui.section.borrow().clone();
    let mut title = None;
    for (i, (group, items)) in groups.into_iter().enumerate() {
        nav_group(ui, group, i == 0);
        for (id, name, icon, count) in items {
            let b = nav_button(&icon, &name, &name);
            let readout = w::label(&count.to_string(), "nav-readout");
            readout.add_css_class("compact-hide");
            if let Some(line) = b.child().and_downcast::<gtk::Box>() {
                line.append(&readout);
            }
            if id == current {
                b.add_css_class("active");
                title = Some(name.clone());
            }
            let u = ui.clone();
            b.connect_clicked(move |_| navigate(&u, &id));
            ui.nav.append(&b);
        }
    }
    match title {
        Some(t) => chrome::set_title(&ui.window, "Passwords", &t),
        // The section's folder or collection is gone: back to everything.
        None => {
            *ui.section.borrow_mut() = "all".into();
            chrome::set_title(&ui.window, "Passwords", "All items");
        }
    }
}

pub fn layout(ui: &Ui) {
    let width = if ui.window.width() > 0 { ui.window.width() } else { ui.window.default_width() };
    let narrow = width > 0 && width < 980;
    nixe_ui::settings_card::fit(&ui.window);
    ui.narrow.set(narrow);
    let compact = narrow || prefs::get().sidebar_collapsed;
    if compact {
        ui.sidebar.add_css_class("compact");
    } else {
        ui.sidebar.remove_css_class("compact");
    }
    chrome::set_head_compact(&ui.head, compact);
    fn hide(root: &gtk::Widget, compact: bool) {
        if root.has_css_class("nav-item")
            && let Some(content) = root.downcast_ref::<gtk::Button>().and_then(|b| b.child())
        {
            content.set_halign(if compact { gtk::Align::Center } else { gtk::Align::Fill });
        }
        if root.has_css_class("compact-hide") {
            root.set_visible(!compact);
        }
        let mut child = root.first_child();
        while let Some(c) = child {
            hide(&c, compact);
            child = c.next_sibling();
        }
    }
    hide(ui.nav.upcast_ref(), compact);
    let empty = visible(ui).is_empty();
    ui.toolbar.set_visible(*ui.section.borrow() != "trash");
    ui.list_scroll.set_hexpand(narrow || empty);
    ui.list_scroll.set_visible(empty || !narrow || !ui.showing_detail.get());
    ui.detail_scroll.set_visible(!empty && (!narrow || ui.showing_detail.get()));
    if let Some(back) = ui.details.first_child() {
        back.set_visible(narrow);
    }
    ui.list_scroll.set_width_request(if narrow || empty { -1 } else { 300 });
}

fn find(ui: &Ui) {
    ui.search.set_visible(true);
    ui.search.grab_focus();
}

fn install_icons() {
    let dir = nixe_core::paths::cache_dir().join("icons");
    let _ = std::fs::create_dir_all(&dir);
    for (name, svg) in [
        ("nixe-card-symbolic.svg", include_str!("../../data/icons/nixe-card-symbolic.svg")),
        ("nixe-key-symbolic.svg", include_str!("../../data/icons/nixe-key-symbolic.svg")),
    ] {
        let _ = std::fs::write(dir.join(name), svg);
    }
    if let Some(display) = gdk::Display::default() {
        gtk::IconTheme::for_display(&display).add_search_path(&dir);
    }
}

/// Empties a box or a list.
pub fn clear(b: &impl IsA<gtk::Widget>) {
    let b = b.upcast_ref::<gtk::Widget>();
    if let Some(list) = b.downcast_ref::<gtk::ListBox>() {
        list.remove_all();
    } else if let Some(bx) = b.downcast_ref::<gtk::Box>() {
        while let Some(c) = bx.first_child() {
            bx.remove(&c);
        }
    }
}

pub fn label(text: &str, class: &str) -> gtk::Label {
    let l = w::label(text, class);
    l.set_xalign(0.0);
    l.set_wrap(true);
    l
}

pub fn scroll(child: &impl IsA<gtk::Widget>) -> gtk::ScrolledWindow {
    gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::External)
        .vexpand(true)
        .child(child)
        .build()
}

pub fn toast(ui: &Ui, text: &str) {
    toast_action(ui, text, None);
}

pub type ToastAction<'a> = Option<(&'a str, Box<dyn Fn()>)>;

pub fn toast_action(ui: &Ui, text: &str, action: ToastAction<'_>) {
    clear(&ui.toast_box);
    let l = label(text, "");
    l.set_max_width_chars(65);
    ui.toast_box.append(&l);
    let has_action = action.is_some();
    if let Some((name, run)) = action {
        let b = gtk::Button::with_label(name);
        let u = ui.clone();
        b.connect_clicked(move |_| {
            run();
            u.toast_box.set_visible(false);
        });
        ui.toast_box.append(&b);
    }
    ui.toast_box.set_visible(true);
    let serial = ui.toast_serial.get() + 1;
    ui.toast_serial.set(serial);
    let weak = Rc::downgrade(ui);
    let shown = if has_action { Duration::from_secs(6) } else { Duration::from_millis(3500) };
    glib::timeout_add_local_once(shown, move || {
        if let Some(u) = weak.upgrade()
            && u.toast_serial.get() == serial
        {
            u.toast_box.set_visible(false);
        }
    });
}

pub const SHORTCUTS: &[(&[&str], &str)] = &[
    (&["Ctrl", "N"], "New login"),
    (&["Ctrl", "F"], "Search the vault"),
    (&["Ctrl", "Shift", "U"], "Copy the username"),
    (&["Ctrl", "Shift", "C"], "Copy the password"),
    (&["Ctrl", "Shift", "O"], "Copy the one-time code"),
    (&["Ctrl", "S"], "Save in the editor"),
    (&["Ctrl", "L"], "Lock the vault"),
    (&["F5"], "Sync now"),
    (&["Ctrl", "B"], "Collapse sidebar"),
    (&["Ctrl", ","], "Settings"),
    (&["Ctrl", "Shift", "P"], "Command palette"),
    (&["Esc"], "Close search, card, or return to the list"),
    (&["F1"], "Show these shortcuts (or ?)"),
    (&["Ctrl", "Q"], "Quit Passwords"),
    (&["Ctrl", "W"], "Close window"),
];

pub fn show_shortcuts() {
    let (dialog, card) = w::dialog("Keyboard shortcuts", 520);
    let list = w::vbox(0);
    list.add_css_class("group-list");
    for (keys, action) in SHORTCUTS {
        list.append(&w::row(action, "", Some(w::key_caps(keys).upcast_ref())));
    }
    let scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::External)
        .propagate_natural_height(true)
        .max_content_height(560)
        .child(&list)
        .build();
    card.append(&scroll);
    let close = gtk::Button::with_label("Close");
    close.set_tooltip_text(Some("Close shortcuts (Esc)"));
    close.set_halign(gtk::Align::End);
    let d = dialog.clone();
    close.connect_clicked(move |_| d.close());
    card.append(&close);
    dialog.present();
}

pub fn open_settings() {
    if let Some(ui) = current() {
        settings::open(&ui);
    }
}
