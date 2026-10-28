//! The window: the shared header, then the sidebar, item list and details while the
//! vault is open; the sign-in or unlock page otherwise (Nyx Design 2.0, STYLE.md).

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use gtk::{gdk, glib, prelude::*};
use nyx_passwords_proto::state;
use nyx_ui::{chrome, widgets as w};

use super::data::{self, Listing};
use super::{account, client, detail, editor, prefs, security, settings, theme};

pub type Ui = Rc<State>;

pub struct State {
    pub window: gtk::ApplicationWindow,
    pub overlay: gtk::Overlay,
    nav: gtk::Box,
    header: chrome::AppHeader,
    collapse: gtk::Button,
    new_button: gtk::Button,
    sidebar: gtk::Box,
    /// "account" (sign in, unlock) or "vault".
    pages: gtk::Stack,
    pub account: gtk::Box,
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
    pub editor: RefCell<Option<editor::Sheet>>,
    /// Bumped whenever details are rebuilt, so timers from older ones stop.
    pub detail_serial: Cell<u64>,
    /// The security report (`security.rs`), and its header action.
    pub security: RefCell<security::Report>,
    security_bar: gtk::Box,
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
    window.set_icon_name(Some("io.github.design_nexus.nyx.Passwords"));
    window.set_titlebar(Some(&w::hbox(0)));
    chrome::set_title(&window, "Passwords", "");
    let overlay = gtk::Overlay::new();
    let frame = w::vbox(0);
    frame.add_css_class("window-frame");

    // The app and the section, the sidebar toggle; search in the middle; the item count
    // and sync, lock, new item and Settings at the end.
    let header = chrome::app_header(&window, "nyx-key-symbolic", "Passwords");
    let collapse = w::bar_button("sidebar-show-symbolic", "Collapse the sidebar (Ctrl+B)");
    header.start.append(&collapse);
    let search = gtk::SearchEntry::new();
    search.set_placeholder_text(Some("Search the vault (Ctrl+F)"));
    search.add_css_class("bar-search");
    // A small minimum keeps the header narrow enough for a half-screen tile.
    search.set_width_chars(8);
    search.set_max_width_chars(SEARCH_WIDE);
    header.center.append(&search);
    header.end.set_spacing(4);
    let status = w::label("", "header-status");
    status.set_ellipsize(gtk::pango::EllipsizeMode::End);
    status.set_max_width_chars(26);
    status.set_margin_end(4);
    header.end.append(&status);
    let sync_button = w::bar_button("view-refresh-symbolic", "Sync now (F5)");
    sync_button.connect_clicked(|_| {
        if let Some(ui) = current() {
            sync(&ui);
        }
    });
    sync_button.set_visible(false);
    // The Security section's breach check, filled in once the state exists.
    let security_bar = w::hbox(0);
    header.end.append(&security_bar);
    header.end.append(&sync_button);
    let lock_button = w::bar_button("system-lock-screen-symbolic", "Lock the vault (Ctrl+L)");
    lock_button.connect_clicked(|_| {
        if let Some(ui) = current() {
            lock(&ui);
        }
    });
    lock_button.set_visible(false);
    header.end.append(&lock_button);
    let new = w::bar_button("list-add-symbolic", "New item (Ctrl+N)");
    new.set_visible(false);
    header.end.append(&new);
    header.end.append(&chrome::settings_button(open_settings));
    frame.append(&header.root);

    let body = w::hbox(0);
    body.set_vexpand(true);
    frame.append(&body);
    overlay.set_child(Some(&frame));
    window.set_child(Some(&overlay));

    let sidebar = w::vbox(0);
    sidebar.set_hexpand(false); // Required: expanding labels must not expand the sidebar.
    sidebar.add_css_class("settings-navigation");
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
        .child(&nyx_ui::clamp::Clamp::new(&details, 920))
        .build();
    detail_scroll.add_css_class("item-detail-pane");
    panes.append(&detail_scroll);
    pages.add_named(&vault, Some("vault"));


    let toast_box = w::hbox(10);
    toast_box.add_css_class("toast");
    toast_box.set_halign(gtk::Align::Center);
    toast_box.set_valign(gtk::Align::End);
    toast_box.set_margin_bottom(48);
    toast_box.set_visible(false);
    overlay.add_overlay(&toast_box);

    let start = section.map(str::to_string).unwrap_or_else(|| nyx_theme::start_page("all", &prefs::get().last_section));
    let ui = Rc::new(State {
        window,
        overlay,
        nav,
        header,
        collapse: collapse.clone(),
        new_button: new.clone(),
        sidebar,
        pages,
        account,
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
        security: RefCell::new(security::Report::default()),
        security_bar,
    });
    ui.security_bar.append(&security::toolbar(&ui));
    UI.with(|u| *u.borrow_mut() = Some(ui.clone()));

    let u = ui.clone();
    new.connect_clicked(move |_| editor::open(&u, None));
    let u = ui.clone();
    collapse.connect_clicked(move |_| {
        prefs::update(|p| p.sidebar_collapsed = !p.sidebar_collapsed);
        layout(&u);
    });
    let u = ui.clone();
    ui.search.connect_search_changed(move |_| refresh_list(&u));
    // Enter opens the first match; Down moves into the list.
    let u = ui.clone();
    ui.search.connect_activate(move |_| {
        if let Some(row) = u.list.row_at_index(0).filter(|r| r.is_selectable()) {
            u.list.select_row(Some(&row));
            u.showing_detail.set(true);
            layout(&u);
        }
    });
    let keys = gtk::EventControllerKey::new();
    let u = ui.clone();
    keys.connect_key_pressed(move |_, key, _, _| {
        if key == gdk::Key::Down
            && let Some(row) = u.list.row_at_index(0)
        {
            row.grab_focus();
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });
    ui.search.add_controller(keys);
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
    nyx_ui::keys::install(
        &ui.window,
        nyx_ui::keys::Common {
            settings: Some(open_settings),
            shortcuts: Some(show_shortcuts),
            close: true,
            ..Default::default()
        },
    );
    let keys = gtk::EventControllerKey::new();
    let u = ui.clone();
    keys.connect_key_pressed(move |_, key, _, mods| {
        // The editor's own keys (Ctrl+S, Esc) only while it's open.
        if u.editor.borrow().is_some() {
            return glib::Propagation::Proceed;
        }
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
                if nyx_ui::settings_card::is_open() {
                    nyx_ui::settings_card::escape();
                } else if !u.search.text().is_empty() {
                    u.search.set_text("");
                    u.search.grab_focus();
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
    refresh_state(&ui);
    watch_state(&ui);
    ui.window.present();
    if prefs::take_broken() {
        toast(&ui, "Settings couldn't be read. The original is kept as settings.toml.bak.");
    }
    #[cfg(debug_assertions)]
    super::fixture::maybe(&ui);
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
                // A browser asking to pair shows here, while the vault is open.
                if *ui.state.borrow() == state::UNLOCKED {
                    super::pairing::check(&ui);
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
    ui.collapse.set_visible(open);
    ui.search.set_visible(open);
    ui.lock_button.set_visible(open);
    ui.sync_button.set_visible(open);
    ui.new_button.set_visible(open);
    if open {
        ui.pages.set_visible_child_name("vault");
        reload(ui);
        ui.search.grab_focus();
    } else {
        // Nothing of the vault stays in the window once it's locked.
        *ui.listing.borrow_mut() = Listing::default();
        *ui.security.borrow_mut() = security::Report::default();
        *ui.selected.borrow_mut() = None;
        clear(&ui.details);
        clear(&ui.list);
        let editor = ui.editor.borrow_mut().take();
        if let Some(e) = editor {
            e.close();
        }
        ui.search.set_text("");
        ui.pages.set_visible_child_name("account");
        if changed || st.is_empty() {
            account::show(ui, st);
        }
        // The subtitle says locked or signed out; the readout is for the open vault.
        ui.status.set_text("");
        set_subtitle(ui, if st == state::LOCKED { "Locked" } else { "Sign in" });
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
                security::refresh(&ui);
            }
            Err(e) if e.is(nyx_passwords_proto::Error::Locked) => set_state(&ui, state::LOCKED),
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
    ui.search.grab_focus();
}

/// The entries shown for the current section and search, in name order.
pub fn visible(ui: &Ui) -> Vec<data::Entry> {
    let section = ui.section.borrow().clone();
    let query = ui.search.text().to_string();
    let report = ui.security.borrow();
    let shown = |e: &data::Entry| if section == "security" { report.flags(e) } else { e.in_section(&section) };
    ui.listing.borrow().entries.iter().filter(|e| shown(e) && e.matches(&query)).cloned().collect()
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
        let subtitle = if *ui.section.borrow() == "security" { ui.security.borrow().describe(e) } else { e.subtitle() };
        let sub = gtk::Label::new(Some(&subtitle));
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
        } else if *ui.section.borrow() == "security" {
            "No weak, reused or old passwords."
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

pub fn nav(ui: &Ui) {
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
    let flagged = listing.entries.iter().filter(|e| ui.security.borrow().flags(e)).count();
    groups.push((
        "Other",
        vec![
            ("security".into(), "Security".into(), "security-high-symbolic".into(), flagged),
            ("trash".into(), "Trash".into(), "user-trash-symbolic".into(), trashed),
        ],
    ));
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
        Some(t) => set_subtitle(ui, &t),
        // The section's folder or collection is gone: back to everything.
        None => {
            *ui.section.borrow_mut() = "all".into();
            set_subtitle(ui, "All items");
        }
    }
    compact_sidebar(ui);
}

const SEARCH_WIDE: i32 = 28;
const SEARCH_NARROW: i32 = 14;

pub fn layout(ui: &Ui) {
    let width = if ui.window.width() > 0 { ui.window.width() } else { ui.window.default_width() };
    let narrow = width > 0 && width < 980;
    nyx_ui::settings_card::fit(&ui.window);
    ui.narrow.set(narrow);
    // The centred search mustn't reach the sidebar toggle or the actions beside it.
    ui.search.set_max_width_chars(if narrow { SEARCH_NARROW } else { SEARCH_WIDE });
    compact_sidebar(ui);
    let empty = visible(ui).is_empty();
    let open = *ui.state.borrow() == state::UNLOCKED;
    ui.security_bar.set_visible(open && *ui.section.borrow() == "security");
    ui.new_button.set_visible(open && *ui.section.borrow() != "trash");
    ui.list_scroll.set_hexpand(narrow || empty);
    ui.list_scroll.set_visible(empty || !narrow || !ui.showing_detail.get());
    ui.detail_scroll.set_visible(!empty && (!narrow || ui.showing_detail.get()));
    if let Some(back) = ui.details.first_child() {
        back.set_visible(narrow);
    }
    ui.list_scroll.set_width_request(if narrow || empty { -1 } else { 300 });
}

/// Puts the sidebar in its icon-only form (narrow window, or collapsed) or its full one.
/// Runs after every rebuild of the sidebar too, or new buttons would show their labels
/// in the narrow column.
fn compact_sidebar(ui: &Ui) {
    let compact = ui.narrow.get() || prefs::get().sidebar_collapsed;
    if compact {
        ui.sidebar.add_css_class("compact");
    } else {
        ui.sidebar.remove_css_class("compact");
    }
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
}

/// The section (or the lock state) beside the app name, and in the window title.
fn set_subtitle(ui: &Ui, text: &str) {
    ui.header.set_subtitle(text);
    chrome::set_title(&ui.window, "Passwords", text);
}

fn find(ui: &Ui) {
    ui.search.grab_focus();
    ui.search.select_region(0, -1);
}

fn install_icons() {
    let dir = nyx_core::paths::cache_dir().join("icons");
    let _ = std::fs::create_dir_all(&dir);
    for (name, svg) in [
        ("nyx-card-symbolic.svg", include_str!("../../data/icons/nyx-card-symbolic.svg")),
        ("nyx-key-symbolic.svg", include_str!("../../data/icons/nyx-key-symbolic.svg")),
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

/// Puts the toast back above overlays added after it (the editor), so it stays visible.
pub fn raise_toast(ui: &Ui) {
    ui.overlay.remove_overlay(&ui.toast_box);
    ui.overlay.add_overlay(&ui.toast_box);
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
    (&["Ctrl", "N"], "New item"),
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
    (&["Esc"], "Clear the search, close a card, or return to the list"),
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
