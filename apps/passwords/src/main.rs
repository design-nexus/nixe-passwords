//! Nyx Passwords: the window. The vault itself lives in `nyx-passwordsd`.

mod app;

use gtk::{gio, glib, prelude::*};

fn main() -> glib::ExitCode {
    nyx_core::app::init(nyx_passwords::daemon::APP);
    let args: Vec<_> = std::env::args().collect();
    if args.iter().any(|s| s == "--help" || s == "-h") {
        println!("Usage: nyx-passwords [--unlock] [--section all|favorites|login|note|card|identity|trash|settings]");
        return glib::ExitCode::SUCCESS;
    }
    if std::env::var_os("GSK_RENDERER").is_none() {
        // SAFETY: set before any thread starts.
        unsafe { std::env::set_var("GSK_RENDERER", "ngl") };
    }
    // NYX_PASSWORDS_APP_ID runs a test copy beside the real one (its own window class).
    let id = std::env::var("NYX_PASSWORDS_APP_ID").unwrap_or_else(|_| "io.github.design_nexus.nyx.Passwords".into());
    let app = gtk::Application::builder()
        .application_id(id)
        .flags(gio::ApplicationFlags::HANDLES_COMMAND_LINE)
        .build();
    app.connect_command_line(|app, cl| {
        let argv: Vec<String> = cl.arguments().iter().map(|s| s.to_string_lossy().into_owned()).collect();
        let section = argv.iter().position(|s| s == "--section").and_then(|i| argv.get(i + 1)).cloned();
        // --unlock (from Glimpse) just brings the window up: it opens on the unlock page
        // while the vault is locked.
        app::ui::present(app, section.as_deref());
        glib::ExitCode::SUCCESS
    });
    app.connect_shutdown(|_| app::prefs::flush());
    app.run()
}
