//! Calls to the vault daemon over its private socket (gio's D-Bus, on the GLib main
//! loop), for the Passwords window and Glimpse. The daemon checks which program is
//! calling before it answers; this side only talks.

use std::cell::RefCell;
use std::path::PathBuf;
use std::time::Duration;

use gio::glib::{self, prelude::*};
use gio::prelude::UnixFDListExtManual;

use crate::{Error, INTERFACE, OBJECT_PATH, SERVICE, address};

/// A failed call: the daemon's error kind when it sent one, and its message.
#[derive(Debug, Clone)]
pub struct Fail {
    pub code: Option<Error>,
    pub message: String,
    /// The daemon doesn't have the method: it's an older build than this program.
    pub unknown_method: bool,
}

impl Fail {
    fn local(message: &str) -> Fail {
        Fail { code: None, message: message.into(), unknown_method: false }
    }

    pub fn is(&self, code: Error) -> bool {
        self.code == Some(code)
    }

    /// The daemon couldn't be reached or started.
    pub fn unreachable(&self) -> bool {
        self.code.is_none() && !self.unknown_method
    }
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut chars = self.message.chars();
        match chars.next() {
            Some(first) => write!(f, "{}{}", first.to_uppercase(), chars.as_str()),
            None => f.write_str("Something went wrong"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Fail>;

thread_local! {
    static CONN: RefCell<Option<gio::DBusConnection>> = const { RefCell::new(None) };
}

/// Calls `method` with `args` (a tuple variant, or `None` for no arguments).
pub async fn call(method: &str, args: Option<glib::Variant>) -> Result<glib::Variant> {
    for attempt in 0..2 {
        let conn = connection().await?;
        let reply = conn
            .call_future(
                None,
                OBJECT_PATH,
                INTERFACE,
                method,
                args.as_ref(),
                None,
                gio::DBusCallFlags::NONE,
                // Signing in runs the key derivation and a sync: give it time.
                180_000,
            )
            .await;
        match reply {
            Ok(v) => return Ok(v),
            // The daemon restarted: connect again once.
            Err(_) if attempt == 0 && conn.is_closed() => CONN.with(|c| *c.borrow_mut() = None),
            Err(e) => return Err(fail(e)),
        }
    }
    Err(Fail::local("Nyx Passwords' service isn't answering"))
}

/// Calls `method` with string arguments followed by a file (a D-Bus handle): the
/// daemon reads or writes the file itself, so its contents never pass through here.
pub async fn call_with_file(method: &str, args: &[&str], file: std::os::fd::OwnedFd) -> Result<glib::Variant> {
    let conn = connection().await?;
    let files = gio::UnixFDList::new();
    let handle = files.append(&file).map_err(fail)?;
    let mut params: Vec<glib::Variant> = args.iter().map(|a| a.to_variant()).collect();
    params.push(glib::variant::Handle(handle).to_variant());
    let reply = conn
        .call_with_unix_fd_list_future(
            None,
            OBJECT_PATH,
            INTERFACE,
            method,
            Some(&glib::Variant::tuple_from_iter(params)),
            None,
            gio::DBusCallFlags::NONE,
            // Attachments can be large: give the transfer time.
            600_000,
            Some(&files),
        )
        .await;
    reply.map(|(v, _)| v).map_err(fail)
}

/// A string reply.
pub async fn text(method: &str, args: Option<glib::Variant>) -> Result<String> {
    let v = call(method, args).await?;
    v.get::<(String,)>().map(|(s,)| s).ok_or_else(|| Fail::local("unexpected answer"))
}

/// `(state, server host, seconds a copy stays on the clipboard)`.
pub async fn status() -> Result<(String, String, u32)> {
    let v = call("Status", None).await?;
    v.get::<(String, String, u32)>().ok_or_else(|| Fail::local("unexpected answer"))
}

/// Puts a field on the clipboard; the seconds until it's cleared.
pub async fn copy(id: &str, field: &str) -> Result<u32> {
    let v = call("Copy", Some((id, field).to_variant())).await?;
    v.get::<(u32,)>().map(|(s,)| s).ok_or_else(|| Fail::local("unexpected answer"))
}

pub async fn reveal(id: &str, field: &str) -> Result<String> {
    text("Reveal", Some((id, field).to_variant())).await
}

/// The current one-time code: `(code, period, seconds left)`.
pub async fn totp(id: &str) -> Result<(String, u32, u32)> {
    let v = call("Totp", Some((id,).to_variant())).await?;
    v.get::<(String, u32, u32)>().ok_or_else(|| Fail::local("unexpected answer"))
}

/// `Search` (or `Suggest` for an empty query): the items and, for `Suggest`, the
/// trusted site's host (empty when there's none).
pub async fn search(query: &str, limit: u32) -> Result<(String, Vec<crate::Item>)> {
    if query.trim().is_empty() {
        let v = call("Suggest", Some((limit,).to_variant())).await?;
        return v.get::<(String, Vec<crate::Item>)>().ok_or_else(|| Fail::local("unexpected answer"));
    }
    let v = call("Search", Some((query, limit).to_variant())).await?;
    v.get::<(Vec<crate::Item>,)>().map(|(items,)| (String::new(), items)).ok_or_else(|| Fail::local("unexpected answer"))
}

/// Whether the daemon is installed for this user (its systemd unit).
pub fn installed() -> bool {
    unit().exists()
}

fn unit() -> PathBuf {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_default();
    config.join("systemd/user").join(SERVICE)
}

fn fail(e: glib::Error) -> Fail {
    let name = gio::DBusError::remote_error(&e);
    let code = name.as_deref().and_then(Error::from_name);
    let unknown_method = name.as_deref() == Some("org.freedesktop.DBus.Error.UnknownMethod");
    let mut e = e;
    gio::DBusError::strip_remote_error(&mut e);
    Fail { code, message: e.message().to_string(), unknown_method }
}

async fn connection() -> Result<gio::DBusConnection> {
    if let Some(c) = CONN.with(|c| c.borrow().clone()).filter(|c| !c.is_closed()) {
        return Ok(c);
    }
    let address = address().ok_or_else(|| Fail::local("XDG_RUNTIME_DIR isn't set"))?;
    let flags = gio::DBusConnectionFlags::AUTHENTICATION_CLIENT;
    for attempt in 0..40 {
        match gio::DBusConnection::for_address_future(&address, flags, None).await {
            Ok(c) => {
                CONN.with(|slot| *slot.borrow_mut() = Some(c.clone()));
                return Ok(c);
            }
            Err(_) => {
                if attempt == 0 && !start_daemon() {
                    return Err(Fail::local("Nyx Passwords isn't installed"));
                }
                glib::timeout_future(Duration::from_millis(100)).await;
            }
        }
    }
    Err(Fail::local("couldn't start Nyx Passwords' service"))
}

/// Starts the daemon: through its systemd unit when installed, otherwise the one next
/// to this binary (a build in a checkout). False when there's neither.
fn start_daemon() -> bool {
    if installed() {
        return std::process::Command::new("systemctl")
            .args(["--user", "start", SERVICE])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok();
    }
    let Some(sibling) = std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join("nyx-passwordsd"))) else {
        return false;
    };
    sibling.exists()
        && std::process::Command::new(sibling)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
}
