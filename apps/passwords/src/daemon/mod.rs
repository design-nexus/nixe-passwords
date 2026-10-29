//! `nyx-passwordsd`: holds the vault's keys and serves the app, Glimpse and the
//! Settings page over a private socket (docs/ARCHITECTURE.md).

mod browser;
mod clipboard;
mod extension;
pub use extension::theme as extension_theme;
mod icons;
mod notify;
pub mod peer;
mod service;
pub mod settings;
mod vault;
mod watch;

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use futures_util::StreamExt;
use nyx_core::{app, paths};
use nyx_passwords_core::store::Store;
use nyx_passwords_proto as proto;
use tokio::net::UnixListener;

use self::service::Service;
use self::vault::Vault;

pub const APP: app::App = app::App { slug: "nyx-passwords", name: "Passwords" };

/// The exit status after an update replaced the binary; the unit starts it again on that
/// (`RestartForceExitStatus`).
const UPDATED: i32 = 75;

/// The binary's path and the file this daemon runs from, as at start.
static BINARY: OnceLock<Option<(PathBuf, (u64, u64))>> = OnceLock::new();
static RESTART: tokio::sync::Notify = tokio::sync::Notify::const_new();

fn file_id(path: &Path) -> Option<(u64, u64)> {
    fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

/// Whether an update has put a new binary where this daemon was started from.
pub fn replaced() -> bool {
    let Some(Some((path, running))) = BINARY.get() else { return false };
    file_id(path).is_some_and(|now| now != *running)
}

/// Stops the daemon (locking first) so that it starts again on the new binary.
pub fn restart() {
    RESTART.notify_one();
}

pub fn run() -> ! {
    app::init(APP);
    harden();
    BINARY.get_or_init(|| Some((std::env::current_exe().ok()?, file_id(Path::new("/proc/self/exe"))?)));
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("tokio runtime");
    let code = runtime.block_on(serve());
    std::process::exit(code)
}

/// Private files, no core dumps, and no ptrace or /proc/<pid>/mem access by other
/// processes of the user (PR_SET_DUMPABLE also covers that with Yama's ptrace_scope).
fn harden() {
    // SAFETY: plain syscalls with constant arguments.
    unsafe {
        libc::umask(0o077);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
    }
}

async fn serve() -> i32 {
    let Some(socket) = proto::socket_path() else {
        eprintln!("nyx-passwordsd: XDG_RUNTIME_DIR isn't set");
        return 1;
    };
    let dir = socket.parent().expect("socket has a directory").to_path_buf();
    if fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).is_err()
        || fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).is_err()
    {
        eprintln!("nyx-passwordsd: couldn't create {}", dir.display());
        return 1;
    }
    let Some(_instance) = single_instance(&dir) else {
        eprintln!("nyx-passwordsd: already running");
        return 0;
    };
    let _ = fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("nyx-passwordsd: couldn't listen on {}: {e}", socket.display());
            return 1;
        }
    };
    let _ = fs::set_permissions(&socket, fs::Permissions::from_mode(0o600));
    let Some(allowed) = peer::allowed_dir() else { return 1 };

    let store = match Store::open(&paths::data_dir().join("vault.sqlite")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("nyx-passwordsd: {e}");
            return 1;
        }
    };
    let settings = settings::Watched::new(paths::prefs_file());
    let vault = Arc::new(Vault::new(store, settings, notify::Notifier::default()));
    watch::spawn_all(&vault);

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
    let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).expect("SIGINT handler");
    let code = loop {
        tokio::select! {
            accepted = listener.accept() => {
                if let Ok((stream, _)) = accepted {
                    tokio::spawn(connection(stream, vault.clone(), allowed.clone()));
                }
            }
            _ = term.recv() => break 0,
            _ = int.recv() => break 0,
            _ = RESTART.notified() => {
                eprintln!("nyx-passwordsd: updated; starting again on the new build");
                break UPDATED;
            }
        }
    };
    // Stopping locks: keys dropped, a copy still on the clipboard cleared.
    vault.lock().await;
    let _ = fs::remove_file(&socket);
    code
}

/// Serves one peer until it disconnects. A peer that isn't one of ours is closed
/// before a single message is read.
async fn connection(stream: tokio::net::UnixStream, vault: Arc<Vault>, allowed: PathBuf) {
    let Some(peer) = peer::identify(stream.as_raw_fd(), &allowed) else { return };
    let service = Service { vault, scope: peer.scope, browser: peer.browser, pid: peer.pid };
    let built = async {
        zbus::connection::Builder::unix_stream(stream)
            .server(zbus::Guid::generate())?
            .p2p()
            .serve_at(proto::OBJECT_PATH, service)?
            .build()
            .await
    };
    let Ok(conn) = built.await else { return };
    // The connection serves calls in the background; keep it until the peer hangs up.
    let mut messages = zbus::MessageStream::from(&conn);
    while messages.next().await.is_some() {}
}

/// Holds a lock file for as long as the daemon runs.
fn single_instance(dir: &Path) -> Option<fs::File> {
    let file = fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("daemon.lock")).ok()?;
    // SAFETY: flock on a descriptor we own.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    (rc == 0).then_some(file)
}
