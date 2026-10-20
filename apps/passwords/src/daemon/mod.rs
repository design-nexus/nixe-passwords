//! `nixe-passwordsd`: holds the vault's keys and serves the app, Glimpse and the
//! Settings page over a private socket (docs/ARCHITECTURE.md).

mod browser;
mod clipboard;
mod notify;
pub mod peer;
mod service;
pub mod settings;
mod vault;
mod watch;

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures_util::StreamExt;
use nixe_core::{app, paths};
use nixe_passwords_core::store::Store;
use nixe_passwords_proto as proto;
use tokio::net::UnixListener;

use self::service::Service;
use self::vault::Vault;

pub const APP: app::App = app::App { slug: "nixe-passwords", name: "Passwords" };

pub fn run() -> ! {
    app::init(APP);
    harden();
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
        eprintln!("nixe-passwordsd: XDG_RUNTIME_DIR isn't set");
        return 1;
    };
    let dir = socket.parent().expect("socket has a directory").to_path_buf();
    if fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).is_err()
        || fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).is_err()
    {
        eprintln!("nixe-passwordsd: couldn't create {}", dir.display());
        return 1;
    }
    let Some(_instance) = single_instance(&dir) else {
        eprintln!("nixe-passwordsd: already running");
        return 0;
    };
    let _ = fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("nixe-passwordsd: couldn't listen on {}: {e}", socket.display());
            return 1;
        }
    };
    let _ = fs::set_permissions(&socket, fs::Permissions::from_mode(0o600));
    let Some(allowed) = peer::allowed_dir() else { return 1 };

    let store = match Store::open(&paths::data_dir().join("vault.sqlite")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("nixe-passwordsd: {e}");
            return 1;
        }
    };
    let settings = settings::Watched::new(paths::prefs_file());
    let vault = Arc::new(Vault::new(store, settings, notify::Notifier::default()));
    watch::spawn_all(&vault);

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
    let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).expect("SIGINT handler");
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                if let Ok((stream, _)) = accepted {
                    tokio::spawn(connection(stream, vault.clone(), allowed.clone()));
                }
            }
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }
    // Stopping locks: keys dropped, a copy still on the clipboard cleared.
    vault.lock().await;
    let _ = fs::remove_file(&socket);
    0
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
