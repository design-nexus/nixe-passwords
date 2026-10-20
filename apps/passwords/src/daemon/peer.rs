//! Who is on the other end of a socket connection, and what it may ask for.
//!
//! The kernel gives the connecting process's uid and a pidfd (SO_PEERCRED,
//! SO_PEERPIDFD). The pidfd pins that exact process: its pid is read before and after
//! resolving `/proc/<pid>/exe`, so a process that exited (and whose pid was reused) in
//! between is refused. The executable must be one of the suite's, installed next to
//! the daemon. This keeps unrelated programs out; it can't stop a process of the same
//! user that runs one of those programs itself (see docs/SECURITY.md).

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

/// What a peer may do; see docs/GLIMPSE_API.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The Passwords window: everything, including reveal, edits and signing in.
    App,
    /// Glimpse: status, search, copy (into the clipboard, never back), open, generate, lock.
    Glimpse,
    /// The Settings page: status, lock, sync.
    Settings,
    /// The browser bridge: sealed messages from a paired extension (`Relay`) only.
    Browser,
}

/// The executables allowed to connect, by file name, and their scopes.
const PEERS: &[(&str, Scope)] = &[
    ("nixe-passwords", Scope::App),
    ("nixe-glimpse", Scope::Glimpse),
    ("nixe-passwords-settings", Scope::Settings),
    ("nixe-passwords-bridge", Scope::Browser),
];

/// Browsers that start the bridge, by executable name, and what they're called in the
/// pairing list.
const BROWSERS: &[(&str, &str)] = &[
    ("firefox", "Firefox"),
    ("firefox-bin", "Firefox"),
    ("zen", "Zen"),
    ("zen-bin", "Zen"),
    ("chromium", "Chromium"),
    ("chrome", "Chrome"),
    ("brave", "Brave"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub pid: i32,
    pub scope: Scope,
    /// For the bridge: the browser that started it (its pid and name).
    pub browser: Option<(i32, String)>,
}

/// Identifies the process behind `fd`, or `None` if it isn't one of ours.
pub fn identify(fd: RawFd, allowed_dir: &Path) -> Option<Peer> {
    let uid = peer_uid(fd)?;
    // SAFETY: getuid has no preconditions.
    if uid != unsafe { libc::getuid() } {
        return None;
    }
    let pidfd = peer_pidfd(fd)?;
    let before = pidfd_pid(&pidfd)?;
    let exe = std::fs::read_link(format!("/proc/{before}/exe")).ok()?;
    let after = pidfd_pid(&pidfd)?;
    if before != after {
        return None;
    }
    let scope = scope_of(&exe, allowed_dir)?;
    // The bridge counts only when a browser started it. Pairing, not this check, is
    // what authenticates an extension; this keeps other programs off the bridge.
    let browser = match scope {
        Scope::Browser => Some(browser_parent(before)?),
        _ => None,
    };
    if pidfd_pid(&pidfd)? != before {
        return None;
    }
    Some(Peer { pid: before, scope, browser })
}

/// The browser that is `pid`'s parent: its pid and name.
fn browser_parent(pid: i32) -> Option<(i32, String)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name is in parentheses and may hold spaces; the parent pid follows
    // the state field after it.
    let ppid: i32 = stat.rsplit_once(')')?.1.split_whitespace().nth(1)?.parse().ok()?;
    let exe = std::fs::read_link(format!("/proc/{ppid}/exe")).ok()?;
    let name = exe.file_name()?.to_str()?;
    BROWSERS.iter().find(|(n, _)| *n == name).map(|(_, b)| (ppid, b.to_string()))
}

/// The scope for an executable path: one of `PEERS`, in `allowed_dir`. A binary that
/// was replaced while running shows as "… (deleted)" and is refused.
pub fn scope_of(exe: &Path, allowed_dir: &Path) -> Option<Scope> {
    if exe.parent()? != allowed_dir {
        return None;
    }
    let name = exe.file_name()?.to_str()?;
    PEERS.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
}

/// Where the suite's binaries are: the daemon's own directory (`~/.local/bin` when
/// installed, `target/<profile>` in a checkout).
pub fn allowed_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(Path::to_path_buf)
}

fn peer_uid(fd: RawFd) -> Option<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for writes of the sizes given.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &raw mut len) };
    (rc == 0).then_some(cred.uid)
}

fn peer_pidfd(fd: RawFd) -> Option<OwnedFd> {
    let mut pidfd: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `pidfd` and `len` are valid for writes of the sizes given.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERPIDFD, (&raw mut pidfd).cast(), &raw mut len) };
    // SAFETY: on success the kernel returned a new descriptor we now own.
    (rc == 0 && pidfd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(pidfd) })
}

/// The pid a pidfd refers to, from `/proc/self/fdinfo`; `None` once the process is gone.
fn pidfd_pid(pidfd: &OwnedFd) -> Option<i32> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd())).ok()?;
    let pid: i32 = info.lines().find_map(|l| l.strip_prefix("Pid:"))?.trim().parse().ok()?;
    (pid > 0).then_some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn scopes_by_name_and_place() {
        let dir = Path::new("/home/u/.local/bin");
        assert_eq!(scope_of(&dir.join("nixe-passwords"), dir), Some(Scope::App));
        assert_eq!(scope_of(&dir.join("nixe-glimpse"), dir), Some(Scope::Glimpse));
        assert_eq!(scope_of(&dir.join("nixe-passwords-settings"), dir), Some(Scope::Settings));
        assert_eq!(scope_of(&dir.join("nixe-passwords-bridge"), dir), Some(Scope::Browser));
        assert_eq!(scope_of(&dir.join("nixe-passwordsd"), dir), None);
        assert_eq!(scope_of(Path::new("/tmp/nixe-passwords"), dir), None);
        assert_eq!(scope_of(Path::new("/home/u/.local/bin/nixe-glimpse (deleted)"), dir), None);
        assert_eq!(scope_of(Path::new("/usr/bin/python3"), dir), None);
    }

    #[test]
    fn reads_the_real_peer() {
        // Both ends are this test process: its own executable isn't on the list.
        let (a, _b) = UnixStream::pair().unwrap();
        let me = std::env::current_exe().unwrap();
        assert_eq!(identify(a.as_raw_fd(), me.parent().unwrap()), None);
        assert_eq!(peer_uid(a.as_raw_fd()), Some(unsafe { libc::getuid() }));
        let pidfd = peer_pidfd(a.as_raw_fd()).expect("SO_PEERPIDFD (Linux 6.5+)");
        assert_eq!(pidfd_pid(&pidfd), Some(std::process::id() as i32));
        // This test's parent is cargo, not a browser.
        assert_eq!(browser_parent(std::process::id() as i32), None);
    }
}
