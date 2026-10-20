//! Copies go through the Wayland data-control protocol from the daemon, so they outlive
//! the window or panel that asked for them. Each copy is marked sensitive
//! (`x-kde-passwordManagerHint: secret`) for clipboard managers that honor it.
//!
//! After the timeout the clipboard is cleared, but only if it still holds the copied
//! value: something the user copied since is left alone. This is best effort; a manager
//! that already stored the value keeps it (docs/SECURITY.md, Clipboard).

use std::io::Read;

use nixe_passwords_core::secret::Secret;
use wl_clipboard_rs::copy::{self, ClipboardType, MimeType, ServeRequests, Source};
use wl_clipboard_rs::paste;

const MAX_READ: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoClipboard;

/// The most recent copy, kept until it's cleared so it can be recognized.
#[derive(Default)]
pub struct Clipboard {
    last: Option<(u64, Secret)>,
    serial: u64,
}

impl Clipboard {
    /// Copies `value`; returns a serial for `clear_if_unchanged`. Blocking: call from a
    /// blocking task.
    pub fn copy(&mut self, value: Secret, paste_once: bool) -> Result<u64, NoClipboard> {
        let mut opts = copy::Options::new();
        opts.clipboard(ClipboardType::Regular).sensitive(true);
        if paste_once {
            opts.serve_requests(ServeRequests::Only(1));
        }
        let bytes: Box<[u8]> = value.expose().as_bytes().into();
        opts.copy(Source::Bytes(bytes), MimeType::Text).map_err(|_| NoClipboard)?;
        self.serial += 1;
        self.last = Some((self.serial, value));
        Ok(self.serial)
    }

    /// Clears the clipboard if copy `serial` is the latest and the clipboard still holds
    /// it. Returns whether it cleared.
    pub fn clear_if_unchanged(&mut self, serial: u64) -> bool {
        match &self.last {
            Some((s, _)) if *s == serial => self.clear_now(),
            _ => false,
        }
    }

    /// Clears the clipboard if it holds the latest copy (on lock and on exit), and
    /// forgets that copy either way.
    pub fn clear_now(&mut self) -> bool {
        let Some((_, value)) = self.last.take() else {
            return false;
        };
        if holds(&value) { copy::clear(ClipboardType::Regular, copy::Seat::All).is_ok() } else { false }
    }
}

/// Whether the clipboard's text is exactly `value`.
fn holds(value: &Secret) -> bool {
    let Ok((pipe, _)) = paste::get_contents(paste::ClipboardType::Regular, paste::Seat::Unspecified, paste::MimeType::Text)
    else {
        return false;
    };
    let mut current = zeroize::Zeroizing::new(Vec::new());
    if pipe.take(MAX_READ).read_to_end(&mut current).is_err() {
        return false;
    }
    value.same_as(&current)
}
