//! Website icons in the window, when they're turned on: the daemon fetches them and
//! hands over the image. Each host is asked about once while the vault is open, and
//! nothing is kept after it locks.

use std::cell::RefCell;
use std::collections::HashMap;

use gtk::{gdk, glib, prelude::*};

use super::{client, prefs};

enum Known {
    /// Asked; these images wait for the answer.
    Pending(Vec<glib::WeakRef<gtk::Image>>),
    Found(gdk::Texture),
    Missing,
}

thread_local! {
    static KNOWN: RefCell<HashMap<String, Known>> = RefCell::new(HashMap::new());
}

/// Puts `host`'s icon in `image` (shown at `size` pixels) once it's known; the image
/// keeps its kind icon until then, and when the site has none.
pub fn show(image: &gtk::Image, host: Option<&str>, size: i32) {
    let Some(host) = host.filter(|h| !h.is_empty() && prefs::get().vault.icons) else { return };
    let ask = KNOWN.with(|known| {
        let mut known = known.borrow_mut();
        match known.get_mut(host) {
            Some(Known::Found(texture)) => {
                set(image, texture, size);
                false
            }
            Some(Known::Missing) => false,
            Some(Known::Pending(waiting)) => {
                waiting.push(image.downgrade());
                false
            }
            None => {
                known.insert(host.to_string(), Known::Pending(vec![image.downgrade()]));
                true
            }
        }
    });
    if !ask {
        return;
    }
    let host = host.to_string();
    glib::spawn_future_local(async move {
        let answer = client::call("Icon", Some((host.as_str(),).to_variant())).await;
        let texture = answer
            .ok()
            .and_then(|v| v.child_value(0).fixed_array::<u8>().ok().map(glib::Bytes::from))
            .and_then(|bytes| gdk::Texture::from_bytes(&bytes).ok());
        let waiting = KNOWN.with(|known| {
            let next = match &texture {
                Some(t) => Known::Found(t.clone()),
                None => Known::Missing,
            };
            match known.borrow_mut().insert(host, next) {
                Some(Known::Pending(waiting)) => waiting,
                _ => Vec::new(),
            }
        });
        if let Some(texture) = texture {
            for image in waiting.iter().filter_map(|w| w.upgrade()) {
                set(&image, &texture, size);
            }
        }
    });
}

fn set(image: &gtk::Image, texture: &gdk::Texture, size: i32) {
    image.set_paintable(Some(texture));
    image.set_pixel_size(size);
    image.remove_css_class("dim");
    image.remove_css_class("accent");
}

/// The vault locked: nothing about its sites stays.
pub fn forget() {
    KNOWN.with(|known| known.borrow_mut().clear());
}
