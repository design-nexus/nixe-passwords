//! Visible dismissal for custom dialog cards; closing keeps existing guards intact.
use gtk::prelude::*;

pub(crate) fn add(window: &gtk::Window, body: &gtk::Box, label: &str) {
    let header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    // Shared cards start with a title. Keep dismissal beside it, above scrolling content.
    if let Some(title) = body.first_child().and_downcast::<gtk::Label>() {
        body.remove(&title);
        title.set_hexpand(true);
        title.set_xalign(0.0);
        header.append(&title);
    } else {
        header.set_halign(gtk::Align::End);
    }
    let button = gtk::Button::with_label(label);
    button.set_valign(gtk::Align::Center);
    button.set_tooltip_text(Some(&format!("{label} (Esc)")));
    let weak = window.downgrade();
    button.connect_clicked(move |_| {
        if let Some(window) = weak.upgrade() {
            window.close();
        }
    });
    header.append(&button);
    body.prepend(&header);
}
