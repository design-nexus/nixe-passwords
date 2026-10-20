//! The Passwords window. It holds no keys: everything goes through the daemon.

mod account;
mod attachments;
mod client;
mod data;
mod detail;
mod editor;
mod pairing;
mod security;
pub mod prefs;
mod settings;
#[cfg(debug_assertions)]
pub mod snapshot;
mod theme;
pub mod ui;
