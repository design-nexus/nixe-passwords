//! The Passwords window. It holds no keys: everything goes through the daemon.

mod account;
mod attachments;
mod client;
mod data;
mod detail;
mod editor;
mod pairing;
pub mod prefs;
mod security;
mod settings;
#[cfg(debug_assertions)]
pub mod fixture;
mod theme;
pub mod ui;
