//! Encrypted values from the server, decrypted with a fixed test key as text, as bytes
//! and as an attachment file. Nothing may panic, whatever the input.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use nyx_passwords_core::crypto::{Keys, is_enc_string};
use nyx_passwords_core::secret::Secret;

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let key: Vec<u8> = (0..64u8).collect();
    Keys::from_user_key(&Secret::new(bitwarden_encoding::B64::from(key).to_string())).expect("test key")
});

fuzz_target!(|data: &[u8]| {
    let mut key = KEYS.item(None, None).expect("user key");
    let _ = key.decrypt_file(None, data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = is_enc_string(text);
        let _ = key.decrypt(text);
        let _ = key.decrypt_bytes(text);
        let _ = KEYS.item(None, Some(text));
    }
});
