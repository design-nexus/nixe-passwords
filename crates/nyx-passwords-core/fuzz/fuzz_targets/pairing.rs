//! What a browser extension sends before and after pairing: a public key for the
//! handshake, then sealed frames opened with the pairing key.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use nyx_passwords_core::crypto::{self, PairKey};
use nyx_passwords_core::secret::Secret;

static KEY: LazyLock<PairKey> = LazyLock::new(|| {
    PairKey::import(&Secret::new(bitwarden_encoding::B64::from(vec![7u8; 32]).to_string())).expect("test key")
});

fuzz_target!(|data: &[u8]| {
    let _ = crypto::pair(data);
    let (aad, sealed) = data.split_at(data.len().min(data.first().copied().unwrap_or(0) as usize));
    let _ = KEY.open(aad, sealed);
});
