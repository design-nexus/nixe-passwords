//! An SSH key item's private key, as the vault or an imported file has it.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = nixe_passwords_core::ssh::read(text);
    }
});
