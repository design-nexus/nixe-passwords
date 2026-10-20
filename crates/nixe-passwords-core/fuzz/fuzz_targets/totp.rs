//! One-time code settings from the vault: otpauth:// links, steam:// and base32 seeds.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nixe_passwords_core::secret::Secret;
use nixe_passwords_core::totp::Generator;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(generator) = Generator::parse(&Secret::new(text)) {
        let _ = generator.now();
    }
});
