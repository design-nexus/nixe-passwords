//! A web address and its match rule from the vault (a regex rule runs what the vault
//! says) against a page: first byte the rule, then the address and the page, split at
//! the first newline.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nixe_passwords_core::matching::matches;

fuzz_target!(|data: &[u8]| {
    let Some((&rule, rest)) = data.split_first() else { return };
    let Ok(text) = std::str::from_utf8(rest) else { return };
    let (item, page) = text.split_once('\n').unwrap_or((text, "https://example.com/login"));
    let Ok(page) = url::Url::parse(page) else { return };
    let _ = matches(Some(i64::from(rule % 8)), item, &page);
});
