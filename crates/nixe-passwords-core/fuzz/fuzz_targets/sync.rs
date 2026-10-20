//! The server's sync answer: parsed, then every cipher's accessors and request body.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nixe_passwords_core::model::Sync;

fuzz_target!(|data: &[u8]| {
    let Ok(sync) = serde_json::from_slice::<Sync>(data) else { return };
    for c in &sync.ciphers {
        let _ = (c.kind(), c.is_deleted(), c.can_edit(), c.can_view_password(), c.can_delete(), c.can_restore());
        let _ = c.to_request(sync.profile.id, Some(&c.revision_date));
    }
    for c in &sync.collections {
        let _ = c.writable();
    }
    // What's kept for round trips must serialize again.
    serde_json::to_vec(&sync).expect("a parsed sync serializes");
});
