# Nixe Passwords — security reviews

Each review reads [SECURITY.md](SECURITY.md) and checks the code against it, rule by
rule, then looks at what changed since the last one. Findings are fixed in the same
change, with a test where one can catch it.

## 2026-10-20: after Phase 4

Covers everything up to Phase 4: organizations, attachments, the security report and
breach check, the Assistant helper and unlocking with the keyring were new since the
threat model was written.

### The rules

| Rule | Result |
| --- | --- |
| 1. No custom cryptography | **Fixed.** The security report hashed passwords in `audit.rs`; SHA-256 and SHA-1 moved into `crypto.rs` (`password_digest`, `breach_hash`). `ssh.rs` uses `ssh-key`, now named in the rule as its one exception. Random numbers (`generate.rs`, browser pairing ids) aren't covered by the rule and stay where they are. |
| 2. No plaintext on disk | Holds. The daemon test plants canaries and scans every file after sync, copy, edit, attachments and lock. Attachments go only where the user saves them (now always 0600, see below); the strength cache and breach results live in memory. |
| 3. No secrets in logs and errors | Holds. The only prints are daemon start-up errors and the Settings helper's settings JSON; `Secret` redacts in `Debug`; error messages carry kinds and file paths, never values. |
| 4. No secrets in argv or environment | Holds. `secret-tool` gets secrets on stdin; attachments pass as file handles; the one program the daemon starts (`nixe-passwords --unlock`) gets no vault data. |
| 5. No general retrieval API | Holds. Every call that returns vault data needs the app's scope; copy and search also let Glimpse and the Assistant in when their setting is on, and return no values. Fill returns a password to a paired extension for its own origin, by design. **Doc fix:** GLIMPSE_API.md said the Settings page may list and revoke pairings; it may not, and doesn't. |
| 6. No indexing of secrets | Holds. Search covers metadata in memory. |
| 7. Lock drops everything | **Fixed.** A breach check that finished after a lock stored its results (ids and counts) in the window; they're now dropped. The strength cache, the editor and the item view were already cleared. |
| 8. Strict input | **Fixed.** Unbounded until now: item drafts (now 256 KB), `ReadSshKey`'s key text (64 KB), Have I Been Pwned's answers (1 MB; a larger one is skipped), and the Assistant helper's input lines (read 1 MB at most before parsing). |

### What changed since the threat model

- **Unlock with the keyring:** turning it on needed no master password, so anything
  able to act as the app while the vault was open could set up a way back in after it
  locked. **Fixed:** turning it on needs the master password confirmed just before (the
  window asks); the daemon test checks the refusal.
- **Attachments:** saving over an existing file kept that file's permissions, which
  could leave a decrypted attachment readable by others. **Fixed:** saved files are
  made 0600. Attachment names come from the vault, which organization members write;
  the save dialog's suggested name is now cut to its last path part.
- **Organizations:** permissions are enforced in the core (read-only items, hidden
  passwords, delete and restore) and covered by a live owner-and-member test. Hidden
  passwords are left out of the security report and the breach check, so neither says
  anything about them.
- **The Assistant helper:** a peer of its own with the narrowest finder scope, off by
  default, rate-limited and notified like Glimpse. Item names it returns can be written
  by others, so the Assistant treats them as untrusted (`Secrets` capability).
- **Breach check:** only five-character SHA-1 prefixes leave the device, with padding,
  and only after the user confirms. The vault lock isn't held during the requests.

### Fuzzing (2026-10-20)

`crates/nixe-passwords-core/fuzz`, with cargo-fuzz (libFuzzer, AddressSanitizer), 150 s
per target from the seeds in `fuzz/seeds/`. No crash, hang or memory blow-up:

| Target | What it feeds | Runs |
| --- | --- | --- |
| `sync` | The server's sync answer: parse, every cipher's accessors and request body, serialize again | 2.4 M |
| `enc_string` | Encrypted values, decrypted as text, bytes and attachment files with a fixed key | 12 M |
| `pairing` | A browser's handshake key and sealed frames | 9.8 M |
| `totp` | `otpauth://`, `steam://` and base32 seeds, then a code | 6.7 M |
| `matching` | An address and its rule against a page, regex rules included | 0.45 M |
| `ssh` | Private key text | 38 M |

The daemon's own frame handling needs a running vault and isn't fuzzed directly; what
it does with a frame before anything else is the JSON parse (size-limited) and the two
calls `pairing` covers.

### Test matrix (2026-10-20)

`crates/nixe-passwords-core/tests/matrix.rs`, live against the test server with `bw`
or the API as the other side:

- **Trashed elsewhere:** an edit from the stale copy is refused as a conflict and the
  trashed state comes in.
- **Deleted for good elsewhere:** edits and trash were refused with "Cipher doesn't
  exist" (a 400 from Vaultwarden, not 404), and the item stayed in this copy until the
  next sync. **Fixed:** the core asks the server for the item after a failed call and
  drops it when the server refuses it, store included.
- **Edited elsewhere at the same time:** a card's edit is refused as a conflict and the
  other edit comes in (logins were already covered).
- **Removed from an organization:** an edit from the stale copy is refused and the item
  leaves at once (it stayed until the next sync before the fix above); the next sync
  drops the organization's collections; the local copy agrees offline.
- **Server unreachable:** create, edit, trash and sync fail as `Unreachable`, nothing
  local changes, and the vault still unlocks and reads.

### Left open

- The extension in Firefox, Chromium and Brave, and the web vault check, need hands.
- Locking on screen lock and sleep, and paste once, are built but not yet tried on the
  desktop.
