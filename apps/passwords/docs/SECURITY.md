# Nixe Passwords — security

This file is the threat model and the rules every change has to keep. If a change
can't meet a rule, the change waits; the rule doesn't bend.

## Assets

| Asset | Where it may exist |
| --- | --- |
| Master password | The app's password entry, then the daemon for the length of one KDF call |
| Master key, user key, private key, org keys, cipher keys | Daemon memory while unlocked |
| Decrypted secret fields (passwords, TOTP seeds, notes, card numbers, SSH keys) | Daemon memory for one request; the app for one reveal or edit; the clipboard after a copy |
| Decrypted attachments | Daemon memory for one download or upload; then only the file the user chose (0600). Never the app, never a temporary file |
| Decrypted metadata (names, usernames, URIs, folder names) | Daemon memory while unlocked; shown in the app and in Glimpse results |
| Access token | Daemon memory |
| Refresh token | Secret Service |
| Encrypted snapshot | `vault.sqlite` (0600), the same ciphertext the server keeps |

Metadata counts as sensitive. It isn't a secret like a password, but it is never
written to disk decrypted, logged, or sent to anything but the app, Glimpse and a
paired browser asking about its own origin.

## Adversaries and what is done about each

| Adversary | In scope | Measures |
| --- | --- | --- |
| Someone who gets the disk (theft, backup, a shared machine) | Yes | Only ciphertext and a refresh token in a keyring are stored. A refresh token alone can't decrypt anything. Unlocking needs the master password. |
| Network attacker | Yes | rustls with system roots. `http://` only on loopback. No certificate-pinning bypass and no "ignore errors" switch. |
| Malicious or compromised web page | Yes | The origin comes from browser tab APIs, not from the page. Base-domain matching uses the PSL. Fill needs a user gesture. No fill into cross-origin frames unless their origin matches. One item per request. |
| A malicious extension or a process pretending to be the extension | Yes | Pairing is confirmed by the user in the desktop app. Every message is authenticated with the pairing key, carries a counter (no replays) and is scoped to its origin. |
| An unrelated app on the session bus | Yes | Vault traffic never goes on the session bus. The socket checks the uid and the executable, and each peer gets a fixed scope. |
| A malicious process running as the same user | **Partly** | See below. |
| A malicious Vaultwarden server | Partly | Server data is parsed strictly with size limits and fuzzing (Phase 5). A server can still withhold or replay data. Detecting a key swap is the official clients' scheme and isn't extended here. |
| root, kernel, firmware, or a key logger in the compositor | No | Out of scope. |

### Same-user processes

On a Linux desktop any process running as the user can read the user's files, run
the user's binaries and talk to the compositor. No password manager fully defends
against that. What Nixe Passwords does:

- The daemon calls `prctl(PR_SET_DUMPABLE, 0)` and sets `RLIMIT_CORE` to 0: no core
  dumps, and with Yama `ptrace_scope ≥ 1` no ptrace by other user processes.
- **Memory:** it doesn't lock its memory against swap. The default `RLIMIT_MEMLOCK`
  (8 MiB) would make `mlockall` fail allocations. What it relies on instead:
  - bitwarden-crypto zeroizes key material;
  - bitwarden-crypto's global allocator, installed in every binary that links it,
    zeroes all freed memory, including D-Bus messages and JSON that carried a secret;
  - decrypted values in the core are zeroizing `Secret`s.

  Encrypted swap (or none) protects the rest.
- **Peer checks:** the socket refuses any executable that isn't one of the suite's,
  installed next to the daemon. The peer is pinned by pidfd (`SO_PEERPIDFD`), so a
  process that exits and has its pid reused can't pass the executable check.
- **What peer checks can't stop:** a same-user process can still run one of those
  executables, or connect and then `exec` one. So each executable's scope also limits
  what it can ask for:
  - Glimpse can search metadata and ask for copies, but can't read a secret back or
    reveal anything.
  - The Assistant's helper can do the same and less (no suggestions, generating or
    opening), only while its setting is on, and the assistant asks for a key press
    before each call.
  - Only the app can reveal a field.
- Rate limits on copy and reveal, plus a notification for each copy, make silent bulk
  extraction visible.
- An attacker with the user's access can read the clipboard after a copy. That is the
  clipboard's nature (below).

### Where the daemon connects

- **Your Vaultwarden server:** everything vault-related.
- **Have I Been Pwned** (`api.pwnedpasswords.com`): only when you press "Check for
  breaches…" in the Security section and confirm. It gets the first five hex
  characters of each password's SHA-1 hash, one request per distinct prefix, with
  padding on; the answer is matched here. Never automatic.

The security report itself (weak, reused, old) is worked out in daemon memory. Its
strength cache keeps only item ids, revisions and a weak/not-weak flag, and is
dropped on lock.

### Browser extensions

- **Pairing:** an extension pairs only after the user compares a code in the
  extension with the one the Passwords window shows, and confirms there.
- **Where the key lives:**
  - The extension keeps the pairing key in the browser's extension storage. Another
    process running as the user can read it there, which is the same limit as above.
  - The daemon keeps it encrypted under the user key, so a locked vault answers no
    one.
- **What a request can get:**
  - only items whose web address matches the tab's URL under its rule;
  - only for a frame on the same base domain;
  - nothing for a plain-`http` page unless the address says `http://`;
  - nothing from an item that asks for the master password again.
- **Fill rate:** at most 30 fills a minute per pairing.
- **Where the URL comes from:** the browser's tab API, never page content. The fill
  re-checks the page's origin before typing anything, so a tab that navigated after
  the request gets nothing.
- **The bridge:** it relays sealed frames and can't read them. The daemon serves it
  only when a browser started it.

## Rules for code

1. **No custom cryptography.** Every KDF, cipher, MAC and key-wrap call goes through
   `nixe-passwords-core/src/crypto.rs`, and that module only calls bitwarden-crypto
   (and, for native messaging, RustCrypto's `x25519-dalek`, `hkdf` and `aes-gcm`).
   No other module names a primitive.
2. **No plaintext on disk.** No decrypted field in SQLite, settings, caches, temp files
   or the plugin storage of any app. A test plants a canary password, runs a sync,
   copy, edit and lock, then scans every file under the app's directories for it.
3. **No secrets in logs, errors, panics or telemetry.** Secret values use the types in
   `secret.rs`, whose `Debug`/`Display` print `[redacted]` and which don't implement
   `Serialize`. Errors carry kinds, not values. There is no telemetry. Logging is off
   by default and never includes metadata.
4. **No secrets in argv, environment or D-Bus signals.** `secret-tool` gets the token on
   stdin. The clipboard is served in-process. Notifications never contain the value.
5. **No general retrieval API.** No method returns a password, TOTP seed, note or card
   number to anything but the app. Glimpse's and the Assistant's copy calls return
   only "copied".
6. **No indexing of secrets.** Search covers names, usernames, URIs, folder and
   collection names, in memory. Glimpse holds results for the panel's lifetime and
   writes nothing.
7. **Lock drops everything.** Every type holding decrypted data lives under the vault
   view. Locking drops it, and a test checks the view is empty afterwards.
8. **Strict input.** Every length-prefixed or JSON input has a size limit. Unknown
   cipher fields are kept for round trips but never interpreted.

## Clipboard

Copies are served by the daemon through the Wayland data-control protocol
(`wl-clipboard-rs`). Hyprland supports this.

- **Hint:** each copy offers the text types plus `x-kde-passwordManagerHint` = `secret`.
  - wl-clipboard ≥ 2.3 sets `CLIPBOARD_STATE=sensitive` for watchers, and KDE's Klipper
    reads the hint directly. Which history managers skip such entries (cliphist and
    Omarchy's own among them) is checked in Phase 2 and listed here.
  - Managers that ignore it **will store the password in their history.** The Settings
    page names the manager it finds and says whether it is known to honor the hint.
- **Clearing:** after the timeout (setting, default 30 s) the daemon reads the current
  selection.
  - If it still holds the copied value (compared in constant time), the daemon clears it.
  - If something else was copied since, it is left alone.
  - A manager that took over the selection or saved a copy is beyond reach. Clearing
    is best effort.
- **Checked on Omarchy (2026-10-19):** a copy offers `TEXT`, `text/plain;charset=utf-8`,
  `text/plain`, `UTF8_STRING`, `STRING` and `x-kde-passwordManagerHint`, and is cleared
  after the set time. No clipboard history manager was running.
- **Paste once (setting):** serve one paste and then clear.
- **Primary selection** is never used.
- Any client with data-control access can read the clipboard while it holds the value.
- If the compositor has no data-control protocol, copying fails with a clear error. It
  never falls back to a visible window or `wl-copy` with argv.

## Supply chain

- `bitwarden-crypto` is pinned (`=4.0.0`). Upgrades are
  deliberate, read and tested against the local Vaultwarden.
- `cargo deny` (licences, advisories, duplicate and banned crates) and `cargo audit`
  run before every release. Allowed licences: MIT, Apache-2.0, BSD, ISC, Zlib,
  Unicode, MPL-2.0, GPL-3.0-only.
- The browser extension has no runtime npm dependencies. Build tooling is pinned by
  lockfile.

## Reporting

Report vulnerabilities privately through GitHub security advisories on
`design-nexus/nixe`, not in public issues.
