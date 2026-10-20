# Nixe Passwords — tasks

## Phase 0
- [x] Inspect Glimpse, Settings, Assistant, shared crates and STYLE.md
- [x] Evaluate the Bitwarden SDK and alternatives (DEPENDENCIES.md)
- [x] Architecture, threat model, plan, Glimpse and Native Messaging specs
- [x] Local Vaultwarden container and test accounts (PBKDF2, Argon2id) — `scripts/test-server.sh`
- [x] `nixe-passwords-core` builds with `bitwarden-crypto =4.0.0` (25 s, 102 new crates, no existing versions changed)
- [x] `cargo deny` passes (rustls → 0.23.46 workspace-wide; RUSTSEC-2023-0071 accepted with reason)
- [x] Spike test: prelogin → token → sync → decrypt all items, matches `bw` (plus write, conflict, refresh, trash)
- [x] Record Vaultwarden behaviour in DEPENDENCIES.md

## Phase 1
- [x] `nixe-core`: default-on `gtk` feature (daemon links no GTK; checked with ldd)
- [x] `nixe-passwords-proto`: names, socket path, wire types, error names
- [x] core `secret`: redacting types + tests
- [x] core `crypto`: adapter on bitwarden-crypto's KeyStore (KDF with upper limits and downgrade check, server hash, user/private/org keys, item keys, strict EncString parsing, URI checksum)
- [x] core `model`: encrypted wire models, exact round trip of unknown fields and types, request bodies with `encryptedFor`
- [x] core `store`: SQLite snapshot, 0600/0700, secure_delete, atomic replace; canary test
- [x] Offline decryption tests from recorded fixtures (`tests/decrypt.rs`)
- [x] core `api`: prelogin, password grant, two-step login (authenticator tested live; email code request written, not tested: the test server has no mail), refresh, sync, cipher create/update/trash/restore, server URL rules, size limits
- [x] core `session`: sign in, offline unlock, sync on the refresh token, KDF downgrade refusal, key-change detection (live tests: `tests/session.rs`)
- [x] core `vault`: decrypted view (all text as `Secret`), ranked search over name/username/host/addresses/folder/collection, single-field reveal, lock drops everything (`tests/vault.rs`)
- [x] core `totp`: otpauth, steam and base32 seeds; RFC 6238 vectors
- [x] core `edit`: login create/edit/trash/restore, revision conflicts refetch the server copy, password history, URI checksums (live with `bw` as the other client: `tests/edit.rs`)
- [x] Refresh token in Secret Service (`keyring.rs`; tried 2026-10-19: saved at sign-in, used by the sync after a daemon restart)
- [x] core `generate`: passwords and passphrases
- [x] daemon: p2p server, peer checks pinned by pidfd, scopes, rate limits (`tests/daemon.rs`, live and offline)
- [x] daemon: lock timer, Hyprland screen lock, logind Lock / PrepareForSleep, lock on stop (written; screen lock and sleep not yet tried on the desktop)
- [x] daemon: clipboard owner, sensitive hint, clear-if-unchanged, paste once (tried on the desktop 2026-10-19: hint offered, cleared on time; paste once not tried)
- [x] daemon: notifications without values (tried 2026-10-19: "Password copied" / "Clears in 10 s", no value)
- [x] daemon: systemd unit (`data/nixe-passwords.service`, verified; installed in the install step)
- [x] app: server setup, sign in, two-step login (authenticator, email), unlock, sign out
- [x] app: sidebar, item list, item detail, reveal/copy (through the daemon), login editor with generator, trash with Undo, re-prompting items
- [x] daemon: master-password re-prompt (`Reprompt`, `VerifyPassword`), `Conflict` error, sync retried when an edit lands during its fetch
- [x] app: settings card (vault, clipboard, generator, integrations, window, keyboard)
- [x] app: checked at 1120 px and 800 px (debug snapshot mode, `PASSWORDS_SNAPSHOT`)
- [x] install.sh, bin/nixe, uninstall.sh, Settings app list, icon, README, LICENSE
- [ ] Compatibility check against `bw` and the web vault

## Phase 2 — Glimpse
- [x] Glimpse native provider (`apps/glimpse/src/pw.rs`, parser in `src/passwords.rs`), prefix routing that keeps `pw` queries from every other provider, Enter / Ctrl+Enter / Alt+Enter / Ctrl+O / Ctrl+C, hints, locked / signed-out / unavailable / help rows
- [x] Shared gio client in `nixe-passwords-proto` (`client` feature), used by the window and Glimpse; Glimpse links no GPL code
- [x] Notifications (tried on the desktop); clipboard: no history manager installed here, so the survey of which ones honor the hint is still open
- [x] Settings extension helper (`nixe-passwords-settings`, Accounts): status, lock, sync, locking, clipboard, sync interval, Glimpse switch

## Phase 3 — browsers
- [x] Daemon: URL matching under Bitwarden's rules (`matching.rs`), pairing (X25519, HKDF, AES-GCM in `crypto.rs`), sealed requests with replay protection, per-page fills, site context for Glimpse
- [x] Bridge (`nixe-passwords-bridge`), host manifests (installer), pairing confirmation in the window and a Browsers settings group
- [x] End-to-end test with the real bridge and a stand-in browser (`tests/daemon.rs`); WebCrypto test vector
- [x] Extension (`browser/`): pairing, popup, fill (origin re-checked in the page), one-time codes, generate into sign-up forms, unlock, Ctrl+Shift+L
- [x] Extension: saving the login typed into a page ("Save login": new, or a new password for the same username)
- [x] Site context for `pw` (the reporting browser must be the focused window)
- [ ] Tried in Firefox, Zen, Chromium, Brave (needs the extension loaded by hand; Firefox release needs signing)

## Phase 4 / 5
See PLAN.md.
- [x] Item view: card, identity and SSH key fields and custom fields, with copy and reveal (`Fields`; secret values only through `Reveal`)
- [ ] Editing notes, cards, identities and SSH keys
