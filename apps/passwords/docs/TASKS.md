# Nyx Passwords — tasks

## Phase 0
- [x] Inspect Glimpse, Settings, Assistant, shared crates and STYLE.md
- [x] Evaluate the Bitwarden SDK and alternatives (DEPENDENCIES.md)
- [x] Architecture, threat model, plan, Glimpse and Native Messaging specs
- [x] Local Vaultwarden container and test accounts (PBKDF2, Argon2id) — `scripts/test-server.sh`
- [x] `nyx-passwords-core` builds with `bitwarden-crypto =4.0.0` (25 s, 102 new crates, no existing versions changed)
- [x] `cargo deny` passes (rustls → 0.23.46 workspace-wide; RUSTSEC-2023-0071 accepted with reason)
- [x] Spike test: prelogin → token → sync → decrypt all items, matches `bw` (plus write, conflict, refresh, trash)
- [x] Record Vaultwarden behaviour in DEPENDENCIES.md

## Phase 1
- [x] `nyx-core`: default-on `gtk` feature (daemon links no GTK; checked with ldd)
- [x] `nyx-passwords-proto`: names, socket path, wire types, error names
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
- [x] daemon: systemd unit (`data/nyx-passwords.service`, verified; installed in the install step)
- [x] app: server setup, sign in, two-step login (authenticator, email), unlock, sign out
- [x] app: sidebar, item list, item detail, reveal/copy (through the daemon), login editor with generator, trash with Undo, re-prompting items
- [x] daemon: master-password re-prompt (`Reprompt`, `VerifyPassword`), `Conflict` error, sync retried when an edit lands during its fetch
- [x] app: settings card (vault, clipboard, generator, integrations, window, keyboard)
- [x] app: checked at 1120 px and 800 px (debug snapshot mode, `PASSWORDS_SNAPSHOT`)
- [x] install.sh, bin/nyx, uninstall.sh, Settings app list, icon, README, LICENSE
- [x] Compatibility check against `bw` (`tests/edit.rs`): logins made here read back in `bw`; editing items `bw` wrote keeps custom fields of every kind, match rules, passkeys, older password history, attachments, an item's own key and an organization item's collection. Fixed on the way: every save reset the password's date, even with the password unchanged
- [ ] The same check by hand in the web vault (it shares `bw`'s client code)

## Phase 2 — Glimpse
- [x] Glimpse native provider (`apps/glimpse/src/pw.rs`, parser in `src/passwords.rs`), prefix routing that keeps `pw` queries from every other provider, Enter / Ctrl+Enter / Alt+Enter / Ctrl+O / Ctrl+C, hints, locked / signed-out / unavailable / help rows
- [x] Shared gio client in `nyx-passwords-proto` (`client` feature), used by the window and Glimpse; Glimpse links no GPL code
- [x] Notifications (tried on the desktop); clipboard: no history manager installed here, so the survey of which ones honor the hint is still open
- [x] Settings extension helper (`nyx-passwords-settings`, Accounts): status, lock, sync, locking, clipboard, sync interval, Glimpse switch

## Phase 3 — browsers
- [x] Daemon: URL matching under Bitwarden's rules (`matching.rs`), pairing (X25519, HKDF, AES-GCM in `crypto.rs`), sealed requests with replay protection, per-page fills, site context for Glimpse
- [x] Bridge (`nyx-passwords-bridge`), host manifests (installer), pairing confirmation in the window and a Browsers settings group
- [x] End-to-end test with the real bridge and a stand-in browser (`tests/daemon.rs`); WebCrypto test vector
- [x] Extension (`browser/`): pairing, popup, fill (origin re-checked in the page), one-time codes, generate into sign-up forms, unlock, Ctrl+Shift+L
- [x] Extension: saving the login typed into a page ("Save login": new, or a new password for the same username)
- [x] Site context for `pw` (the reporting browser must be the focused window)
- [ ] Tried in Firefox, Zen, Chromium, Brave (needs the extension loaded by hand; Firefox release needs signing)

## Phase 6 — closer to Vaultwarden
- [x] One-time code shown at once, following each new code, with a countdown ring (`Totp`: the item's own period)
- [x] Folders: make, rename, delete (items stay, in no folder)
- [x] Custom fields: edit text, hidden and true-or-false fields; linked ones and hidden ones this account can't see are kept
- [x] Password history in the item view (`History`, `history:N`)
- [x] Delete for good from the trash, empty the trash
- [x] Copy an item (secrets, custom fields and notes; not attachments or passkeys)
- [x] Several items at once: move to a folder, trash, restore, delete for good
- [x] Live sync through Vaultwarden's notification hub (SignalR, MessagePack); a burst of changes is one sync; `Revision` tells the window
- [x] Equivalent domains (global and the account's own) in base-domain matching
- [x] Website icons through the server's icon service, opt-in, kept in memory only (a disk cache would put the vault's sites on disk)
- [x] Import (Bitwarden JSON plain/password/account, Bitwarden CSV, 1Password .1pux, Chrome, Firefox and KeePassXC CSV) and export (Bitwarden JSON, password-protected JSON, account JSON, CSV); `tests/transfer.rs` against `bw` both ways
- [x] Sign in with another device (asking and approving, fingerprint phrases), the account's API key, YubiKey OTP, and recovery codes (two-step method 8; Vaultwarden 1.37 dropped `/two-factor/recover`); `tests/signin.rs`
- [ ] Security keys (FIDO2) for two-step login: needs a key to test with
- [ ] Duo: needs a Duo account to test with
- [ ] SSO (OIDC): needs an identity provider beside the test server
- [x] Username generator (word, plus address, catch-all, six alias services; tokens in the keyring) and generator history in memory; `tests/alias.rs` against a stand-in for each service
- [x] Emergency access: invite, confirm after comparing fingerprints, request, approve, reject, remove, view read-only; `tests/emergency.rs` with two accounts. Takeover isn't offered
- [x] Passkeys: listed and deleted in the item view; made and used by the extension (ES256, stored as the official clients store them); `tests/passkeys.rs` reads them back with `bw` and checks signatures
- [x] Extension, the best of Bitwarden's and 1Password's: a menu under login, sign-up, one-time-code, card and address fields; filling as the page loads (setting in both places, per-login opt-out); save and update bar with a never-save list; popup search of the whole vault (fill after a warning, then offer to add the address); copy through the daemon's clipboard; one-time code ring; generator with options and usernames; security tags; universal sign-on ("Sign in with Google" remembered and clicked for you); passkeys (opt-in); badge, shortcuts, context menu, a welcome page
- [x] Extension design (0.4.0): a 1Password-style popup (search, suggestions for the page, filters, the item beside the list with Autofill and click-to-copy fields, generator, settings) and redrawn menu, save bar and passkey window, in the Nyx 2.0 look and Passwords' own theme (`settings` carries it; `nyx.js` applies it); site icons when the app's icon setting is on. `browser/test/preview.mjs` photographs every view with made-up items
- [x] Headless Firefox test (`firefox_extension`, WebDriver BiDi): pairing, fill on load, card menu, save bar, universal sign-on, passkey made and used; `web-ext lint` in CI
- [x] Firefox add-on signing: 0.3.0 signed unlisted on AMO (`web-ext sign --channel unlisted`)
- Live tests: `tests/edit.rs` `folders_fields_history_and_many_items` (with `bw`), `tests/live.rs` (hub, equivalent domains), `tests/daemon.rs` scopes and `live_sync`

## Phase 4 / 5
See PLAN.md.
- [x] Phase 5: threat-model review against the code ([REVIEW.md](REVIEW.md)); six fixes
- [x] Phase 5: offline and conflict test matrix (`tests/matrix.rs`); items gone from the server now leave this copy at once
- [x] Phase 5: fuzzing (`crates/nyx-passwords-core/fuzz`, six targets, `run.sh`); first run found nothing
- [x] Item view: card, identity and SSH key fields and custom fields, with copy and reveal (`Fields`; secret values only through `Reveal`)
- [x] Editing notes, cards and identities (`CreateItem`, `UpdateItem`; fields the app doesn't know are kept)
- [x] Editing SSH keys: generate (Ed25519) or import an OpenSSH private key; the public key and fingerprint always come from it
- [x] SSH keys with a passphrase: the import asks for it and keeps the key without it, as the official clients do (`OpenSshKey`)
- [x] Unlock with the keyring (opt-in, trade-off in the setting; tested against a private keyring that never prompts)
- [ ] Fingerprint unlock (fprintd): needs a reader to test on; none here
- [x] Passkeys investigation ([PASSKEYS.md](PASSKEYS.md)): storage format, what the official clients do as an authenticator, the extension and daemon design, interop tests; built in Phase 6
- [x] Assistant ability: `nyx-passwords-assistant` (MCP, `assistant` scope, off by default), `abilities/passwords`, `Secrets` capability in assistant-policy; tested over the socket and in the policy tests (the Assistant itself is reinstalled separately)
- [x] Security report: weak (zxcvbn), reused and old passwords in memory, as a Security section; breach check through Have I Been Pwned's range API on request (prefixes only, padded), tested against a stand-in server
- [x] Attachments: list, save to a chosen file, attach, delete; the daemon reads and writes the file through a handle the window passes, so the window never holds the contents
- [x] Organizations: permissions enforced (read-only items, hidden passwords, delete and restore), new items in writable collections, changing collections, moving personal items in (rewrapped or re-encrypted, attachments included); live test with an owner and a member
