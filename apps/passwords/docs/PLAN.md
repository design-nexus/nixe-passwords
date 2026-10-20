# Nixe Passwords — plan

Design: [ARCHITECTURE.md](ARCHITECTURE.md). Rules: [SECURITY.md](SECURITY.md).
Checklist: [TASKS.md](TASKS.md).

## Phase 0: research and architecture

Write the documents in this folder, then run the spike. **No security-sensitive code
goes in before the spike passes.**

**Spike:**
1. **Test server:** run Vaultwarden 1.37.4 in a disposable container on `127.0.0.1:8087`
   with a scratch data volume under `target/vaultwarden-test/`.
2. **Test data:** create accounts with the official `bw` CLI, using PBKDF2 (600 000)
   and Argon2id (3 iterations, 64 MiB, parallelism 4). Add a login with TOTP, a note,
   a card, an identity, a folder, an organization with a collection, and a cipher with
   its own key.
3. **Build check:** `nixe-passwords-core` with `bitwarden-crypto =4.0.0` builds in the
   workspace, and `cargo deny check` passes.
4. **Round trip:** an ignored-by-default test (`NIXE_PW_TEST_SERVER=http://127.0.0.1:8087`)
   runs prelogin, token, sync, then decrypts every item. Output matches `bw get item`.
5. **Record the results** in DEPENDENCIES.md (Vaultwarden behaviour table).

**Blockers that stop the work:**
- bitwarden-crypto doesn't build or can't decrypt Vaultwarden data;
- the token endpoint refuses `client_id=desktop`;
- a required 2FA or device-verification step can't be done by a desktop client.

## Phase 1: desktop MVP

Each step builds, passes its tests and is installed (`./install.sh passwords`) before
the next.

1. **Core basics:** `secret`, `crypto` adapter, `model`, `store`. Tests: redaction,
   store round trip, and no plaintext in the database file.
2. **Core API:** prelogin, login, 2FA (authenticator and email), refresh, sync,
   offline unlock from the store.
3. **Core vault:** decrypted view, search, lock/zeroize; login create, edit
   (revision-checked), trash and restore; conflict reporting.
4. **Daemon:**
   - p2p server and peer checks, scopes, lock timer;
   - logind lock and sleep;
   - clipboard owner with timed clear;
   - notifications;
   - the systemd unit.
5. **App:**
   - pages: server setup, sign in (with 2FA), unlock, the vault table, item detail
     (copy, reveal, edit), and the generator in the item editor;
   - the sidebar: All items, Favorites, kinds, folders, collections; plus a Trash page;
   - the settings card;
   - checked at normal width and at 800 px.
6. **Install wiring:** install.sh (ALL, app_info, unit, desktop file, icon), `bin/nixe`,
   uninstall, Settings' app list, the README.

**Offline:** reading and copying work from the stored snapshot. Edits need the server;
the app says so when it's unreachable.

## Phase 2: Glimpse

1. **Provider:** a native Glimpse provider and prefix routing, as in
   [GLIMPSE_API.md](GLIMPSE_API.md).
2. **Copying:** username, password and TOTP copies with key bindings and hints; locked
   and logged-out rows; notifications.
3. **Clipboard check:** test which history managers honor the sensitive hint
   (cliphist, Omarchy's); record the results in SECURITY.md, and show the finding on
   the Settings page.
4. **Settings extension:** `nixe-passwords-settings`.
5. **Icons:** opt-in site icons from the server's icon service.

## Phase 3: browsers

1. The bridge and host manifests per browser, and pairing in the app.
2. **Extension:** popup (search, copy, generate), autofill on click or shortcut, login
   capture with confirmation, TOTP.
3. Site context for Glimpse.
4. Testing in Firefox, Zen, Chromium and Brave.

## Phase 4: more of the vault

- Notes, cards, identities and SSH keys: editing.
- Collections and organizations: editing within permissions.
- Attachments: download decrypted to a file the user picks, never to a temp file;
  upload.
- **Security dashboard:** reused, weak and old passwords computed in memory. An opt-in
  breach check through the HIBP k-anonymity range API.
- Assistant ability (`passwords.find`, `passwords.copy`).
- **Passkeys:** a written investigation (Vaultwarden storage format, WebAuthn in the
  extension, official-client interop). Not advertised until the whole flow works and
  is tested.
- Unlock with the system keyring or a fingerprint (fprintd through polkit). Opt-in,
  with the trade-off stated.

## Phase 5: hardening

- A threat-model review against the code.
- Fuzzing for the sync parser, EncString inputs, Native Messaging frames and
  `otpauth://` URIs.
- Offline and conflict test matrix: edit here and in the web vault at once, deleted on
  the server, org access removed.
- `cargo deny` and `cargo audit` in CI.
- Release workflow (`passwords-v<version>` tags).

## Decisions taken

| Decision | Choice |
| --- | --- |
| Licence | GPL-3.0-only for `nixe-passwords` and `nixe-passwords-core`; the protocol crate is MIT |
| Crypto | `bitwarden-crypto`, pinned, behind one adapter module |
| Testing | A local throwaway Vaultwarden; never the real server without asking |
| IPC | Peer-to-peer D-Bus on a private socket, not the session bus |
| Clipboard | Owned by the daemon through data-control |
