# Nixe Passwords — architecture

Nixe Passwords is a desktop client for a self-hosted Vaultwarden server. It speaks the
Bitwarden client API, so the same account keeps working in the official Bitwarden apps,
the web vault and the `bw` CLI. There is no server component.

## Components

```
 nixe-passwords (GTK) ─┐
 nixe-glimpse          ─┤   peer-to-peer D-Bus over
 nixe-passwords-settings┼── $XDG_RUNTIME_DIR/nixe-passwords/bus ──┐
 nixe-passwords-bridge ─┘   (dir 0700, SO_PEERCRED, exe allowlist) │
   ▲ Native Messaging                                             ▼
 browser extension                                         nixe-passwordsd
                                                    ┌──────────┼───────────────┬───────────────┐
                                                    ▼          ▼               ▼               ▼
                                              Vaultwarden  vault.sqlite   Secret Service   Wayland
                                              (HTTPS)      (ciphertext)   (refresh token)  data-control
                                                                                           (clipboard)
```

| Process | Package / licence | Holds keys | Role |
| --- | --- | --- | --- |
| `nixe-passwordsd` | `apps/passwords`, GPL-3.0-only | yes, the only one | Session, sync, local store, lock state, search, clipboard owner, policy |
| `nixe-passwords` | `apps/passwords`, GPL-3.0-only | no | The window: login, unlock, browse, edit, settings |
| `nixe-passwords-settings` | `apps/passwords`, GPL-3.0-only | no | Settings extension helper (pages JSON) |
| `nixe-passwords-bridge` | `apps/passwords`, GPL-3.0-only | no | Native Messaging host: a relay between one browser connection and the daemon |
| Glimpse `pw` provider | `apps/glimpse`, MIT | no | Native provider in Glimpse; links only `nixe-passwords-proto` |

The daemon is the only process that derives keys, decrypts ciphers or touches the
clipboard with a secret. The others send requests and get back metadata or a result
("copied"). The one exception is the GTK app, which may receive a single field's
plaintext after a user action (reveal, edit).

## Workspace layout

```
crates/
  nixe-passwords-proto/      MIT. Interface name, object path, socket path, scopes,
                             wire types, error names. No crypto, no I/O beyond paths.
  nixe-passwords-core/       GPL-3.0-only. Everything that knows Bitwarden.
    src/secret.rs            Redacting newtypes (Debug/Display/Serialize never print).
    src/crypto.rs            The only module that names bitwarden-crypto types.
    src/api/                 identity (prelogin, token, refresh), api (sync, ciphers).
    src/model.rs             Encrypted wire models: Profile, Cipher, Folder, Collection,
                             Organization; unknown fields kept for round trips.
    src/store.rs             SQLite: the encrypted sync snapshot and account state.
    src/vault.rs             Decrypted in-memory view; search; dropped on lock.
    src/sync.rs              Full sync, revision checks, conflict reporting.
    src/totp.rs              otpauth:// and Steam parsing, code generation (totp-rs).
    src/generate.rs          Password and passphrase generation (thread CSPRNG, EFF word list).
    src/matching.rs          URI match rules (base domain via PSL, host, starts with,
                             exact, regex, never).
apps/passwords/
  src/main.rs                GTK app (nixe-passwords).
  src/bin/nixe-passwordsd.rs Daemon.
  src/bin/nixe-passwords-settings.rs
  src/bin/nixe-passwords-bridge.rs   (Phase 3)
  src/daemon/                server (p2p zbus), peers, policy, lock, clipboard, notify.
  src/ui/                    window, pages, item detail, unlock, settings_dialog.
  data/                      desktop file, systemd unit template.
  browser/                   (Phase 3) one WebExtension source, Firefox and Chromium manifests.
  docs/                      this folder.
```

`nixe-core` gets a default-on `gtk` feature. The daemon and the bridge use `app`,
`paths` and `cmd::atomic_write` with `default-features = false`. Existing apps don't
change.

## Data and storage

| What | Where | Form |
| --- | --- | --- |
| Account state: server URL, email, KDF parameters, the protected user key, private key, org keys | `~/.local/share/nixe-passwords/vault.sqlite` | As the server sends them: EncStrings, never decrypted on disk |
| Sync snapshot: ciphers, folders, collections, policies | same database | Raw server JSON per object, encrypted fields untouched |
| Refresh token | Secret Service (`application nixe-passwords server <url> account <email>`) | Through `secret-tool` stdin, as Git does |
| Access token | daemon memory | |
| Device identifier | `vault.sqlite` | A random UUID, created once per install |
| Preferences | `~/.config/nixe-passwords/settings.toml` | Written by the app (`prefs_store!`); the daemon reads it and reloads when its mtime changes |
| Decrypted fields, search index, keys | daemon memory only | Zeroized on lock |
| Site icons (opt-in, Phase 2) | `~/.cache/nixe-passwords/icons/` | PNGs from the server's icon service |

The database and its directory are created 0600/0700 under umask 077. SQLite runs with
`secure_delete=ON` and `journal_mode=WAL`. Because the snapshot is stored as the server
sent it, an offline unlock works the same way as an online one: KDF over the master
password, decrypt the user key, then decrypt items on demand.

## Flows

**Log in:**
1. `POST {server}/identity/accounts/prelogin {email}` returns the KDF and its parameters.
2. `crypto::master_key(password, email, kdf)` derives the master key, then
   `crypto::master_password_hash`.
3. `POST /identity/connect/token`: `grant_type=password`, `scope=api offline_access`,
   `client_id=desktop`, `deviceType=8` (Linux desktop), `deviceIdentifier`, `deviceName`.
4. A 400 with `TwoFactorProviders2` returns a 2FA challenge to the app. The request is
   then retried with `twoFactorToken` and `twoFactorProvider`.
5. The refresh token goes to Secret Service. The response's `Key` and `PrivateKey` go
   to the store.
6. Full sync, then unlocked.

The server and email are fixed per account. Only `https://` is accepted, except
`http://` on loopback addresses.

**Unlock:** master password → master key → decrypt the user key → decrypt the private
key and org keys → build the in-memory view. The view holds decrypted names, usernames,
URIs and folder names for search and listing. Passwords, TOTP seeds, notes, card
numbers and the like are decrypted per request and zeroized after use.

**Sync:** `GET /api/sync?excludeDomains=true` with the access token, which is refreshed
when it expires. The snapshot is replaced in one transaction. A failed sync keeps the
last good snapshot. Sync runs on unlock, on an interval (setting) and on demand.

**Edit:** the app sends the changed fields. The daemon encrypts them with the item's
key: the cipher's own key if it has one, otherwise the org key or user key. It then
sends `PUT /api/ciphers/{id}` with `lastKnownRevisionDate`. If the server rejects a
stale revision, the daemon refetches the item and reports a conflict to the app, which
shows both versions. Nothing is overwritten silently. Deleting moves the item to the
trash (`PUT /api/ciphers/{id}/delete`). Edits need a connection; offline edits wait for
a later phase.

**Rules for edits:**
- **New items:** created under the user key, without an item key of their own.
  Official clients don't create per-item keys against Vaultwarden either. Items that
  already have their own key keep it.
- **Changing a password:** the old one moves into the item's password history (newest
  first, at most five) and `passwordRevisionDate` is set.
- **Web addresses:** every one is saved with its encrypted checksum. An address that was
  already on the item keeps its match rule.
- **What's sent back unchanged:** custom fields, passkeys, attachments and unknown fields.

**Copy (Glimpse or the app):**
1. The client sends `Copy(id, field)`.
2. The daemon checks the peer's scope and the lock state.
3. It decrypts the one field, offers it on the Wayland clipboard with the
   password-manager hint, and returns the clear-after time.
4. When that time is up, it clears the clipboard if the clipboard still holds the value.
5. A notification confirms the copy without showing the value.

**Lock:** after an inactivity timeout, logind `Lock`, `PrepareForSleep`, `pw lock`, the
app's lock button, or the daemon stopping. Locking drops the view and all keys, and
clears any clipboard value this daemon still owns.

## IPC

- **Vault traffic** goes over a peer-to-peer zbus connection on
  `$XDG_RUNTIME_DIR/nixe-passwords/bus`. There is no message bus in between, so
  `dbus-monitor` can't observe it.
  - Interface `io.github.design_nexus.nixe.Passwords1` at `/io/github/design_nexus/nixe/Passwords`.
  - Methods and scopes are in [GLIMPSE_API.md](GLIMPSE_API.md).
- **Peer identification:** SO_PEERCRED gives the peer's uid and pid. The uid must match
  the daemon's, and `/proc/<pid>/exe` must be a known binary. That fixes the peer's scope.
- **Session bus:** the daemon owns `io.github.design_nexus.nixe.Passwords` only for
  single-instance and activation. It emits `LockStateChanged(s)` with no vault data.
- **Native Messaging:** described in [NATIVE_MESSAGING.md](NATIVE_MESSAGING.md).

## Integrations

- **Glimpse (Phase 2):** a native provider in `apps/glimpse/src/passwords.rs`.
  - A `pw`/`password` prefix takes the query away from every other provider, including
    plugins and semantic search.
  - Talks to the daemon over the socket with gio (`DBusConnection::new_for_address`).
  - The full spec is in [GLIMPSE_API.md](GLIMPSE_API.md).
- **Settings:** an extension helper installed like Glimpse's (`install.sh` writes
  `extension.toml`). Category `Accounts`. Pages: server, sync, lock timeout, clipboard
  timeout, browser pairing, Glimpse, notifications.
- **Assistant (Phase 4):** an ability with `passwords.find` (metadata) and
  `passwords.copy`. Both get explicit lines in `assistant-policy`'s capability table,
  key-press approval and no voice approval. `passwords.copy` returns only "copied".
- **Clipboard:** the daemon owns sensitive copies. Limits are in
  [SECURITY.md](SECURITY.md#clipboard).

## Processes and lifetime

`nixe-passwordsd` runs as a systemd user service (`PartOf=graphical-session.target`,
`UMask=0077`, `Restart=on-failure`), with a `flock` on its runtime directory against a
second instance. The app, Glimpse and the bridge start it with
`systemctl --user start nixe-passwords.service` when the socket is missing. The service
has no `ExecStart` arguments carrying data.
