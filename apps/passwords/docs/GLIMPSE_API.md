# Nixe Passwords — daemon interface and Glimpse integration

## Connection

| | |
| --- | --- |
| Address | `unix:path=$XDG_RUNTIME_DIR/nixe-passwords/bus` (directory 0700, socket 0600) |
| Transport | Peer-to-peer D-Bus (no message bus); the daemon is the server |
| Interface | `io.github.design_nexus.nixe.Passwords1` |
| Object | `/io/github/design_nexus/nixe/Passwords` |
| Start | If the socket is missing: `systemctl --user start nixe-passwords.service`, then retry for up to 2 s |

`nixe-passwords-proto` (MIT) holds these names, the types below and the error names,
so Glimpse needs nothing GPL.

### Peers and scopes

When a peer connects, the daemon reads SO_PEERCRED and `/proc/<pid>/exe`. A peer
whose uid differs, or whose executable isn't in this table (resolved, not by name),
is disconnected before any method runs.

| Executable | Scope |
| --- | --- |
| `~/.local/bin/nixe-passwords` | `app`: everything below plus `Reveal`, edits, login, unlock, settings |
| `~/.local/bin/nixe-glimpse` | `glimpse`: `Status`, `Search`, `Suggest`, `Copy`, `OpenUrl`, `Generate`, `Lock` |
| `~/.local/bin/nixe-passwords-settings` | `settings`: `Status`, `Lock`, `Sync`, pairing list and revoke |
| `~/.local/bin/nixe-passwords-bridge` | `browser`: per-origin calls in [NATIVE_MESSAGING.md](NATIVE_MESSAGING.md) |

Each integration can be turned off in settings (`glimpse = false` and so on). Its peer
is then refused with `Denied`. In debug builds an extra allowlist entry for
`target/debug/` binaries is accepted only when the daemon itself is a debug build.

## Methods for Glimpse

All strings are UTF-8. An `Item` is `(s id, s name, s username, s host, b has_totp, s kind)`:

- `kind`: `login`, `note`, `card`, `identity` or `ssh`
- `host`: the first URI's host, or `""`
- `username`: `""` for kinds without one

| Method | Signature | Notes |
| --- | --- | --- |
| `Status` | `() → (s state, s server_host, u clear_seconds)` | `state`: `logged_out`, `locked` or `unlocked` |
| `Search` | `(s query, u limit) → a(ssssbs)` | Case-insensitive terms over name, username, host, folder and collection; prefix matches on name and host rank first; at most 50 |
| `Suggest` | `(u limit) → (s origin_host, a(ssssbs))` | Items for the trusted active site, else recently used; `origin_host` is `""` when there is no trusted context |
| `Copy` | `(s id, s field) → (u clear_seconds)` | `field`: `username`, `password` or `totp`; the app may also copy any field `Reveal` takes. The daemon puts the value on the clipboard; nothing comes back but the timeout |
| `OpenUrl` | `(s id) → s url` | The item's first `http(s)` URI with any user-info removed; `NoUrl` if none |
| `Generate` | `() → (u clear_seconds)` | Generates with the saved generator settings and copies the result |
| `Lock` | `() → ()` | |

**Errors** (D-Bus error names, prefix `io.github.design_nexus.nixe.Passwords1.Error.`):

| Name | Meaning |
| --- | --- |
| `Locked` | Vault is locked |
| `LoggedOut` | No account |
| `Denied` | Peer not allowed, or the integration is off |
| `NotFound` | No such item |
| `NoField` | The item has no such field (no TOTP, …) |
| `NoUrl` | The item has no web address |
| `Clipboard` | No data-control protocol, or the copy failed |
| `RateLimited` | Too many copies in a short time |
| `Reprompt` | The item asks for the master password again: Glimpse gets no secrets from it; the app calls `VerifyPassword` first (valid five minutes) |
| `Conflict` | The item changed elsewhere; the latest copy is now in the vault and the edit wasn't saved |

Messages carry no values.

**Limits:**
- `Copy`, for Glimpse: 10 per minute.
- `Search` limit: capped at 50.
- Queries: capped at 256 bytes.

**Recently used:** the daemon keeps a list of item ids in memory and drops it on lock.
Item ids are not secret, but the list reveals usage, so it isn't written to disk.

## Methods for the app only

| Method | Signature | Notes |
| --- | --- | --- |
| `SignIn` | `(s server, s email, s password, y method, s code) → (b done, a(ys) methods)` | `method` 255: no two-step answer. Not done: ask for one of `methods` (number, masked hint) and call again |
| `SendEmailCode` | `(s server, s email, s password) → ()` | For two-step login by email |
| `Unlock` | `(s password) → ()` | From the local copy; a sync follows in the background |
| `VerifyPassword` | `(s password) → ()` | For items that ask for the master password again |
| `SignOut` | `() → ()` | Removes the account, the local copy and the saved token |
| `Sync` | `() → ()` | Also allowed for the Settings page |
| `List` | `() → s` | JSON: account, entries (metadata), folders, collections, organizations |
| `Reveal` | `(s id, s field) → s` | `username`, `password`, `totp` (the code), `totp_seed`, `notes`, `custom:N`, or a card, identity or SSH key field (`card.number`, …; the list is `nixe_passwords_proto::fields`) |
| `Fields` | `(s id) → s` | JSON `[{name, label, value, secret}]`: a card's, identity's or SSH key's fields and the custom fields; secret values are left out |
| `GeneratePassword` | `(s rules) → s` | `{"kind":"password",…}` or `{"kind":"passphrase",…}` |
| `CreateLogin` | `(s draft) → s id` | Draft JSON: name, username, password, totp, uris, notes, folder, favorite, reprompt |
| `UpdateLogin` | `(s id, s draft) → ()` | |
| `CreateItem` | `(s draft) → s id` | A note, card, identity or SSH key. Draft JSON: kind (`note`, `card`, `identity`, `ssh`), name, fields (`{"card.number": …}`; one left out is cleared), notes, folder, favorite, reprompt. An SSH key needs only `ssh.privateKey` (OpenSSH, no passphrase); its public key and fingerprint are worked out from it |
| `UpdateItem` | `(s id, s draft) → ()` | The kind must match the item's |
| `GenerateSshKey` | `() → s` | A new Ed25519 key: JSON `{private, public, fingerprint}` |
| `ReadSshKey` | `(s private) → s` | JSON `{public, fingerprint}` for an OpenSSH private key; fails for a key with a passphrase |
| `Trash`, `Restore` | `(s id) → ()` | |

## Glimpse behaviour

### Routing
- **Prefix:** a query whose first word is `pw` or `password` (case-insensitive,
  followed by a space or the end) belongs to the passwords provider alone.
- **What is skipped:** apps, files, index, utilities, plugins and semantic search all
  skip it.
- **Logging:** the query isn't passed to any process argv and isn't logged. The
  plugin-error log never sees it.

### Commands

| Query | Shows | Enter |
| --- | --- | --- |
| `pw` | `Suggest(8)`: site matches first (a heading with the host), else recent items | copy username |
| `pw <terms>` | `Search(terms, 10)` | copy username |
| `pw <terms> user` | same results | copy username |
| `pw <terms> pass` | same results | copy password |
| `pw <terms> otp` | same results; rows without TOTP are dimmed | copy TOTP |
| `pw <terms> open` | same results | open the site |
| `pw generate` | a "Generate password" row, then any items matching "generate" | generate and copy |
| `pw lock` | a "Lock vault" row, then any items matching "lock" | lock |

With nothing to show (bare `pw` before any copies, or no match), a help row says what to
type. A trailing `user`, `pass`, `otp` or `open` is treated as a verb only when other terms
come before it. The verb sets what Enter does and shows in the hint line. The keys
below always work:

| Key | Action |
| --- | --- |
| <kbd>Enter</kbd> | the verb's action (username by default) |
| <kbd>Ctrl</kbd>+<kbd>Enter</kbd> | copy password |
| <kbd>Alt</kbd>+<kbd>Enter</kbd> | copy TOTP |
| <kbd>Ctrl</kbd>+<kbd>O</kbd> | open the site (listed in the preview; the status bar has no room) |
| <kbd>Ctrl</kbd>+<kbd>C</kbd> | copy username (never the password) |

### Rows
- **Content:** a row shows the item's name, then the username and host in `dim_text`.
  Icons: the site icon if icons are on and cached, otherwise a symbolic icon for the
  item's kind.
- **Never shown:** passwords and codes, not even masked to their length.
- **Preview pane:** shows kind, username, host, folder, whether TOTP is set, and the keys.

### States

| `Status` | Glimpse shows |
| --- | --- |
| socket can't be reached | one row "Nixe Passwords isn't running": Enter starts the service |
| `logged_out` | "Sign in to Vaultwarden": Enter runs `nixe-passwords` |
| `locked` | "Vault locked": Enter runs `nixe-passwords --unlock`, which opens the unlock page and, when unlocked, leaves the query to be run again |
| `unlocked` | results |

### Confirmation

Glimpse hides as soon as an action succeeds. The daemon then sends a desktop
notification (setting, on by default) such as "Password copied · clears in 30 s",
naming the field, never the value. Errors stay in Glimpse's footer.

### Site context for bare `pw`

`Suggest` returns an origin only when both of these hold:

1. **The site came from a paired extension.** It reports the active tab on every tab
   switch, navigation and window focus, on load, and every 30 seconds. The last report
   counts until the next one, or until the vault locks.
2. **That browser was the window in front.** Its process, the bridge's parent, owns the
   window most recently focused other than the caller's own. Hyprland's focus history
   gives that, so when Glimpse asks, it's the window you were in before opening Glimpse.

Window titles and URL text read from the screen are never used. Without trusted
context, `pw` shows recent items.

### Glimpse code changes (Phase 2)
- `apps/glimpse/src/passwords.rs`: a gio `DBusConnection::new_for_address_future`
  client, query parsing, and row building.
- `apps/glimpse/src/ui.rs`:
  - a `Password` variant in `Action` (holding id and kind, nothing secret);
  - prefix routing before the worker and enrich threads start;
  - key handling for the bindings above;
  - hints.
- Glimpse never calls `clipboard().set_text` for a password row.
