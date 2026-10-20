# Nixe Passwords — browser Native Messaging protocol

Status: implemented. The daemon side is tested end
to end with the real bridge (`tests/daemon.rs`, `paired_browser`); the extension's
pairing derivation is held to the daemon's by one test vector
(`browser/test/pairing-vector.mjs`, `crypto.rs`'s `pairing_matches_webcrypto`).

## Pieces

| Piece | Where |
| --- | --- |
| Extension | `apps/passwords/browser/` (one source in `src/`, `manifest.firefox.json` and `manifest.chromium.json`), built by `scripts/build-extension.sh` |
| Extension ids | Firefox and Zen: `nixe-passwords@design-nexus.github.io`; Chromium, Chrome and Brave: `gjjphllfkicmjjeiecpfjefafbmgfnbl` (fixed by the manifest's `key`) |
| Host | `nixe-passwords-bridge`, started by the browser for each extension connection |
| Host name | `io.github.design_nexus.nixe.passwords` |
| Host manifests | Firefox and Zen: `~/.mozilla/native-messaging-hosts/` (both read `XREUserNativeManifests`); Chromium: `~/.config/chromium/NativeMessagingHosts/`; Brave: `~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/`; Chrome: `~/.config/google-chrome/NativeMessagingHosts/`. Templates in `browser/hosts/` |
| Allowed callers | Firefox manifest `allowed_extensions`: the extension's fixed gecko id. Chromium manifest `allowed_origins`: `chrome-extension://<id>/` for the published key's id |

The installer writes a host manifest for each browser whose profile folder exists, and
puts the built extension in `~/.local/share/nixe-passwords/browser`.

**Installing the extension:**
- **Chromium, Chrome, Brave:** "Load unpacked" from the `chromium` folder there, with
  developer mode on.
- **Zen:** "Install Add-on From File" with the `.xpi`, after setting
  `xpinstall.signatures.required` to false in `about:config`. Zen's build doesn't
  require signing.
- **Firefox (release builds):** these require extensions signed by Mozilla. Without
  that, the `.xpi` loads only as a temporary add-on (`about:debugging`) until the next
  restart. Permanent options are signing it as an unlisted add-on with a Mozilla
  account, or placing it in Firefox's own app folder, which this build accepts
  unsigned (`MOZ_UNSIGNED_APP_SCOPE`) but which needs root.

## Framing

- **Browser ↔ bridge:** standard Native Messaging, a 32-bit native-endian length
  followed by UTF-8 JSON.
  - Messages to the browser are at most 1 MiB.
  - The bridge refuses messages from the browser over 64 KiB.
- **Bridge ↔ daemon:**
  - The bridge connects to the daemon socket as the `browser` peer and forwards each
    message as one opaque `Relay(s caller, ay frame) → ay` call.
  - `caller` is the extension id the browser passed (Firefox: the first argument;
    Chromium: the origin argument).
  - The bridge doesn't parse or keep frames.
- **Parent check:** the daemon accepts a bridge only if its parent process is a known
  browser binary, by resolved `/proc/<ppid>/exe`. It records that pid for Glimpse's
  site context.

## Pairing

Pairing ties one browser profile to the daemon.

1. **Hello:** the extension generates an X25519 key pair (WebCrypto) and sends
   `{"t":"hello","v":1,"pub":<b64>}` in the clear.
2. **Key agreement:** the daemon generates its own pair. Both sides derive
   `k = HKDF-SHA256(X25519(a,b), salt = pubE ‖ pubD, info = "nixe-passwords pair v1")`
   and a 6-digit code from `HKDF(…, info = "nixe-passwords code v1")`.
3. **Confirmation:** the daemon asks the GTK app to show "Pair <browser> (<extension
   id>)?" with the code. The extension popup shows the same code. The user confirms in
   the desktop app.
4. **Storage:**
   - The daemon stores the pairing under its pairing id: the extension id, browser,
     the public keys, and `k` encrypted with the user key. A locked vault can't use
     pairings.
   - The extension stores `k` and the pairing id in `storage.local`.
   - Unconfirmed pairings expire after 2 minutes.
5. **Revocation:** pairings can be revoked in the app and in Settings.

## Messages after pairing

Each frame is `{"t":"msg","p":<pairing id>,"n":<counter>,"c":<b64 nonce ‖ AES-256-GCM(k, nonce, json, aad = "p|n")>}`.
The reply is sealed the same way with `aad = "p|n|r"`. Unsealed replies say only
`pending`, `locked`, `unknown` (pair again) or `unavailable` (the daemon isn't there).
Sealed requests are `{"r": "<request>", …}`; errors come back as `{"error": "<name>"}`
with the names in `nixe-passwords-proto`.

- **Counters:** the extension uses the time in milliseconds (or one more than its
  last). They must rise strictly per pairing and be within five minutes of the
  daemon's clock, so a recorded frame can't be replayed, even after a restart.
- **Failures:** a frame that fails to decrypt is dropped, and three failures close the
  connection.

| Request | Reply | Allowed when |
| --- | --- | --- |
| `status` | `{state}` | always |
| `context {url}` | `{}` | unlocked. The URL is the active tab's, from `tabs` in the background script; the daemon keeps its origin for 10 s for Glimpse |
| `match {url}` | `[{id, name, username, has_totp}]` | unlocked; only items whose URIs match `url` under their match rule |
| `fill {url, id, frame_url}` | `{username, password}` | unlocked, `id` is among `match(url)`, `frame_url` has the same base domain as `url` (or matches the item explicitly), and the request is marked as coming from a user gesture |
| `totp {url, id}` | `{code, period_left}` | as `fill` |
| `save {url, username, password}` | `{saved: "created" or "updated", id, username}` | unlocked and online; sent only when the user clicks "Save login" in the popup, with what the page's form holds. A login for the page with the same username gets the new password (the old one goes to its history; not for re-prompting items); otherwise a new login named after the host, for the page's origin |
| `generate {url}` | `{password}` | unlocked; a password to fill into a sign-up field |
| `unlock` | `{}` | opens the app's unlock page; returns at once |

**What is never sent:**
- the vault;
- items for other origins;
- notes, cards or identities, until a later request type is added for each, with its
  own rule.

## Origin rules

- **Source of the URL:** the extension's background script takes it from the
  `tabs`/`webNavigation` APIs, never from content-script messages. A content script
  can only ask the background to act on the tab it runs in.
- **Allowed schemes:** `https` (`http` only for loopback or when an item's URI is
  explicitly `http`).
- **Default matching:** base domain, using the PSL. Items keep their own match rules
  (host, starts with, exact, regex, never).
- **Frames:** no autofill into cross-origin iframes unless the frame's origin also
  matches the item. No autofill without a click or shortcut, so there is no
  page-load fill.
- **Fields:** password fields must be visible and focusable. Hidden or off-screen
  fields are skipped.

## Running without the desktop

When the daemon is unreachable, the extension shows "Nixe Passwords isn't running" and
offers nothing else.

A stand-alone mode would sync and decrypt inside the extension. It's a later
milestone; it would need the browser's own storage protections and isn't part of
this protocol.
