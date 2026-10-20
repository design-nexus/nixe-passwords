# Nixe Passwords — browser Native Messaging protocol

Status: specification for Phase 3. Nothing here is implemented yet.

## Pieces

| Piece | Where |
| --- | --- |
| Extension | `apps/passwords/browser/` (one source, `manifest.firefox.json` and `manifest.chromium.json`) |
| Host | `nixe-passwords-bridge`, started by the browser for each extension connection |
| Host name | `io.github.design_nexus.nixe.passwords` |
| Host manifests | Firefox and Zen: `~/.mozilla/native-messaging-hosts/`; Chromium: `~/.config/chromium/NativeMessagingHosts/`; Brave: `~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/`; Chrome: `~/.config/google-chrome/NativeMessagingHosts/` |
| Allowed callers | Firefox manifest `allowed_extensions`: the extension's fixed gecko id. Chromium manifest `allowed_origins`: `chrome-extension://<id>/` for the published key's id |

The installer writes the host manifests only for browsers it finds, and only when
browser integration is turned on.

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

Each frame is `{"t":"msg","p":<pairing id>,"n":<counter>,"c":<b64 AES-256-GCM(k, nonce, json, aad = p ‖ n)>}`.

- **Counters:** they rise strictly. The daemon keeps the last one per pairing and drops
  replays.
- **Failures:** a frame that fails to decrypt is dropped, and three failures close the
  connection.

| Request | Reply | Allowed when |
| --- | --- | --- |
| `status` | `{state}` | always |
| `context {url}` | `{}` | unlocked. The URL is the active tab's, from `tabs` in the background script; the daemon keeps its origin for 10 s for Glimpse |
| `match {url}` | `[{id, name, username, has_totp}]` | unlocked; only items whose URIs match `url` under their match rule |
| `fill {url, id, frame_url}` | `{username, password}` | unlocked, `id` is among `match(url)`, `frame_url` has the same base domain as `url` (or matches the item explicitly), and the request is marked as coming from a user gesture |
| `totp {url, id}` | `{code, period_left}` | as `fill` |
| `save {url, username, password}` | `{saved: id}` | unlocked; the daemon asks the user in the app or a notification before saving |
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
