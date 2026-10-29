# Nyx Passwords — browser Native Messaging protocol

Status: implemented. The daemon side is tested end
to end with the real bridge (`tests/daemon.rs`, `paired_browser`); the extension's
pairing derivation is held to the daemon's by one test vector
(`browser/test/pairing-vector.mjs`, `crypto.rs`'s `pairing_matches_webcrypto`).

## Pieces

| Piece | Where |
| --- | --- |
| Extension | `apps/passwords/browser/` (one source in `src/`, `manifest.firefox.json` and `manifest.chromium.json`), built by `scripts/build-extension.sh` |
| Extension ids | Firefox and Zen: `nyx-passwords@design-nexus.github.io` (the host also allows `nixe-passwords@…`, the id before the rename, for one release); Chromium, Chrome and Brave: `gjjphllfkicmjjeiecpfjefafbmgfnbl` (fixed by the manifest's `key`) |
| Host | `nyx-passwords-bridge`, started by the browser for each extension connection |
| Host name | `io.github.design_nexus.nyx.passwords` |
| Host manifests | Firefox and Zen: `~/.mozilla/native-messaging-hosts/` (both read `XREUserNativeManifests`); Chromium: `~/.config/chromium/NativeMessagingHosts/`; Brave: `~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/`; Chrome: `~/.config/google-chrome/NativeMessagingHosts/`. Templates in `browser/hosts/` |
| Allowed callers | Firefox manifest `allowed_extensions`: the extension's fixed gecko id. Chromium manifest `allowed_origins`: `chrome-extension://<id>/` for the published key's id |

The installer writes a host manifest for each browser whose profile folder exists, and
puts the built extension in `~/.local/share/nyx-passwords/browser`.

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
   and a 6-digit code from `HKDF(…, info = "nixe-passwords code v1")`. The labels keep
   the name from before the rename, so existing pairings stay valid.
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
with the names in `nyx-passwords-proto`.

- **Counters:** the extension uses the time in milliseconds (or one more than its
  last). They must rise strictly per pairing and be within five minutes of the
  daemon's clock, so a recorded frame can't be replayed, even after a restart.
- **Failures:** a frame that fails to decrypt is dropped, and three failures close the
  connection.

| Request | Reply | Allowed when |
| --- | --- | --- |
| `status` | `{state}` | always |
| `settings` | `{fill_on_load, passkeys, icons, theme}` | always; the app's settings, which the daemon enforces, and the suite's theme as Passwords shows it (colours, fonts, radii), which the extension keeps for its pages |
| `context {url}` | `{}` | unlocked. The URL is the active tab's, from `tabs` in the background script; the daemon keeps its origin for 10 s for Glimpse |
| `match {url}` | `{items: [{id, name, username, host, favorite, has_totp, has_password, reprompt, sign_in_with, has_passkey}]}` | unlocked; only items whose URIs match `url` under their match rule (with the account's equivalent domains) |
| `search {q}` | `{items: [{id, name, username, host, kind, sub, has_totp, favorite, reprompt}]}` | unlocked; names and usernames from across the vault (`sub`: a card's brand and last four digits, an identity's name), no secrets; up to 50 hits, or the first 1000 items (favorites first) for an empty query. The background script answers it for the popup only |
| `item {id}` | the summary, plus `uris`, `has_password`, `has_passkey`, `editable`, `sign_in_with` | unlocked; popup only |
| `icon {host}` | `{url}` (a `data:` URL) | unlocked, website icons on in the app, and `host` is a site the vault has an item for; through the server's icon service, kept in memory |
| `fill {url, id, frame, confirmed, trigger}` | `{id, has_totp, username, password}` | unlocked; `id` is among `match(url)` (or, with `confirmed`, any login the user picked in the popup and confirmed for this page after a warning); `frame` has the same base domain as `url`. With `trigger: "load"` there's no `id`: see "Filling as the page loads" |
| `totp {url, id, frame}` | `{code, period, period_left}` | as `fill` without `confirmed` |
| `copy {id, field}` | `{seconds}` | unlocked; `username`, `password` or `totp` of any item, put on the clipboard by the daemon (cleared later). The value never comes back. Not for items that ask for the master password |
| `cards {url}`, `identities {url}` | `{items: [{id, name, sub}]}` | unlocked; for the menu under checkout and address fields; cards only on https |
| `fill_card`, `fill_identity {url, id, frame}` | the item's fields | as `fill`'s frame rule; cards only on https; not items that ask for the master password |
| `check {url, username, password}` | `{state: new, changed (with id), same, locked or excluded}` | unlocked; asked when a form is submitted, to decide whether the save bar asks. Nothing is stored |
| `save {url, username, password}` | `{saved: "created" or "updated", id, username}` | unlocked and online; sent only when the user clicks Save in the bar or the popup. A login for the page with the same username gets the new password (the old one goes to its history; not for re-prompting items); otherwise a new login named after the host, for the page's origin |
| `exclude {url}` | `{}` | unlocked; the host goes on the never-save list (kept encrypted with the user key) |
| `add_uri {url, id}` | `{id}` | unlocked and online; the page's origin is added to a login the user filled there after confirming |
| `security {ids}` | `{items: [{id, weak, reused, old}]}` | unlocked; the security report for those items |
| `generate {rules}` | `{password}` | unlocked; with the popup's options, or the saved ones |
| `username {url}` | `{username}` | unlocked; the username generator (an alias service gets only the site's name) |
| `signin.save {url, provider, username}` | `{saved}` | unlocked and online; universal sign-on: a login for the page with the custom field `nyx:sign-in-with` |
| `passkey.list {url, rp_id, allow}` | `{items: [{id, name, credential_id, user_name}]}` | passkeys on (in the app and the extension); `rp_id` is the page's host or a registrable domain above it (`matching::valid_rp_id`) |
| `passkey.get {url, rp_id, id, credential_id, client_data_hash, confirmed}` | `{credential_id, authenticator_data, signature, user_handle}` | as `passkey.list`, `confirmed` (the user picked it in the extension's own window), not for items that ask for the master password |
| `passkey.create {url, rp_id, rp_name, user_id, user_name, user_display_name, client_data_hash, exclude, rk, into, confirmed}` | `{id, credential_id, attestation_object, authenticator_data, public_key, algorithm}` | as `passkey.get`; `into` is a login matching the page, or none for a new one; refused (`Excluded`) when the site already has one of the listed credentials |
| `unlock` | `{}` | opens the app's unlock page; returns at once |
| `lock` | `{}` | locks the vault (the popup's lock button) |

Fills, copies and changes share a limit of 30 a minute per pairing.

**What is never sent:**
- the vault, or any secret of an item that isn't the page's (unless the user picked
  it and confirmed it for the page);
- a password, code or card number into a frame from another site;
- anything at all while the vault is locked.

## The extension's parts

- **The look:** every page loads `nyx.js`, which applies the theme Passwords reported
  (kept in the extension's storage, so a page opens in the right colours at once), the
  icons and the item tiles.
- **Background script:** holds the pairing key and the sealed link; decides everything,
  from what the browser says about each sender (`sender.tab`, `sender.frameId`,
  `sender.url`), never from what a page says.
- **Content script** (every http and https frame, isolated from the page's scripts):
  notices login, sign-up, one-time-code, card and address fields, form submissions and
  clicks on "Sign in with …". It sees no vault value.
- **The menu under a field, the save bar, the passkey window:** this extension's own
  pages (`menu.html`, `bar.html`, `confirm.html`). The menu and bar are frames inside a
  closed shadow root, so the page can neither read nor press them; each acts only for
  the frame and tab it was opened for, under a random token.
- **Passkey page script** (`page.js`, only when passkeys are on in both places): runs
  in the page's world and hands `navigator.credentials.create` and `.get` for public
  keys to the extension first. The extension builds `clientDataJSON` from the frame's
  origin as the browser reports it; the user confirms in the extension's own window;
  "Use the browser's own" falls back to the browser.

## Filling as the page loads

On by default; off in Passwords → Settings → Browsers (which the daemon enforces) or
in the extension's settings. When a page with a login form loads, the content script
asks once; the daemon fills only:
- on https;
- into the top frame or a frame on the same site;
- a login with an address naming this very host (a base-domain match alone isn't
  enough) or matching under an explicit rule;
- exactly one such login, or the one last used of several;
- never a login that asks for the master password, or one marked "not filled as the
  page loads" (the custom field `nyx:no-fill-on-load`);
- only into empty, visible fields.

## Origin rules

- **Source of the URL:** the extension's background script takes it from the
  `tabs` API and from `sender.url` for frames, never from page content.
- **Allowed schemes:** `https` (`http` only for loopback or when an item's URI is
  explicitly `http`).
- **Default matching:** base domain, using the PSL, plus the account's equivalent
  domains. Items keep their own match rules (host, starts with, exact, regex, never).
- **Frames:** no autofill into cross-origin iframes unless the frame's site matches.
- **Fields:** only visible fields are filled.

## Running without the desktop

When the daemon is unreachable, the extension shows "Nyx Passwords isn't running" and
offers nothing else.

A stand-alone mode would sync and decrypt inside the extension. It's a later
milestone; it would need the browser's own storage protections and isn't part of
this protocol.
