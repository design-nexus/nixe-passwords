# Nyx Passwords — passkeys

Status: investigation (Phase 4). Nothing here is built, and passkeys aren't advertised
until the whole flow works and is tested. What Passwords does today: it keeps every
passkey intact. Edits send them back as they were, and moving an item into an
organization re-encrypts them with the item (both covered by live tests in
`crates/nyx-passwords-core/tests/edit.rs`). It doesn't show or use them.

Checked 2026-10-20 against Bitwarden's clients and SDK source and its contributor
documentation, and against Vaultwarden 1.37.4 with `bw` 2026.2.0.

## How passkeys are stored

A passkey lives on a login item, in `login.fido2Credentials` (a list). The server
stores it inside the item's encrypted data and does nothing else with it. Vaultwarden
needs no passkey support: `bw` round-trips a passkey through it unchanged (checked on
the test server).

Every value is an EncString under the item's key, like the item's other fields.
Decrypted:

| Field | Value |
| --- | --- |
| `credentialId` | A UUID string (what the official clients create), or `b64.` followed by base64url for an imported ID that isn't 16 bytes. The SDK reads both forms (`string_to_guid_bytes`). |
| `keyType` | `public-key` |
| `keyAlgorithm`, `keyCurve` | `ECDSA`, `P-256`: the official clients make ES256 keys only |
| `keyValue` | The private key as PKCS#8, base64url without padding |
| `rpId` | The relying party's id (a domain) |
| `rpName`, `userName`, `userDisplayName` | What the site said at registration, for display |
| `userHandle` | base64url without padding |
| `counter` | A decimal string. New passkeys get `0`, and a counter of `0` is never raised. |
| `discoverable` | `"true"` or `"false"`: whether the site may find it without naming its id (copied from `requireResidentKey`) |
| `creationDate` | ISO 8601 |

## What the official clients do when they act as the authenticator

From `fido2-authenticator.service.ts`:

- **Algorithm:** ES256 (COSE −7) only. A request that allows nothing else is refused
  with `NotSupported`.
- **Attestation:** `none`, with an empty statement and AAGUID
  `d548826e-79b4-db40-a3d8-11116f7e8349`.
- **Flags:** user presence always; user verification when it happened; backup
  eligible and backed up both set (the passkey syncs).
- **Counter:** stays 0, as stored. This avoids clashes between devices that sync.
- **User presence:** always asked. The authenticator doesn't answer until the user
  confirms or declines. User verification is partial: unlocking counts, with the master
  password as the fallback.

Matching all of this is what makes a passkey made here work in the official clients
and the reverse.

## How a browser extension takes part

Browsers give extensions no API for offering passkeys next to their own. Bitwarden's
extension injects a script into each page that replaces `navigator.credentials.create`
and `.get`, keeping the originals. When the user declines Bitwarden, it calls the
browser's own. Another password manager doing the same can get in the way; 1Password
has been reported to stop Bitwarden's override in Firefox.

For Nyx Passwords this means:

1. **A script in every page's main world.** Today the extension touches a page only
   when you click it (`activeTab`). Passkeys need a content script on every page, plus
   one in the page's main world. Both browsers support this in Manifest V3
   (`scripting.registerContentScripts` with `world: "MAIN"`, Firefox 128 and later; the
   extension already needs Firefox 130). That is a much broader permission
   (`<all_urls>`), so it would be its own opt-in, off by default, with the extension
   asking for it when it's turned on.
2. **Who builds `clientDataJSON`.** With the browser's implementation bypassed, the
   extension writes it: `type`, the page's `challenge`, `origin`, `crossOrigin`. The
   origin must come from the extension's view of the tab (the content script's frame),
   never from the page script, which the page controls.
3. **`rpId` checks.** The rpId must be the origin's host or a registrable suffix of it,
   and never a public suffix. That is the public-suffix check `matching.rs` already
   does. Plain `http` origins are refused except `localhost`, as browsers do.
4. **Frames.** Top-level pages and same-origin frames first. Cross-origin frames need the
   permissions-policy check browsers do, and wait.

## Where the key is used

The private key never leaves the daemon, like every other secret:

- **New sealed requests** over Native Messaging (docs/NATIVE_MESSAGING.md):
  - `passkey.list {rpId, allowCredentials}` returns names and user names only;
  - `passkey.get {rpId, credentialId, clientDataHash, uv}` returns authenticator data
    and the signature;
  - `passkey.create {rpId, rpName, user, clientDataHash, excludeCredentials, rk, uv}`
    returns the credential id, authenticator data and COSE public key.

  The daemon checks the rpId against the sealed origin itself.
- **Signing:** ECDSA P-256 over `authenticatorData ‖ SHA-256(clientDataJSON)`, DER as
  WebAuthn expects. This needs the `p256` crate (RustCrypto, MIT/Apache). `coset` and
  `ciborium` are already in the tree for the COSE key and attestation object.
- **User presence:** a confirmation the page can't draw. That means the extension's
  own popup window (`windows.create`), naming the site and the account, or the
  Passwords window, never anything inside the page.
- **User verification:** when a site requires it, a recent master-password
  confirmation, the same grace window "ask for master password" items use.
- **Saving:** a new passkey goes onto the matching login, or a new login, with an edit
  through the core like any other. `fido2Credentials` is encrypted with the item key.
  Items with "ask for master password" ask first, as for filling.

## Interoperability tests

1. **On the test server:**
   - a passkey made here is used to sign in with the official extension, and the
     reverse;
   - `bw get item` shows the same fields after each.
2. **A local relying party** in the test suite: a tiny server using a WebAuthn library.
   It checks attestation `none`, ES256 signatures, flags, counter 0, and the rpId and
   origin rules, including refusals for a wrong origin, a public-suffix rpId, `http`
   and an excluded credential.
3. **Real sites:** webauthn.io and a couple of large ones, in Firefox, Zen and Chromium,
   with the official extension uninstalled and then installed alongside.

## Open questions

- **Two managers in one browser:** whose override wins, and whether to warn about it.
- **Autofill UI:** conditional mediation (`mediation: "conditional"`, passkeys offered
  in the username field's autofill). The official extension supports it, and it needs
  in-page UI.
- **Non-ES256 sites:** whether any site that matters refuses ES256. None found so far.
- **Hardware keys:** the browser's own path stays the fallback for them.

## Order of work, when it's taken up

1. **Read-only:** show an item's passkeys in the item view (site, user name, created),
   and delete one.
2. **Core:** sign and make passkeys, plus the local relying-party tests.
3. **Daemon and Native Messaging:** the three requests, the presence confirmation and
   verification.
4. **Extension:** the opt-in permission, main-world override with fallback, and
   `clientDataJSON` from the tab's origin.
5. **Interop:** the round trips with the official extension, then the security review,
   before anything mentions passkeys.

## Sources

- Bitwarden contributor docs, [passkeys in the browser extension](https://contributing.bitwarden.com/architecture/deep-dives/passkeys/implementations/provider/browser-extension)
  and [credentials](https://contributing.bitwarden.com/architecture/deep-dives/passkeys/credentials)
- Bitwarden clients, [`fido2-authenticator.service.ts`](https://github.com/bitwarden/clients/blob/main/libs/common/src/platform/services/fido2/fido2-authenticator.service.ts)
  and [`fido2-utils.ts`](https://github.com/bitwarden/clients/blob/main/libs/common/src/platform/services/fido2/fido2-utils.ts)
- Bitwarden SDK, [`bitwarden_fido`](https://sdk-api-docs.bitwarden.com/src/bitwarden_fido/lib.rs.html) (credential id parsing)
- FIDO Alliance, [Credential Exchange Format](https://fidoalliance.org/specs/cx/cxf-v1.0-rd-20250313.html) (credential ids as base64url)
- [bitwarden/clients#6925](https://github.com/bitwarden/clients/issues/6925): `bw export` and `fido2Credentials`
- [1Password and Bitwarden's override in Firefox](https://www.1password.community/1password-at-home-31/1password-extension-breaks-bitwarden-passkey-support-24740)
