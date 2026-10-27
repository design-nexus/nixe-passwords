# Nyx Passwords — SDK and dependency evaluation

Checked 2026-10-18 against crates.io and upstream repositories.

## Licensing

The Passwords packages (`nyx-passwords`, `nyx-passwords-core`) are **GPL-3.0-only**,
because they link Bitwarden's GPL crypto. The rest of Nyx stays MIT. MIT code
(`nyx-core`, `nyx-theme`, `nyx-ui`, `nyx-passwords-proto`) may be linked into the
GPL binaries.

Glimpse, Settings and the browser extension never link the GPL crates. They talk to
the daemon over IPC with `nyx-passwords-proto` (MIT).

## Bitwarden SDK

| Crate | Version | Licence | Published | Use |
| --- | --- | --- | --- | --- |
| `bitwarden-crypto` | 4.0.0 (2026-09-30) | GPL-3.0-only OR Bitwarden SDK Licence | crates.io | **Yes.** Master key and KDFs (PBKDF2-SHA256, Argon2id), master password hash, EncString types 2, 4 and 6 and the v2 COSE format, symmetric and asymmetric key types, key store, zeroizing allocations. |
| `bitwarden-generators` | 4.0.0 | same | crates.io | **No.** It's reachable only through a full `bitwarden-core` client. The core generates with `rand` and bitwarden-crypto's EFF word list instead. |
| `bitwarden-core` | 4.0.0 | same | crates.io | **Evaluate in the spike.** Holds client and auth plumbing. Use it only if it works without unpublished crates and without pulling in its own HTTP stack. |
| `bitwarden-vault` | 1.0.0 on crates.io (2024) | non-standard | stale | **No.** The current version lives only in `bitwarden/sdk-internal`. Cipher models are written here. |
| `bitwarden-api-api`, `-identity` | | | | **No.** Generated clients for the whole API; a small hand-written client covers what's needed and can be checked against Vaultwarden. |

Upstream says: "The password manager interface is unstable and will change without
warning." What that means here:

- pin exact versions;
- every bitwarden type stays inside `crypto.rs` (and `generate.rs`);
- each upgrade is a separate change, tested against the local Vaultwarden.

`bitwarden-crypto` 4.0.0 pulls in `uniffi`, `wasm-bindgen`, `tsify` and RustCrypto
release candidates (`argon2 =0.6.0-rc.8`, `rsa 0.10.0-rc.17`, `pbkdf2 0.13.0-rc`,
`chacha20poly1305 0.11.0-rc`). The spike checks that it builds here, what it adds to
build time and binary size, and that `cargo deny` accepts every licence.

### Alternatives considered

- **rbw (MIT, 1.15.0):** Bitwarden cipherstrings over RustCrypto. Not used:
  - it handles only types 2, 4 and 6, not v2 accounts;
  - its library side is shaped around its own CLI and agent.
  It stays useful as a reading reference for API behaviour against Vaultwarden.
- **RustCrypto primitives composed here:** rejected. It means owning the protocol and
  writing v2 support ourselves.

## Other crates

| Crate | Licence | Use | Already in Cargo.lock |
| --- | --- | --- | --- |
| `reqwest` 0.13 (rustls, json; async) | MIT/Apache | Identity and API clients (0.13, the version bitwarden-crypto already pulls in) | yes (0.13.5 via bitwarden-crypto; 0.12.28 elsewhere) |
| `tokio` 1 | MIT | Daemon runtime | yes (1.53) |
| `zbus` 5 (tokio) | MIT | Peer-to-peer server in the daemon | yes (5.19) |
| `rusqlite` 0.40 (bundled) | MIT | Store | yes |
| `serde`, `serde_json` | MIT/Apache | Wire models | yes |
| `uuid` 1 | MIT/Apache | Device id, cipher ids | yes |
| `zeroize` 1 | MIT/Apache | Buffers outside bitwarden-crypto | transitive |
| `totp-rs` 6 | MIT | TOTP, `otpauth://` parsing | no |
| `psl` 2 | MIT/Apache | Base domain for URI matching | no |
| `url` 2 | MIT/Apache | URI parsing | transitive |
| `wl-clipboard-rs` 0.9 | MIT/Apache | Clipboard owner over data-control | no |
| `zxcvbn` 3 | MIT | Password strength for the security report (the estimator the official clients use) | no (added 2026-10-20) |
| `sha1` 0.11 | MIT/Apache | SHA-1 of passwords for the breach check's k-anonymity prefixes (the range API's format) | yes (0.11.0) |
| `ssh-key` =0.7.0-rc.11 (`ed25519`) | MIT/Apache | SSH key items: reading OpenSSH private keys, generating Ed25519 keys, public keys and `SHA256:` fingerprints, as the official clients store them. Bitwarden's own `bitwarden-ssh` isn't published. The release candidate is pinned because it shares the RustCrypto versions bitwarden-crypto already pulls in (`rsa 0.10` rc, `ed25519-dalek 3`, `rand_core 0.10`, `sha2 0.11`); the stable 0.6 line would add a second, older copy of each | no (added 2026-10-20) |
| `libc` | MIT/Apache | `SO_PEERCRED`, `SO_PEERPIDFD`, `prctl`, `flock` | yes |
| `rand` 0.10 | MIT/Apache | The password generator (thread CSPRNG); bitwarden-generators needs a full bitwarden-core client, so it isn't used | via bitwarden-crypto |
| `x25519-dalek`, `hkdf`, `aes-gcm` | BSD-3/MIT/Apache | Native Messaging pairing (Phase 3) | partly |
| `gtk4` 0.11 | MIT | The app | yes |

The daemon and the bridge don't link GTK. The app and the Settings helper link GTK,
but not tokio or reqwest; they talk to the daemon through gio's D-Bus, as Glimpse will.

## Vaultwarden

The target is the latest Vaultwarden, 1.37.4 (2026-10-05). The spike checks these
against a local instance, using the official `bw` CLI to create and read data:

| Behaviour | Why it matters |
| --- | --- |
| `prelogin` KDF fields for PBKDF2 and Argon2id | Unlock |
| Password grant with `client_id=desktop`, `deviceType=8` | Login |
| Email and authenticator 2FA; new-device verification | Login |
| `/api/sync` shape: `profile.key`, `privateKey`, org keys, `cipher.key` | Decryption |
| Whether v2 accounts (COSE user keys) are served | Decryption |
| `lastKnownRevisionDate` rejection on PUT | Conflicts |
| Soft delete and restore | Delete with undo |
| Icon service path | Opt-in icons |

Each result is recorded here when the spike runs.

## Spike results

**2026-10-18, build:** `bitwarden-crypto =4.0.0` builds in the workspace.
- A clean debug build of the crate and its dependencies takes 25 s.
- It adds 102 crates to `Cargo.lock` and changes no existing versions.
- `uniffi`, `wasm-bindgen` and `tsify` are optional and not pulled in.
- It pulls in `reqwest` 0.13 (through `bitwarden-api-key-connector`). Use 0.13 in the
  core too, so there's only one in the Passwords binaries.
- The API needed for unlock is public: `MasterKey::derive`, `derive_master_key_hash`,
  `decrypt_user_key`, `KeyDecryptable` for `EncString`, `PrivateKey::from_der` and
  `UnsignedSharedKey::decapsulate_key_unsigned`.

**2026-10-18, Vaultwarden 1.37.4 round trip** (`crates/nyx-passwords-core/tests/spike.rs`,
server from `apps/passwords/scripts/test-server.sh`; passes for a PBKDF2 600 000 and an
Argon2id 3/64 MiB/4 account):

| Behaviour | Result |
| --- | --- |
| Sign-up | `/identity/accounts/register` is gone. It's `register/send-verification-email` (returns the token when mail is off), then `register/finish` with `userSymmetricKey` and `userAsymmetricKeys`. Test fixture only. |
| Prelogin and password grant | Work with `client_id=desktop`, `deviceType=8`. No new-device verification when the server has no mail configured; with mail, `REQUIRE_DEVICE_EMAIL` can make it send a notice. Check on a real server before release. |
| Decryption | Every field `bw` 2026.2.0 wrote matches what bitwarden-crypto decrypts: login, TOTP, URIs, note, card, identity, custom fields, folders, and an organization item through the RSA-wrapped org key. All EncStrings are type 2. |
| v2 accounts | Not produced by Vaultwarden 1.37.4 sign-up or clients. bitwarden-crypto parses them, but there's no live check. |
| Per-cipher keys | Vaultwarden has no client flag for them, so official clients don't create them there; imported data can still have them. A cipher with its own key written here reads back correctly in `bw`. |
| `uriChecksum` | **Required on write.** Official clients drop a URI whose encrypted SHA-256 checksum is missing. |
| Cipher PUT | Needs `encryptedFor` (the user id). The full synced object is rejected (422); send only the request fields. |
| Conflicts | A stale `lastKnownRevisionDate` gets 400 "out of date", but only when the server copy is more than 1 s newer. Edits within a second of each other aren't detected. |
| Refresh | `grant_type=refresh_token` with `client_id=desktop` works. |
| Soft delete / restore | `PUT /api/ciphers/{id}/delete` and `/restore` work. |
| Login rate limit | 10 per minute by default; the test server raises it. |
| New item types | Vaultwarden 1.37 knows types 6 to 8 (bank account, driver's licence, passport) behind a client flag. The model must keep unknown types intact. |

**cargo deny** (`crates/nyx-passwords-core/deny.toml`):
- Licences: pass.
- `rustls` 0.23.45: four advisories (RUSTSEC-2026-0346, -0347 and two more), fixed in
  0.23.46. That lockfile entry is shared with the rest of the workspace.
- `rsa` 0.10.0-rc.19: RUSTSEC-2023-0071 (Marvin timing side channel), no fixed version.
  - Exposure here: RSA decryption runs only locally, on org-key blobs from the user's
    own server, and its timing isn't observable remotely.
  - Proposed: accept it with this reason in `deny.toml`, and revisit with each
    bitwarden-crypto upgrade.
