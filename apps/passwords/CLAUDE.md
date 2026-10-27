# Passwords — notes for working on this app

- GPL-3.0-only (links `bitwarden-crypto`); `crates/nyx-passwords-proto` is MIT so
  Glimpse and Settings can talk to the daemon without linking GPL code. Design and
  rules: `docs/ARCHITECTURE.md`, `docs/SECURITY.md`; daemon interface:
  `docs/GLIMPSE_API.md`; passkeys (not built): `docs/PASSKEYS.md`; progress: `docs/TASKS.md`.
- Package `nyx-passwords`: the window (`src/main.rs`, `src/app/`) and the daemon
  (`src/bin/nyx-passwordsd.rs`, `src/daemon/`). The daemon must not link GTK: check
  `ldd target/debug/nyx-passwordsd` after dependency changes.
- Vault logic is in `crates/nyx-passwords-core`; only its `crypto.rs` names
  bitwarden-crypto types.
- The daemon only answers the suite's binaries in its own directory (`peer.rs`), so
  run the window and daemon from the same `target/<profile>`; the window starts the
  sibling daemon when no systemd unit is installed.
- Tests: `cargo test -p nyx-passwords -p nyx-passwords-core`. Live tests need the
  throwaway server: `apps/passwords/scripts/test-server.sh start`, then
  `NYX_PW_TEST_SERVER=https://127.0.0.1:8087 NYX_PW_TEST_CA=$PWD/target/vaultwarden-test/ca.pem cargo test … -- --ignored --skip client`.
  Never point them at a real server.
- Fuzzing: `crates/nyx-passwords-core/fuzz/run.sh [seconds] [target…]` (needs a
  rustup nightly and `cargo install cargo-fuzz`). Targets: sync, enc_string, pairing,
  totp, matching, ssh; seeds in `fuzz/seeds/`, crashes in `fuzz/artifacts/`.
- Layout checks: debug builds render to a PNG with `PASSWORDS_SNAPSHOT=out.png`
  (`src/app/snapshot.rs`). Use a short `XDG_RUNTIME_DIR` for scratch runs: socket
  paths are limited to 108 bytes.
