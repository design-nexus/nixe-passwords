# Passwords — notes for working on this app

- GPL-3.0-only (links `bitwarden-crypto`); `crates/nixe-passwords-proto` is MIT so
  Glimpse and Settings can talk to the daemon without linking GPL code. Design and
  rules: `docs/ARCHITECTURE.md`, `docs/SECURITY.md`; daemon interface:
  `docs/GLIMPSE_API.md`; passkeys (not built): `docs/PASSKEYS.md`; progress: `docs/TASKS.md`.
- Package `nixe-passwords`: the window (`src/main.rs`, `src/app/`) and the daemon
  (`src/bin/nixe-passwordsd.rs`, `src/daemon/`). The daemon must not link GTK: check
  `ldd target/debug/nixe-passwordsd` after dependency changes.
- Vault logic is in `crates/nixe-passwords-core`; only its `crypto.rs` names
  bitwarden-crypto types.
- The daemon only answers the suite's binaries in its own directory (`peer.rs`), so
  run the window and daemon from the same `target/<profile>`; the window starts the
  sibling daemon when no systemd unit is installed.
- Tests: `cargo test -p nixe-passwords -p nixe-passwords-core`. Live tests need the
  throwaway server: `apps/passwords/scripts/test-server.sh start`, then
  `NIXE_PW_TEST_SERVER=https://127.0.0.1:8087 NIXE_PW_TEST_CA=$PWD/target/vaultwarden-test/ca.pem cargo test … -- --ignored --skip client`.
  Never point them at a real server.
- Layout checks: debug builds render to a PNG with `PASSWORDS_SNAPSHOT=out.png`
  (`src/app/snapshot.rs`). Use a short `XDG_RUNTIME_DIR` for scratch runs: socket
  paths are limited to 108 bytes.
