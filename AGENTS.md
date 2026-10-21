# Passwords

Application source: apps/passwords. Owned domain crates: nixe-passwords-core, nixe-passwords-proto.
Keep all existing runtime integration resources and public protocols.

Commands: `cargo build --release --locked --manifest-path Cargo.toml`; `./install.sh`

Use the public, pinned shared crates; never import another application's internals.
Keep application names, IDs, paths, D-Bus interfaces, and data formats stable.
Use canonical STYLE.md from the pinned nixe-design dependency. Reuse existing
widgets, theme tokens, icons, and shortcuts. Media Player defines video controls.
Run essential targeted checks only. Do not download models or run inference for
routine verification. Install app updates without opening/restarting them.
Common guidance: https://github.com/design-nexus/nixe/blob/main/docs/AGENTS_COMMON.md
This file carries the essential common rules so offline work remains possible.

This is a local migration pilot. Dependencies use immutable local Git revisions.
Do not publish until file:// dependencies are replaced with approved remote URLs,
lockfiles are regenerated, and compatibility checks pass.
