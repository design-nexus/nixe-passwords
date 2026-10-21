# Passwords

Native Nixe application for Omarchy. Existing names, application IDs, data paths,
and integrations are preserved.

- Source and application documentation: [apps/passwords](apps/passwords).
- Build: `cargo build --release --locked --manifest-path Cargo.toml`.
- Install: `./install.sh` (preserves existing integration resources).
- Package: `python3 tools/package.py`; notes: `python3 tools/release-notes.py`.
- Development rules and public dependency boundaries: [AGENTS.md](AGENTS.md).

Shared dependencies are pinned to immutable GitHub revisions.
Use main for the standalone build; preserved tags describe historical source.
