# Passwords

Native Nixe application for Omarchy. Existing names, application IDs, data paths,
and integrations are preserved.

- Source and application documentation: [apps/passwords](apps/passwords).
- Build: `cargo build --release --locked --manifest-path Cargo.toml`.
- Install: `./install.sh` (preserves existing integration resources).
- Package: `python3 tools/package.py`; notes: `python3 tools/release-notes.py`.
- Development rules and public dependency boundaries: [AGENTS.md](AGENTS.md).

Shared dependencies use immutable local Git sources during migration. Publication
and hosted CI remain gated until approved remote dependency revisions are available.
