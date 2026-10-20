//! The vault daemon: see apps/passwords/docs/ARCHITECTURE.md. Linking bitwarden-crypto
//! installs its zeroizing global allocator, so freed memory (D-Bus messages, JSON that
//! carried a secret) is wiped.

fn main() {
    nixe_passwords::daemon::run()
}
