#!/usr/bin/env bash
# Runs every fuzz target for a while from its seeds (seeds/TARGET), with the nightly
# toolchain rustup has. Crashes land in artifacts/TARGET.
#   ./run.sh [seconds per target] [target…]
set -euo pipefail
cd "$(dirname "$0")"
toolchain=${FUZZ_TOOLCHAIN:-$(rustup toolchain list | grep -o '^nightly[^ ]*' | head -1)}
cargo=$(rustup which cargo --toolchain "$toolchain")
export CARGO=$cargo RUSTC=$(rustup which rustc --toolchain "$toolchain") PATH=$(dirname "$cargo"):$PATH
seconds=${1:-60}
shift || true
targets=("$@")
[[ ${#targets[@]} -gt 0 ]] || targets=(sync enc_string pairing totp matching ssh)
for t in "${targets[@]}"; do
  mkdir -p "corpus/$t"
  echo "== $t (${seconds} s)"
  cargo-fuzz run -O "$t" "corpus/$t" "seeds/$t" -- -max_total_time="$seconds" -rss_limit_mb=2048 -timeout=10 2>&1 \
    | grep -E 'Done [0-9]+ runs|ERROR|SUMMARY|panicked|Test unit written|deadly signal|timeout' || true
done
