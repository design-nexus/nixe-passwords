#!/usr/bin/env bash
# Builds the browser extension from apps/passwords/browser:
#   OUT/chromium/                       for Chromium, Chrome and Brave (Load unpacked)
#   OUT/nixe-passwords-firefox.xpi      for Firefox and Zen
#
#   apps/passwords/scripts/build-extension.sh [OUT]   (default: target/passwords-browser)
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/../.." && pwd)
out=${1:-$root/target/passwords-browser}
icon="$root/crates/nixe-icons/apps/io.github.design_nexus.nixe.Passwords.svg"
command -v rsvg-convert >/dev/null || { echo "rsvg-convert (librsvg) is needed for the icons" >&2; exit 1; }
command -v zip >/dev/null || { echo "zip is needed for the Firefox package" >&2; exit 1; }

rm -rf "$out"
for browser in chromium firefox; do
  dir="$out/$browser"
  mkdir -p "$dir"
  cp "$here"/browser/src/* "$dir/"
  cp "$here/browser/manifest.$browser.json" "$dir/manifest.json"
  for size in 48 128; do rsvg-convert -w "$size" -h "$size" "$icon" -o "$dir/icon-$size.png"; done
done
(cd "$out/firefox" && zip -q -r -X "$out/nixe-passwords-firefox.xpi" .)
rm -rf "$out/firefox"
echo "$out"
