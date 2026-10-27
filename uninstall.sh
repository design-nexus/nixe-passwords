#!/usr/bin/env bash
# Remove Nyx apps.
#
#   ./uninstall.sh music pdf          remove those apps
#   ./uninstall.sh all --purge        remove every app and its settings and data
set -euo pipefail

ALL=(passwords)
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31m==>\033[0m %s\n' "$*" >&2; exit 1; }

if [[ $# == 0 || ${1:-} == --* ]]; then set -- passwords "$@"; fi
apps=() purge=false
for a in "$@"; do
  case $a in
    all) apps=("${ALL[@]}") ;;
    gallery) apps+=(photos) ;;
    write | sheets | present) apps+=(office) ;;
    --purge) purge=true ;;
    *) printf '%s\n' "${ALL[@]}" | grep -qx "$a" || die "No app called '$a'. Apps: ${ALL[*]}"; apps+=("$a") ;;
  esac
done
((${#apps[@]})) || die "Name the apps to remove (or 'all'): ${ALL[*]}"

for selected in "${apps[@]}"; do
  [[ $selected == passwords ]] || die "This repository removes only passwords."
done
bin="$HOME/.local/bin"
share="${XDG_DATA_HOME:-$HOME/.local/share}"
config="${XDG_CONFIG_HOME:-$HOME/.config}"
for a in "${apps[@]}"; do
  case $a in
    settings) bins="nyx-settings nyx-settings-helper nyx-goa-helper" ids="Settings" ;;
    store) bins="nyx-store" ids="Store" ;;
    media-player) bins="nyx-media-player" ids="MediaPlayer" ;;
    office) bins="nyx-office nyx-write nyx-sheets nyx-present" ids="Write Sheets Present" ;;
    photos) bins="nyx-photos nyx-viewer" ids="Photos PhotoViewer" ;;
    pdf) bins="nyx-pdf" ids="Pdf" ;;
    news) bins="nyx-news nyx-news-glimpse" ids="News" ;;
    capture) bins="nyx-capture nyx-capture-glimpse" ids="Capture" ;;
    pulse) bins="nyx-pulse nyx-pulse-glimpse" ids="Pulse" ;;
    *) bins="nyx-$a" ids="${a^}" ;;
  esac
  if [[ $a == glimpse ]]; then
    systemctl --user disable --now nyx-glimpsed.service 2>/dev/null || true
    "$bin/nyx-glimpse" integration restore
    rm -f "$config/systemd/user/nyx-glimpsed.service"
    systemctl --user daemon-reload 2>/dev/null || true
    rm -rf "$share/nyx-settings/extensions/glimpse" "$share/settings/extensions/glimpse"
    bins="nyx-glimpse nyx-glimpsed nyx-glimpse-settings"
  fi
  if [[ $a == passwords ]]; then
    # Stopping the service locks the vault and clears a copy it left on the clipboard.
    systemctl --user stop nyx-passwords.service 2>/dev/null || true
    rm -f "$config/systemd/user/nyx-passwords.service"
    systemctl --user daemon-reload 2>/dev/null || true
    rm -rf "$share/nyx-settings/extensions/passwords" "$share/settings/extensions/passwords"
    for dir in "$HOME/.mozilla/native-messaging-hosts" "$config/chromium/NativeMessagingHosts" \
      "$config/google-chrome/NativeMessagingHosts" "$config/BraveSoftware/Brave-Browser/NativeMessagingHosts"; do
      rm -f "$dir/io.github.design_nexus.nyx.passwords.json"
    done
    bins="nyx-passwords nyx-passwordsd nyx-passwords-settings nyx-passwords-bridge nyx-passwords-assistant"
    # The session token in the desktop keyring; the vault itself stays on the server.
    [[ $purge == true ]] && command -v secret-tool >/dev/null && secret-tool clear application nyx-passwords 2>/dev/null || true
  fi
  if [[ $a == store ]]; then
    sudo rm -f /usr/local/lib/nyx-store/nyx-store-helper /usr/share/polkit-1/actions/io.github.design_nexus.nyx.store.policy
    # Keep root-owned source records even with --purge; reinstalling must not lose provenance.
  fi
  if [[ $a == git ]] && command -v pacman >/dev/null && pacman -Qq nyx-git >/dev/null 2>&1; then
    if [[ -t 0 ]]; then sudo pacman -R --noconfirm nyx-git;
    else pkexec pacman -R --noconfirm nyx-git; fi
  fi
  say "Removing $a"
  for b in $bins; do pkill -x "$b" 2>/dev/null || true; rm -f "$bin/$b"; done
  for id in $ids; do
    rm -f "$share/applications/io.github.design_nexus.nyx.$id.desktop" "$share/icons/hicolor/scalable/apps/io.github.design_nexus.nyx.$id.svg"
  done
  [[ $a == office ]] && rm -f "$share/mime/packages/nyx-office.xml" && update-mime-database "$share/mime" 2>/dev/null || true
  [[ $a == fonts && $purge == true ]] && rm -rf "$share/fonts/nyx-fonts"
  [[ $a == settings ]] && rm -rf "$config/omarchy/plugins/design-nexus.settings-gear"
  slug="nyx-$a"
  rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}/${slug:?}"
  if [[ $purge == true ]]; then
    rm -rf "${config:?}/${slug:?}" "${share:?}/${slug:?}" "${XDG_STATE_HOME:-$HOME/.local/state}/${slug:?}"
  fi
done

# Floating-window rules for apps that are gone.
hypr="$config/hypr/nyx.lua"
if [[ " ${apps[*]} " != " glimpse " && -f $hypr ]]; then
  [[ -x $bin/nyx-notepad ]] || sed -i '/nyx\\\\.Notepad/d' "$hypr"
  [[ -x $bin/nyx-archive ]] || sed -i '/nyx\\\\.Archive/d' "$hypr"
  [[ -x $bin/nyx-weather ]] || sed -i '/nyx\\\\.Weather/d' "$hypr"
  [[ -x $bin/nyx-capture ]] || sed -i '/nyx\\\\.Capture\\\\.Pin/d' "$hypr"
  if ! grep -q 'o\.window' "$hypr"; then
    rm -f "$hypr"
    sed -i '/^require("hypr.nyx")/d' "$config/hypr/hyprland.lua" 2>/dev/null || true
  fi
  hyprctl reload >/dev/null 2>&1 || true
fi

# Weather's bar widget goes with Weather.
if [[ ! -x $bin/nyx-weather && -d $config/omarchy/plugins/design-nexus.weather ]]; then
  rm -rf "$config/omarchy/plugins/design-nexus.weather"
  omarchy-shell shell rescanPlugins >/dev/null 2>&1 || true
fi

# The suite's own command goes with the last app.
compgen -G "$bin/nyx-*" >/dev/null || rm -f "$bin/nyx"

update-desktop-database "$share/applications" 2>/dev/null || true
gtk-update-icon-cache -q "$share/icons/hicolor" 2>/dev/null || true
say "Done."
