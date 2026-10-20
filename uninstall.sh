#!/usr/bin/env bash
# Remove Nixe apps.
#
#   ./uninstall.sh music pdf          remove those apps
#   ./uninstall.sh all --purge        remove every app and its settings and data
set -euo pipefail

ALL=(settings contacts tasks torrents pdf notepad music media-player chat fonts archive office photos glimpse store git passwords weather capture)
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31m==>\033[0m %s\n' "$*" >&2; exit 1; }

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

bin="$HOME/.local/bin"
share="${XDG_DATA_HOME:-$HOME/.local/share}"
config="${XDG_CONFIG_HOME:-$HOME/.config}"
for a in "${apps[@]}"; do
  case $a in
    settings) bins="nixe-settings nixe-settings-helper nixe-goa-helper" ids="Settings" ;;
    store) bins="nixe-store" ids="Store" ;;
    media-player) bins="nixe-media-player" ids="MediaPlayer" ;;
    office) bins="nixe-office nixe-write nixe-sheets nixe-present" ids="Write Sheets Present" ;;
    photos) bins="nixe-photos nixe-viewer" ids="Photos PhotoViewer" ;;
    pdf) bins="nixe-pdf" ids="Pdf" ;;
    capture) bins="nixe-capture nixe-capture-glimpse" ids="Capture" ;;
    *) bins="nixe-$a" ids="${a^}" ;;
  esac
  if [[ $a == glimpse ]]; then
    systemctl --user disable --now nixe-glimpsed.service 2>/dev/null || true
    "$bin/nixe-glimpse" integration restore
    rm -f "$config/systemd/user/nixe-glimpsed.service"
    systemctl --user daemon-reload 2>/dev/null || true
    rm -rf "$share/nixe-settings/extensions/glimpse" "$share/settings/extensions/glimpse"
    bins="nixe-glimpse nixe-glimpsed nixe-glimpse-settings"
  fi
  if [[ $a == passwords ]]; then
    # Stopping the service locks the vault and clears a copy it left on the clipboard.
    systemctl --user stop nixe-passwords.service 2>/dev/null || true
    rm -f "$config/systemd/user/nixe-passwords.service"
    systemctl --user daemon-reload 2>/dev/null || true
    rm -rf "$share/nixe-settings/extensions/passwords" "$share/settings/extensions/passwords"
    for dir in "$HOME/.mozilla/native-messaging-hosts" "$config/chromium/NativeMessagingHosts" \
      "$config/google-chrome/NativeMessagingHosts" "$config/BraveSoftware/Brave-Browser/NativeMessagingHosts"; do
      rm -f "$dir/io.github.design_nexus.nixe.passwords.json"
    done
    bins="nixe-passwords nixe-passwordsd nixe-passwords-settings nixe-passwords-bridge nixe-passwords-assistant"
    # The session token in the desktop keyring; the vault itself stays on the server.
    [[ $purge == true ]] && command -v secret-tool >/dev/null && secret-tool clear application nixe-passwords 2>/dev/null || true
  fi
  if [[ $a == store ]]; then
    sudo rm -f /usr/local/lib/nixe-store/nixe-store-helper /usr/share/polkit-1/actions/io.github.design_nexus.nixe.store.policy
    # Keep root-owned source records even with --purge; reinstalling must not lose provenance.
  fi
  if [[ $a == git ]] && command -v pacman >/dev/null && pacman -Qq nixe-git >/dev/null 2>&1; then
    if [[ -t 0 ]]; then sudo pacman -R --noconfirm nixe-git;
    else pkexec pacman -R --noconfirm nixe-git; fi
  fi
  say "Removing $a"
  for b in $bins; do pkill -x "$b" 2>/dev/null || true; rm -f "$bin/$b"; done
  for id in $ids; do
    rm -f "$share/applications/io.github.design_nexus.nixe.$id.desktop" "$share/icons/hicolor/scalable/apps/io.github.design_nexus.nixe.$id.svg"
  done
  [[ $a == office ]] && rm -f "$share/mime/packages/nixe-office.xml" && update-mime-database "$share/mime" 2>/dev/null || true
  [[ $a == fonts && $purge == true ]] && rm -rf "$share/fonts/nixe-fonts"
  [[ $a == settings ]] && rm -rf "$config/omarchy/plugins/design-nexus.settings-gear"
  slug="nixe-$a"
  rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}/${slug:?}"
  if [[ $purge == true ]]; then
    rm -rf "${config:?}/${slug:?}" "${share:?}/${slug:?}" "${XDG_STATE_HOME:-$HOME/.local/state}/${slug:?}"
  fi
done

# Floating-window rules for apps that are gone.
hypr="$config/hypr/nixe.lua"
if [[ " ${apps[*]} " != " glimpse " && -f $hypr ]]; then
  [[ -x $bin/nixe-notepad ]] || sed -i '/nixe\\\\.Notepad/d' "$hypr"
  [[ -x $bin/nixe-archive ]] || sed -i '/nixe\\\\.Archive/d' "$hypr"
  [[ -x $bin/nixe-capture ]] || sed -i '/nixe\\\\.Capture\\.Pin/d' "$hypr"
  if ! grep -q 'o\.window' "$hypr"; then
    rm -f "$hypr"
    sed -i '/^require("hypr.nixe")/d' "$config/hypr/hyprland.lua" 2>/dev/null || true
  fi
  hyprctl reload >/dev/null 2>&1 || true
fi

# The suite's own command goes with the last app.
compgen -G "$bin/nixe-*" >/dev/null || rm -f "$bin/nixe"

update-desktop-database "$share/applications" 2>/dev/null || true
gtk-update-icon-cache -q "$share/icons/hicolor" 2>/dev/null || true
say "Done."
