#!/usr/bin/env bash
# Install Nixe apps.
#
#   curl -fsSL https://raw.githubusercontent.com/design-nexus/nixe/main/install.sh | bash -s -- music pdf
#   curl -fsSL https://raw.githubusercontent.com/design-nexus/nixe/main/install.sh | bash -s -- all
#
# Apps: settings contacts tasks torrents pdf notepad music media-player theater chat fonts archive office photos glimpse store git passwords weather news capture
# Options:
#   --default  make the installed apps open their file types
#   --gear     also add the Settings gear to the Omarchy bar (with settings)
#   --list     list the apps and exit
set -euo pipefail

REPO="design-nexus/nixe"
ALL=(settings contacts tasks torrents pdf notepad music media-player theater chat fonts archive office photos glimpse store git passwords weather news capture)

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m==>\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m==>\033[0m %s\n' "$*" >&2; exit 1; }

# ---------- What each app is ----------
# dir: folder under apps/   pkg: cargo package   bins: programs it installs
# deps: Arch packages it needs   old_*: what the app was called before Nixe
app_info() {
  dir=$1 pkg="nixe-$1" bins="nixe-$1" deps="" ids="" old_bins="" old_desktops="" old_icons="" defaults=false
  case $1 in
    settings) ids="Settings" old_bins="settings settings-helper"; bins="nixe-settings nixe-settings-helper nixe-goa-helper" ;;
    glimpse) ids="Glimpse" bins="nixe-glimpse nixe-glimpsed nixe-glimpse-settings" deps="bubblewrap" ;;
    contacts) ids="Contacts" defaults=true ;;
    git) ids="Git" deps="gtksourceview5 libsecret git-lfs" ;;
    passwords) ids="Passwords" bins="nixe-passwords nixe-passwordsd nixe-passwords-settings nixe-passwords-bridge nixe-passwords-assistant" deps="libsecret librsvg zip" ;;
    store) ids="Store" bins="nixe-store nixe-store-helper" deps="pacman appstream libarchive polkit base-devel libjxl" ;;
    tasks) ids="Tasks" old_bins="tasks" ;;
    torrents) ids="Torrents" old_bins="torrents" deps="libtorrent-rasterbar boost" defaults=true ;;
    pdf) ids="Pdf" old_bins="pdf" deps="poppler-glib" defaults=true ;;
    notepad) ids="Notepad" old_bins="notepad" ;;
    music) ids="Music" old_bins="music" deps="gstreamer gst-plugins-base gst-plugins-good gst-libav" defaults=true ;;
    media-player) ids="MediaPlayer" old_bins="media-player" deps="mpv ffmpeg" defaults=true ;;
    theater) ids="Theater" deps="mpv ffmpeg libsecret" ;;
    chat) ids="Chat" old_bins="chat" ;;
    fonts) ids="Fonts" old_bins="fonts" deps="fontconfig pango tar xz" ;;
    archive) ids="Archive" old_bins="archive" deps="7zip" defaults=true ;;
    weather) ids="Weather" ;;
    news) ids="News" deps="libsecret" bins="nixe-news nixe-news-glimpse" ;;
    capture) ids="Capture" deps="grim wl-clipboard tesseract gtk4-layer-shell tesseract-data-eng" bins="nixe-capture nixe-capture-glimpse" ;;
    office)
      bins="nixe-office nixe-write nixe-sheets nixe-present" ids="Write Sheets Present" defaults=true
      deps="gtksourceview5 libspelling hunspell hunspell-en_us"
      old_bins="nexus-office nexus-write nexus-sheets nexus-present"
      old_desktops="nexus-write.desktop nexus-sheets.desktop nexus-present.desktop" ;;
    assistant) dir=assistant pkg="" bins="nixe-assistant nixe-assistantd" ids="" deps="nodejs npm jq ripgrep" ;;
    photos)
      dir=gallery bins="nixe-photos nixe-viewer" ids="Photos PhotoViewer" defaults=true
      old_bins="nexus-photos npv nexus-photos-viewer" old_desktops="nexus-photos.desktop npv.desktop"
      old_icons="io.github.nexus.photos.svg" ;;
    *) return 1 ;;
  esac
  for id in $ids; do
    [[ $1 == office || $1 == photos ]] || old_desktops+=" io.github.design_nexus.$id.desktop"
    [[ $1 == photos ]] || old_icons+=" io.github.design_nexus.$id.svg"
  done
}

# ---------- Arguments ----------
apps=() make_default=false gear=false
for a in "$@"; do
  case $a in
    all) apps=("${ALL[@]}") ;;
    gallery) apps+=(photos) ;;
    write | sheets | present) apps+=(office) ;;
    --default) make_default=true ;;
    --gear) gear=true ;;
    --list) printf '%s\n' "${ALL[@]}"; exit 0 ;;
    -h | --help) sed -n '2,13p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) app_info "$a" >/dev/null || die "No app called '$a'. Apps: ${ALL[*]}"; apps+=("$a") ;;
  esac
done
((${#apps[@]})) || die "Name the apps to install (or 'all'): ${ALL[*]}"
mapfile -t apps < <(printf '%s\n' "${apps[@]}" | awk '!seen[$0]++')

command -v hyprctl >/dev/null || warn "Hyprland wasn't found. Nixe apps are made for Omarchy (Hyprland), but run elsewhere too."

# Keep a pacman-managed Git installation managed by pacman on subsequent updates.
if [[ " ${apps[*]} " == *" git "* ]] && command -v pacman >/dev/null && pacman -Qq nixe-git >/dev/null 2>&1; then
  package_helper=""
  if [[ -n ${BASH_SOURCE[0]:-} && -f ${BASH_SOURCE[0]} ]]; then
    package_helper="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/apps/git/packaging/build.sh"
  fi
  [[ -x $package_helper ]] || die "Git is managed by pacman. Update from a Nixe checkout with apps/git/packaging/build.sh --install."
  "$package_helper" --install
  remaining=()
  for a in "${apps[@]}"; do [[ $a == git ]] || remaining+=("$a"); done
  apps=("${remaining[@]}")
  ((${#apps[@]})) || exit 0
fi

# ---------- Dependencies ----------
if command -v pacman >/dev/null; then
  need=()
  wanted="gtk4 pkgconf gcc git curl"
  for a in "${apps[@]}"; do app_info "$a"; wanted+=" $deps"; done
  for p in $wanted; do pacman -Qq "$p" >/dev/null 2>&1 || need+=("$p"); done
  if ((${#need[@]})); then
    say "Installing ${need[*]}"
    sudo pacman -S --needed --noconfirm "${need[@]}"
  fi
fi

# ---------- Source ----------
here=""
[[ -n ${BASH_SOURCE[0]:-} && -f ${BASH_SOURCE[0]} ]] && here=$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
locked=(--locked)
# A release built by CI, for an app: its tag, or nothing.
release_tag() {
  curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=100" 2>/dev/null |
    grep -o "\"tag_name\": *\"$1-v[^\"]*\"" | head -1 | sed 's/.*"\([^"]*\)"$/\1/'
}

# The assistant builds and installs itself (CUDA, its own services and binds).
if [[ " ${apps[*]} " == *" assistant "* ]]; then
  mapfile -t apps < <(printf '%s\n' "${apps[@]}" | grep -vx assistant || true)
  if [[ -n $here && -x $here/apps/assistant/scripts/install.sh ]]; then
    asrc="$here/apps/assistant"
  else
    say "Fetching the assistant"
    git clone -q --depth 1 --filter=blob:none --sparse "https://github.com/$REPO.git" "$work/assistant"
    git -C "$work/assistant" sparse-checkout set apps/assistant
    asrc="$work/assistant/apps/assistant"
  fi
  command -v cargo >/dev/null || die "Rust (cargo) is needed to build the assistant."
  say "Building and installing the assistant (it takes a while the first time)"
  "$asrc/scripts/install.sh"
  ((${#apps[@]})) || exit 0
fi

prebuilt=false
if [[ -n $here && -f $here/.prebuilt ]]; then
  src=$here
  prebuilt=true
elif [[ -n $here && -f $here/Cargo.toml && -d $here/crates ]]; then
  src=$here
elif [[ ${NIXE_BUILD:-} != 1 ]] && tags=$(for a in "${apps[@]}"; do t=$(release_tag "$a"); [[ -n $t ]] || exit 1; echo "$t"; done); then
  # Every app asked for has a release: unpack them over one another, no build.
  say "Fetching ${apps[*]}"
  src="$work/src"
  mkdir -p "$src"
  for t in $tags; do
    curl -fsSL "https://github.com/$REPO/releases/download/$t/${t%-v*}-x86_64.tar.gz" | tar -xz -C "$src"
  done
  prebuilt=true
else
  # Fetch only the shared crates and the apps asked for.
  say "Fetching the source"
  git clone -q --depth 1 --filter=blob:none --sparse "https://github.com/$REPO.git" "$work/src"
  dirs=(crates bin)
  for a in "${apps[@]}"; do app_info "$a"; dirs+=("apps/$dir"); done
  # Their Glimpse plugins build alongside them (see the Build step).
  for a in news capture; do
    if [[ " ${apps[*]} " == *" $a "* ]]; then dirs+=("apps/$a-glimpse"); fi
  done
  git -C "$work/src" sparse-checkout set "${dirs[@]}"
  src="$work/src"
  # The lockfile lists every app; with only some present, cargo trims it.
  locked=()
fi

# ---------- Build ----------
if [[ $prebuilt == false ]]; then
  if ! command -v cargo >/dev/null; then
    command -v pacman >/dev/null || die "Rust (cargo) is needed to build Nixe apps. Install it and run this again."
    say "Installing rust"
    sudo pacman -S --needed --noconfirm rust
  fi
  pkgs=()
  for a in "${apps[@]}"; do app_info "$a"; pkgs+=(-p "$pkg"); done
  if [[ " ${apps[*]} " == *" settings "* ]]; then pkgs+=(-p nixe-goa-helper); fi
  if [[ " ${apps[*]} " == *" news "* ]]; then pkgs+=(-p nixe-news-glimpse); fi
  if [[ " ${apps[*]} " == *" capture "* ]]; then pkgs+=(-p nixe-capture-glimpse); fi
  say "Building ${apps[*]} (a few minutes the first time)"
  (cd "$src" && cargo build --release "${locked[@]}" "${pkgs[@]}")
fi

# ---------- Install ----------
bin="$HOME/.local/bin"
share="${XDG_DATA_HOME:-$HOME/.local/share}"
config="${XDG_CONFIG_HOME:-$HOME/.config}"
desk="$share/applications"
icons="$share/icons/hicolor/scalable/apps"
mkdir -p "$bin" "$desk" "$icons"

# A program of ours from before the rename: one that names the old app ids
# (Settings' account helper names none, but has its own commands).
ours() {
  [[ -f $1 ]] || return 1
  grep -aqE 'design_nexus|nexus\.photos|nexus-office' "$1" && return 0
  [[ $(basename "$1") == settings-helper ]] && grep -aq 'add-user' "$1"
}

mimeapps="$config/mimeapps.list"
for a in "${apps[@]}"; do
  app_info "$a"
  d="$src/apps/$dir"
  say "Installing $a"
  for b in $bins; do
    if [[ -f $src/target/release/$b ]]; then
      install -m 755 "$src/target/release/$b" "$bin/$b"
    elif [[ -f $d/packaging/$b ]]; then
      install -m 755 "$d/packaging/$b" "$bin/$b"
    fi
  done
  for f in "$d"/data/io.github.design_nexus.nixe.*.desktop; do install -m 644 "$f" "$desk/"; done
  for id in $ids; do install -m 644 "$src/crates/nixe-icons/apps/io.github.design_nexus.nixe.$id.svg" "$icons/"; done
  if [[ $a == news && -f $src/target/release/nixe-news-glimpse ]]; then
    plug="$share/nixe-news/glimpse"
    mkdir -p "$plug"
    install -m 755 "$src/target/release/nixe-news-glimpse" "$plug/nixe-news-glimpse"
    install -m 644 "$src/apps/news-glimpse/plugin.toml" "$plug/plugin.toml"
  fi
  if [[ $a == capture && -f $src/target/release/nixe-capture-glimpse ]]; then
    plug="$share/nixe-capture/glimpse"
    mkdir -p "$plug"
    install -m 755 "$src/target/release/nixe-capture-glimpse" "$plug/nixe-capture-glimpse"
    install -m 644 "$src/apps/capture-glimpse/plugin.toml" "$plug/plugin.toml"
  fi
  if [[ -f $d/data/nixe-office.xml ]]; then
    mkdir -p "$share/mime/packages"
    install -m 644 "$d/data/nixe-office.xml" "$share/mime/packages/"
    rm -f "$share/mime/packages/nexus-office.xml"
    update-mime-database "$share/mime" 2>/dev/null || true
  fi

  if [[ $a == store ]]; then
    say "Installing Store's root-owned package helper and authorization policy"
    sudo install -d -m 755 /usr/local/lib/nixe-store /var/lib/nixe-store
    sudo install -m 755 "$src/target/release/nixe-store-helper" /usr/local/lib/nixe-store/nixe-store-helper
    sudo install -m 644 "$d/data/io.github.design_nexus.nixe.store.policy" /usr/share/polkit-1/actions/io.github.design_nexus.nixe.store.policy
    # The privileged entry point is never executed from a user-writable directory.
    rm -f "$bin/nixe-store-helper"
  fi

  if [[ $a == passwords ]]; then
    # The vault service: started by the app (and Glimpse) when they need it.
    mkdir -p "$config/systemd/user"
    install -m 644 "$d/data/nixe-passwords.service" "$config/systemd/user/nixe-passwords.service"
    systemctl --user daemon-reload 2>/dev/null || true
    # A running vault restarts on the new build, which locks it.
    systemctl --user try-restart nixe-passwords.service 2>/dev/null || true
    for host in nixe-settings settings; do
      ext="$share/$host/extensions/passwords"
      mkdir -p "$ext"
      cat >"$ext/extension.toml" <<'MANIFEST'
id = "passwords"
name = "Passwords"
category = "Accounts"
version = "0.1.0"
description = "Vault locking, clipboard clearing and Glimpse."
exec = "nixe-passwords-settings"
MANIFEST
    done
    # The browser extension, built for installing from the browser, and the native
    # messaging host for each browser that has a profile here.
    "$d/scripts/build-extension.sh" "$share/nixe-passwords/browser" >/dev/null
    host=io.github.design_nexus.nixe.passwords
    for target in "firefox:$HOME/.mozilla/native-messaging-hosts" \
      "chromium:$config/chromium/NativeMessagingHosts" \
      "chromium:$config/google-chrome/NativeMessagingHosts" \
      "chromium:$config/BraveSoftware/Brave-Browser/NativeMessagingHosts"; do
      kind=${target%%:*} dir=${target#*:}
      [[ -d $(dirname "$dir") ]] || continue
      mkdir -p "$dir"
      sed "s|@BRIDGE@|$bin/nixe-passwords-bridge|" "$d/browser/hosts/$kind.json" >"$dir/$host.json"
    done
  fi

  if [[ $a == glimpse ]]; then
    gshare="$share/nixe-glimpse"
    mkdir -p "$gshare/scripts" "$gshare/inference"
    cp -a "$d/scripts/." "$gshare/scripts/"
    cp -a "$d/inference/." "$gshare/inference/"
    for host in nixe-settings settings; do
      ext="$share/$host/extensions/glimpse"
      mkdir -p "$ext"
      cat >"$ext/extension.toml" <<'MANIFEST'
id = "glimpse"
name = "Glimpse"
category = "Desktop"
version = "0.1.0"
description = "Local search, sources, semantic models, plugins, and privacy."
exec = "nixe-glimpse-settings"
MANIFEST
    done
    [[ ! -f $config/hypr/hyprland.lua ]] || "$bin/nixe-glimpse" integration window
  fi

  # The same app from before the rename.
  for b in $old_bins; do ours "$bin/$b" && rm -f "$bin/$b" && say "Removed the old $b"; done
  for f in $old_desktops; do rm -f "$desk/$f"; done
  for f in $old_icons; do rm -f "$icons/$f"; done
  if [[ -f $mimeapps ]]; then
    for old in $old_desktops; do
      case $old in
        io.github.design_nexus.*) new=${old/design_nexus./design_nexus.nixe.} ;;
        nexus-photos.desktop) new=io.github.design_nexus.nixe.Photos.desktop ;;
        npv.desktop) new=io.github.design_nexus.nixe.PhotoViewer.desktop ;;
        nexus-*.desktop) k=${old#nexus-}; k=${k%.desktop}; new="io.github.design_nexus.nixe.${k^}.desktop" ;;
      esac
      if grep -q "$old" "$mimeapps"; then
        [[ -f $mimeapps.nixe-bak ]] || cp "$mimeapps" "$mimeapps.nixe-bak"
        sed -i "s/\b${old//./\\.}/$new/g" "$mimeapps"
      fi
    done
  fi

  if [[ $make_default == true && $defaults == true ]]; then
    for f in "$d"/data/io.github.design_nexus.nixe.*.desktop; do
      # Write leaves plain text and Markdown to the text editor.
      types=$(sed -n 's/^MimeType=//p' "$f" | tr ';' '\n' | grep -v '^text/plain$\|^text/markdown$\|x-nexus-' | tr '\n' ' ')
      # shellcheck disable=SC2086
      [[ -n ${types// /} ]] && xdg-mime default "$(basename "$f")" $types
    done
    say "$a now opens its file types"
  fi
done

# The suite's own command: nixe list, install, update, uninstall.
install -m 755 "$src/bin/nixe" "$bin/nixe"

update-desktop-database "$desk" 2>/dev/null || true
gtk-update-icon-cache -q "$share/icons/hicolor" 2>/dev/null || true

# ---------- Hyprland: windows that open floating ----------
hypr="$config/hypr"
if [[ " ${apps[*]} " != " glimpse " && -f $hypr/hyprland.lua ]] && grep -q 'o\.window' "$hypr/hyprland.lua" 2>/dev/null; then
  rules=""
  [[ -x $bin/nixe-notepad ]] && rules+='o.window("^io\\.github\\.design_nexus\\.nixe\\.Notepad$", { float = true, center = true, size = { 900, 700 } })'$'\n'
  [[ -x $bin/nixe-capture ]] && rules+='o.window("^io\\.github\\.design_nexus\\.nixe\\.Capture\\.Pin$", { float = true, pin = true, size = { 480, 320 } })'$'\n'
  [[ -x $bin/nixe-archive ]] && rules+='o.window("^io\\.github\\.design_nexus\\.nixe\\.Archive$", { float = true, center = true, size = { 960, 640 } })'$'\n'
  if [[ -x $bin/nixe-weather ]] && grep -q '^float_window *= *true' "$config/nixe-weather/settings.toml" 2>/dev/null; then
    rules+='o.window("^io\\.github\\.design_nexus\\.nixe\\.Weather$", { float = true, center = true, size = { 460, 720 } })'$'\n'
  fi
  # Weather writes its own rule into nixe.lua when it's set to float, so the file
  # must be loaded even while no rule is in it yet.
  if [[ -n $rules || -x $bin/nixe-weather ]]; then
    printf -- '-- Written by the Nixe installer: Nixe apps that open as floating windows.\n-- Reinstalling an app rewrites this file.\n%s' "$rules" >"$hypr/nixe.lua"
    if ! grep -q 'require("hypr.nixe")' "$hypr/hyprland.lua"; then
      cp "$hypr/hyprland.lua" "$hypr/hyprland.lua.bak.$(date +%s)"
      # Drop the hand-written rule for Notepad's old window class; nixe.lua has it now.
      sed -i '/^-- Nexus Notepad opens floating and centered\.$/d; /design_nexus\\\\\.Notepad\$"/d' "$hypr/hyprland.lua"
      if grep -q '^require("hypr.settings")' "$hypr/hyprland.lua"; then
        sed -i 's/^require("hypr.settings")/require("hypr.nixe") -- Nixe apps (floating windows)\n&/' "$hypr/hyprland.lua"
      else
        printf '\nrequire("hypr.nixe") -- Nixe apps (floating windows)\n' >>"$hypr/hyprland.lua"
      fi
    fi
    if command -v hyprctl >/dev/null && hyprctl reload >/dev/null 2>&1; then
      errors=$(hyprctl configerrors 2>/dev/null | grep -v '^$' || true)
      [[ -z $errors || $errors == *"no errors"* ]] || warn "Hyprland reports: $errors"
    fi
  fi
fi

# ---------- Settings ----------
# Weather's bar widget, for omarchy-shell; it's turned on from Settings → Plugins.
if printf '%s\n' "${apps[@]}" | grep -qx weather && [[ -d $config/omarchy/plugins && -f $src/apps/weather/plugin/BarWidget.qml ]]; then
  dest="$config/omarchy/plugins/design-nexus.weather"
  mkdir -p "$dest"
  install -m 644 "$src/apps/weather/plugin/manifest.json" "$src/apps/weather/plugin/BarWidget.qml" "$dest/"
  omarchy-shell shell rescanPlugins >/dev/null 2>&1 || true
fi

if printf '%s\n' "${apps[@]}" | grep -qx settings; then
  # Rewrite the managed Hyprland file so its bindings call the new programs.
  if [[ -f $config/settings/state.json || -f $config/nixe-settings/state.json ]]; then
    "$bin/nixe-settings" --apply || true
  fi
  if [[ $gear == true ]]; then
    dest="$config/omarchy/plugins/design-nexus.settings-gear"
    mkdir -p "$dest"
    install -m 644 "$src/apps/settings/plugin/manifest.json" "$src/apps/settings/plugin/BarWidget.qml" "$dest/"
    omarchy-shell shell rescanPlugins >/dev/null 2>&1 || true
    omarchy-plugin-enable design-nexus.settings-gear right >/dev/null 2>&1 || warn "Enable it from Settings → Plugins."
  fi
  if [[ -e /usr/local/lib/settings/settings-helper ]]; then
    warn "The old account helper is still in /usr/local/lib/settings. Settings installs the new one when you next"
    warn "change an account; then remove the old one with:"
    warn "  sudo rm -r /usr/local/lib/settings /usr/share/polkit-1/actions/io.github.design_nexus.settings.policy"
  fi
fi

case ":$PATH:" in
  *":$bin:"*) ;;
  *) warn "$bin isn't on your PATH; open the apps from the app launcher, or add it to PATH." ;;
esac
say "Done. Open ${apps[*]} from the app launcher."
