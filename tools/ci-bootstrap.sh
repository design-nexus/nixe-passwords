#!/usr/bin/env bash
set -euo pipefail
# Immutable Arch package snapshot; do not combine with rolling mirror packages.
printf 'Server = https://archive.archlinux.org/repos/2026/10/20/$repo/os/$arch\n' > /etc/pacman.d/mirrorlist
pacman -Syyuu --noconfirm --needed base-devel rust python git curl github-cli gtk4 pkgconf cmake ninja clang "$@"
[[ $(rustc --version) == 'rustc 1.99.1 '* ]]
