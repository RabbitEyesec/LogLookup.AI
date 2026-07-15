#!/usr/bin/env bash
# LogLookup AI  per-user uninstaller (mirror of deploy/install.sh).
# Keeps ~/.config/loglookup (settings + encrypted secrets) unless --purge.

set -euo pipefail

APP=loglookup
DATA_DIR="${HOME}/.local/share/${APP}"
CONFIG_DIR="${HOME}/.config/${APP}"

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user disable --now loglookup.service >/dev/null 2>&1 || true
  rm -f "${HOME}/.config/systemd/user/loglookup.service"
  systemctl --user daemon-reload || true
fi

rm -f "${HOME}/.local/bin/loglookup"
rm -f "${HOME}/.local/share/applications/loglookup.desktop"
rm -f "${HOME}/.local/share/icons/hicolor/scalable/apps/loglookup.svg"
command -v update-desktop-database >/dev/null 2>&1 && \
  update-desktop-database "${HOME}/.local/share/applications" >/dev/null 2>&1 || true

rm -rf "$DATA_DIR"

if [ "$PURGE" = 1 ]; then
  rm -rf "$CONFIG_DIR"
  echo "removed ${CONFIG_DIR} (settings + encrypted secrets)"
else
  echo "kept ${CONFIG_DIR} (settings + encrypted secrets); use --purge to remove"
fi
echo "LogLookup AI uninstalled."
