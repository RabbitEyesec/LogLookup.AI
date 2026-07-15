#!/usr/bin/env bash
# LogLookup AI  one-line Linux installer (AI Constitution 3).
#
#   From a source checkout:   bash deploy/install.sh
#   One line from a host:     curl -fsSL <raw-url>/deploy/install.sh | bash
#                             (set LOGLOOKUP_SRC=<git url or tarball dir>)
#
# What it does (all per-user, no root required):
#   1. checks Linux + Python >=3.11,<3.14
#   2. creates a virtualenv under ~/.local/share/loglookup/venv and installs
#      the engine into it
#   3. installs the `loglookup` launcher into ~/.local/bin
#   4. registers the desktop app: icon + .desktop entry in the app menu
#   5. installs + enables the systemd user service (auto-start, watchdog,
#      restart-on-failure, graceful shutdown)
#   6. builds the MITRE ATT&CK knowledge base (skippable: --skip-kb)
#
# After install: open "LogLookup AI" from the app menu, or run `loglookup open`.
# First launch shows the onboarding wizard no config files, no env vars.

set -euo pipefail

APP=loglookup
DATA_DIR="${HOME}/.local/share/${APP}"
VENV="${DATA_DIR}/venv"
BIN_DIR="${HOME}/.local/bin"
APPS_DIR="${HOME}/.local/share/applications"
ICON_DIR="${HOME}/.local/share/icons/hicolor/scalable/apps"
UNIT_DIR="${HOME}/.config/systemd/user"
CONFIG_DIR="${HOME}/.config/${APP}"

SKIP_KB=0
SKIP_SERVICE=0
for arg in "$@"; do
  case "$arg" in
    --skip-kb) SKIP_KB=1 ;;
    --skip-service) SKIP_SERVICE=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# -- 1. platform checks -------------------------------------------------------

[ "$(uname -s)" = "Linux" ] || fail "LogLookup AI v1 supports Linux only (found $(uname -s))."

PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; sys.exit(0 if (3, 11) <= sys.version_info < (3, 14) else 1)'; then
      PYTHON="$(command -v "$candidate")"
      break
    fi
  fi
done
[ -n "$PYTHON" ] || fail "LogLookup AI requires Python >=3.11,<3.14. Python 3.14 is not yet supported; install Python 3.11, 3.12, or 3.13."
say "using $PYTHON ($("$PYTHON" --version 2>&1))"

# -- 2. locate the source ------------------------------------------------------

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd || true)"
SRC="${LOGLOOKUP_SRC:-}"
if [ -z "$SRC" ] && [ -n "$SCRIPT_DIR" ] && [ -f "${SCRIPT_DIR}/../pyproject.toml" ]; then
  SRC="$(cd "${SCRIPT_DIR}/.." && pwd)"
fi
if [ -z "$SRC" ]; then
  fail "cannot locate the LogLookup source. Run from a checkout (bash deploy/install.sh) or set LOGLOOKUP_SRC=<path or git url>."
fi
case "$SRC" in
  http://*|https://*|git@*)
    command -v git >/dev/null 2>&1 || fail "git is required to fetch $SRC"
    CLONE_DIR="$(mktemp -d)"
    trap 'rm -rf "$CLONE_DIR"' EXIT
    say "cloning $SRC"
    git clone --depth 1 "$SRC" "$CLONE_DIR/src"
    SRC="$CLONE_DIR/src"
    ;;
esac
[ -f "${SRC}/pyproject.toml" ] || fail "no pyproject.toml in ${SRC}"
say "installing from ${SRC}"

# -- 3. virtualenv + package -----------------------------------------------------

mkdir -p "$DATA_DIR" "$BIN_DIR" "$APPS_DIR" "$ICON_DIR" "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

if [ ! -x "${VENV}/bin/python" ]; then
  say "creating virtualenv at ${VENV}"
  "$PYTHON" -m venv "$VENV"
fi
say "installing the engine (this pulls Python dependencies)"
"${VENV}/bin/pip" install --upgrade pip --quiet
# Pin resolution to the release-validated dependency set when the lock file
# is present (it ships with the source); a missing file falls back to the
# package's own version ranges.
CONSTRAINTS="${SRC}/deploy/requirements-lock.txt"
if [ -f "$CONSTRAINTS" ]; then
  "${VENV}/bin/pip" install --quiet -c "$CONSTRAINTS" "${SRC}"
else
  "${VENV}/bin/pip" install --quiet "${SRC}"
fi

ln -sf "${VENV}/bin/loglookup" "${BIN_DIR}/loglookup"
say "launcher: ${BIN_DIR}/loglookup"
case ":$PATH:" in
  *":${BIN_DIR}:"*) ;;
  *) echo "    note: add ${BIN_DIR} to PATH to run 'loglookup' directly" ;;
esac

# -- 4. desktop integration --------------------------------------------------------

install -m 644 "${SRC}/deploy/icons/loglookup.svg" "${ICON_DIR}/loglookup.svg"
# Point Exec at the absolute launcher so the menu entry works without PATH.
sed "s|^Exec=loglookup |Exec=${BIN_DIR}/loglookup |" \
  "${SRC}/deploy/loglookup.desktop" > "${APPS_DIR}/loglookup.desktop"
chmod 644 "${APPS_DIR}/loglookup.desktop"
command -v update-desktop-database >/dev/null 2>&1 && \
  update-desktop-database "$APPS_DIR" >/dev/null 2>&1 || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && \
  gtk-update-icon-cache -q "${HOME}/.local/share/icons/hicolor" 2>/dev/null || true
say "desktop entry + icon installed (app menu: LogLookup AI)"

# -- 5. systemd user service ---------------------------------------------------------

if [ "$SKIP_SERVICE" = 0 ] && command -v systemctl >/dev/null 2>&1; then
  mkdir -p "$UNIT_DIR"
  install -m 644 "${SRC}/deploy/systemd/loglookup.service" \
    "${UNIT_DIR}/loglookup.service"
  systemctl --user daemon-reload
  systemctl --user enable loglookup.service >/dev/null 2>&1 || true
  if systemctl --user start loglookup.service; then
    say "service started (systemctl --user status loglookup)"
  else
    echo "    service install ok, but start failed — check: journalctl --user -u loglookup"
  fi
  # Keep the engine running after logout on server-style installs.
  # ${USER:-...}: USER is not set in every install context (su -c, scripted
  # installs) and this script runs under `set -u`.
  command -v loginctl >/dev/null 2>&1 && \
    loginctl enable-linger "${USER:-$(id -un)}" >/dev/null 2>&1 || true
else
  [ "$SKIP_SERVICE" = 1 ] && say "skipping systemd service (--skip-service)" \
    || echo "    systemd not found — run the engine with: loglookup serve"
fi

# -- 6. ATT&CK knowledge base ----------------------------------------------------------

if [ "$SKIP_KB" = 0 ]; then
  say "building the MITRE ATT&CK knowledge base (official STIX bundle, ~50MB)"
  if LOGLOOKUP_HOME="$CONFIG_DIR" "${VENV}/bin/python" -m engine.ai.kb --build \
      --out "${CONFIG_DIR}/attack_kb.json"; then
    say "knowledge base ready"
  else
    echo "    KB build failed (offline?) — AI triage stays honestly disabled"
    echo "    until it is built: ${VENV}/bin/python -m engine.ai.kb --build --out ${CONFIG_DIR}/attack_kb.json"
  fi
else
  say "skipping ATT&CK KB build (--skip-kb)"
fi

say "install complete."
echo
echo "  Open 'LogLookup AI' from your app menu, or run: loglookup open"
echo "  First launch shows the onboarding wizard (SIEM + AI provider)."
echo "  Uninstall: bash ${SRC}/deploy/uninstall.sh"
