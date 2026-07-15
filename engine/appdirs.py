"""Application home directory (XDG-aware, service-overridable).

Everything the installed application manages lives under one directory:
``config.yaml`` (non-secret settings), ``secrets.key`` + ``secrets.enc``
(encrypted credential store), the ATT&CK knowledge base, and the retrieval
index. The systemd service points ``LOGLOOKUP_HOME`` somewhere durable;
interactive use defaults to ``~/.config/loglookup``.
"""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "loglookup"


def app_home() -> Path:
    """Root for app-managed state; ``LOGLOOKUP_HOME`` overrides XDG."""
    override = os.environ.get("LOGLOOKUP_HOME")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / APP_NAME


def ensure_app_home() -> Path:
    """Create the app home with owner-only permissions and return it."""
    home = app_home()
    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    return home
