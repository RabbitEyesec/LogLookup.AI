"""Minimal sd_notify client (pure stdlib) for systemd integration.

Lets the service unit use ``Type=notify`` + ``WatchdogSec`` so systemd
knows exactly when the engine is ready, restarts it if the event loop
wedges, and gets a clean STOPPING signal on shutdown. Outside systemd
(no ``NOTIFY_SOCKET``) every call is a silent no-op — the dev CLI and
macOS development machines are unaffected.
"""

from __future__ import annotations

import logging
import os
import socket

logger = logging.getLogger(__name__)


def notify(state: str) -> bool:
    """Send one sd_notify state string; False if not running under systemd."""
    target = os.environ.get("NOTIFY_SOCKET")
    if not target:
        return False
    if target.startswith("@"):  # abstract namespace socket
        target = "\0" + target[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(target)
            sock.send(state.encode("utf-8"))
        return True
    except OSError as exc:
        logger.debug("sd_notify(%s) failed: %s", state, exc)
        return False


def watchdog_interval_seconds() -> float | None:
    """Half the systemd watchdog window, or None when no watchdog is set."""
    usec = os.environ.get("WATCHDOG_USEC")
    if not usec:
        return None
    pid = os.environ.get("WATCHDOG_PID")
    if pid and pid != str(os.getpid()):
        return None
    try:
        window = int(usec) / 1_000_000.0
    except ValueError:
        return None
    if window <= 0:
        return None
    return window / 2.0
