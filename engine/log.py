"""Logging setup for the engine.

Plain stdlib logging: one stream handler, UTC timestamps (the same
UTC-everywhere rule the pipeline itself follows).
"""

from __future__ import annotations

import logging
import sys
import time


def setup_logging(level: str = "INFO") -> None:
    """Configure root logging once for CLI / pipeline runs."""
    formatter = logging.Formatter(
        fmt="%(asctime)sZ %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.converter = time.gmtime

    # Use the process stream rather than a short-lived redirected wrapper
    # (test runners and service supervisors may close those wrappers later).
    handler = logging.StreamHandler(sys.__stderr__)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())
