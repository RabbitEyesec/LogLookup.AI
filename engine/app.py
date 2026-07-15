"""loglookup — the installed application entry point.

    loglookup serve     run the engine + dashboard as a managed service
    loglookup open      make sure the service is up, open the dashboard
    loglookup status    print engine / SIEM / AI health from the service
    loglookup version   print the installed version

Managed mode differences from the dev CLI (``python -m engine.server``):

- configuration lives in the app home (``~/.config/loglookup`` or
  ``$LOGLOOKUP_HOME``) with secrets in the encrypted store — no config
  file to hand-edit, no environment variables required;
- first launch serves the onboarding wizard; polling + write-back start
  automatically once setup completes, without a restart;
- SIEM / AI settings changed through the UI are applied live AND
  persisted;
- systemd integration: sd_notify READY / WATCHDOG / STOPPING, graceful
  shutdown on SIGTERM.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Optional
from urllib.parse import urlparse

from engine import sdnotify
from engine.appdirs import ensure_app_home
from engine.config import Config
from engine.log import setup_logging
from engine.settings import ManagedSettings, PollCursorStore

logger = logging.getLogger(__name__)


class AppRunner:
    """Managed lifecycle: wizard-gated engine with live reconfiguration."""

    def __init__(self, settings: ManagedSettings) -> None:
        # Imported here so `loglookup open/status/version` stay fast.
        from engine.api.server import create_app

        self.settings = settings
        self.config: Config = settings.load()
        self._cursor_store = PollCursorStore(settings.home)
        self._reconfigure_lock = asyncio.Lock()
        self.runner = self._build(self.config)
        self.app = create_app(
            self.config,
            self.runner.service,
            pipeline=self.runner.pipeline,
            reader=self.runner.reader,
            settings=settings,
            lifespan=self._lifespan,
        )
        self.app.state.siem_live = self.runner.siem_live
        self.app.state.on_setup_complete = self.reconfigure
        self.app.state.apply_siem = self.reconfigure

    def _build(self, config: Config):
        from engine.server import EngineRunner

        live = self.settings.setup_complete and bool(config.siem.host)
        return EngineRunner(
            config,
            input_file=None,
            mode="poll" if live else None,
            since_ms=None,
            until_ms=None,
            writeback=live,
            ai_enabled=True,
            cursor_store=self._cursor_store,
        )

    async def reconfigure(self, config: Config) -> None:
        """Swap in a new engine for new settings — no process restart.

        Serialized: concurrent settings changes (wizard completion racing a
        SIEM edit) must never interleave stop/start of two engines.
        """
        async with self._reconfigure_lock:
            old = self.runner
            await old.stop()
            self.runner = self._build(config)
            self.config = config
            state = self.app.state
            state.config = config
            state.service = self.runner.service
            state.pipeline = self.runner.pipeline
            state.reader = self.runner.reader
            state.siem_live = self.runner.siem_live
            await self.runner.start()
            logger.info(
                "engine reconfigured (siem=%s, polling=%s)",
                config.siem.host or "not configured", self.runner.siem_live,
            )

    @contextlib.asynccontextmanager
    async def _lifespan(self, _app):
        await self.runner.start()
        sdnotify.notify("READY=1")
        watchdog: Optional[asyncio.Task] = None
        interval = sdnotify.watchdog_interval_seconds()
        if interval:
            async def heartbeat() -> None:
                while True:
                    await asyncio.sleep(interval)
                    sdnotify.notify("WATCHDOG=1")

            watchdog = asyncio.get_running_loop().create_task(heartbeat())
        try:
            yield
        finally:
            sdnotify.notify("STOPPING=1")
            if watchdog is not None:
                watchdog.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await watchdog
            await self.runner.stop()


def _dashboard_url(settings: ManagedSettings) -> str:
    try:
        return settings.load().output.dashboard_base_url
    except Exception:
        return "http://localhost:8080"


def _probe(url: str, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(f"{url.rstrip('/')}/api/setup",
                                    timeout=timeout) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    setup_logging(args.log_level)
    home = ensure_app_home()
    settings = ManagedSettings(home)
    runner = AppRunner(settings)

    parsed = urlparse(runner.config.output.dashboard_base_url)
    host = args.host or parsed.hostname or "127.0.0.1"
    port = args.port or parsed.port or 8080

    if not settings.setup_complete:
        logger.info("first launch: onboarding wizard at http://%s:%d/setup",
                    host, port)
    logger.info("dashboard: http://%s:%d/ (home: %s)", host, port, home)
    uvicorn.run(runner.app, host=host, port=port,
                log_level=args.log_level.lower())
    return 0


def cmd_open(_args: argparse.Namespace) -> int:
    settings = ManagedSettings(ensure_app_home())
    url = _dashboard_url(settings)
    if not _probe(url):
        started = False
        if sys.platform.startswith("linux") and shutil.which("systemctl"):
            result = subprocess.run(
                ["systemctl", "--user", "start", "loglookup.service"],
                capture_output=True,
            )
            started = result.returncode == 0
        if not started:
            # No service manager: run the engine detached from this launcher.
            log_path = settings.home / "loglookup.log"
            with open(log_path, "ab") as log_file:
                subprocess.Popen(
                    [sys.executable, "-m", "engine.app", "serve"],
                    stdout=log_file, stderr=log_file,
                    start_new_session=True,
                )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not _probe(url):
            time.sleep(0.5)
    if not _probe(url):
        print(f"engine did not come up at {url}; check "
              f"{settings.home / 'loglookup.log'}", file=sys.stderr)
        return 1
    if shutil.which("xdg-open"):
        subprocess.Popen(["xdg-open", url], start_new_session=True)
    else:
        import webbrowser

        webbrowser.open(url)
    print(url)
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    settings = ManagedSettings(ensure_app_home())
    url = _dashboard_url(settings).rstrip("/")
    try:
        with urllib.request.urlopen(f"{url}/api/status", timeout=5) as response:
            print(json.dumps(json.load(response), indent=2))
        return 0
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"engine not reachable at {url}: {exc}", file=sys.stderr)
        return 1


def cmd_version(_args: argparse.Namespace) -> int:
    from importlib.metadata import PackageNotFoundError, version

    try:
        print(version("loglookup-ai"))
    except PackageNotFoundError:
        print("unknown (not installed as a package)")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="loglookup", description="LogLookup AI application."
    )
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="run the engine + dashboard")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--log-level", default="INFO")
    serve.set_defaults(func=cmd_serve)

    open_cmd = sub.add_parser("open", help="open the dashboard (start if needed)")
    open_cmd.set_defaults(func=cmd_open)

    status = sub.add_parser("status", help="print engine health")
    status.set_defaults(func=cmd_status)

    version_cmd = sub.add_parser("version", help="print the version")
    version_cmd.set_defaults(func=cmd_version)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
