"""Serve the bundled dashboard with in-browser sample data only."""

from __future__ import annotations

import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import webbrowser


STATIC = Path(__file__).resolve().parent / "engine" / "dashboard" / "static"


class PreviewHandler(SimpleHTTPRequestHandler):
    """Route production dashboard paths to static preview assets."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC), **kwargs)

    def _route(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/" or path.startswith("/incident/"):
            self.path = "/incident.html"
        elif path.startswith("/static/"):
            self.path = path.removeprefix("/static")
        elif path == "/setup":
            self.path = "/setup.html"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        self._route()
        super().do_GET()

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler contract
        self._route()
        super().do_HEAD()

    def log_message(self, format: str, *args) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4173)
    parser.add_argument("--no-open", action="store_true")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), PreviewHandler)
    url = f"http://{args.host}:{args.port}/?preview=1"
    print(f"LogLookup AI UI preview: {url}")
    if not args.no_open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
