"""Loopback-only HTTP server for a read-only, replay-backed web prototype."""

import json
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import urlsplit


_STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}
_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'none'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'"
)


def make_handler(graph: dict | Callable[[], dict]) -> type[BaseHTTPRequestHandler]:
    """Create an HTTP handler that serves one immutable graph snapshot."""

    class PreviewHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Guard against a remote origin using DNS rebinding to query
            # loopback-only discovery data through a forged Host header.
            host = self.headers.get("Host", "").split(":")[0].lower()
            if host not in ("127.0.0.1", "localhost"):
                self._respond(403, b"Forbidden", "text/plain; charset=utf-8")
                return

            path = urlsplit(self.path).path
            if path == "/api/graph":
                body = json.dumps(
                    graph() if callable(graph) else graph,
                    separators=(",", ":"),
                ).encode("utf-8")
                self._respond(200, body, "application/json; charset=utf-8")
                return
            if path in _STATIC:
                file_name, content_type = _STATIC[path]
                body = (
                    resources.files("novxis.web.static")
                    .joinpath(file_name)
                    .read_bytes()
                )
                self._respond(200, body, content_type)
                return
            self._respond(404, b"Not found", "text/plain; charset=utf-8")

        def _respond(self, status: int, body: bytes, content_type: str):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", _CSP)
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            # Avoid logging local capture names and request metadata.
            pass

    return PreviewHandler


def create_server(
    graph: dict | Callable[[], dict], port: int = 8765
) -> ThreadingHTTPServer:
    """Never expose packet-derived data on a non-loopback address."""
    if not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(graph))
    server.daemon_threads = True
    return server
