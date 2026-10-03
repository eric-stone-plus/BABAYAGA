#!/usr/bin/env python3
"""Loopback http-get lab fixture for the BABAYAGA demo path (B14 seed).

A stdlib basic-auth HTTP server that simulates lockout policy: after
LOCKOUT_THRESHOLD consecutive failures for a user, every further attempt
gets 401 with an X-Lab-Lockout header until LOCKOUT_RESET_S passes.

Run:  python3 engine/lab/http_get_lab.py [port]   (default 8080, 127.0.0.1 only)

Port 0 binds an ephemeral loopback port. Once bound (listen socket ready)
the server prints one readiness line to stdout: "127.0.0.1 <port>" — the
`babayaga run --lab` runner spawns the fixture as a subprocess and reads
that line to learn the port (core/run.py).
"""

from __future__ import annotations

import base64
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
LOCKOUT_THRESHOLD = 5
LOCKOUT_RESET_S = 15 * 60

USERS = {
    "labuser1": "Spring2026-lab!",   # guessable: budget 3 < threshold 5
    "labuser2": "un-guessable-9f2c", # stays invalid across the demo
}

_failures: dict[str, list[float]] = {}


def is_locked(user: str) -> bool:
    now = time.time()
    fails = [t for t in _failures.get(user, []) if now - t < LOCKOUT_RESET_S]
    _failures[user] = fails
    return len(fails) >= LOCKOUT_THRESHOLD


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 — http.server API
        header = self.headers.get("Authorization", "")
        user, ok = self._basic(header)
        if ok and not is_locked(user):
            self.send_response(200)
            self.send_header("X-Lab-Outcome", "valid")
            self.end_headers()
            self.wfile.write(b"lab-ok\n")
            return
        if user in USERS:
            _failures.setdefault(user, []).append(time.time())
        locked = user in USERS and is_locked(user)
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="babayaga-lab"')
        if locked:
            self.send_header("X-Lab-Lockout", "true")
        self.send_header("X-Lab-Outcome", "locked" if locked else "invalid")
        self.end_headers()

    def _basic(self, header: str) -> tuple[str, bool]:
        if not header.startswith("Basic "):
            return "", False
        try:
            decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
            user, _, password = decoded.partition(":")
        except Exception:
            return "", False
        return user, USERS.get(user) == password

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("[lab] " + fmt % args + "\n")


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = ThreadingHTTPServer((HOST, port), Handler)
    # Readiness line: the listen socket is live once ThreadingHTTPServer's
    # constructor returns, so the runner can connect as soon as it reads this.
    print(f"{HOST} {server.server_address[1]}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
