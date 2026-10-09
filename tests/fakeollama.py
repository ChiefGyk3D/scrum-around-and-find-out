# SPDX-License-Identifier: MIT
"""A fake Ollama on a loopback port. It records every request so a test can prove what was and was not asked."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class FakeOllama:
    def __init__(self, installed: list[str], loaded: list[str]) -> None:
        self.installed = installed
        self.loaded = loaded
        self.requests: list[tuple[str, str, dict[str, Any]]] = []
        self.generate_status = 200
        self.drop_generate = False  # close the connection without answering: the endpoint went away mid-task
        self.reply: dict[str, Any] = {
            "model": "",
            "response": "A short answer.",
            "eval_count": 100,
            "prompt_eval_count": 40,
            "eval_duration": 2_000_000_000,
        }
        self.url = ""
        self.stall_seconds = 0.0  # hold every GET this long before answering: a reachable host that is hung
        self.raw_reply: bytes | None = None  # answer /api/generate and /api/tags with these exact bytes, status 200
        self.redirect_to = ""  # answer every request with a 302 to this URL

    @contextmanager
    def serve(self) -> Iterator[FakeOllama]:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, status: int, body: dict[str, Any]) -> None:
                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _raw(self) -> bool:
                if fake.redirect_to:
                    self.send_response(302)
                    self.send_header("Location", fake.redirect_to)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return True
                if fake.raw_reply is not None:
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(fake.raw_reply)))
                    self.end_headers()
                    self.wfile.write(fake.raw_reply)
                    return True
                return False

            def do_GET(self) -> None:
                fake.requests.append(("GET", self.path, {}))
                if fake.stall_seconds:
                    time.sleep(fake.stall_seconds)
                if self._raw():
                    return
                if self.path == "/api/tags":
                    self._send(200, {"models": [{"name": n} for n in fake.installed]})
                elif self.path == "/api/ps":
                    self._send(200, {"models": [{"name": n} for n in fake.loaded]})
                else:
                    self._send(404, {})

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                fake.requests.append(("POST", self.path, body))
                if self._raw():
                    return
                if fake.drop_generate:
                    self.close_connection = True
                    return
                if self.path != "/api/generate":
                    self._send(404, {})
                elif fake.generate_status != 200:
                    self._send(fake.generate_status, {"error": "boom"})
                else:
                    self._send(200, {**fake.reply, "model": body.get("model", "")})

            def log_message(self, format: str, *args: Any) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{server.server_address[1]}"
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield self
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    @property
    def generates(self) -> list[dict[str, Any]]:
        return [b for m, p, b in self.requests if m == "POST" and p == "/api/generate"]
