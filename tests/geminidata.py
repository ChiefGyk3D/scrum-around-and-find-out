# SPDX-License-Identifier: Apache-2.0
"""Support for the Gemini tests: a fake Gemini on a loopback port and a configuration that points at it.

No test here needs a key, a network or the real ledger: the key is a fixed fake string, every file is under tmp_path.
"""

from __future__ import annotations

import datetime as dt
import json
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

FAKE_KEY = "FAKE-KEY-for-tests-0123456789"
NOW = dt.datetime(2026, 10, 29, 20, 0, tzinfo=dt.UTC)  # 13:00 on 2026-10-29 in Pacific time
MODEL = "gemini-3.6-flash"
IMAGE_MODEL = "gemini-image-test"

OK_BODY: dict[str, Any] = {
    "candidates": [{"content": {"parts": [{"text": "A cited answer."}]}}],
    "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 20, "totalTokenCount": 30},
}


class QuietServer(ThreadingHTTPServer):
    """A client that gives up mid-answer (a refused redirect, an oversized body) is the test, not a failure."""

    def handle_error(self, request: Any, client_address: Any) -> None:
        return


class FakeGemini:
    """Records every request (path, headers, body) and answers from a script, so a test can prove what was sent."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, str], dict[str, Any]]] = []
        self.status = 200
        self.body: Any = OK_BODY
        self.raw: bytes | None = None
        self.drop = False  # close the connection without answering
        self.stall = 0.0
        self.redirect_to = ""
        self.headers_out: dict[str, str] = {}
        self.url = ""

    @contextmanager
    def serve(self) -> Iterator[FakeGemini]:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                size = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(size) or b"{}")
                fake.requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
                if fake.stall:
                    time.sleep(fake.stall)
                if fake.drop:
                    self.close_connection = True
                    return
                if fake.redirect_to:
                    self.send_response(302)
                    self.send_header("Location", fake.redirect_to)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                payload = fake.raw if fake.raw is not None else json.dumps(fake.body).encode()
                self.send_response(fake.status)
                for k, v in fake.headers_out.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: Any) -> None:
                return

        server = QuietServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{server.server_address[1]}"
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield self
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


def config_dict(url: str, ledger: Path, **over: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "version": 1,
        "endpoint": url,
        "price_source": "https://ai.google.dev/gemini-api/docs/pricing",
        "price_checked": "2026-10-29",
        "secrets": {
            "project": "image-gen",
            "free_config": "prd",
            "paid_config": "prd_paid",
            "key_name": "GEMINI_API_KEY",
        },
        "caps": {"job_usd": 2, "month_usd": 10, "block_usd": 2},
        "ledger": str(ledger),
        "private_terms": "none",
        "timeout_seconds": 5,
        "max_output_tokens": 1000,
        "free": {MODEL: {"rpm": 3, "tpm": 1000, "rpd": 5}},
        "paid": {
            MODEL: {"input_per_mtok": 0.75, "output_per_mtok": 3.75, "valid_through": "2026-12-31"},
            IMAGE_MODEL: {
                "input_per_mtok": 0.5,
                "output_per_mtok": 30,
                "valid_through": "2026-12-31",
                "modality": "image",
            },
        },
    }
    data.update(over)
    return data


def write_config(path: Path, url: str, ledger: Path, **over: Any) -> Path:
    path.write_text(yaml.safe_dump(config_dict(url, ledger, **over)))
    path.chmod(0o600)
    return path


def ledger_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def seed(path: Path, rows: list[dict[str, Any]]) -> None:
    """Rows already in a ledger: written as the wrapper writes them, plus the maintainer's two hand-written kinds."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")


def start_row(
    when: dt.datetime, *, tier: str = "free", model: str = MODEL, tokens: int = 10, usd: float = 0, call_id: str = "c"
) -> list[dict[str, Any]]:
    """A finished call as two rows, so a counter that reads only one of them is caught."""
    stamp = when.strftime("%Y-%m-%dT%H:%M:%SZ")
    return [
        {
            "type": "call_start",
            "call_id": call_id,
            "ts": stamp,
            "date": stamp[:10],
            "tier": tier,
            "model": model,
            "est_input_tokens": tokens,
            "est_usd": usd,
            "job": "j",
        },
        {
            "type": "call_end",
            "call_id": call_id,
            "ts": stamp,
            "status": "ok",
            "http": 200,
            "prompt_tokens": tokens,
            "output_tokens": 1,
            "actual_usd": usd,
        },
    ]


def minutes_ago(n: float) -> dt.datetime:
    return NOW - dt.timedelta(minutes=n)


def hard_timeout(seconds: float) -> Callable[[Callable[..., None]], Callable[..., None]]:
    """Run a test in a forked child and fail it cleanly if it has not finished in `seconds`. A regex search in C cannot
    be interrupted by a signal, so a regression that lets a slow term through would otherwise hang the whole run."""
    import functools
    import multiprocessing
    import traceback

    import pytest

    def decorate(fn: Callable[..., None]) -> Callable[..., None]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> None:
            ctx = multiprocessing.get_context("fork")
            outcome = ctx.Queue()

            def child() -> None:
                try:
                    fn(*args, **kwargs)
                    outcome.put("")
                except BaseException:
                    outcome.put(traceback.format_exc())

            process = ctx.Process(target=child)
            process.start()
            process.join(seconds)
            if process.is_alive():
                process.kill()
                process.join()
                pytest.fail(f"{fn.__name__} did not finish in {seconds:g} s (a hang)", pytrace=False)
            try:
                failure = outcome.get(timeout=2)
            except Exception:
                pytest.fail(f"{fn.__name__}: the child ended without a result", pytrace=False)
            if failure:
                pytest.fail(failure, pytrace=False)

        return wrapper

    return decorate
