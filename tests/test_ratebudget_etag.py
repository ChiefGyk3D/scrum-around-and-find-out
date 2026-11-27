# SPDX-License-Identifier: Apache-2.0
"""Conditional GitHub reads (#532): ETag cache under the ratebudget state folder.

No network and no gh: the wrapper's `run` is a stub that answers 304 when it sees the right If-None-Match.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

from safo import ratebudget as rb
from test_ratebudget import OK, T0, Harness, done, http

BODY = '{"n": 5}'
TAG = '"abc123"'


class Origin(Harness):
    """A stub GitHub: a 200 with an ETag, or a 304 when If-None-Match matches the current tag."""

    def __init__(self, tmp_path: Path) -> None:
        super().__init__(tmp_path)
        self.tag = TAG
        self.body = BODY
        self.seen: list[str | None] = []

    def run(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        if argv[1:3] == ["api", "user"]:
            return super().run(argv, **kw)
        sent = next((w.split(": ", 1)[1] for w in argv if w.startswith("If-None-Match: ")), None)
        self.seen.append(sent)
        self.calls.append(argv)
        if sent == self.tag:
            return subprocess.CompletedProcess(
                [], 1, http("304 Not Modified", {**OK, "etag": self.tag}, ""), "gh: HTTP 304\n"
            )
        return done(http("200 OK", {**OK, "etag": self.tag}, self.body))

    @property
    def cache_file(self) -> Path:
        return self.tmp / ".local" / "state" / "safo" / "ratebudget" / "etags.json"


def test_second_read_is_conditional_and_a_304_serves_the_cache(tmp_path: Path) -> None:
    h = Origin(tmp_path)
    assert h.go(["api", "repos/o/r/issues/5"]) == 0
    assert h.seen == [None]
    h.out.truncate(0)
    h.out.seek(0)
    assert h.go(["api", "repos/o/r/issues/5"]) == 0
    assert h.seen == [None, TAG]
    assert h.out.getvalue() == BODY
    assert "HTTP 304" not in h.err.getvalue()
    rows = h.ledger.rows()
    assert [r.get("cache") for r in rows] == [None, "hit"]
    assert h.ledger.by_caller()["agent-a"]["core"]["hits"] == 1


def test_changed_resource_returns_the_new_body_and_updates_the_tag(tmp_path: Path) -> None:
    h = Origin(tmp_path)
    h.go(["api", "repos/o/r/issues/5"])
    h.tag, h.body = '"def456"', '{"n": 6}'
    h.out.truncate(0)
    h.out.seek(0)
    assert h.go(["api", "repos/o/r/issues/5"]) == 0
    assert h.out.getvalue() == '{"n": 6}'
    h.go(["api", "repos/o/r/issues/5"])
    assert h.seen[-1] == '"def456"'


def test_another_endpoint_or_account_never_gets_the_entry(tmp_path: Path) -> None:
    h = Origin(tmp_path)
    h.go(["api", "repos/o/r/issues/5"])
    h.go(["api", "repos/o/other/issues/5"])
    assert h.seen == [None, None]
    h.login, h.cred = "someone-else", "t1-credential"
    h.go(["api", "repos/o/r/issues/5"])
    assert h.seen[-1] is None


def test_cache_file_is_private_and_holds_no_credential(tmp_path: Path) -> None:
    h = Origin(tmp_path)
    h.go(["api", "repos/o/r/issues/5"])
    assert stat.S_IMODE(h.cache_file.stat().st_mode) == 0o600
    text = h.cache_file.read_text()
    assert h.cred not in text and "octocat" not in text and "issues/5" not in text
    assert h.cred not in h.err.getvalue()


def test_writes_and_unusual_calls_are_never_cached(tmp_path: Path) -> None:
    h = Origin(tmp_path)
    h.go(["api", "-X", "PATCH", "repos/o/r/issues/5", "-f", "state=open"])
    h.go(["api", "repos/o/r/issues/5", "--jq", ".n"])
    h.go(["api", "-H", "Accept: x", "repos/o/r/issues/5"])
    h.go(["api", "--paginate", "repos/o/r/issues"])
    assert not h.cache_file.exists()


def test_corrupt_cache_means_a_normal_request(tmp_path: Path) -> None:
    h = Origin(tmp_path)
    h.go(["api", "repos/o/r/issues/5"])
    h.cache_file.write_text("{not json")
    h.out.truncate(0)
    h.out.seek(0)
    assert h.go(["api", "repos/o/r/issues/5"]) == 0
    assert h.seen[-1] is None
    assert h.out.getvalue() == BODY


def test_symlinked_cache_is_not_followed(tmp_path: Path) -> None:
    h = Origin(tmp_path)
    h.go(["api", "repos/o/r/issues/5"])
    real = tmp_path / "elsewhere.json"
    real.write_text(h.cache_file.read_text())
    h.cache_file.unlink()
    os.symlink(real, h.cache_file)
    assert h.go(["api", "repos/o/r/issues/5"]) == 0
    assert h.seen[-1] is None


def test_old_entries_are_not_used(tmp_path: Path) -> None:
    h = Origin(tmp_path)
    h.go(["api", "repos/o/r/issues/5"])
    h.clock.now = T0 + rb.ETAG_MAX_AGE + 5
    h.go(["api", "repos/o/r/issues/5"])
    assert h.seen[-1] is None


def test_oversized_bodies_are_not_stored(tmp_path: Path) -> None:
    h = Origin(tmp_path)
    h.body = "x" * (rb.ETAG_MAX_BODY + 1)
    h.go(["api", "repos/o/r/issues/5"])
    h.go(["api", "repos/o/r/issues/5"])
    assert h.seen == [None, None]


def test_cache_is_bounded_in_entries(tmp_path: Path) -> None:
    h = Origin(tmp_path)
    for n in range(rb.ETAG_MAX_ENTRIES + 10):
        h.go(["api", f"repos/o/r/issues/{n}"])
    entries = json.loads(h.cache_file.read_text())["entries"]
    assert len(entries) == rb.ETAG_MAX_ENTRIES
    assert h.cache_file.stat().st_size <= rb.ETAG_MAX_BYTES


def test_malformed_etag_is_not_stored(tmp_path: Path) -> None:
    h = Origin(tmp_path)
    h.tag = 'bad tag"\r\nX: y'
    h.go(["api", "repos/o/r/issues/5"])
    assert not h.cache_file.exists()


def test_cache_target_accepts_only_plain_reads() -> None:
    assert rb.cache_target(["api", "repos/o/r"]) == "repos/o/r"
    assert rb.cache_target(["api", "--hostname", "h.example", "repos/o/r"]) == "h.example repos/o/r"
    assert rb.cache_target(["api", "-X", "GET", "repos/o/r"]) is None
    assert rb.cache_target(["issue", "view", "5"]) is None
    assert rb.cache_target(["api", "graphql"]) is None
