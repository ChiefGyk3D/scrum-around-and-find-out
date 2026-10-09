# SPDX-License-Identifier: MIT
"""Nothing private in anything public: docs/, examples/, README.md."""

from __future__ import annotations

from pathlib import Path

import pytest

from privacy import EXCLUDED, ROOT, extra_patterns, findings, scanned_files


@pytest.mark.parametrize("path", scanned_files(), ids=lambda p: str(p.relative_to(ROOT)))
def test_a_public_file_names_no_host_machine_or_callsign(path: Path) -> None:
    hits = findings(path.read_text(encoding="utf-8"))
    assert not hits, f"{path.relative_to(ROOT)}: " + "; ".join(hits)


def test_only_the_plans_and_specs_are_excluded() -> None:
    assert EXCLUDED == ("docs/superpowers/plans", "docs/superpowers/specs")


def test_the_scan_covers_the_docs_the_examples_and_the_readme() -> None:
    names = {str(p.relative_to(ROOT)) for p in scanned_files()}
    assert {"README.md", "agents.yaml", "examples/renegade-penguin.yaml", "examples/outcomes-2026-10.jsonl"} <= names


@pytest.mark.parametrize(
    "text,category",
    [
        ("the box at 192.168.1.20 and 10.0.0.5", "private IPv4 address"),
        ("NAS at storage-01.local", "hostname"),
        ("ssh build.lan", "hostname"),
        ("serial: ABC123XYZ9", "machine identifier"),
        ("asset tag # 0042A9", "machine identifier"),
        ("de K1ABC listening", "callsign-shaped token"),
        ("grid FN42ab", "Maidenhead grid square"),
        ("aa:bb:cc:dd:ee:ff", "MAC address"),
        ("/home/someone/src", "home-directory path"),
        ("see intranet.example.corp", "hostname"),
        ("the box at 172.20.4.9 and 169.254.1.1", "private IPv4 address"),
        ("reach it at 100.101.102.103 over the VPN", "carrier-grade NAT address (a VPN's)"),
        ("host mybox.tail1234.ts.net", "tailnet name"),
        ("through twingate or Tailscale", "tailnet name"),
        ("http://nas.home:11434", "hostname"),
    ],
)
def test_the_patterns_catch_what_they_are_for(text: str, category: str) -> None:
    assert any(hit.startswith(category + ":") for hit in findings(text))


@pytest.mark.parametrize(
    "text",
    [
        "N0CALL and N0TST are the placeholders",
        "grid FN31pr",
        "https://github.com/ChiefGyk3D/scrum-around-and-find-out",
        "api.github.com:443 pypi.org:443 files.pythonhosted.org:443",
        "http://ollama.lan:11434 and http://ollama.lan:11435",
        "a zero-trust remote-access client",
        "agents.local.yaml and ~/.config/safo/agents.local.yaml",
        "board.yaml, action.yml, requirements.txt, P2 later, S (hours), M (a day)",
        "Python 3.11, the W3C, PyYAML 6.0.3 and scripts/apply-baseline.sh",
    ],
)
def test_ordinary_text_passes(text: str) -> None:
    assert findings(text) == []


def test_private_terms_come_from_a_file_outside_the_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    extra = tmp_path / "private.txt"
    extra.write_text("# one regex per line\nacme-secret-corp\n")
    monkeypatch.setenv("SAFO_PRIVACY_EXTRA_FILE", str(extra))
    assert findings("worked at acme-secret-corp once") == ["private term 1: line 1"]
    assert findings("nothing here") == []


@pytest.mark.parametrize(
    "text,category",
    [
        ("https://private.example.xyz/path", "hostname"),
        ("HTTPS://PRIVATE.EXAMPLE.XYZ/path", "hostname"),
        ("fd00::1", "private IPv6 address"),
        ("http://singleprivate/path", "hostname"),
    ],
)
def test_domain_and_ipv6_bypasses_are_detected(text: str, category: str) -> None:
    assert any(hit.startswith(category + ":") for hit in findings(text))


def test_failure_diagnostics_never_repeat_private_terms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import traceback

    extra = tmp_path / "private.txt"
    extra.write_text("sentinel-private-term\n")
    monkeypatch.setenv("SAFO_PRIVACY_EXTRA_FILE", str(extra))
    hits = findings("sentinel-private-term")
    assert hits
    try:
        assert not hits, "public.md: " + "; ".join(hits)
    except AssertionError as err:
        diagnostic = "".join(traceback.format_exception_only(err))
    assert "sentinel-private-term" not in diagnostic


@pytest.mark.parametrize(
    "text,category",
    [
        ("192.168.0.1", "private IPv4 address"),
        ("172.16.0.1", "private IPv4 address"),
        ("100.64.1.1", "carrier-grade NAT address (a VPN's)"),
        ("100.100.200.30", "carrier-grade NAT address (a VPN's)"),
        ("my-device.tailscale.net", "tailnet name"),
        ("N1ABC", "callsign-shaped token"),
        ("internal.server.local", "hostname"),
    ],
)
def test_more_private_shapes_are_caught(text: str, category: str) -> None:
    assert any(hit.startswith(category + ":") for hit in findings(text))


def test_the_grid_square_placeholder_alone_passes() -> None:
    assert findings("FN31pr") == []


def test_a_terms_file_inside_the_repository_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    inside = ROOT / "privacy-terms.txt"
    monkeypatch.setenv("SAFO_PRIVACY_EXTRA_FILE", str(inside))
    with pytest.raises(RuntimeError, match="outside"):
        extra_patterns()
