# SPDX-License-Identifier: Apache-2.0
"""The egress part of the runbook: the vendor host is pasted into a root-owned file, observe mode first, then drop."""

from __future__ import annotations

import re

from safo.broker import runbook


def doc() -> str:
    return runbook.render(maintainer="MAINTAINER_LOGIN")


def lines() -> list[str]:
    return [x for x in doc().splitlines() if x.startswith("ssh ")]


def test_no_command_names_the_vendor_host() -> None:
    text = doc()
    assert "googleapis" not in text
    assert "PASTE_VENDOR_API_HOST_HERE" in text
    assert "VENDOR_HOST=PASTE_VENDOR_API_HOST_HERE" in text


def test_the_config_starts_in_observe_mode() -> None:
    line = next(x for x in lines() if "broker-egress.conf" in x and "printf" in x)
    assert "MODE=observe" in line
    assert "MODE=drop" not in line


def test_the_steps_run_in_order_conf_then_egress_then_socket_then_drop() -> None:
    text = doc()
    order = [
        "broker-egress.conf",
        "systemctl enable --now safo-broker-egress.service",
        "systemctl enable --now safo-broker.socket",
        "MODE=drop",
    ]
    positions = [text.index(x) for x in order]
    assert positions == sorted(positions)


def test_the_directory_for_the_hosts_view_is_made_and_removed() -> None:
    assert any("install -d -m 0755" in x and " /etc/safo/egress " in x for x in lines())
    assert any(
        x.startswith("ssh -t host 'sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin rmdir") and "/etc/safo/egress" in x
        for x in lines()
    )


def test_the_drop_step_has_a_rollback_to_observe_and_names_its_blast_radius() -> None:
    step = next(
        s
        for s in re.split(r"^### Step ", doc(), flags=re.MULTILINE)
        if s.startswith(tuple("0123456789")) and "drop mode" in s.splitlines()[0]
    )
    assert "Blast radius:" in step
    assert "MODE=drop/ MODE=observe/" not in step
    assert "s/^MODE=drop/MODE=observe/" in step
    assert step.index("Rollback:") < step.index("s/^MODE=drop/MODE=observe/")


def test_the_observe_step_reads_the_log_and_the_set_without_changing_anything() -> None:
    assert any("journalctl -k" in x and "safo-broker-egress-observe" in x for x in lines())
    assert any("nft list set inet safo_broker_egress vendor_v4" in x for x in lines())


def test_the_vendor_restriction_section_is_dated_and_marks_what_is_unverified() -> None:
    text = doc()
    assert "read 2026-10-31" in text
    assert "Restrict to Gemini API only" in text
    assert "Not verified" in text
    assert "spend cap" in text
