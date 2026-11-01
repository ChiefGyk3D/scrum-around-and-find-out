# SPDX-License-Identifier: Apache-2.0
"""The example broker config and the example client config load through the REAL loaders (#298, item 2).

Nothing created either file before: the server needs /etc/safo/broker.yaml (allowed uids, caps, price table, deadline)
and the client needs ~/.config/safo/broker-client.yaml. The round trip below is the guard against the example, the
loader and the runbook step drifting apart.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import os
import re
import shutil
from pathlib import Path

import pytest

from safo.broker import client, config, runbook
from safo.broker.errors import Refused
from safo.broker.pipeline import DEFAULT_DEADLINE_SECONDS
from safo.broker.policy import JOB_CAP_MICRO, MONTH_CAP_MICRO
from safo.broker.server import ServerConfig
from safo.errors import SafoError

ROOT = Path(__file__).resolve().parents[1]
BROKER_EXAMPLE = ROOT / "examples" / "broker.example.yaml"
CLIENT_EXAMPLE = ROOT / "examples" / "broker-client.example.yaml"
UID = os.getuid()


def installed(tmp_path: Path, source: Path = BROKER_EXAMPLE, name: str = "broker.yaml", uid: int = 1000) -> Path:
    """Copy a file where the loader's ownership walk accepts it (owned by this test user, not group/other writable)."""
    folder = tmp_path / "etc"
    folder.mkdir(exist_ok=True)
    folder.chmod(0o755)
    target = folder / name
    target.write_text(source.read_text().replace("allowed_uids: []", f"allowed_uids: [{uid}]"))
    target.chmod(0o644)
    return target


def load(path: Path) -> config.BrokerConfig:
    return config.load_broker_config(path, trust_uid=UID)


def test_the_example_broker_config_loads_through_the_real_loader(tmp_path: Path) -> None:
    cfg = load(installed(tmp_path))
    assert cfg.server.allowed_uids == frozenset(
        {1000}
    )  # the example names an account; the runbook inserts the real one
    assert cfg.policy.caps.job_micro == JOB_CAP_MICRO and cfg.policy.caps.month_micro == MONTH_CAP_MICRO
    assert cfg.deadline_seconds == DEFAULT_DEADLINE_SECONDS
    assert set(cfg.policy.prices.models) == {"gemini-nano-banana-2.1", "gemini-3.1-flash-lite-image"}


def test_the_example_as_shipped_is_refused_so_nobody_installs_it_unchanged(tmp_path: Path) -> None:
    """It names no account on purpose: an empty list is refused by the loader with a clear sentence."""
    folder = tmp_path / "etc"
    folder.mkdir()
    folder.chmod(0o755)
    path = folder / "broker.yaml"
    shutil.copyfile(BROKER_EXAMPLE, path)
    path.chmod(0o644)
    assert "allowed_uids: []" in path.read_text()
    with pytest.raises(SafoError, match="allowed_uids is a non-empty list"):
        load(path)


def test_the_example_states_every_server_key_with_the_value_the_code_defaults_to(tmp_path: Path) -> None:
    """A key the example leaves out, or a default that moved, would make the example lie about the running broker."""
    data = config.read_config(installed(tmp_path), UID)
    server = data["server"]
    fields = {f.name for f in dataclasses.fields(ServerConfig)}
    assert set(server) == fields
    defaults = ServerConfig(allowed_uids=frozenset({1000}))
    for name in fields - {"allowed_uids"}:
        assert server[name] == getattr(defaults, name), name


def test_every_key_of_the_example_has_a_comment() -> None:
    lines = BROKER_EXAMPLE.read_text().splitlines()
    for number, line in enumerate(lines):
        match = re.match(r"^(\s*)([A-Za-z_][\w.-]*|\"[^\"]+\"):", line)
        if match is None or line.lstrip().startswith("#"):
            continue
        key = match.group(2).strip('"')
        if key in {"1K", "2K", "4K"}:  # the size keys sit inside a one-line table whose own key has the comment
            continue
        above = number > 0 and lines[number - 1].lstrip().startswith("#")
        assert above or "#" in line, f"line {number + 1} ({key}) has no comment saying what it is"


def test_the_price_table_names_its_source_and_the_date_it_was_read() -> None:
    text = BROKER_EXAMPLE.read_text()
    assert "read 2026-10-31" in text and "Last updated 2026-10-30 UTC" in text
    assert "vendor pricing page" in text


def test_the_price_table_is_valid_on_the_day_it_was_read(tmp_path: Path) -> None:
    cfg = load(installed(tmp_path))
    table = cfg.policy.prices
    assert table.checked == dt.date(2026, 10, 31)
    for name, price in table.models.items():
        assert price.valid_through > table.checked, name
        assert price.kind == "image" and not price.cap_verified, name  # a table starts unverified, root verifies later
        assert price.image_usd.keys() == price.image_tokens.keys(), name
        assert "pro" not in name.split("-"), "a Pro-class model is not listed until its output cap is shown to hold"


def test_a_missing_section_an_unknown_section_or_no_uid_is_refused(tmp_path: Path) -> None:
    good = BROKER_EXAMPLE.read_text()
    cases = {
        "unknown section": good + "\nextras: {}\n",
        "no prices": good.split("\nprices:")[0] + "\n",
        "no uid": good.replace("allowed_uids: [1000]", "allowed_uids: []"),
        "uid as text": good.replace("allowed_uids: [1000]", 'allowed_uids: ["1000"]'),
        "caps above the built-in": good.replace('job_usd: "2.50"', 'job_usd: "3.00"'),
        "deadline out of range": good.replace("deadline_seconds: 180", "deadline_seconds: 9000"),
        "unknown caps key": good.replace("  month_usd:", '  year_usd: "1.00"\n  month_usd:'),
    }
    for label, text in cases.items():
        path = tmp_path / f"{re.sub(r'[^a-z]', '-', label)}.yaml"
        path.write_text(text)
        path.chmod(0o644)
        with pytest.raises(SafoError):
            load(path)
        assert label  # (named so a failure says which case)


def test_a_config_that_is_not_root_owned_or_is_group_writable_is_refused(tmp_path: Path) -> None:
    path = installed(tmp_path)
    path.chmod(0o664)
    with pytest.raises(SafoError):
        load(path)
    path.chmod(0o644)
    with pytest.raises(SafoError):
        config.load_broker_config(path, trust_uid=UID + 1)


def test_the_server_reads_its_config_through_the_same_function(tmp_path: Path) -> None:
    """__main__ must not parse the sections a second way: the preflight and the service accept exactly the same file."""
    import inspect

    from safo.broker import __main__ as entry

    source = inspect.getsource(entry.run)
    assert "load_broker_config(" in source
    for stale in ("parse_prices(", "ServerConfig.from_mapping(", "_SECTIONS"):
        assert stale not in source


def test_the_example_client_config_loads_through_the_real_loader(tmp_path: Path) -> None:
    home = tmp_path / "home"
    folder = home / ".config" / "safo"
    folder.mkdir(parents=True)
    for part in (home / ".config", folder, home):
        part.chmod(0o700)
    target = folder / "broker-client.yaml"
    shutil.copyfile(CLIENT_EXAMPLE, target)
    target.chmod(0o600)
    cfg = client.load_client_config(home=home, root_path=tmp_path / "no-such-root-config.yaml")
    assert cfg.socket == client.DEFAULT_SOCKET
    assert cfg.principal == "yubikey-a" and cfg.signing_key.startswith("/")
    assert cfg.image_dir.startswith("/") and cfg.private_terms == "default"
    assert cfg.reply_seconds == client.DEFAULT_REPLY_SECONDS
    again = client.parse_user_config(CLIENT_EXAMPLE.read_text())
    assert again == cfg


def test_every_key_of_the_example_client_config_has_a_comment() -> None:
    lines = CLIENT_EXAMPLE.read_text().splitlines()
    keys = [n for n, line in enumerate(lines) if re.match(r"^\s*[a-z_]+:", line) and not line.lstrip().startswith("#")]
    assert len(keys) >= 6
    for number in keys:
        assert lines[number - 1].lstrip().startswith("#") or "#" in lines[number], lines[number]


def test_the_runbook_step_writes_exactly_the_example_with_the_uid_filled_in(tmp_path: Path) -> None:
    """One source of truth: the here-document in the runbook and examples/broker.example.yaml are the same text, apart
    from the line that holds the account id (a mark the step swaps for `id -u LOGIN`, a sample number in the example)."""
    template = runbook.broker_config("1000")
    shipped = BROKER_EXAMPLE.read_text()
    assert shipped == "# SPDX-License-Identifier: Apache-2.0\n" + runbook.broker_config("")  # only the licence line
    assert "allowed_uids: []" in shipped  # the shipped example names no account
    rendered = runbook.render(maintainer="alice")
    assert runbook.BROKER_CONFIG in rendered  # the text is embedded unchanged, with the mark and no expansion
    assert rendered.count("sh $(id -u alice) <<") == 1  # the id is asked of the machine and passed as an argument
    path = tmp_path / "etc"
    path.mkdir()
    (path / "broker.yaml").write_text(template)
    (path / "broker.yaml").chmod(0o644)
    assert load(path / "broker.yaml").server.allowed_uids == frozenset({1000})


def test_no_model_in_the_example_is_one_decision_13_keeps_refused(tmp_path: Path) -> None:
    """The shipped table lists only models the policy accepts at their largest size with the cap still unverified."""
    from safo.broker.policy import UNVERIFIED_LIMIT_MICRO, is_pro_class
    from safo.broker.prices import reserve_amount

    cfg = load(installed(tmp_path))
    today = dt.date(2026, 10, 31)
    assert cfg.policy.prices.models
    for name, price in cfg.policy.prices.models.items():
        assert not is_pro_class(name), name
        for size in price.image_tokens:
            reserved = reserve_amount(
                price,
                kind="image",
                prompt_bytes=200_000,
                max_output_tokens=price.output_token_limit,
                image_size=size,
                count=1,
                today=today,
            ).total_micro
            assert reserved <= UNVERIFIED_LIMIT_MICRO, (name, size, reserved)
            cfg.policy.check_unverified(price, reserved)  # the policy itself agrees: no model_refused
    # and the negative case: the same check does refuse a model whose worst case is over the limit
    worst = max(m.output_token_limit for m in cfg.policy.prices.models.values())
    big = dataclasses.replace(next(iter(cfg.policy.prices.models.values())), output_token_limit=worst * 4)
    with pytest.raises(Refused, match="refused until its output cap"):
        cfg.policy.check_unverified(big, UNVERIFIED_LIMIT_MICRO + 1)
