# SPDX-License-Identifier: Apache-2.0
"""The broker client against the real server (socketpairs, the fake vendor, a software key), the configuration it reads,
the socket it trusts, the safe image writer it falls back to, the signer's argument vector and the command line."""

from __future__ import annotations

import importlib
import io
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import types
from pathlib import Path
from typing import Any

import pytest

import clientdata as d
from fakevendor import png
from geminidata import make_key
from pipedata import LABEL, Rig
from safo import geminisign
from safo.broker import client, protocol
from safo.errors import SafoError
from serverdata import CRED, Env

CHARGED = "THE CALL MAY HAVE BEEN CHARGED"


@pytest.fixture(scope="module")
def key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_key(tmp_path_factory.mktemp("sysclientkey") / "k")


# -- the real server ---------------------------------------------------------------------------------------------------


class Live:
    """A client wired to the real server over socketpairs; every connection is served by its own thread."""

    def __init__(self, tmp: Path, key: Path, image_dir: Path | None = None) -> None:
        self.rig = Rig(tmp, key)
        self.env = Env(self.rig)
        self.threads: list[threading.Thread] = []
        self.events: list[str] = []
        self.out, self.err = io.StringIO(), io.StringIO()
        self.cfg = client.ClientConfig(
            socket="/run/x.sock", signing_key="/x", principal=LABEL, image_dir=str(image_dir or tmp / "images")
        )
        self.deps = client.Deps(
            connect=self.connect,
            sign=d.Signer(key, self.events),
            now=self.rig.clock.wall,
            mono=self.rig.clock.mono,
            writer=client.adapter_write_image,
            sidecar=client.adapter_write_sidecar,
            check_dir=client.check_image_dir,
            terms=lambda text: None,
            confirm=lambda prompt: "approve " + self.job,
            interactive=True,
        )
        self.job = "job-one"

    def connect(self) -> socket.socket:
        ours, theirs = socket.socketpair()
        thread = threading.Thread(target=self.env.server.handle_connection, args=(theirs, CRED))
        thread.start()
        self.threads.append(thread)
        return ours

    def run(self, params: client.PaidParams) -> int:
        self.job = params.job
        try:
            return client.run_paid(params, self.cfg, self.deps, self.out, self.err)
        finally:
            for thread in self.threads:
                thread.join(timeout=30)
                assert not thread.is_alive()


@pytest.fixture
def live(tmp_path: Path, key: Path) -> Live:
    return Live(tmp_path, key)


def test_a_text_call_works_end_to_end_against_the_real_server(live: Live) -> None:
    assert live.run(d.text_params()) == 0
    assert live.err.getvalue() == ""
    assert "receipt: call " in live.out.getvalue() and len(live.rig.vendor.requests) == 1
    assert live.rig.vendor.requests[0] is not None


def test_a_vendor_429_is_exit_3_with_the_retry_hint_and_is_not_repeated(live: Live) -> None:
    live.rig.vendor.mode = "status"
    live.rig.vendor.status = 429
    live.rig.vendor.headers = {"Retry-After": "30"}
    assert live.run(d.text_params()) == 3
    assert "retry hint from the vendor: 30 seconds" in live.err.getvalue() and CHARGED in live.err.getvalue()
    assert len(live.rig.vendor.requests) == 1


def test_a_vendor_that_goes_silent_is_outcome_unknown_with_the_broker_receipt(live: Live) -> None:
    live.rig.vendor.mode = "timeout"
    assert live.run(d.text_params()) == 4
    assert "outcome_unknown" in live.err.getvalue() and "receipt: call " in live.err.getvalue()
    assert len(live.rig.vendor.requests) == 1


def test_the_off_switch_is_reported_before_anything_is_signed(live: Live) -> None:
    live.env.enabled = False
    assert live.run(d.text_params()) == 2
    assert "disabled" in live.err.getvalue() and live.events == []


def test_an_image_call_writes_a_private_file_and_a_receipt_beside_it(tmp_path: Path, key: Path) -> None:
    folder = tmp_path / "images"
    folder.mkdir(mode=0o700)
    live = Live(tmp_path, key, folder)
    live.rig.vendor.image = png()
    live.rig.vendor.mime = "image/png"
    params = d.image_params(max_usd="2.5", max_output_tokens=4000)
    assert live.run(params) == 0, live.err.getvalue()
    files = sorted(p.name for p in folder.iterdir())
    assert len(files) == 2 and files[0].endswith(".png") and files[1] == files[0] + ".receipt.json"
    image, sidecar = (folder / files[0]), (folder / files[1])
    assert image.read_bytes() == png() and stat.S_IMODE(image.stat().st_mode) == 0o600
    assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600
    side = json.loads(sidecar.read_text())
    assert side["reviewed"] is False and side["image"]["bytes"] == len(png())
    assert f"({len(png())} bytes, type png)" in live.out.getvalue()


# -- the configuration -------------------------------------------------------------------------------------------------


def write_config(path: Path, text: str, mode: int = 0o600) -> Path:
    path.write_text(text)
    path.chmod(mode)
    return path


USER_TEXT = """\
version: 1
socket: /run/user-chosen.sock
signing:
  key: /home/x/.ssh/id_sk
  principal: yubikey-a
image_output_dir: /home/x/images
private_terms: none
reply_seconds: 90
"""


def load(tmp_path: Path, user: str | None = None, root: str | None = None, **kw: Any) -> client.ClientConfig:
    user_path = write_config(tmp_path / "user.yaml", user) if user is not None else tmp_path / "missing-user.yaml"
    root_path = (
        write_config(tmp_path / "root.yaml", root, 0o644) if root is not None else tmp_path / "missing-root.yaml"
    )
    return client.load_client_config(
        home=tmp_path, user_path=user_path, root_path=root_path, root_uid=os.geteuid(), **kw
    )


def test_with_no_file_the_default_socket_is_used(tmp_path: Path) -> None:
    cfg = load(tmp_path)
    assert cfg.socket == client.DEFAULT_SOCKET == "/run/safo-broker.sock"
    assert (cfg.signing_key, cfg.principal, cfg.image_dir) == ("", "", "")


def test_a_user_file_names_the_socket_the_key_and_the_folder(tmp_path: Path) -> None:
    cfg = load(tmp_path, USER_TEXT)
    assert cfg.socket == "/run/user-chosen.sock"
    assert (cfg.signing_key, cfg.principal) == ("/home/x/.ssh/id_sk", "yubikey-a")
    assert (cfg.image_dir, cfg.private_terms, cfg.reply_seconds) == ("/home/x/images", "none", 90.0)


def test_a_root_owned_socket_setting_wins_over_the_user_file(tmp_path: Path) -> None:
    cfg = load(tmp_path, USER_TEXT, "version: 1\nsocket: /run/root-chosen.sock\n")
    assert cfg.socket == "/run/root-chosen.sock" and cfg.signing_key == "/home/x/.ssh/id_sk"


def test_the_root_file_may_set_nothing_but_the_socket(tmp_path: Path) -> None:
    with pytest.raises(SafoError):
        load(tmp_path, None, "version: 1\nsigning:\n  key: /x\n")


def test_a_root_file_the_account_can_write_is_refused(tmp_path: Path) -> None:
    root = write_config(tmp_path / "root.yaml", "version: 1\nsocket: /run/x.sock\n", 0o666)
    with pytest.raises(SafoError):
        client.load_client_config(home=tmp_path, user_path=tmp_path / "none", root_path=root, root_uid=os.geteuid())


def test_the_environment_never_names_the_socket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SAFO_BROKER_SOCKET", "/tmp/evil.sock")
    monkeypatch.setenv("BROKER_SOCKET", "/tmp/evil.sock")
    assert load(tmp_path, USER_TEXT).socket == "/run/user-chosen.sock"
    assert load(tmp_path).socket == client.DEFAULT_SOCKET


@pytest.mark.parametrize(
    "text",
    [
        "version: 2\n",
        "version: 1\nunknown: 1\n",
        "version: 1\nsocket: relative.sock\n",
        "version: 1\nsocket: ''\n",
        "version: 1\nsocket: 5\n",
        "version: 1\nsigning:\n  key: relative\n",
        "version: 1\nsigning:\n  principal: Bad Name\n",
        "version: 1\nimage_output_dir: relative/dir\n",
        "version: 1\nprivate_terms: maybe\n",
        "version: 1\nreply_seconds: 5\n",
        "version: 1\nreply_seconds: 100000\n",
        "version: 1\nreply_seconds: true\n",
        "version: 1\na: &x 1\nsocket: *x\n",
        "- not a mapping\n",
        "version: 1\nsocket: /a\nsocket: /b\n",
    ],
)
def test_a_bad_user_file_is_refused(tmp_path: Path, text: str) -> None:
    with pytest.raises(SafoError):
        load(tmp_path, text)


def test_a_user_file_others_can_write_is_refused(tmp_path: Path) -> None:
    user = write_config(tmp_path / "user.yaml", USER_TEXT, 0o666)
    with pytest.raises(SafoError):
        client.load_client_config(home=tmp_path, user_path=user, root_path=tmp_path / "none", root_uid=os.geteuid())


def test_the_user_file_default_place_is_under_the_account_home(tmp_path: Path) -> None:
    assert client.user_config_path(tmp_path) == tmp_path / ".config" / "safo" / "broker-client.yaml"


# -- the socket it trusts ----------------------------------------------------------------------------------------------


@pytest.fixture
def sock_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("s")


def listening(path: Path) -> socket.socket:
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(4)
    return srv


def test_a_socket_owned_by_the_expected_account_is_connected_to(sock_dir: Path) -> None:
    srv = listening(sock_dir / "b.sock")
    conn = client.connect_unix(str(sock_dir / "b.sock"), owner=os.geteuid())
    peer, _ = srv.accept()
    conn.sendall(b"hi")
    assert peer.recv(2) == b"hi"
    for s in (conn, peer, srv):
        s.close()


def test_a_socket_owned_by_someone_else_is_refused(sock_dir: Path) -> None:
    srv = listening(sock_dir / "b.sock")
    with pytest.raises(SafoError, match="not owned"):
        client.connect_unix(str(sock_dir / "b.sock"), owner=os.geteuid() + 1)
    srv.close()


def test_the_default_owner_is_root_so_a_socket_the_account_made_is_refused(sock_dir: Path) -> None:
    srv = listening(sock_dir / "b.sock")
    if os.geteuid() == 0:
        pytest.skip("running as root: the account would own a root socket")
    with pytest.raises(SafoError, match="not owned"):
        client.connect_unix(str(sock_dir / "b.sock"))
    srv.close()


def test_a_symlink_to_a_good_socket_is_refused(sock_dir: Path) -> None:
    srv = listening(sock_dir / "real.sock")
    (sock_dir / "link.sock").symlink_to(sock_dir / "real.sock")
    with pytest.raises(SafoError, match="not a socket"):
        client.connect_unix(str(sock_dir / "link.sock"), owner=os.geteuid())
    srv.close()


def test_a_regular_file_is_refused(sock_dir: Path) -> None:
    (sock_dir / "f").write_text("x")
    with pytest.raises(SafoError, match="not a socket"):
        client.connect_unix(str(sock_dir / "f"), owner=os.geteuid())


def test_a_world_writable_socket_is_refused(sock_dir: Path) -> None:
    srv = listening(sock_dir / "b.sock")
    (sock_dir / "b.sock").chmod(0o666)
    with pytest.raises(SafoError, match="writable by everyone"):
        client.connect_unix(str(sock_dir / "b.sock"), owner=os.geteuid())
    srv.close()


def test_a_missing_socket_is_not_reachable(sock_dir: Path) -> None:
    with pytest.raises(SafoError, match="not reachable"):
        client.connect_unix(str(sock_dir / "nothing.sock"), owner=os.geteuid())


def test_a_socket_nobody_listens_on_is_not_reachable(sock_dir: Path) -> None:
    srv = listening(sock_dir / "b.sock")
    srv.close()
    with pytest.raises(SafoError, match="not reachable"):
        client.connect_unix(str(sock_dir / "b.sock"), owner=os.geteuid())


@pytest.mark.parametrize("path", ["relative.sock", "", "/run/with\x00nul"])
def test_a_path_that_is_not_absolute_is_refused(path: str) -> None:
    with pytest.raises(SafoError):
        client.connect_unix(path, owner=os.geteuid())


# -- the image writer the client falls back to -------------------------------------------------------------------------


@pytest.fixture
def folder(tmp_path: Path) -> Path:
    path = tmp_path / "pics"
    path.mkdir(mode=0o700)
    return path


def test_the_adapter_writes_a_private_file_and_returns_its_path(folder: Path) -> None:
    where = client.adapter_write_image(d.PNG, str(folder), "name-1", 1000)
    assert where == str(folder / "name-1.png")
    assert (folder / "name-1.png").read_bytes() == d.PNG
    assert stat.S_IMODE((folder / "name-1.png").stat().st_mode) == 0o600


@pytest.mark.parametrize(("data", "ext"), [(d.PNG, "png"), (d.JPEG, "jpg"), (d.WEBP, "webp")])
def test_the_adapter_picks_the_extension_from_the_first_bytes(folder: Path, data: bytes, ext: str) -> None:
    assert client.adapter_write_image(data, str(folder), "s", 1000).endswith("." + ext)


def test_the_adapter_never_overwrites(folder: Path) -> None:
    client.adapter_write_image(d.PNG, str(folder), "same", 1000)
    with pytest.raises((SafoError, OSError)):
        client.adapter_write_image(d.PNG + b"2", str(folder), "same", 1000)
    assert (folder / "same.png").read_bytes() == d.PNG


def test_the_adapter_does_not_follow_a_link_at_the_target(folder: Path, tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("keep")
    (folder / "t.png").symlink_to(victim)
    with pytest.raises((SafoError, OSError)):
        client.adapter_write_image(d.PNG, str(folder), "t", 1000)
    assert victim.read_text() == "keep"


def test_the_adapter_refuses_what_is_not_an_allowed_image(folder: Path) -> None:
    for data in (b"", b"<html></html>", b"GIF89a" + b"\x00" * 20, d.PNG + b"x" * 2000):
        with pytest.raises((SafoError, OSError)):
            client.adapter_write_image(data, str(folder), "x", 1000)
    assert list(folder.iterdir()) == []


def test_the_adapter_cleans_the_stem(folder: Path) -> None:
    where = client.adapter_write_image(d.PNG, str(folder), "../../evil name\n", 1000)
    assert (
        os.path.dirname(where) == str(folder)
        and ".." not in os.path.basename(where)
        and "/" not in os.path.basename(where)
    )


def test_the_adapter_refuses_a_directory_that_is_not_private(tmp_path: Path) -> None:
    open_dir = tmp_path / "open"
    open_dir.mkdir(mode=0o755)
    open_dir.chmod(0o755)
    with pytest.raises((SafoError, OSError)):
        client.adapter_write_image(d.PNG, str(open_dir), "x", 1000)


def test_the_adapter_refuses_a_symlinked_directory(folder: Path, tmp_path: Path) -> None:
    link = tmp_path / "linkdir"
    link.symlink_to(folder)
    with pytest.raises((SafoError, OSError)):
        client.adapter_write_image(d.PNG, str(link), "x", 1000)


def test_the_sidecar_is_exclusive_and_private(folder: Path) -> None:
    image = client.adapter_write_image(d.PNG, str(folder), "pic", 1000)
    side = client.adapter_write_sidecar(image, b'{"a":1}')
    assert side == image + ".receipt.json" and stat.S_IMODE(os.stat(side).st_mode) == 0o600
    with pytest.raises((SafoError, OSError)):
        client.adapter_write_sidecar(image, b"{}")
    assert Path(side).read_bytes() == b'{"a":1}'


def test_the_folder_check_accepts_a_private_folder_and_refuses_the_rest(folder: Path, tmp_path: Path) -> None:
    client.check_image_dir(str(folder))
    open_dir = tmp_path / "open"
    open_dir.mkdir()
    open_dir.chmod(0o755)
    (tmp_path / "file").write_text("x")
    link = tmp_path / "ln"
    link.symlink_to(folder)
    for bad in (open_dir, tmp_path / "file", link, tmp_path / "missing"):
        with pytest.raises((SafoError, OSError)):
            client.check_image_dir(str(bad))
    with pytest.raises(SafoError):
        client.check_image_dir("relative")


def test_the_default_writer_is_the_phase_4a_writer_when_it_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = types.SimpleNamespace(write_image=lambda data, directory, stem, max_bytes: "x")
    real = importlib.import_module

    def present(name: str, *a: Any) -> Any:
        return fake if name == "safo.broker.imagewrite" else real(name, *a)

    monkeypatch.setattr(importlib, "import_module", present)
    assert client.default_writer() is fake.write_image


def test_the_default_writer_is_the_adapter_while_phase_4a_is_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    real = importlib.import_module

    def absent(name: str, *a: Any) -> Any:
        if name == "safo.broker.imagewrite":
            raise ModuleNotFoundError(name=name)
        return real(name, *a)

    monkeypatch.setattr(importlib, "import_module", absent)
    assert client.default_writer() is client.adapter_write_image


def test_a_different_missing_module_inside_the_writer_is_not_hidden(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(name: str, *a: Any) -> Any:
        raise ModuleNotFoundError(name="somethingelse")

    monkeypatch.setattr(importlib, "import_module", broken)
    with pytest.raises(ModuleNotFoundError):
        client.default_writer()


# -- the signer --------------------------------------------------------------------------------------------------------


def test_the_default_signer_runs_ssh_keygen_with_a_fixed_vector_and_a_clean_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(args: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        seen["args"], seen["kw"] = args, kw
        return subprocess.CompletedProcess(
            args, 0, b"-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"
        )

    monkeypatch.setattr("safo.geminisign.subprocess.run", fake_run)
    cfg = client.ClientConfig(socket="/s", signing_key="/home/x/.ssh/id_sk", principal=LABEL)
    env = {
        "HOME": "/home/x",
        "SSH_AUTH_SOCK": "/run/agent",
        "TERM": "xterm",
        "DOPPLER_TOKEN": "secret",
        "PYTHONPATH": "/evil",
        "LD_PRELOAD": "/evil.so",
        "SAFO_BROKER_SOCKET": "/evil",
    }
    armor = client.default_signer(cfg, env)(b'{"a":1}')
    assert armor.startswith("-----BEGIN SSH SIGNATURE-----")
    assert seen["args"] == [
        geminisign.ssh_keygen(),
        "-Y",
        "sign",
        "-f",
        "/home/x/.ssh/id_sk",
        "-n",
        "safo-gemini-approval",
    ]
    kw = seen["kw"]
    assert kw["input"] == b'{"a":1}' and not kw.get("shell")
    assert "stderr" not in kw and "stdin" not in kw, "the touch prompt must reach the terminal"
    assert kw["env"] == {"HOME": "/home/x", "SSH_AUTH_SOCK": "/run/agent", "TERM": "xterm", "PATH": "/usr/bin:/bin"}


def test_the_default_signer_refuses_a_missing_key_path() -> None:
    with pytest.raises(SafoError):
        client.default_signer(client.ClientConfig(socket="/s"), {})


# -- the command line --------------------------------------------------------------------------------------------------


def command(tmp_path: Path, prompt: str = d.PROMPT, **over: str) -> list[str]:
    path = tmp_path / "prompt.txt"
    path.write_text(prompt)
    words = {
        "--model": "flat-test",
        "--job": "job-one",
        "--max-output-tokens": "500",
        "--max-usd": "0.5",
        "--quote": d.QUOTE,
        "--quoted-at": "2026-10-30T11:59:00Z",
        "--prompt-file": str(path),
        "--issue": "ChiefGyk3D/scrum-around-and-find-out#260",
    }
    words.update(over)
    return [x for pair in words.items() for x in pair]


def test_the_command_line_runs_the_paid_flow(tmp_path: Path, key: Path) -> None:
    rig = d.make_rig(key)
    out, err = io.StringIO(), io.StringIO()
    code = client.main(command(tmp_path), env={}, stdin=io.StringIO(), out=out, err=err, deps=rig.deps, cfg=rig.cfg)
    assert code == 0 and d.ANSWER in out.getvalue() and err.getvalue() == ""
    assert rig.broker.requests[0]["model"] == "flat-test" and rig.broker.requests[0]["max_usd"] == "0.5"


def test_the_command_line_reads_an_image_request(tmp_path: Path, key: Path) -> None:
    rig = d.make_rig(key, ["approve job-img"])
    rig.broker.answer("begin", d.offer_reply(thinking_level="minimal"))
    rig.broker.answer("call", d.ok_call(text="", rcpt=d.image_receipt(), images=(d.PNG,)))
    args = command(
        tmp_path,
        **{
            "--model": "gemini-nano-banana-2.1",
            "--job": "job-img",
            "--kind": "image",
            "--image-size": "1K",
            "--aspect-ratio": "16:9",
        },
    )
    out, err = io.StringIO(), io.StringIO()
    assert client.main(args, env={}, stdin=io.StringIO(), out=out, err=err, deps=rig.deps, cfg=rig.cfg) == 0
    assert rig.broker.requests[0]["aspect_ratio"] == "16:9" and rig.broker.requests[0]["count"] == 1


def test_a_missing_required_option_is_a_usage_error(tmp_path: Path, key: Path) -> None:
    rig = d.make_rig(key)
    args = command(tmp_path)
    del args[args.index("--model") : args.index("--model") + 2]
    with pytest.raises(SystemExit) as stop:
        client.main(args, env={}, stdin=io.StringIO(), out=io.StringIO(), err=io.StringIO(), deps=rig.deps, cfg=rig.cfg)
    assert stop.value.code == 2 and rig.broker.opened == 0


def test_an_unreadable_prompt_file_is_refused(tmp_path: Path, key: Path) -> None:
    rig = d.make_rig(key)
    err = io.StringIO()
    args = command(tmp_path, **{"--prompt-file": str(tmp_path / "missing.txt")})
    assert client.main(args, env={}, stdin=io.StringIO(), out=io.StringIO(), err=err, deps=rig.deps, cfg=rig.cfg) == 2
    assert rig.broker.opened == 0 and "prompt file" in err.getvalue()


def test_a_prompt_file_that_is_not_utf8_or_too_big_is_refused(tmp_path: Path, key: Path) -> None:
    rig = d.make_rig(key)
    bad = tmp_path / "bad.txt"
    bad.write_bytes(b"\xff\xfe\x00")
    big = tmp_path / "big.txt"
    big.write_bytes(b"x" * (protocol.MAX_PROMPT_BYTES + 1))
    for path in (bad, big):
        args = command(tmp_path, **{"--prompt-file": str(path)})
        assert (
            client.main(
                args, env={}, stdin=io.StringIO(), out=io.StringIO(), err=io.StringIO(), deps=rig.deps, cfg=rig.cfg
            )
            == 2
        )
    assert rig.broker.opened == 0


def test_the_command_line_without_a_terminal_signs_nothing(tmp_path: Path, key: Path) -> None:
    out = io.StringIO()
    rig = d.make_rig(key)
    rig.deps.interactive = False
    err = io.StringIO()
    assert (
        client.main(command(tmp_path), env={}, stdin=io.StringIO(), out=out, err=err, deps=rig.deps, cfg=rig.cfg) == 2
    )
    assert rig.signer.payloads == [] and "terminal" in err.getvalue()


def test_the_socket_path_the_command_line_connects_to_ignores_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    def record(path: str, **kw: Any) -> socket.socket:
        seen.append(path)
        raise FileNotFoundError

    monkeypatch.setattr(client, "connect_unix", record)
    monkeypatch.setattr(client, "_tty", lambda stream: True)
    monkeypatch.setattr(
        client,
        "load_client_config",
        lambda **kw: client.ClientConfig(
            socket="/run/configured.sock", signing_key="/k", principal=LABEL, private_terms="none"
        ),
    )
    env = {"SAFO_BROKER_SOCKET": "/tmp/evil.sock", "HOME": str(tmp_path)}
    err = io.StringIO()
    code = client.main(command(tmp_path), env=env, stdin=io.StringIO(), out=io.StringIO(), err=err)
    assert code == 2 and seen == ["/run/configured.sock"]


def test_the_module_can_be_run_as_a_script_and_prints_usage() -> None:
    done = subprocess.run(
        [sys.executable, "-I", "-m", "safo.broker.client", "--help"], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0 and "--max-usd" in done.stdout


def test_a_relative_socket_path_is_refused_as_such() -> None:
    with pytest.raises(SafoError, match="absolute"):
        client.connect_unix("relative.sock", owner=os.geteuid())


def test_an_image_command_without_an_aspect_ratio_asks_for_one_to_one(tmp_path: Path, key: Path) -> None:
    rig = d.make_rig(key)
    rig.broker.answer("begin", d.offer_reply(thinking_level="minimal"))
    rig.broker.answer("call", d.ok_call(text="", rcpt=d.image_receipt(), images=(d.PNG,)))
    args = command(
        tmp_path,
        **{"--model": "gemini-nano-banana-2.1", "--job": "job-img", "--kind": "image", "--image-size": "1K"},
    )
    out, err = io.StringIO(), io.StringIO()
    assert client.main(args, env={}, stdin=io.StringIO(), out=out, err=err, deps=rig.deps, cfg=rig.cfg) == 0
    assert rig.broker.requests[0]["aspect_ratio"] == "1:1"


def test_an_image_count_of_zero_on_the_command_line_is_refused(tmp_path: Path, key: Path) -> None:
    rig = d.make_rig(key)
    args = command(tmp_path, **{"--kind": "image", "--image-size": "1K", "--count": "0"})
    err = io.StringIO()
    assert client.main(args, env={}, stdin=io.StringIO(), out=io.StringIO(), err=err, deps=rig.deps, cfg=rig.cfg) == 2
    assert rig.broker.opened == 0


def test_a_text_command_with_image_options_is_refused(tmp_path: Path, key: Path) -> None:
    rig = d.make_rig(key)
    args = command(tmp_path, **{"--image-size": "1K"})
    assert (
        client.main(args, env={}, stdin=io.StringIO(), out=io.StringIO(), err=io.StringIO(), deps=rig.deps, cfg=rig.cfg)
        == 2
    )
    assert rig.broker.opened == 0


def test_a_folder_that_belongs_to_someone_else_is_refused(folder: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client.check_image_dir(str(folder))
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(folder).st_uid + 1)
    with pytest.raises(SafoError, match="owned by this account"):
        client.check_image_dir(str(folder))
