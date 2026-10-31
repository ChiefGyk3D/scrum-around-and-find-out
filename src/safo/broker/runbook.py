# SPDX-License-Identifier: Apache-2.0
"""The one-time root setup runbook for the paid broker, as text.

This module only builds a string. It imports nothing that can run a command and nothing in it is ever executed: the
maintainer reads the plan and pastes each line himself. Every command is a full `ssh -t host 'sudo ...'` line (`host` is
a placeholder, never a real name), and every step states its blast radius and its rollback before the change.

The key itself is never in this text: the credential step reads it on the remote terminal with `read -rs`, so it is
never in an argument, a history file or `ps`. The enable switch is left OFF: no line here creates it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

LOGIN = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
PASTE_KEY = "PASTE_RELEASE_PUBLIC_KEY_HERE"


@dataclass(frozen=True)
class Step:
    title: str
    why: str
    commands: tuple[str, ...]
    blast: str
    rollback: tuple[str, ...]
    note: str = ""


ENV = "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin"  # root never inherits the remote session's PATH or pager settings
PAGER_ENV = "LESSSECURE=1 LESSOPEN= LESSCLOSE= TERM=$TERM"  # no shell escape, no preprocessor, a terminal that works


def ssh(cmd: str, *, env: str = "") -> str:
    """Wrap one remote command as a full copy-paste line. `cmd` must not contain a single quote."""
    if "'" in cmd:
        msg = "a remote command may not contain a single quote"
        raise ValueError(msg)
    return f"ssh -t host 'sudo {ENV} {env + ' ' if env else ''}{cmd}'"


def steps(login: str) -> tuple[Step, ...]:
    return (
        Step(
            "Create the service user, the client group, and add the maintainer to the group",
            "The broker runs as its own unprivileged user. Only members of the client group can open the socket.",
            (
                ssh("groupadd --system safo-broker-clients"),
                ssh(
                    "useradd --system --user-group --home-dir /nonexistent --no-create-home "
                    "--shell /usr/sbin/nologin safo-broker"
                ),
                ssh(f"usermod -aG safo-broker-clients {login}"),
            ),
            "One new system user and two groups; the maintainer gains the client group at the next login (socket "
            "access "
            "only, no file access). No service is touched.",
            (
                ssh(f"gpasswd -d {login} safo-broker-clients"),
                ssh("userdel safo-broker"),
                ssh("groupdel safo-broker-clients"),
            ),
        ),
        Step(
            "Create the root-owned directories",
            "Trust files, the encrypted credential, the releases and the installer's version record live here.",
            (
                ssh(
                    "install -d -m 0755 -o root -g root /etc/safo /opt/safo-broker /opt/safo-broker/releases "
                    "/var/lib/safo-broker-install"
                ),
                ssh("install -d -m 0700 -o root -g root /etc/safo/broker"),
            ),
            "Empty directories owned by root. If /etc/safo already exists from the approval keys, install -d leaves "
            "its "
            "contents alone but sets its mode to 0755.",
            (ssh("rmdir /opt/safo-broker/releases /opt/safo-broker /etc/safo/broker /var/lib/safo-broker-install"),),
            "Do not make the state directory: systemd creates it (StateDirectory=) at the first service start.",
        ),
        Step(
            "Install the installer (the first copy, from a checkout you have read)",
            "Later installer versions arrive inside signed releases. This first copy is trust on first use. The "
            "checkout "
            "is writable by your account, so root first takes one copy into a root-only folder, and you read, hash and "
            "install that same root-owned copy; nothing is read from the checkout twice. Replace "
            "/path/to/reviewed/checkout with the checkout you reviewed. The installer needs python3 with pip and venv "
            "available (the last line checks pip).",
            (
                ssh("install -d -m 0700 -o root -g root /var/lib/safo-broker-install/stage"),
                ssh(
                    "install -m 0600 -o root -g root /path/to/reviewed/checkout/packaging/safo_broker_install.py "
                    "/var/lib/safo-broker-install/stage/safo-broker-install"
                ),
                ssh("sha256sum /var/lib/safo-broker-install/stage/safo-broker-install"),
                ssh("less /var/lib/safo-broker-install/stage/safo-broker-install", env=PAGER_ENV),
                ssh(
                    "install -m 0755 -o root -g root /var/lib/safo-broker-install/stage/safo-broker-install "
                    "/usr/local/sbin/safo-broker-install"
                ),
                ssh("rm -r /var/lib/safo-broker-install/stage"),
                ssh("/usr/bin/python3 -I -m pip --version"),
            ),
            "One root-run program is added. It does nothing until you run it, and it refuses to touch the state "
            "directory.",
            (
                ssh("rm /usr/local/sbin/safo-broker-install"),
                ssh("rm -rf /var/lib/safo-broker-install/stage"),
            ),
            "Compare the hash with the one you recorded when you reviewed the checkout. If the two differ, stop here "
            "and do not run the install line.",
        ),
        Step(
            "Create the credential for the paid key",
            "Make a new key in the vendor console first, on a device that is not this laptop, restricted to the one "
            "API. "
            "The key is typed at a hidden prompt on the remote terminal and goes straight into the encrypter. Use "
            "--with-key=host+tpm2 instead of --with-key=host on a machine with a TPM.",
            (
                ssh(
                    'bash -c "set -euo pipefail; umask 077; rm -f /etc/safo/broker/paid-key.new; '
                    'read -rs -p \\"paid key: \\" K; echo; '
                    'printf %s \\"\\$K\\" | systemd-creds encrypt --name=paid-key --with-key=host - '
                    "/etc/safo/broker/paid-key.new; unset K; chmod 0600 /etc/safo/broker/paid-key.new; "
                    "systemd-creds decrypt --name=paid-key /etc/safo/broker/paid-key.new /dev/null; "
                    'mv /etc/safo/broker/paid-key.new /etc/safo/broker/paid-key"'
                ),
                ssh("systemd-creds decrypt --name=paid-key /etc/safo/broker/paid-key /dev/null && echo credential-ok"),
            ),
            "One 0600 root file. The key is never in a command line, in the environment or on disk in clear. Nothing "
            "uses it yet. The script stops at the first error and replaces an older credential only after the new "
            "one decrypts.",
            (ssh("rm -f /etc/safo/broker/paid-key /etc/safo/broker/paid-key.new"),),
            "Delete the old paid key at the vendor and its secret-store entry afterwards; until then the account can "
            "still call the vendor directly.",
        ),
        Step(
            "Enroll the release signing key and set the version floor",
            "Only a tag signed by a key in this file installs. Use the public half of a release key kept apart from "
            "the "
            "approval keys, and replace the placeholder with the key field (the type is ssh-ed25519 here; change it "
            "for "
            "another key type).",
            (
                ssh(
                    'sh -c "printf \\"%s namespaces=\\\\042git\\\\042 %s %s\\\\n\\" release-signer ssh-ed25519 '
                    f'{PASTE_KEY} > /etc/safo/broker-release-signers && chmod 0644 /etc/safo/broker-release-signers"'
                ),
                ssh(
                    'sh -c "printf \\"0.0.0\\\\n\\" > /etc/safo/broker-min-version '
                    '&& chmod 0644 /etc/safo/broker-min-version"'
                ),
            ),
            "Two small root files. A wrong key here only makes installs refuse. The floor starts at the lowest value "
            "and "
            "root raises it after a security fix.",
            (ssh("rm /etc/safo/broker-release-signers /etc/safo/broker-min-version"),),
        ),
        Step(
            "Dry run, then install the first release",
            "The dry run fetches the tag, verifies the signature, checks the lock and shows the review; it writes "
            "nothing. Replace X.Y.Z with the reviewed version. The apply run asks you to type the version.",
            (
                ssh("/usr/local/sbin/safo-broker-install install X.Y.Z"),
                ssh("/usr/local/sbin/safo-broker-install install X.Y.Z --apply"),
            ),
            "Adds a read-only release under /opt/safo-broker, the two unit files under /etc/systemd/system and one "
            "version record. It restarts nothing that is running; a failed install rolls itself back.",
            (ssh("/usr/local/sbin/safo-broker-install rollback"),),
            "On a first install there is no earlier release, so rollback has nothing to go back to; to remove it, "
            "delete the unit files and the release directory under /opt/safo-broker/releases.",
        ),
        Step(
            "Enable the socket",
            "The socket starts the service on demand. The service also needs the switch file to exist, which this "
            "runbook does not create.",
            (ssh("systemctl enable --now safo-broker.socket"),),
            "A listening socket in /run owned by root with the client group. No service runs and the paid key is not "
            "read until the switch exists.",
            (ssh("systemctl disable --now safo-broker.socket safo-broker.service"),),
        ),
        Step(
            "Check the socket permissions (after your next login)",
            "Every parent must be traversable and the socket must be root:safo-broker-clients, mode 0660.",
            (ssh("namei -l /run/safo-broker.sock"),),
            "Read-only.",
            (ssh("true"),),
            "Nothing to undo; the rollback line above is a no-op.",
        ),
    )


def render(*, maintainer: str) -> str:
    """Return the whole runbook. Raises ValueError if `maintainer` is not a plain login name."""
    if not LOGIN.fullmatch(maintainer) and maintainer != "MAINTAINER_LOGIN":
        msg = "maintainer must be a plain login name"
        raise ValueError(msg)
    out = [
        "# Broker setup runbook (one time, as root)",
        "",
        "Printed by the installer; never run by it. Paste one line at a time. `host` is a placeholder for your "
        "machine.",
        "Every step says what it changes, what else it can affect, and how to undo it. Read the whole page first.",
        "",
        "## Before you start",
        "",
        "- Create a new paid key in the vendor console on another device. Do not reuse the old one.",
        "- Have a release signing key (a hardware key, separate from the approval keys) and its public half ready.",
        "- Run these on a virtual console or another machine's shell, not in a desktop terminal where an agent runs.",
        "",
    ]
    for number, step in enumerate(steps(maintainer), start=1):
        out += [f"### Step {number}: {step.title}", "", step.why, "", "```", *step.commands, "```", ""]
        out += [f"Blast radius: {step.blast}", "", "Rollback:", "", "```", *step.rollback, "```", ""]
        if step.note:
            out += [f"Note: {step.note}", ""]
    out += [
        "## The switch stays OFF",
        "",
        "This runbook never creates the root-owned switch file, /etc/safo/gemini-paid-enabled. Create it last, as "
        "the keys guide describes, after the dry",
        "run with a real key. While it is absent the service will not start, so no call can reach the vendor.",
        "",
        "## Optional extra",
        "",
        "A host firewall rule that lets only the broker user reach port 443 is a good second layer. The vendor "
        "addresses",
        "are not fixed, so the unit does not pin them; the rule belongs to your own network setup.",
        "",
    ]
    return "\n".join(out)
