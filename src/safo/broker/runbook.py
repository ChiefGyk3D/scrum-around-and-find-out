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
                    "install -d -m 0755 -o root -g root /etc/safo /etc/safo/egress /opt/safo-broker "
                    "/opt/safo-broker/releases /var/lib/safo-broker-install"
                ),
                ssh("install -d -m 0700 -o root -g root /etc/safo/broker"),
            ),
            "Empty directories owned by root. If /etc/safo already exists from the approval keys, install -d leaves "
            "its "
            "contents alone but sets its mode to 0755.",
            (
                ssh(
                    "rmdir /opt/safo-broker/releases /opt/safo-broker /etc/safo/egress /etc/safo/broker "
                    "/var/lib/safo-broker-install"
                ),
            ),
            "Do not make the state directory: systemd creates it (StateDirectory=) at the first service start.",
        ),
        Step(
            "Install the installer and the egress helper (the first copies, from a checkout you have read)",
            "Later installer versions arrive inside signed releases. These first copies are trust on first use, and "
            "the egress helper is never part of a release: it is the only code root runs from a timer, so it changes "
            "only when you install a new reviewed copy yourself. The checkout is writable by your account, so root "
            "first takes one copy of each file into a root-only folder, and you read, hash and install those same "
            "root-owned copies; nothing is read from the checkout twice. Replace /path/to/reviewed/checkout with the "
            "checkout you reviewed. The installer needs python3 with pip and venv available (the last line checks "
            "pip).",
            (
                ssh("install -d -m 0700 -o root -g root /var/lib/safo-broker-install/stage"),
                ssh(
                    "install -m 0600 -o root -g root /path/to/reviewed/checkout/packaging/safo_broker_install.py "
                    "/var/lib/safo-broker-install/stage/safo-broker-install"
                ),
                ssh(
                    "install -m 0600 -o root -g root /path/to/reviewed/checkout/packaging/safo_broker_egress.py "
                    "/var/lib/safo-broker-install/stage/safo-broker-egress"
                ),
                ssh(
                    "sha256sum /var/lib/safo-broker-install/stage/safo-broker-install "
                    "/var/lib/safo-broker-install/stage/safo-broker-egress"
                ),
                ssh("less /var/lib/safo-broker-install/stage/safo-broker-install", env=PAGER_ENV),
                ssh("less /var/lib/safo-broker-install/stage/safo-broker-egress", env=PAGER_ENV),
                ssh(
                    "install -m 0755 -o root -g root /var/lib/safo-broker-install/stage/safo-broker-install "
                    "/usr/local/sbin/safo-broker-install"
                ),
                ssh(
                    "install -m 0755 -o root -g root /var/lib/safo-broker-install/stage/safo-broker-egress "
                    "/usr/local/sbin/safo-broker-egress"
                ),
                ssh("rm -r /var/lib/safo-broker-install/stage"),
                ssh("/usr/bin/python3 -I -m pip --version"),
            ),
            "Two root-run programs are added. Neither does anything until it is run or a unit calls it, and the "
            "installer refuses to touch the state directory.",
            (
                ssh("rm /usr/local/sbin/safo-broker-install /usr/local/sbin/safo-broker-egress"),
                ssh("rm -rf /var/lib/safo-broker-install/stage"),
            ),
            "Compare the hashes with the ones you recorded when you reviewed the checkout. If either differs, stop "
            "here and do not run the install line.",
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
            "the approval keys, and replace the placeholder with the key field. The installer accepts only hardware "
            "key types here (sk-ssh-ed25519 and sk-ecdsa), so a software key is refused.",
            (
                ssh(
                    'sh -c "printf \\"%s namespaces=\\\\042git\\\\042 %s %s\\\\n\\" release-signer '
                    "sk-ssh-ed25519@openssh.com "
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
            "Name the vendor host for the egress control (observe mode)",
            "The egress rules need the vendor API host name from a root-owned file, so the name is in no unit and no "
            "command line. Replace PASTE_VENDOR_API_HOST_HERE with the host named in the design page, section "
            "'The transport to the vendor'. The file starts in observe mode: connections outside the allowed set "
            "are logged and let through.",
            (
                ssh(
                    'sh -c "printf \\"VENDOR_HOST=PASTE_VENDOR_API_HOST_HERE\\\\nMODE=observe\\\\n\\" '
                    '> /etc/safo/broker-egress.conf && chmod 0644 /etc/safo/broker-egress.conf"'
                ),
            ),
            "One small root file. Nothing reads it until the egress service runs.",
            (ssh("rm /etc/safo/broker-egress.conf"),),
        ),
        Step(
            "Turn the egress control on, in observe mode",
            "This loads an nftables table that matches only the broker's service user (port 443 to a set of vendor "
            "addresses that a timer refreshes every minute; no DNS and no IPv6 for that user) and writes the "
            "hosts view the broker unit bind-mounts. In observe mode nothing is blocked. Run it before the socket "
            "step. The checks at the end: the table must exist and the set must hold addresses, and the timer must "
            "be scheduled. Traffic to the vendor set is accepted before the logging rule, so it never appears in "
            "this log; the log shows only what the rules would drop.",
            (
                ssh("systemctl enable --now safo-broker-egress.service safo-broker-egress-refresh.timer"),
                ssh("nft list table inet safo_broker_egress"),
                ssh("systemctl list-timers safo-broker-egress-refresh.timer"),
                ssh("journalctl -k --since -1day --grep safo-broker-egress-observe"),
            ),
            "Adds one firewall table that applies only to the service user's own connections, and a timer. Other "
            "users and the rest of the machine are not matched. The service user does not exist as a login and "
            "nothing runs as it yet, so nothing is affected until the broker starts.",
            (ssh("systemctl disable --now safo-broker-egress-refresh.timer safo-broker-egress.service"),),
            "Stopping the egress service deletes the table. A reboot also clears it when the service is disabled. If "
            "something else reloads the firewall and removes the table, the next timer run (within a minute) "
            "puts it back; check the table again after any firewall change.",
        ),
        Step(
            "Enable the socket",
            "The socket starts the service on demand. The broker reads the switch file on every request, so with the "
            "switch absent it still answers status and dry run and refuses every paid call as disabled; this runbook "
            "never creates the switch. The broker unit is bound to the egress service and starts only with it.",
            (ssh("systemctl enable --now safo-broker.socket"),),
            "A listening socket in /run owned by root with the client group. The service starts on the first request. "
            "While the switch is absent the paid key is not read and nothing reaches the vendor.",
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
        Step(
            "Switch the egress control to drop mode (after about a week of clean observation)",
            "Run this only after a clean observation week (an empty observe log, a table that exists, a set that holds "
            "addresses, a scheduled timer). In drop mode a connection from the broker's service user to anything "
            "outside the allowed set is logged at a limited rate and dropped. The third line is a deliberately "
            "blocked probe: the service user tries to connect to a documentation address that is never in the set; "
            "it must fail after the timeout, and the last line must then show the drop log entry. If either does not "
            "happen, run the rollback lines.",
            (
                ssh("sed -i s/^MODE=observe/MODE=drop/ /etc/safo/broker-egress.conf"),
                ssh("systemctl restart safo-broker-egress.service"),
                ssh('timeout 5 runuser -u safo-broker -- /usr/bin/bash -c "echo probe > /dev/tcp/203.0.113.1/443"'),
                ssh("journalctl -k --since -2min --grep safo-broker-egress-drop"),
            ),
            "Only the broker's own connections are affected. If the vendor changes addresses faster than the "
            "refresh timer (every minute), or the timer stops, calls fail closed until the next good refresh (the "
            "previous set expires after an hour).",
            (
                ssh("sed -i s/^MODE=drop/MODE=observe/ /etc/safo/broker-egress.conf"),
                ssh("systemctl restart safo-broker-egress.service"),
            ),
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
        "- Restrict the new key at the vendor as described in the last sections before the broker first uses it.",
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
        "run with a real key. While it is absent the broker answers status and dry run, and every paid call is "
        "answered as "
        "disabled before the ledger is written or the key is read, so no call can reach the vendor.",
        "",
        "## Restrict the new key at the vendor (the vendor documentation, read 2026-10-31)",
        "",
        "Verified on the vendor's Gemini API key page on 2026-10-31:",
        "",
        "- Keys created in the vendor's AI Studio since 2026-05-28 are authorization keys, bound to a service account "
        "and restricted to the Gemini API by default. The API rejects unrestricted standard keys.",
        "- To restrict a standard key to the Gemini API only: on the API Keys page in AI Studio, find the key marked "
        "Unrestricted, choose Add restrictions, select Restrict to Gemini API only, then Restrict key. You need the "
        "permission to update API "
        "keys on the project.",
        "- Set billing alerts in the cloud console, and after a suspected leak: create a new key, switch the broker to "
        "it, disable the old key, then review billing.",
        "",
        "Not verified, so do not rely on it: whether the optional IP-address application restriction applies to "
        "authorization keys, and any vendor-side hard spend cap. The IP restriction would also need a fixed egress "
        "address, which a roaming machine does not have.",
        "",
        "## Observe, then drop",
        "",
        "Keep the egress control in observe mode for about a week of real use. Because vendor traffic is accepted "
        "before the logging rule, a clean week is an empty log: read the log line from the egress step and "
        "investigate every entry until there is nothing unexplained. Also check that the table exists, the set "
        "holds addresses and the timer is scheduled. Then run the drop-mode step, and afterwards make a deliberately "
        "blocked probe: a connection from the service user to a destination outside the set, which must now be "
        "dropped and logged with the drop prefix. If a call fails in drop mode, the rollback line puts it back in "
        "observe mode at once.",
        "",
    ]
    return "\n".join(out)
