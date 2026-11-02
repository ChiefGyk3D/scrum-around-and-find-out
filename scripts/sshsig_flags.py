#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only: print user-present / user-verified from an SSH signature file.

Parses an armored SSHSIG (PROTOCOL.sshsig) whose signature is a security-key
type (PROTOCOL.u2f: string alg, string sig, byte flags, uint32 counter).
Does NOT verify the signature cryptographically; run `ssh-keygen -Y verify`
first. The flags byte is covered by the signature, so a verified signature
means these flags are authentic. Usage: sshsig_flags.py SIGFILE
Exit: 0 = UP and UV both set, 1 = parsed but UV (or UP) not set, 2 = error.
"""

import base64
import struct
import sys

UP, UV = 0x01, 0x04  # sk-api.h SSH_SK_USER_PRESENCE_REQD / _VERIFICATION_REQD
HDR, FTR = "-----BEGIN SSH SIGNATURE-----", "-----END SSH SIGNATURE-----"


class Rd:
    def __init__(self, b):
        self.b, self.i = b, 0

    def take(self, n):
        if n < 0 or self.i + n > len(self.b):
            raise ValueError("truncated")
        v = self.b[self.i : self.i + n]
        self.i += n
        return v

    def u8(self):
        return self.take(1)[0]

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def string(self):
        return self.take(self.u32())


def parse(text):
    lines = [x.strip() for x in text.strip().splitlines()]
    if not lines or lines[0] != HDR or lines[-1] != FTR:
        raise ValueError("not an armored SSH signature")
    r = Rd(base64.b64decode("".join(lines[1:-1]), validate=True))
    if r.take(6) != b"SSHSIG":
        raise ValueError("bad magic")
    if r.u32() != 1:
        raise ValueError("unsupported sshsig version")
    pub, ns, _res, halg, sig = (r.string() for _ in range(5))
    if r.i != len(r.b):
        raise ValueError("trailing data")
    kt = Rd(pub).string().decode()
    s = Rd(sig)
    alg = s.string().decode()
    if not alg.startswith(("sk-ssh-ed25519@", "sk-ecdsa-sha2-nistp256@")):
        raise ValueError("not a security-key signature: " + alg)
    s.string()  # raw signature
    flags, counter = s.u8(), s.u32()
    if s.i != len(s.b):
        raise ValueError("trailing data in signature (extensions?)")
    return kt, ns.decode(), halg.decode(), flags, counter


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="ascii") as f:
            kt, ns, halg, flags, counter = parse(f.read())
    except (OSError, ValueError, UnicodeDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    up, uv = bool(flags & UP), bool(flags & UV)
    print(f"key-type={kt} namespace={ns} hash={halg}")
    print(f"flags=0x{flags:02x} counter={counter}")
    print(f"user-present={up} user-verified={uv}")
    return 0 if (up and uv) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
