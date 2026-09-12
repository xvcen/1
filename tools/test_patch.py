#!/usr/bin/env python3
"""Emulate the patched license-acquire routine against fake core key files."""
import os
import struct
import sys

os.environ["OSIL_BIN"] = "/home/user/1/libOSIL.patched.so"
sys.path.insert(0, "/home/user/1/tools")

from unicorn.arm64_const import UC_ARM64_REG_X0   # noqa: E402
from emu import Emu, STACK, STACK_SZ              # noqa: E402

ACQ = 0x5730e0
KEY = bytes.fromhex("f32a93ad7918b3fb427203c16e866409428df2b6bf7265cc3ef79a12926246bc")
FILE = {"data": None}
HANDLES = {}


def args(uc):
    return [uc.reg_read(UC_ARM64_REG_X0 + i) for i in range(8)]


def ret(uc, v):
    uc.reg_write(UC_ARM64_REG_X0, v)


class PatchedEmu(Emu):
    """Adds the three stdio stubs the new acquire routine uses."""

    def _stub(self, name):
        uc = self.uc
        a = args(uc)
        if name == "fopen":
            if FILE["data"] is None:
                return ret(uc, 0)
            h = self.heap_ptr
            self.heap_ptr += 0x100
            HANDLES[h] = {"pos": 0}
            return ret(uc, h)
        if name == "fread":
            buf, size, nmemb, fh = a[0], a[1], a[2], a[3]
            st = HANDLES.setdefault(fh, {"pos": 0})
            want = size * nmemb
            chunk = FILE["data"][st["pos"]:st["pos"] + want]
            uc.mem_write(buf, chunk)
            st["pos"] += len(chunk)
            return ret(uc, len(chunk) if size else 0)
        if name in ("fclose", "close"):
            HANDLES.pop(a[0], None)
            return ret(uc, 0)
        return super()._stub(name)


def run_case(label, data):
    FILE["data"] = data
    HANDLES.clear()
    emu = PatchedEmu()
    key_arg = STACK + STACK_SZ - 0x100
    emu.wr(key_arg, b"444444444444\x00")
    res = emu.call(ACQ, (key_arg,))
    st = emu.rd(res, 0xA0)
    status = struct.unpack_from("<i", st, 0)[0]
    ptr, ln = struct.unpack_from("<QQ", st, 0x88)
    kb = emu.rd(ptr, ln) if (ptr and 0 < ln < 0x100) else b""
    print("%-18s status=%-3d payload=%s len=%-3d key=%s"
          % (label, status, hex(ptr) if ptr else "NULL", ln, kb.hex() or "-"))
    return status, ptr, ln, kb


checks = []
checks.append(run_case("no key file", None))
checks.append(run_case("32 raw bytes", KEY))
checks.append(run_case("64 hex chars", KEY.hex().encode()))
checks.append(run_case("hex + newline", KEY.hex().encode() + b"\n"))
checks.append(run_case("20 bytes", KEY[:20]))
checks.append(run_case("garbage 64 ch", b"zz" * 32))

expect = [(0, 0, 0), (0, 1, 32), (0, 1, 32), (0, 1, 32), (0, 0, 0), (0, 0, 0)]
ok = True
for (s, p, n, k), (es, ep, en) in zip(checks, expect):
    ok &= (s == es and (bool(p) == bool(ep)) and n == en)
# key content checks
ok &= (checks[1][3] == KEY and checks[2][3] == KEY and checks[3][3] == KEY)
print("ALL OK" if ok else "FAILURES PRESENT")
