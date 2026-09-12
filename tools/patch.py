#!/usr/bin/env python3
"""Patch libOSIL.so into a build that works without the license server.

Patches
-------
A. 0x56d74c  b.lo -> b            : the init routine no longer aborts when the
                                    built-in integrity gate reports a verdict >= 2
                                    (patching the file would otherwise trip it)
B. 0x56f39c  b.hi -> nop          : the core path no longer aborts on verdict > 1
C. 0x5730e0  sub_5730e0 replaced  : license acquire is now fully local:
                                      * returns status 0 ("ok, no error") so the
                                        tier file gets written with the default tier
                                      * if /sdcard/Documents/OSIL/corekey.bin exists
                                        (32 raw bytes or 64 hex chars) its content is
                                        installed as the 32 byte core key payload, which
                                        makes the loader decrypt the embedded core blob
                                        locally instead of asking the server
D. 0x56fcf4  b 0x56ff34           : onKeyEntered accepts any 12 character key
                                    (the server side validation is gone anyway)
"""
import io
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

SRC = "/home/user/1/libOSIL.so"
DST = "/home/user/1/libOSIL.patched.so"

# PLT entries (authoritative names from /tmp/plt.json)
MALLOC = 0x598190
FREE = 0x5980f0
MEMSET = 0x597e10
FOPEN = 0x597d00
FREAD = 0x597da0
FCLOSE = 0x597d30

ACQ = 0x5730e0                 # sub_5730e0 (license acquire), 2020 bytes long
ACQ_END = 0x5738c4
KEYPATH = b"/sdcard/Documents/OSIL/corekey.bin\x00"
MODRB = b"rb\x00"

# (instruction, label) - labels are resolved to absolute addresses
CODE = [
    ("stp x29, x30, [sp, #-0x40]!", None),
    ("stp x19, x20, [sp, #0x10]", None),
    ("stp x21, x22, [sp, #0x20]", None),
    ("mov x29, sp", None),
    # result struct: zeroed -> status 0, empty strings, default tier
    ("mov w0, #0x200", None),
    ("bl #%d" % MALLOC, None),
    ("cbz x0, L_nofail", None),
    ("mov x19, x0", None),
    ("mov x0, x19", None),
    ("mov w1, #0", None),
    ("mov w2, #0x200", None),
    ("bl #%d" % MEMSET, None),
    # optional local core key file
    ("movz x0, #0", None),          # idx 12 - patched with keypath address
    ("movk x0, #0, lsl #16", None),  # idx 13
    ("movz x1, #0", None),          # idx 14 - patched with mode string address
    ("movk x1, #0, lsl #16", None),  # idx 15
    ("bl #%d" % FOPEN, None),
    ("cbz x0, L_done", None),
    ("mov x20, x0", None),
    ("mov w0, #0x60", None),
    ("bl #%d" % MALLOC, None),
    ("cbz x0, L_closeonly", None),
    ("mov x21, x0", None),
    ("mov x0, x21", None),
    ("mov w1, #1", None),
    ("mov w2, #0x60", None),
    ("mov x3, x20", None),
    ("bl #%d" % FREAD, None),
    ("mov x22, x0", None),
    ("mov x0, x20", None),
    ("bl #%d" % FCLOSE, None),
    ("cmp x22, #32", None),
    ("b.eq L_raw", None),
    ("cmp x22, #64", None),
    ("b.lo L_nokey", None),
    ("cmp x22, #67", None),
    ("b.hs L_nokey", None),
    ("mov x9, xzr", None),
    ("cmp x9, #64", "L_hexloop"),
    ("b.hs L_hexdone", None),
    ("ldrb w11, [x21, x9]", None),
    ("sub w13, w11, #0x30", None),
    ("cmp w13, #9", None),
    ("b.ls L_hexval", None),
    ("sub w13, w11, #0x37", None),
    ("cmp w13, #0xf", None),
    ("b.ls L_hexval", None),
    ("sub w13, w11, #0x57", None),
    ("cmp w13, #0xf", None),
    ("b.hi L_nokey", None),
    ("lsr w14, w9, #1", "L_hexval"),
    ("add w14, w14, #0x40", None),
    ("tst w9, #1", None),
    ("b.ne L_hexodd", None),
    ("lsl w13, w13, #4", None),
    ("strb w13, [x21, x14]", None),
    ("b L_hexnext", None),
    ("ldrb w15, [x21, x14]", "L_hexodd"),
    ("orr w13, w13, w15", None),
    ("strb w13, [x21, x14]", None),
    ("add x9, x9, #1", "L_hexnext"),
    ("b L_hexloop", None),
    ("add x21, x21, #0x40", "L_hexdone"),
    ("mov x22, #32", None),
    ("str x21, [x19, #0x88]", "L_raw"),
    ("str x22, [x19, #0x90]", None),
    ("b L_done", None),
    ("mov x0, x21", "L_nokey"),
    ("bl #%d" % FREE, None),
    ("b L_done", None),
    ("mov x0, x20", "L_closeonly"),
    ("bl #%d" % FCLOSE, None),
    ("mov x0, x19", "L_done"),
    ("ldp x19, x20, [sp, #0x10]", None),
    ("ldp x21, x22, [sp, #0x20]", None),
    ("ldp x29, x30, [sp], #0x40", None),
    ("ret", None),
    ("mov x0, xzr", "L_nofail"),
    ("ldp x19, x20, [sp, #0x10]", None),
    ("ldp x21, x22, [sp, #0x20]", None),
    ("ldp x29, x30, [sp], #0x40", None),
    ("ret", None),
]


def build_acquire():
    """Assemble the replacement license-acquire routine (two passes for adr/imm)."""
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    def emit(addr_of_keypath, addr_of_modrb):
        text = ""
        for i, (ins, label) in enumerate(CODE):
            if label:
                text += "%s:\n" % label
            if i == 12:
                ins = "movz x0, #%d" % (addr_of_keypath & 0xFFFF)
            elif i == 13:
                ins = "movk x0, #%d, lsl #16" % (addr_of_keypath >> 16)
            elif i == 14:
                ins = "movz x1, #%d" % (addr_of_modrb & 0xFFFF)
            elif i == 15:
                ins = "movk x1, #%d, lsl #16" % (addr_of_modrb >> 16)
            text += ins + "\n"
        code, _ = ks.asm(text, ACQ)
        return bytes(code)

    # pass 1: learn the code size (immediates do not change instruction widths)
    probe = emit(0, 0)
    n = len(probe)
    assert n % 4 == 0
    kp = ACQ + n
    md = kp + len(KEYPATH)
    code = emit(kp, md)
    assert len(code) == n
    return code + KEYPATH + MODRB


def assemble_branch(text, addr, target):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    code, _ = ks.asm(text, addr)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    ins = next(md.disasm(bytes(code), addr))
    got = int(ins.op_str.strip().lstrip("#"), 16)
    assert got == target, "branch encoded to 0x%x, want 0x%x" % (got, target)
    return bytes(code)


def verify_code(code):
    """Disassemble the new routine and check every branch/call target."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    lo, hi = ACQ, ACQ + len(code)
    allowed_calls = {MALLOC, FREE, MEMSET, FOPEN, FREAD, FCLOSE}
    for ins in md.disasm(code, ACQ):
        if not ins.op_str.startswith("#"):
            continue
        tgt = int(ins.op_str.strip().lstrip("#"), 16)
        if ins.mnemonic == "bl":
            assert tgt in allowed_calls, "bad call 0x%x: %s" % (ins.address, ins.op_str)
        elif ins.mnemonic.startswith("b"):
            assert lo <= tgt < hi, "branch escapes at 0x%x -> 0x%x" % (ins.address, tgt)
    return True


def main():
    data = bytearray(open(SRC, "rb").read())
    orig = bytes(data)
    elffile = ELFFile(io.BytesIO(orig))
    assert elffile["e_machine"] == "EM_AARCH64"
    log = []

    # ---- A: 0x56d74c  b.lo -> b ----
    off = 0x56d74c
    ins = struct.unpack_from("<I", data, off)[0]
    assert (ins >> 24) == 0x54, "unexpected insn at 0x56d74c: %08x" % ins
    new = (ins & ~0xF) | 0xE
    struct.pack_into("<I", data, off, new)
    log.append("A 0x56d74c  b.lo -> b       %08x -> %08x" % (ins, new))

    # ---- B: 0x56f39c  b.hi -> nop ----
    off = 0x56f39c
    ins = struct.unpack_from("<I", data, off)[0]
    assert (ins >> 24) == 0x54, "unexpected insn at 0x56f39c: %08x" % ins
    struct.pack_into("<I", data, off, 0xD503201F)
    log.append("B 0x56f39c  b.hi -> nop     %08x -> d503201f" % ins)

    # ---- C: replace sub_5730e0 ----
    code = build_acquire()
    verify_code(code)
    assert len(code) <= ACQ_END - ACQ
    data[ACQ:ACQ + len(code)] = code
    log.append("C 0x5730e0  offline license acquire installed (%d bytes, "
               "old body after it is unreachable)" % len(code))

    # ---- D: 0x56fcf4  b 0x56ff34 ----
    off = 0x56fcf4
    ins = struct.unpack_from("<I", data, off)[0]
    nb = assemble_branch("b #0x56ff34", off, 0x56ff34)
    struct.pack_into("<I", data, off, struct.unpack("<I", nb)[0])
    log.append("D 0x56fcf4  b 0x56ff34     %08x -> %s" % (ins, nb.hex()))

    open(DST, "wb").write(bytes(data))
    diff = sum(1 for a, b in zip(orig, data) if a != b)
    print("\n".join(log))
    print("changed bytes: %d\nwritten: %s (%d bytes)" % (diff, DST, len(data)))
    print("core key path: %s" % KEYPATH[:-1].decode())


if __name__ == "__main__":
    main()
