#!/usr/bin/env python3
"""Annotated AArch64 disassembler for libOSIL.so (PLT symbols + string refs)."""
import json
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_OPT_DETAIL
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

BIN = "/home/user/1/libOSIL.so"
DATA = open(BIN, "rb").read()
PLT = {}
try:
    PLT = {int(k, 16): v for k, v in json.load(open("/tmp/plt.json")).items()}
except Exception:
    pass

RODATA = (0xa620, 0xa620 + 0x55ac54)
INTERP = {}   # addr -> label, filled below

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

GL = {
    0x5a3470: "g_jvm", 0x5a3478: "g_key_ok", 0x5a3460: "g_init_once",
    0x5a3480: "g_ctx?", 0x5a3488: "g_?", 0x5a3490: "g_?", 0x5a34b8: "g_?",
    0x5a34c0: "g_?", 0x5a34a0: "g_?", 0x5a3463: "g_flag3", 0x5a3462: "g_flag2",
    0x5a3464: "g_q1", 0x5a3468: "g_q2", 0x5a3430: "selfhash_magic",
    0x5a3440: "selfhash_digest",
}


def cstr(addr):
    if not (RODATA[0] <= addr < RODATA[1]):
        return None
    end = DATA.find(b"\x00", addr)
    if end < 0:
        return None
    try:
        s = DATA[addr:end].decode()
    except UnicodeDecodeError:
        return None
    return "".join(ch if 32 <= ord(ch) < 127 else "." for ch in s)


def dis(start, size, base=None, ann=True):
    base = start if base is None else base
    out = []
    reg = {}
    for ins in md.disasm(DATA[start:start + size], base):
        note = ""
        m, ops = ins.mnemonic, ins.operands
        if m == "bl" and ops and ops[0].type == ARM64_OP_IMM:
            t = ops[0].imm
            if t in PLT:
                note = "-> " + PLT[t]
            else:
                note = "-> sub_%x" % t
        elif m in ("b", "bl") and ops and ops[0].type == ARM64_OP_IMM:
            note = "-> loc_%x" % ops[0].imm
        # address tracking
        if m == "adrp" and len(ops) == 2:
            reg[md.reg_name(ops[0].reg)] = ops[1].imm
        elif m == "adr" and len(ops) == 2:
            reg[md.reg_name(ops[0].reg)] = ops[1].imm
            note = note or ("=0x%x" % ops[1].imm)
        elif m in ("add", "sub") and len(ops) == 3 and ops[2].type == ARM64_OP_IMM:
            b = md.reg_name(ops[1].reg)
            if b in reg:
                v = reg[b] + (ops[2].imm if m == "add" else -ops[2].imm)
                reg[md.reg_name(ops[0].reg)] = v
                s = cstr(v)
                if s and len(s) > 2:
                    note = (note + " " if note else "") + "str@0x%x %r" % (v, s[:70])
                elif v in GL:
                    note = (note + " " if note else "") + GL[v]
                elif 0x5a3460 <= v < 0x5c43d0:
                    note = (note + " " if note else "") + "bss_%x" % v
        # string / global comment for memory ops
        if len(ops) >= 2:
            src = ops[-1]
            for op in ops:
                if op.type == ARM64_OP_MEM and op.mem.base and op.mem.index == 0:
                    b = md.reg_name(op.mem.base)
                    if b in reg:
                        v = reg[b] + op.mem.disp
                        s = cstr(v)
                        if s and len(s) > 2:
                            note = (note + " " if note else "") + "str@0x%x %r" % (v, s[:70])
                        elif v in GL:
                            note = (note + " " if note else "") + GL[v]
                        elif 0x5a3460 <= v < 0x5c43d0:
                            note = (note + " " if note else "") + "bss_%x" % v
        # invalidate
        for op in ops:
            if op.type == ARM64_OP_REG and op.access & 2 and not (op.access & 1):
                r = md.reg_name(op.reg)
                if r in reg and m not in ("cmp", "cmn"):
                    del reg[r]
        if m in ("ret", "br", "blr"):
            reg.clear()
        out.append("  0x%06x  %-8s %-34s%s" % (ins.address, m, ins.op_str,
                                               (" ; " + note) if (ann and note) else ""))
    return "\n".join(out)


if __name__ == "__main__":
    a = int(sys.argv[1], 0)
    n = int(sys.argv[2], 0) if len(sys.argv) > 2 else 200
    print(dis(a, n))
