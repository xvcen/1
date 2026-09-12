#!/usr/bin/env python3
"""AArch64 address-reference scanner for libOSIL.so.

Tracks adrp/adr page+offset register values and reports every instruction that
computes or accesses one of the requested target virtual addresses.
"""
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_OPT_DETAIL
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

BIN = "/home/user/1/libOSIL.so"
DATA = open(BIN, "rb").read()
TEXT_OFF, TEXT_SIZE = 0x56d5a0, 0x2a6ac

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
W = 2  # CS_AC_WRITE


def scan(targets, lo=TEXT_OFF, hi=TEXT_OFF + TEXT_SIZE):
    """Yield (insn_addr, target_addr, kind, op_str)."""
    tset = set(targets)
    hits = []
    reg = {}  # regname -> concrete address value
    for ins in md.disasm(DATA[lo:hi], lo):
        m, ops = ins.mnemonic, ins.operands
        if m == "adrp" and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
            reg[md.reg_name(ops[0].reg)] = ops[1].imm
            continue
        if m == "adr" and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
            reg[md.reg_name(ops[0].reg)] = ops[1].imm
            for t in tset:
                if t == ops[1].imm:
                    hits.append((ins.address, t, "adr", ins.op_str))
            continue
        if m in ("add", "sub") and len(ops) == 3 and ops[1].type == ARM64_OP_REG \
                and ops[2].type == ARM64_OP_IMM:
            b = md.reg_name(ops[1].reg)
            if b in reg:
                v = reg[b] + ops[2].imm if m == "add" else reg[b] - ops[2].imm
                d = md.reg_name(ops[0].reg)
                reg[d] = v
                for t in tset:
                    if t == v:
                        hits.append((ins.address, t, "add", ins.op_str))
                continue
        if m in ("ldr", "ldrb", "ldrh", "ldrsw", "ldrsb", "str", "strb", "strh") \
                and len(ops) == 2 and ops[1].type == ARM64_OP_MEM and ops[1].mem.base:
            b = md.reg_name(ops[1].mem.base)
            if b in reg and ops[1].mem.index == 0:
                v = reg[b] + ops[1].mem.disp
                for t in tset:
                    if t == v:
                        hits.append((ins.address, t, m, ins.op_str))
        # invalidate written regs
        for op in ops:
            if op.type == ARM64_OP_REG and op.access & W:
                r = md.reg_name(op.reg)
                if r in reg and not (op.access & 1):
                    del reg[r]
        if m in ("ret", "br", "blr"):
            reg.clear()
    return hits


def read_cstr(addr):
    if not (0xa620 <= addr < 0xa620 + 0x55ac54):
        return None
    end = DATA.find(b"\x00", addr)
    if end < 0:
        return None
    try:
        s = DATA[addr:end].decode()
    except UnicodeDecodeError:
        return None
    return s if len(s) >= 2 else None


if __name__ == "__main__":
    tgts = [int(a, 0) for a in sys.argv[1:]]
    for a, t, k, o in scan(tgts):
        s = read_cstr(t)
        print("0x%06x -> 0x%x  %-5s %-28s %s" % (a, t, k, o, repr(s) if s else ""))
