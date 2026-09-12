#!/usr/bin/env python3
"""Minimal AArch64 user-mode emulator for libOSIL.so internals (Unicorn).

Maps the ELF, applies RELATIVE relocations, stubs the bionic/libc imports, and
lets you call arbitrary internal functions with arguments.
"""
import json
import struct
import sys
from unicorn import *
from unicorn.arm64_const import *
from elftools.elf.elffile import ELFFile

import os
BIN = os.environ.get("OSIL_BIN", "/home/user/1/libOSIL.so")
DATA = open(BIN, "rb").read()
PLT = {int(k, 16): v for k, v in json.load(open("/tmp/plt.json")).items()}
PLT_LO, PLT_HI = 0x597c50, 0x598230

STACK = 0x70000000
STACK_SZ = 0x200000
TLS = 0x72000000
HEAP = 0x74000000
HEAP_SZ = 0x2000000
RET_MAGIC = 0x7fff0000


class Emu:
    def __init__(self, verbose=False, log_calls=None):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.verbose = verbose
        self.log_calls = log_calls if log_calls is not None else []
        self.hooks = {}
        self.heap_ptr = HEAP
        self._load()
        self._setup()

    # ---------- loading ----------
    def _load(self):
        import io
        e = ELFFile(io.BytesIO(DATA))
        for seg in e.iter_segments():
            if seg['p_type'] != 'PT_LOAD':
                continue
            va, msz, fsz, off = seg['p_vaddr'], seg['p_memsz'], seg['p_filesz'], seg['p_offset']
            self.uc.mem_map(va & ~0xfff, ((msz + (va & 0xfff)) + 0xfff) & ~0xfff, UC_PROT_ALL)
            self.uc.mem_write(va, DATA[off:off + fsz])
        # relocations
        rel = e.get_section_by_name('.rela.dyn')
        for i in range(rel.num_relocations()):
            r = rel.get_relocation(i)
            if r['r_info_type'] == 1027:  # R_AARCH64_RELATIVE
                self.uc.mem_write(r['r_offset'], struct.pack('<Q', r['r_addend']))

    def _setup(self):
        self.uc.mem_map(STACK, STACK_SZ, UC_PROT_ALL)
        self.uc.mem_map(TLS, 0x10000, UC_PROT_ALL)
        self.uc.mem_map(HEAP, HEAP_SZ, UC_PROT_ALL)
        self.uc.mem_write(TLS + 0x28, b'\x11\x22\x33\x44\x55\x66\x77\x88')
        self.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
        self.uc.reg_write(UC_ARM64_REG_SP, STACK + STACK_SZ - 0x1000)
        self.uc.hook_add(UC_HOOK_CODE, self._on_code)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._unmapped)

    def _unmapped(self, uc, access, address, size, value, user):
        try:
            base = address & ~0xfff
            uc.mem_map(base, 0x1000, UC_PROT_ALL)
            return True
        except Exception:
            return False

    # ---------- libc stubs ----------
    def _on_code(self, uc, addr, size, user):
        if PLT_LO <= addr < PLT_HI:
            name = PLT.get(addr, "sub_%x" % addr)
            self._stub(name)
            lr = uc.reg_read(UC_ARM64_REG_LR)
            uc.reg_write(UC_ARM64_REG_PC, lr)

    def _stub(self, name):
        uc, sp = self.uc, self.uc.reg_read(UC_ARM64_REG_SP)
        a = [uc.reg_read(UC_ARM64_REG_X0 + i) for i in range(8)]
        if self.verbose:
            print("   [stub] %s(%s)" % (name, ", ".join(hex(x) for x in a[:4])))
        ret = 0
        if name in ("__strlen_chk", "strlen"):
            n = 0
            while uc.mem_read(a[0] + n, 1) != b'\x00':
                n += 1
            ret = n
        elif name in ("memset", "__memset_chk"):
            uc.mem_write(a[0], bytes([a[1] & 0xff]) * a[2])
            ret = a[0]
        elif name in ("memcpy", "memmove"):
            uc.mem_write(a[0], bytes(uc.mem_read(a[1], a[2])))
            ret = a[0]
        elif name in ("memcmp",):
            x = bytes(uc.mem_read(a[0], a[2]))
            y = bytes(uc.mem_read(a[1], a[2]))
            ret = 0 if x == y else (1 if x > y else -1)
        elif name in ("malloc", "operator new"):
            ret = self.heap_ptr
            self.heap_ptr = (self.heap_ptr + a[0] + 15) & ~15
        elif name == "free":
            ret = 0
        elif name == "snprintf" or name == "vsnprintf":
            ret = 0
        elif name in ("__android_log_print", "__android_log_vprint"):
            if self.verbose:
                print("   [log] %s" % hex(a[0]))
            ret = 0
        elif name == "clock_gettime":
            struct.pack_into('<qq', bytearray(16), 0, 0, 0)
            ret = 0
        else:
            if self.log_calls is not None:
                self.log_calls.append(name)
        uc.reg_write(UC_ARM64_REG_X0, ret)

    # ---------- helpers ----------
    def rd(self, addr, n):
        return bytes(self.uc.mem_read(addr, n))

    def wr(self, addr, data):
        self.uc.mem_write(addr, data)

    def rdstr(self, addr):
        out = b''
        while True:
            c = self.rd(addr + len(out), 1)
            if c == b'\x00':
                break
            out += c
        return out.decode(errors='replace')

    def call(self, func, args=(), verbose=None):
        v = self.verbose if verbose is None else verbose
        old = self.verbose
        self.verbose = v
        sp = STACK + STACK_SZ - 0x2000
        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        self.uc.reg_write(UC_ARM64_REG_LR, RET_MAGIC)
        for i, a in enumerate(args):
            self.uc.reg_write(UC_ARM64_REG_X0 + i, a)
        try:
            self.uc.emu_start(func, RET_MAGIC, timeout=60 * 1000000, count=50_000_000)
        except UcError as ex:
            if v:
                print("   [emu error] %s pc=0x%x" % (ex, self.uc.reg_read(UC_ARM64_REG_PC)))
            self.verbose = old
            return None
        self.verbose = old
        return self.uc.reg_read(UC_ARM64_REG_X0)


if __name__ == "__main__":
    emu = Emu(verbose=True)
    # decode obfuscated string: sub_57393c(id, src, len, dst)
    for ident, src, ln in ((0x33, 0x115e0, 0x0c), (0x11, 0x11600, 0x20),
                           (0x44, 0x115f0, 0x0f), (0x33, 0x115e0, 0x0c)):
        out = STACK + STACK_SZ - 0x800
        emu.call(0x57393c, (ident, src, ln, out))
        print("id=0x%02x len=%d -> %r" % (ident, ln, emu.rd(out, ln)))
