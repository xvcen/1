#!/usr/bin/env python3
"""Try to recover the ChaCha20 keystream layout/key for the embedded core blob."""
import hashlib
import struct

D = open('/home/user/1/libOSIL.so', 'rb').read()
BLOB = 0x1176b
SIZE = 0x551fb8
TAG_OFF = BLOB + SIZE - 0x10
NONCE_OFF = 0x563723
CIPHER = D[BLOB:BLOB + 64]
TAIL16 = D[NONCE_OFF:NONCE_OFF + 16]
CONST32 = bytes.fromhex('f32a93ad7918b3fb427203c16e866409428df2b6bf7265cc3ef79a12926246bc')


def rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xffffffff


def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 7)


def chacha_block(key, tail4, counter):
    consts = struct.unpack('<4I', b'expand 32-byte k')
    st = list(consts) + list(struct.unpack('<8I', key)) + list(tail4)
    st[12] = counter
    w = list(st)
    for _ in range(10):
        qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15)
        qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14)
    return struct.pack('<16I', *[(w[i] + st[i]) & 0xffffffff for i in range(16)])


w = struct.unpack('<4I', TAIL16)
LAYOUTS = {
    'as-is': [w[0], w[1], w[2], w[3]],
    'be-as-is': [struct.unpack('>I', TAIL16[0:4])[0], struct.unpack('>I', TAIL16[4:8])[0],
                 struct.unpack('>I', TAIL16[8:12])[0], struct.unpack('>I', TAIL16[12:16])[0]],
    'rot1': [w[1], w[2], w[3], w[0]],
    'rot2': [w[2], w[3], w[0], w[1]],
    'swap01': [w[1], w[0], w[2], w[3]],
    'perm_b': [w[1], w[2], 0, w[3]],
    'perm_c': [w[0], w[2], w[1], w[3]],
    'perm_d': [w[3], w[2], w[1], w[0]],
    'zero-plus-sz': [0, 0, 0, w[3]],
    'sz-only': [w[3], 0, 0, 0],
}


def keys():
    yield 'const32', CONST32
    yield 'const32-rev', CONST32[::-1]
    for s in ('nyashka-b2', 'nyashka', 'lunaware', 'lunaware.fun', 'OSIL', 'OSILLIC1',
              'osil-lic-v1', 'dodik', 'LunaWare', 'lunaware', 'oxidesurvivalisland',
              'Pickaxe', 'lnwrkey_bot', 'OSILCORE1', 'crackme', 'b2'):
        yield 'sha256(%s)' % s, hashlib.sha256(s.encode()).digest()
        yield 'md5pad(%s)' % s, (hashlib.md5(s.encode()).digest() * 2)
        yield 'raw(%s)' % s, (s.encode() + b'\x00' * 32)[:32]
    yield 'sha256(const)', hashlib.sha256(CONST32).digest()


def check(pt):
    return pt.startswith(b'OSILCORE1') or pt.startswith(b'\x7fELF') or b'ELF' in pt[:8]


hits = 0
for kname, key in keys():
    for lname, tail in LAYOUTS.items():
        for ctr in (0, 1, 2):
            ks = chacha_block(key, tail, ctr)
            pt = bytes(a ^ b for a, b in zip(CIPHER, ks))
            if check(pt):
                print('HIT key=%s layout=%s ctr=%d -> %r' % (kname, lname, ctr, pt))
                hits += 1
print('done, hits =', hits)
