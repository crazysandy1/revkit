"""Cryptographic constant recognition (S-boxes, hash IVs, CRC tables, Base64 alphabets, ChaCha/Salsa sigma)."""
from __future__ import annotations

import struct
from typing import Dict, List

from .db import Database
from .search import search_bytes

# (name, weak, description, byte pattern as hex, endianness note)
_AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
_AES_INV_SBOX = bytes(_AES_SBOX.index(i) for i in range(256))

CONSTANTS = [
    ("AES", False, "S-box", _AES_SBOX),
    ("AES", False, "inverse S-box", _AES_INV_SBOX),
    ("MD5", True, "init vector A/B/C/D", struct.pack("<4I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)),
    ("MD5", True, "T-table start", struct.pack("<4I", 0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE)),
    ("SHA1", True, "init vector H0-H4", struct.pack(">5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)),
    ("SHA1", True, "init vector (LE)", struct.pack("<5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)),
    ("SHA256", False, "K table start", struct.pack("<4I", 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5)),
    ("SHA256", False, "K table start (BE)", struct.pack(">4I", 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5)),
    ("SHA256", False, "init vector", struct.pack("<4I", 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A)),
    ("SHA512", False, "K table start", struct.pack("<2Q", 0x428A2F98D728AE22, 0x7137449123EF65CD)),
    ("CRC32", True, "table (poly 0xEDB88320) start", struct.pack("<8I", 0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
                                                                  0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3)),
    ("Base64", False, "alphabet", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
    ("Base64", False, "URL-safe alphabet", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"),
    ("ChaCha/Salsa20", False, "sigma constant", b"expand 32-byte k"),
    ("ChaCha/Salsa20", False, "tau constant", b"expand 16-byte k"),
    ("DES", True, "initial permutation (IP)", bytes([58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4])),
    ("Blowfish", False, "P-array/pi start", struct.pack("<4I", 0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344)),
    ("RC4", True, "identity permutation (KSA init)", bytes(range(32))),
    ("TEA/XTEA", False, "delta 0x9E3779B9", struct.pack("<I", 0x9E3779B9)),
    ("Twofish/Camellia", False, "Camellia sigma1", struct.pack(">2I", 0xA09E667F, 0x3BCC908B)),
]


def find_crypto_constants(db: Database, limit_per_pattern: int = 8) -> List[dict]:
    hits: List[dict] = []
    for name, weak, desc, pat in CONSTANTS:
        if name == "RC4" or name == "TEA/XTEA":
            # extremely short / generic patterns: only report when referenced from code
            addrs = search_bytes(db, pat.hex(), limit=limit_per_pattern)
            addrs = [a for a in addrs if db.xrefs_to.get(a)] if name == "RC4" else addrs
            if name == "TEA/XTEA":
                addrs = [a for a in search_bytes(db, pat.hex(), limit=64, code_only=False)]
                addrs = [a for a in addrs if a in db.insns or db.xrefs_to.get(a)]
        else:
            addrs = search_bytes(db, pat.hex(), limit=limit_per_pattern)
        for a in addrs:
            hits.append({"name": name, "weak": weak, "addr": a, "detail": desc, "size": len(pat)})
    # immediate-operand constants used inside code (e.g. mov eax, 0x67452301 in unrolled hash implementations)
    imm_consts = {0x67452301: "MD5/SHA1 init A", 0xEFCDAB89: "MD5/SHA1 init B", 0x9E3779B9: "TEA/XTEA delta",
                  0xEDB88320: "CRC32 polynomial", 0x6A09E667: "SHA-256 init H0", 0x61707865: "ChaCha/Salsa 'expa'"}
    for a, ins in ((a, db.insn(a)) for a in sorted(db.insns)):
        if ins is None:
            continue
        for v in ins.imms:
            if v in imm_consts:
                nm = imm_consts[v].split()[0].split("/")[0]
                hits.append({"name": nm, "weak": nm in ("MD5", "SHA1", "CRC32"), "addr": a,
                             "detail": f"immediate {v:#x} ({imm_consts[v]})", "size": 4})
    # de-duplicate
    seen, out = set(), []
    for h in hits:
        k = (h["name"], h["addr"])
        if k not in seen:
            seen.add(k)
            out.append(h)
    return out
