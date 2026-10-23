"""Searching: byte patterns (with wildcards), text in listing, immediates, names, strings."""
from __future__ import annotations

import re
from typing import Iterator, List, Optional, Tuple

from .db import Database
from .listing import Listing, render_insn


def parse_byte_pattern(pat: str) -> Tuple[bytes, bytes]:
    """'48 8B ?? 05' or '488B??05' -> (pattern, mask) where mask byte 0xFF means must-match."""
    toks = pat.replace(",", " ").split()
    if len(toks) == 1 and len(toks[0]) > 2:
        t = toks[0]
        toks = [t[i:i + 2] for i in range(0, len(t), 2)]
    out, mask = bytearray(), bytearray()
    for t in toks:
        if t in ("?", "??", "..", "**"):
            out.append(0)
            mask.append(0)
        elif len(t) == 2 and ("?" in t):
            hi, lo = t
            out.append((int(hi, 16) << 4 if hi != "?" else 0) | (int(lo, 16) if lo != "?" else 0))
            mask.append((0xF0 if hi != "?" else 0) | (0x0F if lo != "?" else 0))
        else:
            out.append(int(t, 16))
            mask.append(0xFF)
    if not out:
        raise ValueError("empty pattern")
    return bytes(out), bytes(mask)


def search_bytes(db: Database, pattern: str, start: Optional[int] = None, end: Optional[int] = None,
                 limit: int = 1000, code_only: bool = False) -> List[int]:
    pat, mask = parse_byte_pattern(pattern)
    img = db.image
    results: List[int] = []
    # fast path: no wildcards -> bytes.find
    exact = all(m == 0xFF for m in mask)
    # build regex for the wildcard case
    if exact:
        rx = re.compile(re.escape(pat), re.S)
    else:
        parts = []
        for b, m in zip(pat, mask):
            if m == 0xFF:
                parts.append(re.escape(bytes([b])))
            elif m == 0:
                parts.append(b".")
            else:
                cls = b"".join(re.escape(bytes([v])) for v in range(256) if v & m == b & m)
                parts.append(b"[" + cls + b"]")
        rx = re.compile(b"".join(parts), re.S)
    for seg in img.segments:
        lo = seg.start if start is None else max(seg.start, start)
        hi = seg.end if end is None else min(seg.end, end)
        if lo >= hi:
            continue
        data = bytes(seg.data[lo - seg.start:hi - seg.start])
        pos = 0
        while True:
            m = rx.search(data, pos)
            if not m:
                break
            a = lo + m.start()
            if not code_only or a in db.insns:
                results.append(a)
                if len(results) >= limit:
                    return results
            pos = m.start() + 1
    return results


def search_text(db: Database, query: str, regex: bool = False, case: bool = False, limit: int = 500,
                start: Optional[int] = None) -> List[Tuple[int, str]]:
    """Search the rendered disassembly (mnemonic + operands + comments + names)."""
    flags = 0 if case else re.I
    rx = re.compile(query if regex else re.escape(query), flags)
    out = []
    for a in sorted(db.insns):
        if start is not None and a < start:
            continue
        ins = db.insn(a)
        if ins is None:
            continue
        text = render_insn(db, ins)
        full = text + " ; " + db.comments.get(a, "") + " " + db.rep_comments.get(a, "")
        if rx.search(full):
            out.append((a, text))
            if len(out) >= limit:
                break
    return out


def search_immediate(db: Database, value: int, limit: int = 500) -> List[int]:
    out = []
    mask64 = (1 << 64) - 1
    for a in sorted(db.insns):
        ins = db.insn(a)
        if ins is None:
            continue
        for v in ins.imms:
            if (v & mask64) == (value & mask64):
                out.append(a)
                break
        if len(out) >= limit:
            break
    return out


def search_names(db: Database, query: str, regex: bool = False, limit: int = 500) -> List[Tuple[int, str]]:
    rx = re.compile(query if regex else re.escape(query), re.I)
    out = []
    for a, n in sorted(db.names.items()):
        if rx.search(n):
            out.append((a, n))
    for a, f in db.functions.items():
        if a not in db.names and rx.search(db.default_name(a)):
            out.append((a, db.default_name(a)))
    return sorted(out)[:limit]


def search_strings(db: Database, query: str, regex: bool = False, limit: int = 500) -> List[Tuple[int, str]]:
    rx = re.compile(query if regex else re.escape(query), re.I)
    return [(a, s.text) for a, s in sorted(db.strings.items()) if rx.search(s.text)][:limit]
