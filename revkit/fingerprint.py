"""Position-independent function fingerprints (shared by binary diffing and the metadata service)."""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from typing import Dict, List

from .arch import CALL, CJMP, INDCALL, JMP
from .db import Database, Function

_NUM = re.compile(r"(?<![\w$.])(?:0x[0-9a-fA-F]+|\d+)(?![\w.])")
_RIP = re.compile(r"\[(?:rip|eip)[^\]]*\]")


def normalize_insn(db: Database, ins) -> str:
    """Mnemonic + operands with addresses/large immediates/displacements replaced by placeholders."""
    if ins.flow in (CALL, JMP, CJMP):
        return f"{ins.mnemonic} ADDR"
    ops = ins.op_str
    if db.image.arch.name == "x86":
        ops = _RIP.sub("[RIP]", ops)

    def r(m):
        try:
            v = int(m.group(0), 0)
        except ValueError:
            return m.group(0)
        return "IMM" if (v >= 0x10000 and db.image.is_mapped(v)) else m.group(0)
    return f"{ins.mnemonic} {_NUM.sub(r, ops)}".strip()


def function_hash(db: Database, f: Function) -> str:
    h = hashlib.sha1()
    for b in sorted(f.blocks.values(), key=lambda x: x.start):
        for a in b.insns:
            ins = db.insn(a)
            if ins is not None:
                h.update(normalize_insn(db, ins).encode())
                h.update(b"\n")
    return h.hexdigest()


def structural_hash(db: Database, f: Function) -> str:
    """CFG-shape hash: block count, per-block successor counts and instruction counts (ignores instruction content)."""
    blocks = sorted(f.blocks.values(), key=lambda x: x.start)
    idx = {b.start: i for i, b in enumerate(blocks)}
    parts = [(len(b.insns), tuple(sorted(idx.get(t, -1) for t, _ in b.succs))) for b in blocks]
    return hashlib.sha1(repr(parts).encode()).hexdigest()


def features(db: Database, f: Function) -> Dict[str, object]:
    mn = Counter()
    consts = set()
    strs = set()
    callees = set()
    for b in f.blocks.values():
        for a in b.insns:
            ins = db.insn(a)
            if ins is None:
                continue
            mn[ins.mnemonic] += 1
            for v in ins.imms:
                if v > 0xFF and not db.image.is_mapped(v):
                    consts.add(v)
            for kind, t in ins.refs:
                s = db.strings.get(t)
                if s is not None:
                    strs.add(s.text)
            for to, k in db.xrefs_from.get(a, ()):
                if k == "call":
                    imp = db.import_at(to)
                    nm = imp.display if imp else db.names.get(to)
                    if nm and not nm.startswith("sub_"):
                        callees.add(nm)
    return {"mnemonics": mn, "consts": consts, "strings": strs, "callees": callees, "nblocks": len(f.blocks),
            "ninsns": sum(len(b.insns) for b in f.blocks.values()),
            "nedges": sum(len(b.succs) for b in f.blocks.values())}


def jaccard(a, b) -> float:
    a, b = set(a), set(b)
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def multiset_similarity(a: Counter, b: Counter) -> float:
    if not a and not b:
        return 1.0
    inter = sum((a & b).values())
    union = sum((a | b).values())
    return inter / union if union else 1.0


def similarity(fa: Dict, fb: Dict) -> float:
    s_mn = multiset_similarity(fa["mnemonics"], fb["mnemonics"])
    s_c = jaccard(fa["consts"], fb["consts"])
    s_s = jaccard(fa["strings"], fb["strings"])
    s_call = jaccard(fa["callees"], fb["callees"])
    size = 1 - abs(fa["nblocks"] - fb["nblocks"]) / max(fa["nblocks"], fb["nblocks"], 1)
    w = [(0.45, s_mn), (0.1, s_c), (0.15, s_s), (0.15, s_call), (0.15, size)]
    return round(sum(a * b for a, b in w), 4)
