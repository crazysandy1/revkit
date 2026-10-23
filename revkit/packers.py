"""Packing / obfuscation heuristics: entropy, section anomalies, known packer markers, import-table sparsity."""
from __future__ import annotations

import math
from collections import Counter
from typing import Dict, List

PACKER_SECTION_NAMES = {
    b"UPX0": "UPX", b"UPX1": "UPX", b"UPX2": "UPX", b".aspack": "ASPack", b".adata": "ASPack", b".themida": "Themida",
    b".vmp0": "VMProtect", b".vmp1": "VMProtect", b".vmp2": "VMProtect", b".petite": "Petite", b".nsp0": "NsPack",
    b".nsp1": "NsPack", b".MPRESS1": "MPRESS", b".MPRESS2": "MPRESS", b".enigma1": "Enigma", b".enigma2": "Enigma",
    b".perplex": "Perplex", b"pec1": "PECompact", b"PEC2": "PECompact", b".Upack": "Upack", b"kkrunchy": "kkrunchy",
}
BYTE_MARKERS = [(b"UPX!", "UPX"), (b"$Info: This file is packed with the UPX", "UPX"), (b"This program cannot be run in DOS mode", None),
                (b"PECompact2", "PECompact"), (b"ASPack", "ASPack"), (b"Themida", "Themida"), (b"VMProtect", "VMProtect")]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def block_entropy(data: bytes, block: int = 4096) -> List[float]:
    return [round(entropy(data[i:i + block]), 3) for i in range(0, len(data), block)]


def analyze_packing(proj) -> dict:
    img, db = proj.image, proj.db
    findings: List[dict] = []
    sections = []
    for s in img.segments:
        if s.name == "HEADER":
            continue
        raw = bytes(s.orig[:s.size]) if s.file_offset is not None else b""
        e = entropy(raw)
        sections.append({"name": s.name, "start": s.start, "size": s.size, "perms": s.perms, "entropy": round(e, 3),
                         "file_backed": s.file_offset is not None})
        if e > 7.2 and len(raw) > 512:
            findings.append({"severity": "medium", "title": f"High entropy in {s.name} ({e:.2f})",
                             "detail": "Compressed or encrypted content is typical of packers/crypters."})
        if s.executable and "w" in s.perms:
            findings.append({"severity": "medium", "title": f"{s.name} is writable+executable",
                             "detail": "Self-modifying or unpacking code needs RWX memory."})
        nm = s.name.encode("latin1", "ignore")
        for k, v in PACKER_SECTION_NAMES.items():
            if nm.startswith(k):
                findings.append({"severity": "high", "title": f"Section name matches {v}", "detail": s.name})
    for pat, name in BYTE_MARKERS:
        if name and pat in img.raw:
            findings.append({"severity": "high", "title": f"Marker string for {name}", "detail": pat[:40].decode("latin1")})
    n_imp = len(img.imports)
    if img.fmt.startswith("PE") and n_imp < 15 and any(i.name in ("LoadLibraryA", "GetProcAddress", "LoadLibraryW") for i in img.imports):
        findings.append({"severity": "medium", "title": "Sparse import table with dynamic resolution",
                         "detail": f"{n_imp} imports including LoadLibrary/GetProcAddress"})
    if img.entry_points:
        ep = img.entry_points[0][0]
        seg = img.segment_at(ep)
        if seg is not None and sections:
            last = max((s for s in img.segments if s.name != "HEADER"), key=lambda s: s.start)
            if seg is last and len(img.segments) > 2:
                findings.append({"severity": "medium", "title": "Entry point in the last section",
                                 "detail": f"{seg.name}; common for packers that append a stub"})
    if any(k == "tls_callback" for _, k in img.entry_points):
        findings.append({"severity": "low", "title": "TLS callbacks present",
                         "detail": "Code runs before the entry point (anti-debug/unpack technique, but also legitimate)."})
    # code coverage: share of executable bytes decoded as code
    exec_bytes = sum(s.size for s in img.segments if s.executable)
    code_bytes = sum(db.insns.values())
    cov = code_bytes / exec_bytes if exec_bytes else 1.0
    if exec_bytes > 4096 and cov < 0.2:
        findings.append({"severity": "medium", "title": f"Low code coverage ({cov:.0%} of executable bytes decoded)",
                         "detail": "Large undecoded executable regions suggest packed or encrypted code."})
    verdict = "likely packed/obfuscated" if any(f["severity"] == "high" for f in findings) or \
        sum(f["severity"] == "medium" for f in findings) >= 2 else ("suspicious" if findings else "no packing indicators")
    return {"verdict": verdict, "sections": sections, "findings": findings, "code_coverage": round(cov, 3),
            "note": "Heuristic indicators only; unpack dynamically to confirm."}
