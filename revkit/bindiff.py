"""Binary comparison: function matching (name, exact hash, structural hash, similarity) with call-graph propagation."""
from __future__ import annotations

import difflib
from typing import Dict, List, Optional, Tuple

from . import graphs
from .fingerprint import features, function_hash, similarity, structural_hash
from .listing import render_insn


def _is_auto(name: str) -> bool:
    return name.startswith(("sub_", "loc_", "j_sub_"))


def diff_projects(a, b, min_similarity: float = 0.6) -> dict:
    da, db_ = a.db, b.db
    fa = {s: f for s, f in da.functions.items() if "import" not in f.flags}
    fb = {s: f for s, f in db_.functions.items() if "import" not in f.flags}
    ha = {s: function_hash(da, f) for s, f in fa.items()}
    hb = {s: function_hash(db_, f) for s, f in fb.items()}
    feats_a = {s: features(da, f) for s, f in fa.items()}
    feats_b = {s: features(db_, f) for s, f in fb.items()}
    matches: Dict[int, Tuple[int, str, float]] = {}
    used_b = set()

    def take(x, y, how, sim):
        if x in matches or y in used_b:
            return False
        matches[x] = (y, how, sim)
        used_b.add(y)
        return True

    # 1. identical names (user/symbol names only)
    by_name_b = {}
    for s in fb:
        n = db_.display_name(s)
        if not _is_auto(n):
            by_name_b.setdefault(n, []).append(s)
    for s in fa:
        n = da.display_name(s)
        if not _is_auto(n) and len(by_name_b.get(n, ())) == 1:
            y = by_name_b[n][0]
            take(s, y, "name", similarity(feats_a[s], feats_b[y]))
    # 2. unique exact hashes
    inv_b: Dict[str, List[int]] = {}
    for s, h in hb.items():
        inv_b.setdefault(h, []).append(s)
    inv_a: Dict[str, List[int]] = {}
    for s, h in ha.items():
        inv_a.setdefault(h, []).append(s)
    for h, xs in inv_a.items():
        ys = inv_b.get(h, [])
        if len(xs) == 1 and len(ys) == 1:
            take(xs[0], ys[0], "exact-hash", 1.0)
    # 3. structural hash + features
    sa = {s: structural_hash(da, f) for s, f in fa.items() if s not in matches}
    sb = {s: structural_hash(db_, f) for s, f in fb.items() if s not in used_b}
    inv_sb: Dict[str, List[int]] = {}
    for s, h in sb.items():
        inv_sb.setdefault(h, []).append(s)
    for s, h in sa.items():
        c = [y for y in inv_sb.get(h, ()) if y not in used_b]
        if len(c) == 1 and similarity(feats_a[s], feats_b[c[0]]) >= min_similarity:
            take(s, c[0], "structure", similarity(feats_a[s], feats_b[c[0]]))
    # 4. call-graph propagation from matched pairs
    ga, gb = graphs.call_graph(da), graphs.call_graph(db_)
    for _ in range(4):
        grew = False
        for x, (y, _, _) in list(matches.items()):
            ca = sorted(c for c in ga.get(x, ()) if c in fa and c not in matches)
            cb = [c for c in sorted(gb.get(y, ())) if c in fb and c not in used_b]
            for cx in ca:
                best = max(((similarity(feats_a[cx], feats_b[cy]), cy) for cy in cb if cy not in used_b), default=(0, None))
                if best[1] is not None and best[0] >= min_similarity:
                    if take(cx, best[1], "callgraph", best[0]):
                        grew = True
        if not grew:
            break
    # 5. greedy best similarity among the rest (bounded)
    rest_a = [s for s in fa if s not in matches]
    rest_b = [s for s in fb if s not in used_b]
    if len(rest_a) * len(rest_b) <= 4_000_000:
        scored = []
        for x in rest_a:
            for y in rest_b:
                if abs(feats_a[x]["nblocks"] - feats_b[y]["nblocks"]) > max(3, feats_a[x]["nblocks"]):
                    continue
                sc = similarity(feats_a[x], feats_b[y])
                if sc >= min_similarity:
                    scored.append((sc, x, y))
        scored.sort(reverse=True)
        for sc, x, y in scored:
            take(x, y, "similarity", sc)
    out = []
    for x, (y, how, sim) in sorted(matches.items()):
        out.append({"a": x, "b": y, "name_a": da.display_name(x), "name_b": db_.display_name(y), "method": how,
                    "similarity": sim, "identical": ha[x] == hb[y]})
    return {
        "matched": out, "changed": [m for m in out if not m["identical"]],
        "removed": [{"addr": s, "name": da.display_name(s)} for s in sorted(fa) if s not in matches],
        "added": [{"addr": s, "name": db_.display_name(s)} for s in sorted(fb) if s not in used_b],
        "summary": {"functions_a": len(fa), "functions_b": len(fb), "matched": len(out),
                    "identical": sum(m["identical"] for m in out), "changed": sum(not m["identical"] for m in out),
                    "removed": len(fa) - len(out), "added": len(fb) - len(out),
                    "overall_similarity": round(sum(m["similarity"] for m in out) / max(len(fa), len(fb), 1), 4)},
    }


def function_diff(a, b, fa: int, fb: int) -> str:
    """Unified diff of the normalised disassembly of two functions."""
    from .fingerprint import normalize_insn

    def lines(p, s):
        f = p.db.functions[s]
        out = []
        for blk in sorted(f.blocks.values(), key=lambda x: x.start):
            for ia in blk.insns:
                ins = p.db.insn(ia)
                out.append(normalize_insn(p.db, ins) if ins else "?")
        return out
    return "\n".join(difflib.unified_diff(lines(a, fa), lines(b, fb), a.db.display_name(fa), b.db.display_name(fb), lineterm=""))
