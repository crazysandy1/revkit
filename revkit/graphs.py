"""Graph utilities: CFG export, dominators, loops, call graph, proximity browser, path finding."""
from __future__ import annotations

import json
from collections import deque
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .arch import CALL, CJMP, INDCALL, JMP, RET
from .db import Database, Function, Block, X_CALL


# -------------------------------------------------------------------- CFG
def cfg(db: Database, f: Function) -> dict:
    """Function CFG as JSON-serialisable nodes/edges with rendered block text."""
    from .listing import render_insn
    nodes, edges = [], []
    for b in sorted(f.blocks.values(), key=lambda x: x.start):
        lines = []
        for a in b.insns:
            ins = db.insn(a)
            lines.append({"addr": a, "text": render_insn(db, ins) if ins else "?"})
        nodes.append({"id": b.start, "start": b.start, "end": b.end, "lines": lines,
                      "label": db.display_name(b.start)})
        for t, kind in b.succs:
            edges.append({"from": b.start, "to": t, "kind": kind})
    return {"function": f.start, "name": db.display_name(f.start), "nodes": nodes, "edges": edges}


def cfg_dot(db: Database, f: Function) -> str:
    g = cfg(db, f)
    out = [f'digraph "{g["name"]}" {{', '  node [shape=box, fontname="Consolas", fontsize=10];']
    for n in g["nodes"]:
        label = "\\l".join(f'{l["addr"]:x}: {l["text"]}'.replace('"', '\\"') for l in n["lines"]) + "\\l"
        out.append(f'  "{n["id"]:x}" [label="{label}"];')
    color = {"true": "green", "false": "red", "jump": "blue", "fall": "black", "switch": "purple"}
    for e in g["edges"]:
        out.append(f'  "{e["from"]:x}" -> "{e["to"]:x}" [color={color.get(e["kind"], "black")}];')
    out.append("}")
    return "\n".join(out)


def dominators(f: Function) -> Dict[int, Set[int]]:
    nodes = set(f.blocks)
    preds: Dict[int, Set[int]] = {n: set() for n in nodes}
    for b in f.blocks.values():
        for t, _ in b.succs:
            if t in preds:
                preds[t].add(b.start)
    dom = {n: set(nodes) for n in nodes}
    dom[f.start] = {f.start}
    changed = True
    order = sorted(nodes)
    while changed:
        changed = False
        for n in order:
            if n == f.start:
                continue
            ps = [dom[p] for p in preds[n]] or [set()]
            new = set.intersection(*ps) | {n}
            if new != dom[n]:
                dom[n] = new
                changed = True
    return dom


def loops(f: Function) -> List[dict]:
    """Natural loops via back edges (edge whose target dominates its source)."""
    dom = dominators(f)
    preds: Dict[int, Set[int]] = {n: set() for n in f.blocks}
    for b in f.blocks.values():
        for t, _ in b.succs:
            if t in preds:
                preds[t].add(b.start)
    result = []
    for b in f.blocks.values():
        for t, _ in b.succs:
            if t in dom.get(b.start, ()):
                body = {t, b.start}
                work = [b.start]
                while work:
                    n = work.pop()
                    for p in preds.get(n, ()):
                        if p not in body:
                            body.add(p)
                            work.append(p)
                result.append({"header": t, "latch": b.start, "body": sorted(body)})
    return result


def cyclomatic_complexity(f: Function) -> int:
    """McCabe complexity with a virtual exit node joined from every exit block (handles multiple returns)."""
    e = sum(len(b.succs) for b in f.blocks.values())
    exits = sum(1 for b in f.blocks.values() if not b.succs)
    return max(1, e - len(f.blocks) + exits + 1)


# -------------------------------------------------------------------- call graph
def call_graph(db: Database) -> Dict[int, Set[int]]:
    g: Dict[int, Set[int]] = {}
    for a, f in db.functions.items():
        outs = set()
        for b in f.blocks.values():
            for ia in b.insns:
                for to, k in db.xrefs_from.get(ia, ()):
                    if k == X_CALL:
                        tf = db.functions.get(to)
                        if tf is not None:
                            outs.add(to)
                        elif to in db.import_slots():
                            outs.add(to)
                        else:
                            ff = db.function_at(to)
                            if ff is not None:
                                outs.add(ff.start)
                    elif k == "jump" and to in db.functions and to != a and to not in f.blocks:
                        outs.add(to)      # tail call
        g[a] = outs
    return g


def reverse_graph(g: Dict[int, Set[int]]) -> Dict[int, Set[int]]:
    r: Dict[int, Set[int]] = {}
    for a, outs in g.items():
        r.setdefault(a, set())
        for o in outs:
            r.setdefault(o, set()).add(a)
    return r


def proximity(db: Database, center: int, depth: int = 2, max_nodes: int = 80) -> dict:
    """Neighbourhood of `center` in the call graph (callers and callees up to `depth`)."""
    g = call_graph(db)
    r = reverse_graph(g)
    seen = {center: 0}
    dq = deque([center])
    edges = set()
    while dq and len(seen) < max_nodes:
        n = dq.popleft()
        if seen[n] >= depth:
            continue
        for m in g.get(n, ()):
            edges.add((n, m))
            if m not in seen:
                seen[m] = seen[n] + 1
                dq.append(m)
        for m in r.get(n, ()):
            edges.add((m, n))
            if m not in seen:
                seen[m] = seen[n] + 1
                dq.append(m)
    return {"center": center, "nodes": [{"id": a, "name": db.display_name(a), "dist": d} for a, d in seen.items()],
            "edges": [{"from": a, "to": b} for a, b in edges if a in seen and b in seen]}


def find_paths(db: Database, src: int, dst: int, max_paths: int = 20, max_len: int = 12) -> List[List[int]]:
    g = call_graph(db)
    paths: List[List[int]] = []

    def dfs(n, path):
        if len(paths) >= max_paths or len(path) > max_len:
            return
        if n == dst:
            paths.append(list(path))
            return
        for m in sorted(g.get(n, ())):
            if m not in path:
                path.append(m)
                dfs(m, path)
                path.pop()
    dfs(src, [src])
    return paths


def reachable_from(db: Database, root: int) -> Set[int]:
    g = call_graph(db)
    seen = {root}
    st = [root]
    while st:
        n = st.pop()
        for m in g.get(n, ()):
            if m not in seen:
                seen.add(m)
                st.append(m)
    return seen


def call_graph_dot(db: Database, root: Optional[int] = None, depth: int = 3) -> str:
    g = call_graph(db)
    nodes = reachable_from(db, root) if root is not None else set(g)
    out = ["digraph callgraph {", '  node [shape=box, fontname="Consolas", fontsize=10];']
    for a in nodes:
        out.append(f'  "{a:x}" [label="{db.display_name(a)}"];')
    for a in nodes:
        for b in g.get(a, ()):
            if b in nodes:
                out.append(f'  "{a:x}" -> "{b:x}";')
    out.append("}")
    return "\n".join(out)
