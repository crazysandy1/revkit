"""Control-flow structuring (if/else, loops, switch, break/continue, goto fallback) and C rendering."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from ..types import Func as FuncT, TypeError_
from .ir import (Assign, AsmStmt, Bin, CallE, Cast, Comment, Const, CJump, Expr, ExprStmt, Goto, Intr, Mem, Namer, Reg,
                 Return, Stmt, SwitchJ, Un, Var, fmt, simplify, sign, walk, ctype, NEG_CMP)


# ----------------------------------------------------------------------------- AST
class Node:
    pass


class SNode(Node):
    def __init__(self, s: Stmt):
        self.s = s


class IfNode(Node):
    def __init__(self, cond: Expr, then: List[Node], els: List[Node], addr: int = 0):
        self.cond, self.then, self.els, self.addr = cond, then, els, addr


class WhileNode(Node):
    def __init__(self, cond: Optional[Expr], body: List[Node], addr: int = 0):
        self.cond, self.body, self.addr = cond, body, addr          # cond None => while(1)


class DoWhileNode(Node):
    def __init__(self, body: List[Node], cond: Expr, addr: int = 0):
        self.body, self.cond, self.addr = body, cond, addr


class ForNode(Node):
    def __init__(self, init: Stmt, cond: Expr, step: Stmt, body: List[Node], addr: int = 0):
        self.init, self.cond, self.step, self.body, self.addr = init, cond, step, body, addr


class SwitchNode(Node):
    def __init__(self, index: Expr, cases: List[Tuple[List[int], List[Node]]], default: Optional[List[Node]], addr: int = 0):
        self.index, self.cases, self.default, self.addr = index, cases, default, addr


class BreakNode(Node):
    pass


class ContinueNode(Node):
    pass


class GotoNode(Node):
    def __init__(self, bid: int):
        self.bid = bid


class LabelNode(Node):
    def __init__(self, bid: int):
        self.bid = bid


def terminal(nodes: List[Node]) -> bool:
    if not nodes:
        return False
    n = nodes[-1]
    if isinstance(n, (BreakNode, ContinueNode, GotoNode)):
        return True
    if isinstance(n, SNode) and isinstance(n.s, Return):
        return True
    if isinstance(n, SNode):
        from .decompile import ends_in_noreturn
        if ends_in_noreturn([n.s]):
            return True
    if isinstance(n, IfNode):
        return bool(n.els) and terminal(n.then) and terminal(n.els)
    return False


# ----------------------------------------------------------------------------- analysis helpers
def _rpo(succ: Dict[int, List[int]], entry: int) -> List[int]:
    seen, order = set(), []

    def dfs(n):
        stack = [(n, iter(succ.get(n, ())))]
        seen.add(n)
        while stack:
            node, it = stack[-1]
            for m in it:
                if m not in seen:
                    seen.add(m)
                    stack.append((m, iter(succ.get(m, ()))))
                    break
            else:
                order.append(node)
                stack.pop()
    dfs(entry)
    order.reverse()
    return order


def _idoms(succ: Dict[int, List[int]], entry: int) -> Dict[int, int]:
    rpo = _rpo(succ, entry)
    idx = {n: i for i, n in enumerate(rpo)}
    pred: Dict[int, List[int]] = defaultdict(list)
    for n in rpo:
        for m in succ.get(n, ()):
            if m in idx:
                pred[m].append(n)
    idom: Dict[int, int] = {entry: entry}

    def inter(a, b):
        while a != b:
            while idx[a] > idx[b]:
                a = idom[a]
            while idx[b] > idx[a]:
                b = idom[b]
        return a
    changed = True
    while changed:
        changed = False
        for n in rpo[1:]:
            ps = [p for p in pred[n] if p in idom]
            if not ps:
                continue
            new = ps[0]
            for p in ps[1:]:
                new = inter(new, p)
            if idom.get(n) != new:
                idom[n] = new
                changed = True
    return idom


EXIT = -1


class Structurer:
    def __init__(self, dec):
        self.d = dec
        self.db = dec.db
        self.f = dec.f
        self.bbs = dec.bbs
        self.emitted: Set[int] = set()
        self.goto_targets: Set[int] = set()
        self.loops: Dict[int, dict] = {}
        self.loop_stack: List[dict] = []
        self.switch_default_for: Dict[int, int] = {}

    # ---------------------------------------------------------------- preprocessing
    def _thread(self):
        """Remove blocks consisting solely of an unconditional jump by redirecting predecessors."""
        bbs = self.bbs
        entry = self.f.start
        changed = True
        while changed:
            changed = False
            for ba, bb in list(bbs.items()):
                if ba == entry or len(bb.stmts) != 1 or not isinstance(bb.stmts[0], Goto):
                    continue
                tgt = bb.stmts[0].target
                if tgt == ba:
                    continue
                for pa, pb in bbs.items():
                    if pa == ba:
                        continue
                    t = pb.term
                    hit = False
                    if isinstance(t, Goto) and t.target == ba:
                        t.target = tgt
                        hit = True
                    elif isinstance(t, CJump):
                        if t.t == ba:
                            t.t = tgt
                            hit = True
                        if t.f == ba:
                            t.f = tgt
                            hit = True
                    elif isinstance(t, SwitchJ):
                        t.cases = [(k, tgt if x == ba else x) for k, x in t.cases]
                        hit = any(x == ba for _, x in t.cases) or hit
                    if hit:
                        pb.succs = [tgt if s == ba else s for s in pb.succs]
                        changed = True
        # recompute preds and drop unreachable blocks
        reach = set()
        st = [entry]
        while st:
            n = st.pop()
            if n in reach or n not in bbs:
                continue
            reach.add(n)
            st.extend(bbs[n].succs)
        for ba in list(bbs):
            if ba not in reach:
                del bbs[ba]
        for bb in bbs.values():
            bb.preds = []
            bb.succs = list(dict.fromkeys(s for s in bb.succs if s in bbs))
        for ba, bb in bbs.items():
            for s in bb.succs:
                bbs[s].preds.append(ba)

    def _analyse(self):
        entry = self.f.start
        succ = {ba: list(bb.succs) for ba, bb in self.bbs.items()}
        self.succ = succ
        self.idom = _idoms(succ, entry)
        # post-dominators on reverse graph with virtual exit
        rsucc: Dict[int, List[int]] = defaultdict(list)
        for n, ss in succ.items():
            if not ss:
                rsucc[EXIT].append(n)
            for m in ss:
                rsucc[m].append(n)
        # blocks inside infinite loops have no path to EXIT: connect their back-edge sources
        self.ipdom = _idoms(rsucc, EXIT)
        # natural loops
        rpo = _rpo(succ, entry)
        rpo_idx = {n: i for i, n in enumerate(rpo)}
        self.rpo_idx = rpo_idx

        def dominates(a, b):
            while True:
                if a == b:
                    return True
                p = self.idom.get(b)
                if p is None or p == b:
                    return False
                b = p
        self.dominates = dominates
        loops: Dict[int, dict] = {}
        for n in rpo:
            for m in succ.get(n, ()):
                if m in rpo_idx and dominates(m, n):          # back edge n -> m
                    L = loops.setdefault(m, {"header": m, "latches": [], "body": {m}})
                    L["latches"].append(n)
                    work = [n]
                    L["body"].add(n)
                    while work:
                        x = work.pop()
                        for p in self.bbs[x].preds:
                            if p not in L["body"] and dominates(m, p):
                                L["body"].add(p)
                                work.append(p)
        for h, L in loops.items():
            exits = []
            for n in L["body"]:
                for m in succ.get(n, ()):
                    if m not in L["body"] and m not in exits:
                        exits.append(m)
            L["exits"] = exits
            # primary exit: header's exit if any, else the exit reached by most blocks, else lowest address
            hx = [m for m in succ.get(h, ()) if m not in L["body"]]
            if hx:
                L["exit"] = hx[0]
            elif exits:
                L["exit"] = min(exits, key=lambda e: (-sum(1 for n in L["body"] if e in succ.get(n, ())), e))
            else:
                L["exit"] = None
        self.loops = loops

    # ---------------------------------------------------------------- emission
    def render(self):
        from .decompile import Pseudocode
        self._thread()
        self._analyse()
        nodes = self.seq(self.f.start, set())
        # blocks never reached by the structured walk (irreducible regions) are appended behind labels
        for ba in sorted(self.bbs):
            if ba not in self.emitted:
                self.goto_targets.add(ba)
                nodes.append(GotoNode(-ba))   # marker: unreachable-by-structure separator (not printed)
                nodes += self.seq(ba, set())
        nodes = self._post(nodes)
        return self._to_pseudocode(nodes)

    def _next_in_loop_context(self, b: int) -> Optional[Node]:
        if self.loop_stack:
            L = self.loop_stack[-1]
            if b == L["header"]:
                return ContinueNode()
            if b == L["exit"]:
                return BreakNode()
        return None

    def seq(self, b: Optional[int], stops: Set[int]) -> List[Node]:
        out: List[Node] = []
        while True:
            if b is None:
                return out
            jump = self._next_in_loop_context(b)
            if jump is not None:
                out.append(jump)
                return out
            if b in stops:
                return out
            if b not in self.bbs:
                return out
            if b in self.emitted:
                self.goto_targets.add(b)
                out.append(GotoNode(b))
                return out
            if b in self.loops and not any(L["header"] == b for L in self.loop_stack):
                node, after = self.emit_loop(b, stops)
                out.append(node)
                b = after
                continue
            self.emitted.add(b)
            bb = self.bbs[b]
            out.append(LabelNode(b))
            term = bb.term
            body = bb.stmts[:-1] if term is not None else bb.stmts
            for s in body:
                out.append(SNode(s))
            if term is None:
                return out
            if isinstance(term, Return):
                out.append(SNode(term))
                return out
            if isinstance(term, Goto):
                b = term.target
                continue
            if isinstance(term, SwitchJ):
                node, merge = self.emit_switch(b, term, stops, None)
                out.append(node)
                b = merge
                continue
            if isinstance(term, CJump):
                node, merge = self.emit_if(b, term, stops)
                if isinstance(node, list):
                    out.extend(node)
                else:
                    out.append(node)
                if terminal(out):
                    return out
                b = merge
                continue
            return out

    def _merge_point(self, b: int, extra_stops: Set[int]) -> Optional[int]:
        m = self.ipdom.get(b)
        if m is None or m == EXIT or m == b:
            return None
        return m

    def emit_if(self, b: int, term: CJump, stops: Set[int]):
        T, F = term.t, term.f
        cond = term.cond
        # switch fold: bounds check guarding a switch block
        sw = self._try_switch_fold(b, term, stops)
        if sw is not None:
            return sw
        merge = self._merge_point(b, stops)
        # keep merge inside the current loop body when the immediate post-dominator is the loop exit
        if merge is not None and self.loop_stack and merge == self.loop_stack[-1]["exit"]:
            merge = None if self._both_leave(T, F) else merge
        inner_stops = set(stops)
        if merge is not None:
            inner_stops.add(merge)
        then = self.seq(T, inner_stops)
        els = self.seq(F, inner_stops)
        if not then and els:
            cond = simplify(Un("!", cond, 1))
            then, els = els, []
        if terminal(then) and els:
            node = [IfNode(cond, then, [], term.addr)] + els
            return node, merge
        if terminal(els) and then:
            return IfNode(cond, then, els, term.addr), merge
        return IfNode(cond, then, els, term.addr), merge

    def _both_leave(self, T, F) -> bool:
        L = self.loop_stack[-1]
        return T not in L["body"] and F not in L["body"]

    def _try_switch_fold(self, b: int, term: CJump, stops):
        for default, sw_b in ((term.t, term.f), (term.f, term.t)):
            sb = self.bbs.get(sw_b)
            if sb is None or not isinstance(sb.term, SwitchJ) or len(sb.preds) != 1 or len(sb.stmts) != 1:
                continue
            cond = term.cond
            if not isinstance(cond, Bin):
                continue
            idx = sb.term.index
            # cond: idx u> N  (branch to default) or negated form
            n = None
            if default == term.t and cond.op in ("u>", "u>=") and isinstance(cond.b, Const):
                n = cond.b.v + (1 if cond.op == "u>" else 0)
            elif default == term.f and cond.op in ("u<=", "u<") and isinstance(cond.b, Const):
                n = cond.b.v + (1 if cond.op == "u<=" else 0)
            if n is None or n < len(sb.term.cases) - 0 and n != len(sb.term.cases):
                if n is None:
                    continue
            if self._same_index(cond.a, idx) or (n is not None and n == len(sb.term.cases)):
                self.emitted.add(sw_b)
                node, merge = self.emit_switch(sw_b, sb.term, stops, default, guard=cond.a)
                return node, merge
        return None

    def _same_index(self, a: Expr, b: Expr) -> bool:
        def strip(e):
            while isinstance(e, Cast):
                e = e.a
            return e
        return strip(a) == strip(b) or fmt(strip(a)) == fmt(strip(b))

    def emit_switch(self, b: int, term: SwitchJ, stops: Set[int], default: Optional[int], guard=None):
        cases = term.cases
        targets = []
        for k, t in cases:
            if t not in targets:
                targets.append(t)
        # merge point of the switch: common post-dominator of the targets (and default)
        cand = None
        nodes_all = list(targets) + ([default] if default is not None else [])
        pd = [self._pdom_chain(t) for t in nodes_all]
        if pd:
            common = [x for x in pd[0] if all(x in c for c in pd[1:])]
            cand = common[0] if common else None
        merge = cand
        if merge is not None and merge in nodes_all:
            merge = None if len(nodes_all) == 1 else merge
        by_target: Dict[int, List[int]] = defaultdict(list)
        for k, t in cases:
            by_target[t].append(k)
        inner = set(stops)
        if merge is not None:
            inner.add(merge)
        self.switch_break_stack = getattr(self, "switch_break_stack", [])
        outcases = []
        # break inside switch bodies jumps to merge: emulate by treating merge as a stop (falls to `break`)
        for t in targets:
            if t == merge:
                continue
            body = self.seq(t, inner)
            if not terminal(body):
                body.append(BreakNode())
            outcases.append((by_target[t], body))
        dflt = None
        if default is not None and default != merge:
            dflt = self.seq(default, inner)
            if not terminal(dflt):
                dflt.append(BreakNode())
        idx = guard if guard is not None else term.index
        return SwitchNode(idx, outcases, dflt, term.addr), merge

    def _pdom_chain(self, n: int) -> List[int]:
        out = []
        seen = set()
        x = n
        out.append(x)
        while x in self.ipdom and x not in seen:
            seen.add(x)
            p = self.ipdom[x]
            if p == EXIT or p == x:
                break
            out.append(p)
            x = p
        return out

    def emit_loop(self, h: int, stops: Set[int]):
        L = self.loops[h]
        exit_b = L["exit"]
        self.loop_stack.append(L)
        body_stops = set(stops)
        # emit the loop body: the header block is emitted by seq() while L is on the loop stack
        self.emitted_loop_header = h
        body = self.seq_loop_body(h)
        self.loop_stack.pop()
        node = WhileNode(None, body, 0)
        return node, exit_b

    def seq_loop_body(self, h: int) -> List[Node]:
        # temporarily allow emitting the header (seq() checks loop_stack header -> Continue), so emit it manually
        bb = self.bbs[h]
        self.emitted.add(h)
        out: List[Node] = [LabelNode(h)]
        term = bb.term
        body = bb.stmts[:-1] if term is not None else bb.stmts
        for s in body:
            out.append(SNode(s))
        if isinstance(term, Return):
            out.append(SNode(term))
        elif isinstance(term, Goto):
            out += self.seq(term.target, set())
        elif isinstance(term, CJump):
            node, merge = self.emit_if(h, term, set())
            out.extend(node if isinstance(node, list) else [node])
            if merge is not None and merge != self.loops[h]["exit"]:
                out += self.seq(merge, set())
        elif isinstance(term, SwitchJ):
            node, merge = self.emit_switch(h, term, set(), None)
            out.append(node)
            if merge is not None:
                out += self.seq(merge, set())
        return out

    # ---------------------------------------------------------------- post-processing
    def _post(self, nodes: List[Node]) -> List[Node]:
        out: List[Node] = []
        for n in nodes:
            if isinstance(n, GotoNode) and n.bid < 0:
                continue
            out.append(self._post_node(n))
        return out

    def _post_node(self, n: Node) -> Node:
        if isinstance(n, IfNode):
            n.then = self._post(n.then)
            n.els = self._post(n.els)
        elif isinstance(n, WhileNode):
            n.body = self._post(n.body)
            self._loopify(n)
        elif isinstance(n, SwitchNode):
            n.cases = [(v, self._post(b)) for v, b in n.cases]
            if n.default is not None:
                n.default = self._post(n.default)
        return n

    def _strip_labels(self, body: List[Node]) -> List[Node]:
        return [x for x in body if not isinstance(x, LabelNode)]

    def _loopify(self, n: WhileNode):
        body = n.body
        # leading `if (c) break;`  ->  while (!c)
        core = [x for x in body if not isinstance(x, LabelNode)]
        labels_prefix = [x for x in body if isinstance(x, LabelNode)]
        if core and isinstance(core[0], IfNode):
            f = core[0]
            if f.then and len(f.then) == 1 and isinstance(f.then[0], BreakNode) and not f.els:
                n.cond = simplify(Un("!", f.cond, 1))
                n.body = labels_prefix + core[1:]
                self._trim_continue(n)
                return
            if f.els and len(f.els) == 1 and isinstance(f.els[0], BreakNode) and f.then:
                n.cond = f.cond
                n.body = labels_prefix + f.then + core[1:]
                self._trim_continue(n)
                return
        # trailing `if (c) continue; else break;` / `if (!c) break;` -> do { } while (c)
        if core:
            last = core[-1]
            if isinstance(last, IfNode) and last.then and isinstance(last.then[-1], ContinueNode) and len(last.then) == 1 \
                    and last.els and len(last.els) == 1 and isinstance(last.els[0], BreakNode):
                pre = body[:body.index(last)]
                self._rewrite_do(n, pre, last.cond)
                return
            if isinstance(last, IfNode) and last.then and len(last.then) == 1 and isinstance(last.then[0], BreakNode) and not last.els:
                pre = body[:body.index(last)]
                self._rewrite_do(n, pre, simplify(Un("!", last.cond, 1)))
                return
        self._trim_continue(n)

    def _rewrite_do(self, n: WhileNode, pre, cond):
        n.__class__ = DoWhileNode
        n.body = pre
        n.cond = cond
        self._trim_continue(n)

    def _trim_continue(self, n):
        if n.body and isinstance(n.body[-1], ContinueNode):
            n.body.pop()

    # ---------------------------------------------------------------- rendering
    def _to_pseudocode(self, nodes):
        from .decompile import Pseudocode
        d = self.d
        db = self.db
        f = self.f
        namer = Namer(db)
        pc = Pseudocode(f.start, db.display_name(f.start), warnings=list(d.warnings))
        # apply user variable renames/types
        used_vars: Dict[str, Var] = {}
        self._collect(nodes, used_vars)
        for name, v in list(used_vars.items()):
            ov = db.var_names.get((f.start, name))
            if ov:
                v.name = ov[0] or v.name
                if ov[1]:
                    v.ty = ov[1]
        self._infer_types(nodes, used_vars)
        self._apply_struct_fields(nodes, used_vars)
        pc.calls = self._gather_calls(nodes)
        pc.stack_buffers = self._stack_buffer_sizes()
        # ---- header
        proto_txt = db.func_protos.get(f.start)
        params = [v for _, v in d.params]
        cc = {"cdecl": "__cdecl", "stdcall": "__stdcall", "fastcall": "__fastcall", "thiscall": "__thiscall"}.get(f.callconv, "")
        ret = "void"
        if d.ret_val:
            ret = ctype(d.ret_size or d.lifter.w)
        pnames = []
        pdecl = []
        proto_f = None
        if proto_txt:
            try:
                proto_f = db.types.parse_prototype(proto_txt)
            except TypeError_:
                proto_f = None
        if proto_f is not None:
            ret = db.types.format(proto_f.ret)
            if proto_f.cc:
                cc = f"__{proto_f.cc}"
            for i, (pn, pt) in enumerate(proto_f.params):
                if i < len(params):
                    if pn and not db.var_names.get((f.start, params[i].name)):
                        params[i].name = pn
                    params[i].ty = db.types.format(pt)
            for i in range(len(proto_f.params), len(params)):
                pass
            for i, (pn, pt) in enumerate(proto_f.params[len(params):], start=len(params)):
                v = Var(pn or f"a{i + 1}", db.types.sizeof(pt), "param")
                v.ty = db.types.format(pt)
                params.append(v)
        for v in params:
            pdecl.append(f"{self._vtype(v)} {v.name}")
        sig = f"{ret} {cc + ' ' if cc else ''}{db.display_name(f.start)}({', '.join(pdecl) if pdecl else 'void'})"
        lines: List[Tuple[str, int]] = []
        lines.append((sig, f.start))
        lines.append(("{", 0))
        # ---- declarations
        locs = [v for n, v in used_vars.items() if v not in params and v.kind in ("local", "stack") and n != "retaddr"]
        seen = set()
        def _k(x):
            m = re.match(r"^([A-Za-z_]+)([0-9A-Fa-f]*)$", x.name)
            return (x.kind != "local", m.group(1) if m else x.name, int(m.group(2), 16) if m and m.group(2) and x.kind != "local" else
                    (int(m.group(2)) if m and m.group(2).isdigit() else 0))
        for v in sorted(locs, key=_k):
            if v.name in seen:
                continue
            seen.add(v.name)
            if v.kind == "stack" and v.off is not None and v.size == 0:
                cmt = f"  // [{'rsp' if d.lifter.bits == 64 else 'esp'}{v.off:+#x}]"
                lines.append((f"  char {v.name}[?];{cmt}", 0))
                continue
            cmt = f"  // [bp{(v.off - d.lifter.fp_off):+#x}]" if v.off is not None and d.lifter.fp_off is not None and v.off != d.lifter.fp_off else ""
            lines.append((f"  {self._vtype(v)} {v.name};{cmt}", 0))
        if locs:
            lines.append(("", 0))
        self._render_nodes(nodes, 1, lines, namer, True)
        lines.append(("}", 0))
        pc.lines = lines
        return pc

    def _apply_struct_fields(self, nodes, used):
        """Rewrite `*(T *)(var + off)` into `var->field` when `var` has a pointer-to-struct type."""
        from ..types import Struct, Ptr, Arr, Named
        tm = self.db.types
        typed = {}
        for n, v in used.items():
            if v.ty and v.ty.rstrip().endswith("*"):
                try:
                    t = tm.parse_type(v.ty)
                    rt = tm.resolve(t)
                    if isinstance(rt, Ptr):
                        tgt = tm.resolve(rt.target)
                        if isinstance(tgt, Struct):
                            tm.layout(tgt)
                            typed[v.name] = tgt
                except Exception:
                    continue
        if not typed:
            return

        def find_field(st, off, size, prefix=""):
            for f in st.fields:
                ft = tm.resolve(f.type)
                fsz = tm.sizeof(f.type)
                if f.offset <= off < f.offset + max(fsz, 1):
                    name = prefix + (f.name or "")
                    if isinstance(ft, Struct) and (off != f.offset or size != fsz):
                        sub_ = find_field(ft, off - f.offset, size, name + ".")
                        if sub_:
                            return sub_
                    if off == f.offset:
                        return name
            return None

        def fix(e):
            if isinstance(e, Mem):
                a = e.addr
                base, off = None, 0
                if isinstance(a, Var) and a.name in typed:
                    base, off = a, 0
                elif isinstance(a, Bin) and a.op == "+" and isinstance(a.a, Var) and a.a.name in typed and isinstance(a.b, Const):
                    base, off = a.a, sign(a.b.v, a.b.size)
                if base is not None:
                    fld = find_field(typed[base.name], off, e.size)
                    if fld:
                        return Var(f"{base.name}->{fld}", e.size, "field")
            return e

        from .decompile import _map_stmt

        def apply_nodes(ns):
            for n in ns:
                if isinstance(n, SNode):
                    _map_stmt(n.s, fix)
                elif isinstance(n, IfNode):
                    n.cond = n.cond.map(fix)
                    apply_nodes(n.then)
                    apply_nodes(n.els)
                elif isinstance(n, (WhileNode, DoWhileNode)):
                    if n.cond is not None:
                        n.cond = n.cond.map(fix)
                    apply_nodes(n.body)
                elif isinstance(n, SwitchNode):
                    n.index = n.index.map(fix)
                    for _, b in n.cases:
                        apply_nodes(b)
                    if n.default:
                        apply_nodes(n.default)
        apply_nodes(nodes)

    def _gather_calls(self, nodes) -> List[dict]:
        calls: List[dict] = []

        def from_expr(e, addr):
            for x in walk(e):
                if isinstance(x, CallE):
                    calls.append({"addr": addr, "name": x.name, "args": list(x.args), "target": x.target, "proto": x.proto})

        def visit(ns):
            for n in ns:
                if isinstance(n, SNode):
                    s = n.s
                    if isinstance(s, Assign):
                        from_expr(s.src, s.addr)
                        from_expr(s.dst, s.addr)
                    elif isinstance(s, ExprStmt):
                        from_expr(s.e, s.addr)
                    elif isinstance(s, Return) and s.e is not None:
                        from_expr(s.e, s.addr)
                elif isinstance(n, IfNode):
                    from_expr(n.cond, n.addr)
                    visit(n.then)
                    visit(n.els)
                elif isinstance(n, (WhileNode, DoWhileNode)):
                    if n.cond is not None:
                        from_expr(n.cond, n.addr)
                    visit(n.body)
                elif isinstance(n, SwitchNode):
                    from_expr(n.index, n.addr)
                    for _, b in n.cases:
                        visit(b)
                    if n.default:
                        visit(n.default)
        visit(nodes)
        return calls

    def _stack_buffer_sizes(self) -> Dict[str, int]:
        """Estimate each stack object's size as the distance to the next object (or to the saved frame area)."""
        d = self.d
        vs = sorted({(v.off, v.name) for v in d.stack_vars.values() if v.off is not None and v.off < 0})
        out: Dict[str, int] = {}
        for i, (off, name) in enumerate(vs):
            nxt = vs[i + 1][0] if i + 1 < len(vs) else (d.lifter.fp_off - 0 if d.lifter.fp_off is not None and d.lifter.fp_off > off else 0)
            if nxt > off:
                out[name] = nxt - off
        return out

    def _collect(self, nodes, out):
        for n in nodes:
            if isinstance(n, SNode):
                self._collect_stmt(n.s, out)
            elif isinstance(n, IfNode):
                self._collect_expr(n.cond, out)
                self._collect(n.then, out)
                self._collect(n.els, out)
            elif isinstance(n, (WhileNode, DoWhileNode)):
                if n.cond is not None:
                    self._collect_expr(n.cond, out)
                self._collect(n.body, out)
            elif isinstance(n, SwitchNode):
                self._collect_expr(n.index, out)
                for _, b in n.cases:
                    self._collect(b, out)
                if n.default:
                    self._collect(n.default, out)

    def _collect_stmt(self, s, out):
        from .decompile import Decompiler
        if isinstance(s, Assign):
            self._collect_expr(s.dst, out)
            self._collect_expr(s.src, out)
        elif isinstance(s, ExprStmt):
            self._collect_expr(s.e, out)
        elif isinstance(s, Return) and s.e is not None:
            self._collect_expr(s.e, out)

    def _collect_expr(self, e, out):
        for x in walk(e):
            if isinstance(x, Var):
                out.setdefault(x.name, x)

    def _vtype(self, v: Var) -> str:
        if v.ty:
            return v.ty
        sz = v.size or self.d.lifter.w
        if getattr(v, "ptr", False):
            return "void *"
        return ctype(sz)

    def _infer_types(self, nodes, used):
        """Propagate types from call prototypes and pointer-use."""
        db = self.db
        tm = db.types

        def visit_expr(e):
            for x in walk(e):
                if isinstance(x, Mem) and isinstance(x.addr, Var):
                    x.addr.ptr = True
                elif isinstance(x, Mem) and isinstance(x.addr, Bin) and x.addr.op == "+" and isinstance(x.addr.a, Var):
                    x.addr.a.ptr = True
                if isinstance(x, CallE) and x.proto is not None:
                    for (pn, pt), a in zip(x.proto.params, x.args):
                        if isinstance(a, Var) and not a.ty:
                            try:
                                a.ty = tm.format(pt)
                            except TypeError_:
                                pass
        def visit(ns):
            for n in ns:
                if isinstance(n, SNode):
                    s = n.s
                    if isinstance(s, Assign):
                        if isinstance(s.src, CallE) and s.src.proto is not None and isinstance(s.dst, Var) and not s.dst.ty:
                            try:
                                rt = tm.format(s.src.proto.ret)
                                if rt != "void":
                                    s.dst.ty = rt
                            except TypeError_:
                                pass
                        visit_expr(s.src)
                        visit_expr(s.dst)
                    elif isinstance(s, ExprStmt):
                        visit_expr(s.e)
                    elif isinstance(s, Return) and s.e is not None:
                        visit_expr(s.e)
                elif isinstance(n, IfNode):
                    visit_expr(n.cond)
                    visit(n.then)
                    visit(n.els)
                elif isinstance(n, (WhileNode, DoWhileNode)):
                    if n.cond is not None:
                        visit_expr(n.cond)
                    visit(n.body)
                elif isinstance(n, SwitchNode):
                    visit_expr(n.index)
                    for _, b in n.cases:
                        visit(b)
                    if n.default:
                        visit(n.default)
        visit(nodes)

    def _stmt_text(self, s: Stmt, namer: Namer) -> Optional[str]:
        if isinstance(s, Assign):
            dst, src = s.dst, s.src
            if isinstance(src, Intr) and src.name == "__undefined":
                return f"{fmt(dst, namer)} = __undefined;"
            if isinstance(src, Bin) and src.a == dst and src.op in ("+", "-", "*", "|", "&", "^", "<<", ">>") and \
                    not isinstance(dst, Mem):
                if src.op in ("+", "-") and isinstance(src.b, Const) and src.b.v == 1:
                    return f"{'++' if src.op == '+' else '--'}{fmt(dst, namer)};"
                return f"{fmt(dst, namer)} {src.op}= {fmt(src.b, namer)};"
            return f"{fmt(dst, namer)} = {fmt(src, namer)};"
        if isinstance(s, ExprStmt):
            return f"{fmt(s.e, namer)};"
        if isinstance(s, Return):
            return f"return {fmt(s.e, namer)};" if s.e is not None else "return;"
        if isinstance(s, AsmStmt):
            return f"__asm {{ {s.text} }}"
        if isinstance(s, Comment):
            return f"// {s.text}"
        return None

    def _render_nodes(self, nodes, ind, lines, namer, top=False):
        pad = "  " * ind
        for n in nodes:
            if isinstance(n, LabelNode):
                if n.bid in self.goto_targets:
                    lines.append((f"LABEL_{n.bid:X}:", n.bid))
            elif isinstance(n, SNode):
                t = self._stmt_text(n.s, namer)
                if t is not None:
                    lines.append((pad + t + self._cmt(n.s.addr), n.s.addr))
            elif isinstance(n, IfNode):
                lines.append((f"{pad}if ( {fmt(n.cond, namer)} )", n.addr))
                self._block(n.then, ind, lines, namer)
                if n.els:
                    if len(n.els) == 1 and isinstance(n.els[0], IfNode) and False:
                        pass
                    lines.append((f"{pad}else", 0))
                    self._block(n.els, ind, lines, namer)
            elif isinstance(n, WhileNode):
                lines.append((f"{pad}while ( {fmt(n.cond, namer) if n.cond is not None else '1'} )", n.addr))
                self._block(n.body, ind, lines, namer)
            elif isinstance(n, DoWhileNode):
                lines.append((f"{pad}do", 0))
                self._block(n.body, ind, lines, namer)
                lines.append((f"{pad}while ( {fmt(n.cond, namer)} );", n.addr))
            elif isinstance(n, SwitchNode):
                lines.append((f"{pad}switch ( {fmt(n.index, namer)} )", n.addr))
                lines.append((f"{pad}{{", 0))
                for vals, body in n.cases:
                    for v in vals[:-1]:
                        lines.append((f"{pad}  case {v}:", 0))
                    lines.append((f"{pad}  case {vals[-1]}:", 0))
                    self._render_nodes(body, ind + 2, lines, namer)
                if n.default is not None:
                    lines.append((f"{pad}  default:", 0))
                    self._render_nodes(n.default, ind + 2, lines, namer)
                lines.append((f"{pad}}}", 0))
            elif isinstance(n, BreakNode):
                lines.append((pad + "break;", 0))
            elif isinstance(n, ContinueNode):
                lines.append((pad + "continue;", 0))
            elif isinstance(n, GotoNode):
                lines.append((f"{pad}goto LABEL_{n.bid:X};", 0))

    def _block(self, nodes, ind, lines, namer):
        pad = "  " * ind
        core = [x for x in nodes if not isinstance(x, LabelNode) or x.bid in self.goto_targets]
        lines.append((pad + "{", 0))
        self._render_nodes(nodes, ind + 1, lines, namer)
        lines.append((pad + "}", 0))

    def _cmt(self, addr: int) -> str:
        c = self.db.comments.get(addr)
        return f"  // {c}" if c else ""
