"""Decompiler driver: lift -> variable recovery -> liveness/DCE -> webs -> inlining -> structuring -> C."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ..arch import CALL, CJMP, HALT, INDCALL, INDJMP, JMP, NORMAL, RET
from ..db import Database, Function
from ..types import Func as FuncT, Prim, Ptr, Named, TypeError_
from . import ir
from .ir import (Assign, AsmStmt, Bin, CallE, Cast, Comment, Const, CJump, Expr, ExprStmt, Goto, Intr, Ite, Mem, Reg,
                 Return, Stmt, SwitchJ, Un, Var, fmt, mask, simplify, sign, walk)
from .x86lift import (ARGREGS_MS, ARGREGS_SYSV, LState, X86Lifter)


class DecompileError(Exception):
    pass


@dataclass
class Pseudocode:
    function: int
    name: str
    lines: List[Tuple[str, int]] = field(default_factory=list)      # (text, address or 0)
    warnings: List[str] = field(default_factory=list)
    calls: List[dict] = field(default_factory=list)       # {addr, name, args:[Expr], stmt_addr}
    stack_buffers: Dict[str, int] = field(default_factory=dict)   # stack object name -> size to next object / frame top

    @property
    def text(self) -> str:
        return "\n".join(t for t, _ in self.lines)

    def line_for(self, addr: int) -> Optional[int]:
        best = None
        for i, (_, a) in enumerate(self.lines):
            if a and a <= addr:
                best = i
        return best

    def addr_for_line(self, i: int) -> int:
        return self.lines[i][1] if 0 <= i < len(self.lines) else 0


# ===========================================================================================================
class Context:
    """Per-database caches shared across functions (callee arity/prototype lookup)."""

    def __init__(self, db: Database):
        self.db = db
        self._arity: Dict[int, int] = {}
        self._ci: Dict[Tuple, dict] = {}

    # prototype / calling convention knowledge for a call target
    def callee_info(self, lifter: X86Lifter, target: Optional[int], slot: Optional[int]) -> dict:
        db = self.db
        key = (target, slot)
        name = ""
        proto: Optional[FuncT] = None
        cc = ""
        noret = False
        imp = None
        if slot is not None:
            imp = db.import_at(slot)
            if imp is not None:
                name = imp.display
            else:
                name = db.names.get(slot, "").replace("__imp_", "")
        elif target is not None:
            imp = db.import_at(target)
            f = db.functions.get(target)
            name = db.names.get(target) or (f.name if f else "") or ""
            if imp is not None:
                name = imp.display
        addr_for_proto = target
        if target is not None and target in db.func_protos:
            try:
                proto = db.types.parse_prototype(db.func_protos[target])
            except TypeError_:
                proto = None
        if proto is None and name:
            proto = db.types.lookup_proto(name)
        if target is not None and target in db.noreturn:
            noret = True
        from ..analysis.auto import NORETURN_NAMES
        if name and (name in NORETURN_NAMES or name.lstrip("_") in NORETURN_NAMES):
            noret = True
        bits = lifter.bits
        callee_f = db.functions.get(target) if target is not None else None
        if callee_f is not None and callee_f.thunk_target is not None and callee_f.thunk_target in db.import_slots():
            imp = db.import_slots()[callee_f.thunk_target]
            name = imp.display
            if proto is None:
                proto = db.types.lookup_proto(name)
        # calling convention
        if proto is not None and proto.cc:
            cc = proto.cc
        elif callee_f is not None:
            cc = callee_f.callconv
        if not cc:
            if lifter.__class__.__name__ == "A64Lifter":
                cc = "aapcs64"
            else:
                cc = "ms_x64" if lifter.ms64 else ("sysv_x64" if bits == 64 else "cdecl")
        ret_float = False
        float_args: Dict[int, bool] = {}
        void = False
        ret_size = lifter.w
        nargs = 0
        if proto is not None:
            tm = db.types
            nargs = len(proto.params)
            try:
                rt = tm.resolve(proto.ret)
                if isinstance(rt, Prim) and rt.kind == "void":
                    void = True
                elif isinstance(rt, Prim) and rt.kind == "float":
                    ret_float = True
                    ret_size = rt.size
                else:
                    ret_size = max(1, min(tm.sizeof(proto.ret), 8))
            except TypeError_:
                pass
            for i, (pn, pt) in enumerate(proto.params):
                try:
                    r = tm.resolve(pt)
                    if isinstance(r, Prim) and r.kind == "float":
                        float_args[i] = True
                except TypeError_:
                    pass
            if proto.varargs:
                nargs += self._vararg_count(lifter, proto)
        else:
            nargs = self.arity(lifter, target)
        if proto is not None and cc in ("stdcall", "cdecl", "fastcall", "thiscall") and bits == 32:
            pass
        info = {"name": name, "proto": proto, "cc": cc, "nargs": nargs, "ret_size": ret_size, "void": void,
                "ret_float": ret_float, "float_args": float_args, "noret": noret}
        return info

    def _vararg_count(self, lifter, proto) -> int:
        """Estimate extra arguments of a printf-style call from the constant format string at the call site."""
        fixed = len(proto.params)
        fmt_idx = None
        for i, (pn, pt) in enumerate(proto.params):
            if "format" in pn.lower() or pn in ("fmt", "lpFmt"):
                fmt_idx = i
        extra = getattr(lifter, "_vararg_hint", None)
        return extra if extra is not None else 0

    def arity(self, lifter: X86Lifter, target: Optional[int]) -> int:
        """Argument count for an unknown callee: stack bytes popped (x86) or arg registers read before written."""
        if target is None:
            return getattr(lifter, "_adhoc_nargs", 0)
        if target in self._arity:
            return self._arity[target]
        db = self.db
        f = db.functions.get(target)
        n = 0
        if f is not None and lifter.__class__.__name__ == "A64Lifter":
            n = self._reg_arity_a64(f)
        elif f is not None:
            if lifter.bits == 32:
                if f.args_size:
                    n = f.args_size // 4
                else:
                    n = self._stack_arity32(f)
            else:
                n = self._reg_arity64(f, lifter)
        self._arity[target] = n
        return n

    def _reg_arity_a64(self, f: Function) -> int:
        """x0..x7 read before being written on some path from the entry."""
        db = self.db
        max_idx = -1
        seen = set()
        work = [f.start]
        budget = 400
        while work and budget > 0:
            ba = work.pop()
            if ba in seen or ba not in f.blocks:
                continue
            seen.add(ba)
            written = set()
            for a in f.blocks[ba].insns:
                budget -= 1
                ins = db.insn(a)
                if ins is None:
                    continue
                try:
                    rr, rw = ins.cs_insn.regs_access()
                except Exception:
                    rr, rw = [], []
                for r in rr:
                    nm = ins.cs_insn.reg_name(r)
                    if nm[0] in "xw" and nm[1:].isdigit() and int(nm[1:]) < 8 and int(nm[1:]) not in written:
                        max_idx = max(max_idx, int(nm[1:]))
                for r in rw:
                    nm = ins.cs_insn.reg_name(r)
                    if nm[0] in "xw" and nm[1:].isdigit():
                        written.add(int(nm[1:]))
            for t, _ in f.blocks[ba].succs:
                work.append(t)
        return max_idx + 1

    def _stack_arity32(self, f: Function) -> int:
        db = self.db
        mx = 0
        for b in f.blocks.values():
            for a in b.insns:
                ins = db.insn(a)
                if ins is None:
                    continue
                m = re.search(r"\[(?:ebp|esp)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]", ins.op_str)
                if m and "ebp" in ins.op_str and "frame_pointer" in f.flags:
                    off = int(m.group(1), 0)
                    if off >= 8:
                        mx = max(mx, (off - 8) // 4 + 1)
        return mx

    def _reg_arity64(self, f: Function, lifter: X86Lifter) -> int:
        db = self.db
        argregs = lifter.argregs
        fam = {"rcx": "cx", "rdx": "dx", "rsi": "si", "rdi": "di", "r8": "r8", "r9": "r9"}
        written: Set[str] = set()
        max_idx = -1
        seen = set()
        work = [f.start]
        budget = 400
        import capstone as cs
        while work and budget > 0:
            ba = work.pop()
            if ba in seen or ba not in f.blocks:
                continue
            seen.add(ba)
            wr_local = set(written)
            for a in f.blocks[ba].insns:
                budget -= 1
                ins = db.insn(a)
                if ins is None:
                    continue
                try:
                    rr, rw = ins.cs_insn.regs_access()
                except Exception:
                    rr, rw = [], []
                for r in rr:
                    nm = ins.cs_insn.reg_name(r)
                    for i, ar in enumerate(argregs):
                        if _same_fam(nm, ar) and ar not in wr_local:
                            max_idx = max(max_idx, i)
                for r in rw:
                    nm = ins.cs_insn.reg_name(r)
                    for ar in argregs:
                        if _same_fam(nm, ar) and not (len(nm) <= 2 and nm.endswith(("l", "h", "x")) and False):
                            wr_local.add(ar)
            for t, _ in f.blocks[ba].succs:
                work.append(t)
        return max_idx + 1


def _same_fam(reg: str, fam: str) -> bool:
    names = {"rcx": ("rcx", "ecx", "cx", "cl", "ch"), "rdx": ("rdx", "edx", "dx", "dl", "dh"),
             "rsi": ("rsi", "esi", "si", "sil"), "rdi": ("rdi", "edi", "di", "dil"),
             "r8": ("r8", "r8d", "r8w", "r8b"), "r9": ("r9", "r9d", "r9w", "r9b")}
    return reg in names.get(fam, (fam,))


# ===========================================================================================================
@dataclass
class BB:
    start: int
    stmts: List[Stmt] = field(default_factory=list)
    succs: List[int] = field(default_factory=list)
    preds: List[int] = field(default_factory=list)

    @property
    def term(self) -> Optional[Stmt]:
        return self.stmts[-1] if self.stmts and isinstance(self.stmts[-1], (Goto, CJump, Return, SwitchJ)) else None


class Decompiler:
    def __init__(self, db: Database, ctx: Optional[Context] = None):
        self.db = db
        self.ctx = ctx or Context(db)
        self.warnings: List[str] = []

    # ------------------------------------------------------------------ top level
    def run(self, addr: int) -> Pseudocode:
        db = self.db
        f = db.functions.get(addr) or db.function_at(addr)
        if f is None:
            raise DecompileError(f"no function at {addr:#x}")
        arch_name = db.image.arch.name
        if arch_name not in ("x86", "arm64"):
            from .generic import decompile_generic
            return decompile_generic(db, f, self.ctx)
        self.f = f
        if arch_name == "arm64":
            from .a64lift import A64Lifter
            self.lifter = A64Lifter(db, f, self.ctx)
        else:
            self.lifter = X86Lifter(db, f, self.ctx)
        self.w = self.lifter.w
        self._detect_frame_pointer()
        self._lift()
        self._recover_stack_vars()
        self._simplify_all()
        self._dce()
        self._webs()
        self._narrow()
        self._inline()
        self._dce_vars()
        self._tidy_calls()
        from .structure import Structurer
        st = Structurer(self)
        return st.render()

    # ------------------------------------------------------------------ frame pointer
    def _detect_frame_pointer(self):
        if hasattr(self.lifter, "detect_frame_pointer"):
            return self.lifter.detect_frame_pointer(self)
        db, lf, f = self.db, self.lifter, self.f
        bp = lf.bp_fam
        entry = f.blocks.get(f.start)
        spd = 0
        found = None
        cnt = 0
        lea_disp = None
        for b in f.blocks.values():
            for a in b.insns:
                ins = db.insn(a)
                if ins is None:
                    continue
                ci = ins.cs_insn
                if ins.mnemonic == "mov" and len(ci.operands) == 2 and ci.operands[0].type == 1 and ci.operands[1].type == 1:
                    d, s = ci.reg_name(ci.operands[0].reg), ci.reg_name(ci.operands[1].reg)
                    if d == lf.bp and s == lf.sp:
                        cnt += 1
                elif ins.mnemonic == "lea" and len(ci.operands) == 2 and ci.operands[0].type == 1 and \
                        ci.reg_name(ci.operands[0].reg) == lf.bp and ci.operands[1].type == 3 and \
                        ci.reg_name(ci.operands[1].mem.base) == lf.sp and not ci.operands[1].mem.index:
                    cnt += 1
                    lea_disp = ci.operands[1].mem.disp
        if cnt != 1 or entry is None:
            return
        # compute spd at the mov in the entry block
        for a in entry.insns:
            ins = db.insn(a)
            ci = ins.cs_insn
            if ins.mnemonic == "mov" and len(ci.operands) == 2 and ci.operands[0].type == 1 and ci.operands[1].type == 1 \
                    and ci.reg_name(ci.operands[0].reg) == lf.bp and ci.reg_name(ci.operands[1].reg) == lf.sp:
                found = spd
                break
            if lea_disp is not None and ins.mnemonic == "lea" and len(ci.operands) == 2 and ci.operands[0].type == 1 and \
                    ci.reg_name(ci.operands[0].reg) == lf.bp and ci.operands[1].type == 3:
                found = spd + lea_disp
                break
            if ins.stack_delta is not None and ins.flow != RET:
                spd += ins.stack_delta
        if found is None:
            return
        # make sure rbp isn't used as a general register elsewhere: only push/pop/leave/mov-from-rsp may write it
        for b in f.blocks.values():
            for a in b.insns:
                ins = db.insn(a)
                if ins is None:
                    continue
                ci = ins.cs_insn
                if ins.mnemonic in ("push", "pop", "leave", "call", "ret", "jmp", "cmp", "test"):
                    continue
                if ins.mnemonic == "lea" and lea_disp is not None and ci.operands[0].type == 1 and \
                        ci.reg_name(ci.operands[0].reg) == lf.bp:
                    continue
                try:
                    rr, rw = ci.regs_access()
                except Exception:
                    continue
                for r in rw:
                    if ci.reg_name(r) in (lf.bp, {"rbp": "ebp", "ebp": "bp"}.get(lf.bp, "")) and not (
                            ins.mnemonic == "mov" and ci.reg_name(ci.operands[1].reg) == lf.sp if ci.operands and len(ci.operands) == 2 and ci.operands[1].type == 1 else False):
                        return
        lf.fp_off = found

    # ------------------------------------------------------------------ lifting
    def _lift(self):
        db, f, lf = self.db, self.f, self.lifter
        self.bbs: Dict[int, BB] = {}
        order = sorted(f.blocks)
        entry_spd: Dict[int, int] = {f.start: 0}
        entry_cc: Dict[int, object] = {f.start: None}
        entry_known: Dict[int, dict] = {f.start: {}}
        work = [f.start]
        done = set()
        npreds: Dict[int, int] = defaultdict(int)
        for b in f.blocks.values():
            for t, _ in b.succs:
                npreds[t] += 1
        while work:
            ba = work.pop(0)
            if ba in done:
                continue
            done.add(ba)
            blk = f.blocks[ba]
            st = LState(entry_spd[ba], entry_cc.get(ba))
            st.known = dict(entry_known.get(ba, {}))
            bb = BB(ba)
            out = bb.stmts
            insns = [db.insn(a) for a in blk.insns]
            for i, ins in enumerate(insns):
                last = i == len(insns) - 1
                nxt = insns[i + 1] if not last else None
                self._peek_call_args(ins, nxt, insns, i)
                if ins.flow in (CALL,) or ins.flow == INDCALL:
                    lf.lift_insn(ins, st, out, nxt)
                elif ins.flow in (JMP, CJMP, RET, INDJMP):
                    pass
                else:
                    lf.lift_insn(ins, st, out, nxt)
            last = insns[-1]
            self._terminate(bb, blk, last, st)
            bb.succs = [t for t in bb.succs if t in f.blocks]
            self.bbs[ba] = bb
            for t in bb.succs:
                if t not in entry_spd:
                    entry_spd[t] = st.spd
                    entry_cc[t] = st.cc if npreds[t] == 1 else None
                    entry_known[t] = dict(st.known) if npreds[t] == 1 else {}
                if t not in done:
                    work.append(t)
        for ba, bb in self.bbs.items():
            for t in bb.succs:
                if t in self.bbs:
                    self.bbs[t].preds.append(ba)

    def _peek_call_args(self, ins, nxt, insns, i):
        """Hints for call lifting: callee-cleaned arg count (`add esp, N` after the call) and printf-style format counts."""
        lf = self.lifter
        if hasattr(lf, "peek_call_args"):
            return lf.peek_call_args(self, ins, nxt, insns, i)
        lf._adhoc_nargs = 0
        lf._vararg_hint = None
        if ins.mnemonic == "syscall":
            num = None
            written = set()
            for p in reversed(insns[:i]):
                ci = p.cs_insn
                if p.mnemonic == "mov" and len(ci.operands) == 2 and ci.operands[0].type == 1 and \
                        ci.reg_name(ci.operands[0].reg) in ("eax", "rax") and ci.operands[1].type == 2 and num is None:
                    num = ci.operands[1].imm
                try:
                    rr, rw = ci.regs_access()
                except Exception:
                    continue
                for r in rw:
                    written.add(ci.reg_name(r))
            from ..syscalls import lookup
            k = lookup(num, 64) if num is not None else None
            if k:
                lf._syscall = (num, k[1])
            else:
                n = 0
                for nm in (("rdi", "edi"), ("rsi", "esi"), ("rdx", "edx"), ("r10", "r10d"), ("r8", "r8d"), ("r9", "r9d")):
                    if any(x in written for x in nm):
                        n += 1
                    else:
                        break
                lf._syscall = (num, n)
            return
        if ins.flow not in (CALL, INDCALL):
            return
        if lf.bits == 32 and nxt is not None and nxt.mnemonic == "add" and nxt.op_str.replace(" ", "").startswith(f"{lf.sp},"):
            try:
                lf._adhoc_nargs = int(nxt.op_str.split(",")[1].strip(), 0) // 4
            except ValueError:
                pass
        elif lf.bits == 64:
            # count contiguous argument registers written earlier in this block
            argregs = lf.argregs
            seenregs: Set[str] = set()
            for p in reversed(insns[:i]):
                if p.flow in (CALL, INDCALL):
                    break
                try:
                    rr, rw = p.cs_insn.regs_access()
                except Exception:
                    continue
                for r in rw:
                    nm = p.cs_insn.reg_name(r)
                    for k, ar in enumerate(argregs):
                        if _same_fam(nm, ar):
                            seenregs.add(ar)
            n = 0
            while n < len(argregs) and argregs[n] in seenregs:
                n += 1
            lf._adhoc_nargs = n
        else:
            # 32-bit unknown cdecl: count pushes since previous call
            n = 0
            for p in reversed(insns[:i]):
                if p.flow in (CALL, INDCALL):
                    break
                if p.mnemonic == "push":
                    n += 1
            lf._adhoc_nargs = n
        # printf-family: count % conversions in the nearest constant string argument
        info_name = ""
        if ins.targets:
            info_name = self.db.names.get(ins.targets[0], "")
        elif ins.ind_slot is not None:
            imp = self.db.import_at(ins.ind_slot)
            info_name = imp.display if imp else ""
        if re.match(r"^_*(?:v?[sfdn]*printf|wsprintf[AW]?|syslog|scanf|sscanf|fscanf|snprintf)", info_name or ""):
            fmt_str = None
            for p in reversed(insns[:i + 1]):
                for kind, a in p.refs:
                    s = self.db.strings.get(a)
                    if s is not None:
                        fmt_str = s.text
                        break
                if fmt_str is not None:
                    break
            if fmt_str is not None:
                lf._vararg_hint = len(re.findall(r"%(?!%)[-+ #0]*[\d*]*(?:\.[\d*]+)?(?:hh|h|ll|l|z|j|t|L)?[diouxXeEfgGcsSpn]", fmt_str))

    def _terminate(self, bb: BB, blk, last, st: LState):
        if hasattr(self.lifter, "terminate"):
            return self.lifter.terminate(self, bb, blk, last, st)
        db, f, lf = self.db, self.f, self.lifter
        out = bb.stmts
        fl = last.flow
        addr = last.addr
        nxt = blk.end
        if fl == RET:
            out.append(Return(Reg(lf.rax, lf.w), addr))
        elif fl == JMP:
            t = last.targets[0]
            if t in self.f.blocks:
                out.append(Goto(t, addr))
                bb.succs = [t]
            else:
                # tail call
                info = self.ctx.callee_info(lf, t, None)
                call = CallE(Const(t, lf.w), [], info["name"], info["ret_size"], info["proto"], t, info["cc"])
                st2 = LState(st.spd, None)
                tmp: List[Stmt] = []
                fake = last
                # reuse lift_call with a synthetic call instruction
                class _C: pass
                c = _C()
                lf.lift_call(_FakeCall(last, t), last.cs_insn, st2, tmp)
                out.extend(tmp)
                out.append(Return(Reg(lf.rax, lf.w), addr))
        elif fl == CJMP:
            code = _jcc_code(last.mnemonic)
            cond = lf.cond(code, st) if code else Intr("__loop_cond", [])
            t = last.targets[0]
            if t not in self.f.blocks:
                t = nxt
            out.append(CJump(cond, t, nxt, addr))
            bb.succs = [t, nxt] if t != nxt else [t]
        elif fl == INDJMP:
            sw = db.switches.get(addr)
            if sw:
                idx = _switch_index(lf, last, st, sw)
                cases = [(k, t) for k, t in enumerate(sw["cases"])]
                out.append(SwitchJ(idx, cases, addr))
                bb.succs = sorted(set(sw["targets"]))
            else:
                tgt = lf.rd(last.cs_insn, last.cs_insn.operands[0], st, lf.w) if last.cs_insn.operands else Intr("?", [])
                out.append(ExprStmt(Intr("JUMPOUT", [tgt]), addr))
                out.append(Return(None, addr))
        elif fl == HALT:
            out.append(Return(None, addr))
        else:
            # falls through (or ends in noreturn call)
            tail = None
            if fl == CALL or fl == INDCALL:
                pass
            succ = [t for t, _ in blk.succs]
            if succ:
                out.append(Goto(succ[0], addr))
                bb.succs = [succ[0]]
            elif not ends_in_noreturn(out):
                out.append(Return(None, addr))        # a block ending in a no-return call needs no terminator
            return
        if fl == CJMP:
            pass

    # ------------------------------------------------------------------ stack variable recovery
    def _recover_stack_vars(self):
        lf = self.lifter
        sp0 = lf.sp0
        self.stack_vars: Dict[Tuple[int, int], Var] = {}
        self.addr_taken: Set[int] = set()
        w = self.w

        def stack_off(e: Expr) -> Optional[int]:
            e = simplify(e)
            if e == sp0:
                return 0
            if isinstance(e, Bin) and e.op == "+" and e.a == sp0 and isinstance(e.b, Const):
                return sign(e.b.v, e.b.size)
            return None

        def mkvar(off: int, size: int) -> Var:
            key = (off, size)
            v = self.stack_vars.get(key)
            if v is None:
                if off < 0:
                    nm = f"var_{-off:X}"
                    kind = "stack"
                elif lf.bits == 32 and off >= 4 and off % 4 == 0 and off < 0x1000:
                    nm = f"a{(off - 4) // 4 + 1}"
                    kind = "param"
                elif off == 0:
                    nm = "retaddr"
                    kind = "stack"
                else:
                    nm = f"arg_{off:X}"
                    kind = "stack"
                v = Var(nm, size, kind, off=off)
                self.stack_vars[key] = v
            return v

        def conv(e: Expr) -> Expr:
            if isinstance(e, Mem):
                off = stack_off(e.addr)
                if off is not None and not e.seg:
                    return mkvar(off, e.size)
                return e
            if isinstance(e, Bin) or (isinstance(e, Reg) and e == sp0):
                off = stack_off(e)
                if off is not None:
                    # address of stack object
                    self.addr_taken.add(off)
                    base = mkvar(off, 0)
                    return Un("&", base, w)
            return e

        def fix(e: Expr) -> Expr:
            # Mem must be converted before its address sub-expression is turned into '&var'
            return _map_mem_first(e, conv, stack_off, mkvar, self)

        for bb in self.bbs.values():
            for s in bb.stmts:
                _apply_top(s, fix)
        # unify overlapping slots: slots whose offsets overlap with a different size become memory again
        by_off: Dict[int, List[Var]] = defaultdict(list)
        for (off, size), v in self.stack_vars.items():
            by_off[off].append(v)
        self.stack_slots = by_off

    # ------------------------------------------------------------------ simplification passes
    def _simplify_all(self):
        for bb in self.bbs.values():
            for s in bb.stmts:
                _map_stmt(s, simplify)

    # ------------------------------------------------------------------ liveness / DCE on registers + stack vars
    def _is_var(self, e: Expr) -> bool:
        return isinstance(e, (Reg, Var)) and not (isinstance(e, Reg) and e.name == "sp0")

    def _vkey(self, e: Expr):
        if isinstance(e, Reg):
            return ("r", e.name)
        if isinstance(e, Var):
            return ("v", e.name) if not (e.kind in ("stack", "param") and e.off in self.addr_taken) else None
        return None

    def _stmt_uses(self, s: Stmt) -> List[Expr]:
        if isinstance(s, Assign):
            u = list(walk(s.src))
            if isinstance(s.dst, Mem):
                u += list(walk(s.dst.addr))
            return u
        if isinstance(s, ExprStmt):
            return list(walk(s.e))
        if isinstance(s, CJump):
            return list(walk(s.cond))
        if isinstance(s, Return):
            return list(walk(s.e)) if s.e is not None else []
        if isinstance(s, SwitchJ):
            return list(walk(s.index))
        return []

    def _stmt_def(self, s: Stmt):
        if isinstance(s, Assign) and isinstance(s.dst, (Reg, Var)):
            return s.dst
        return None

    def _liveness(self):
        live_in: Dict[int, Set] = {b: set() for b in self.bbs}
        live_out: Dict[int, Set] = {b: set() for b in self.bbs}
        changed = True
        order = sorted(self.bbs, reverse=True)
        while changed:
            changed = False
            for ba in order:
                bb = self.bbs[ba]
                out = set()
                for t in bb.succs:
                    if t in live_in:
                        out |= live_in[t]
                cur = set(out)
                for s in reversed(bb.stmts):
                    d = self._stmt_def(s)
                    if d is not None:
                        k = self._vkey(d)
                        if k is not None:
                            cur.discard(k)
                    for u in self._stmt_uses(s):
                        k = self._vkey(u) if isinstance(u, (Reg, Var)) else None
                        if k is not None:
                            cur.add(k)
                if out != live_out[ba] or cur != live_in[ba]:
                    live_out[ba], live_in[ba] = out, cur
                    changed = True
        return live_in, live_out

    def _returns_value(self) -> bool:
        lf = self.lifter
        for bb in self.bbs.values():
            for s in bb.stmts:
                if isinstance(s, Assign) and isinstance(s.dst, Reg) and s.dst.name == lf.rax and \
                        not (isinstance(s.src, Intr) and s.src.name == "__undefined"):
                    return True
        return False

    def _ret_size(self) -> int:
        lf = self.lifter
        sizes = []
        for bb in self.bbs.values():
            for s in bb.stmts:
                if isinstance(s, Assign) and isinstance(s.dst, Reg) and s.dst.name == lf.rax and \
                        not (isinstance(s.src, Intr) and s.src.name == "__undefined"):
                    sizes.append(_eff_size(s.src))
        pos = [x for x in sizes if x and x > 0]
        if pos:
            return max(pos)
        return lf.w if any(x < 0 for x in sizes) else 4

    def _dce(self):
        # first pass: keep Return(rax) so definitions feeding a return survive
        self.ret_val = True
        self.ret_size = 0
        self._dce_loop()
        ret_val = self._returns_value()
        self.ret_val = ret_val
        self.ret_size = self._ret_size() if ret_val else 0
        for bb in self.bbs.values():
            for s in bb.stmts:
                if isinstance(s, Return):
                    if not ret_val:
                        s.e = None
                    elif self.ret_size and self.ret_size < self.lifter.w:
                        s.e = Cast("tr", Reg(self.lifter.rax, self.lifter.w), self.ret_size)
        if not ret_val:
            self._dce_loop()
        self._live_in_entry = self._liveness()[0].get(self.f.start, set())

    def _dce_loop(self):
        for _ in range(12):
            live_in, live_out = self._liveness()
            removed = False
            for ba, bb in self.bbs.items():
                cur = set(live_out[ba])
                new = []
                for s in reversed(bb.stmts):
                    d = self._stmt_def(s)
                    keep = True
                    if d is not None:
                        k = self._vkey(d)
                        if k is not None and k not in cur:
                            if isinstance(s.src, CallE):
                                # keep the call, drop the dead result
                                new.append(ExprStmt(s.src, s.addr))
                                removed = True
                                for u in self._stmt_uses(s):
                                    uk = self._vkey(u) if isinstance(u, (Reg, Var)) else None
                                    if uk is not None:
                                        cur.add(uk)
                                continue
                            keep = False
                        elif k is not None:
                            cur.discard(k)
                    if not keep:
                        removed = True
                        continue
                    for u in self._stmt_uses(s):
                        uk = self._vkey(u) if isinstance(u, (Reg, Var)) else None
                        if uk is not None:
                            cur.add(uk)
                    new.append(s)
                new.reverse()
                bb.stmts = new
            if not removed:
                break

    # ------------------------------------------------------------------ webs (reaching-definition partitioning)
    def _webs(self):
        lf = self.lifter
        # collect definition sites per variable key
        defs: Dict[object, List[Tuple[int, int]]] = defaultdict(list)        # key -> [(block, idx)]
        for ba, bb in self.bbs.items():
            for i, s in enumerate(bb.stmts):
                d = self._stmt_def(s)
                if d is not None:
                    k = self._vkey(d)
                    if k is not None:
                        defs[k].append((ba, i))
        # reaching definitions via iterative dataflow; def ids are (block, idx) or ('entry', key)
        gen: Dict[int, Dict[object, Tuple]] = {}
        for ba, bb in self.bbs.items():
            g: Dict[object, Tuple] = {}
            for i, s in enumerate(bb.stmts):
                d = self._stmt_def(s)
                if d is not None:
                    k = self._vkey(d)
                    if k is not None:
                        g[k] = (ba, i)
            gen[ba] = g
        rin: Dict[int, Dict[object, Set]] = {b: defaultdict(set) for b in self.bbs}
        rout: Dict[int, Dict[object, Set]] = {b: defaultdict(set) for b in self.bbs}
        entry = self.f.start
        order = sorted(self.bbs)
        changed = True
        while changed:
            changed = False
            for ba in order:
                bb = self.bbs[ba]
                new_in: Dict[object, Set] = defaultdict(set)
                if ba == entry:
                    for k in defs:
                        new_in[k].add(("entry", k))
                for p in bb.preds:
                    if p in rout:
                        for k, s_ in rout[p].items():
                            new_in[k] |= s_
                new_out: Dict[object, Set] = defaultdict(set)
                for k, s_ in new_in.items():
                    new_out[k] = set(s_)
                for k, d in gen[ba].items():
                    new_out[k] = {d}
                if dict(new_in) != dict(rin[ba]) or dict(new_out) != dict(rout[ba]):
                    rin[ba], rout[ba] = new_in, new_out
                    changed = True
        parent: Dict = {}

        def find(x):
            while parent.setdefault(x, x) != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        use_sites: List[Tuple[int, int, object, Set]] = []
        for ba, bb in self.bbs.items():
            cur: Dict[object, Set] = {k: set(v) for k, v in rin[ba].items()}
            for i, s in enumerate(bb.stmts):
                for u in self._stmt_uses(s):
                    if isinstance(u, (Reg, Var)):
                        k = self._vkey(u)
                        if k is None:
                            continue
                        ds = cur.get(k)
                        if not ds:
                            ds = {("entry", k)}
                        ds = list(ds)
                        for d in ds[1:]:
                            union(ds[0], d)
                        find(ds[0])
                d = self._stmt_def(s)
                if d is not None:
                    k = self._vkey(d)
                    if k is not None:
                        cur[k] = {(ba, i)}
                        find((ba, i))
        # create a Var per web
        web_var: Dict = {}
        counter = [0]
        param_regs = lf.argregs if lf.bits == 64 else []
        self.params: List[Tuple[int, Var]] = []
        self.locals: List[Var] = []
        fam_of_param = {r: i for i, r in enumerate(param_regs)}

        def webvar(root, k, size_hint):
            v = web_var.get(root)
            if v is None:
                kind, name = k
                if root[0] == "entry" if isinstance(root, tuple) and root and root[0] == "entry" else False:
                    pass
                is_entry = any(isinstance(m, tuple) and m and m[0] == "entry" for m in members.get(root, ()))
                if kind == "r" and is_entry and name in fam_of_param:
                    idx = fam_of_param[name]
                    v = Var(f"a{idx + 1}", size_hint, "param", off=None)
                    v.ty = ""
                    self.params.append((idx, v))
                elif kind == "v":
                    v = Var(name, size_hint, "stack")
                else:
                    counter[0] += 1
                    v = Var(f"v{counter[0]}", size_hint, "local")
                    self.locals.append(v)
                web_var[root] = v
            return v

        members: Dict = defaultdict(list)
        for x in list(parent):
            members[find(x)].append(x)
        # stack Var webs keep their slot identity: map every Var(stack) key to a single Var
        slot_var: Dict[Tuple, Var] = {}

        def conv(e: Expr) -> Expr:
            if isinstance(e, (Reg, Var)):
                k = self._vkey(e)
                if k is None:
                    return e
                return e
            return e

        # rewrite statements
        def rewrite_expr(e: Expr, ds_lookup) -> Expr:
            def f_(x):
                if isinstance(x, Reg) and x.name != "sp0":
                    k = ("r", x.name)
                    root = ds_lookup(k)
                    return Cast("tr", webvar(root, k, self.w), x.size) if x.size < self.w and False else webvar(root, k, x.size if False else self.w) if root is not None else x
                return x
            return e.map(f_)

        # per-statement reaching defs for rewriting
        for ba, bb in self.bbs.items():
            cur: Dict[object, Set] = {k: set(v) for k, v in rin[ba].items()}
            new_stmts = []
            for i, s in enumerate(bb.stmts):
                def lookup(k, cur=cur):
                    ds = cur.get(k)
                    if not ds:
                        ds = {("entry", k)}
                    return find(next(iter(ds)))
                # rewrite sources / uses
                def map_use(x, lookup=lookup):
                    if isinstance(x, Reg) and x.name != "sp0":
                        k = ("r", x.name)
                        root = lookup(k)
                        return webvar(root, k, x.size)
                    return x
                _map_stmt_uses(s, map_use)
                d = self._stmt_def(s)
                if d is not None:
                    k = self._vkey(d)
                    if k is not None:
                        root = find((ba, i))
                        v = webvar(root, k, d.size)
                        s.dst = v
                        cur[k] = {(ba, i)}
            # (cur updated in place)
        self.web_var = web_var
        self.params.sort(key=lambda t: t[0])
        # x64 parameters: make the prefix contiguous (rcx used but not rdx -> still need a1.. a_n)
        if self.params:
            mx = max(i for i, _ in self.params)
            have = {i for i, _ in self.params}
            for i in range(mx + 1):
                if i not in have:
                    self.params.append((i, Var(f"a{i + 1}", self.w, "param")))
            self.params.sort(key=lambda t: t[0])
        # 32-bit stack params
        if lf.bits == 32:
            ps = sorted({v.off: v for v in self.stack_vars.values() if v.kind == "param"}.items())
            for off, v in ps:
                self.params.append(((off - 4) // 4, v))
            self.params.sort(key=lambda t: t[0])
            have = {i for i, _ in self.params}
            if have:
                for i in range(max(have) + 1):
                    if i not in have:
                        self.params.append((i, Var(f"a{i + 1}", 4, "param")))
                self.params.sort(key=lambda t: t[0])

    # ------------------------------------------------------------------ width recovery
    def _narrow(self):
        """Give each recovered variable its natural width (e.g. 32-bit int) and drop redundant extensions."""
        info: Dict[str, dict] = {}
        vars_: Dict[str, Var] = {}

        def note(v: Var, kind: str, size: int):
            vars_[v.name] = v
            info.setdefault(v.name, {"defs": [], "reads": []})[kind].append(size)

        def visit(e: Expr, parent_tr: Optional[int] = None):
            if isinstance(e, Var):
                if e.kind in ("local", "param"):
                    note(e, "reads", parent_tr if parent_tr else self.w)
                return
            if isinstance(e, Cast) and e.kind == "tr" and isinstance(e.a, Var):
                visit(e.a, e.size)
                return
            for c in e.children():
                visit(c)

        for bb in self.bbs.values():
            for s in bb.stmts:
                if isinstance(s, Assign):
                    if isinstance(s.dst, Var) and s.dst.kind in ("local", "param"):
                        note(s.dst, "defs", _eff_size(s.src))
                    visit(s.src)
                    if isinstance(s.dst, Mem):
                        visit(s.dst.addr)
                else:
                    for u in self._stmt_exprs_top(s):
                        visit(u)
        for name, d in info.items():
            v = vars_[name]
            if not (d["defs"] + d["reads"]):
                continue
            d["defs"] = [x for x in d["defs"] if x >= 0] or ([self.w] if d["defs"] else [])
            if v.kind == "param" and not d["defs"]:
                new = max(d["reads"]) if d["reads"] else self.w
            else:
                new = max(max(d["defs"]) if d["defs"] else 1, max(d["reads"]) if d["reads"] else 1)
                new = min(new, self.w)
                if d["reads"] and d["defs"] and max(d["defs"]) < max(d["reads"]):
                    new = max(d["reads"])
            new = {0: 4, 3: 4, 5: 8, 6: 8, 7: 8}.get(new, new)
            v.size = new
        for bb in self.bbs.values():
            for s in bb.stmts:
                if isinstance(s, Assign) and isinstance(s.dst, Var) and s.dst.kind in ("local", "param") and s.dst.size:
                    src = s.src
                    if isinstance(src, Cast) and src.kind == "zx" and src.a.size == s.dst.size:
                        s.src = src.a
                    elif src.size and src.size > s.dst.size and not isinstance(src, Const):
                        s.src = Cast("tr", src, s.dst.size)
                _map_stmt(s, simplify)

    def _tidy_calls(self):
        def fix(e):
            if isinstance(e, CallE):
                args = []
                for a in e.args:
                    if isinstance(a, Cast) and a.kind == "zx" and a.a.size == 4:
                        a = a.a
                    args.append(a)
                return CallE(e.target, args, e.name, e.size, e.proto, e.addr, e.cc, e.noret)
            return e
        for bb in self.bbs.values():
            for s in bb.stmts:
                _map_stmt(s, fix)
                _map_stmt(s, simplify)

    def _stmt_exprs_top(self, s: Stmt):
        if isinstance(s, ExprStmt):
            return [s.e]
        if isinstance(s, CJump):
            return [s.cond]
        if isinstance(s, Return):
            return [s.e] if s.e is not None else []
        if isinstance(s, SwitchJ):
            return [s.index]
        return []

    # ------------------------------------------------------------------ inlining / copy propagation
    def _inline(self):
        self._trim_undef_args()
        for _round in range(60):
            changed = False
            defs: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
            usec: Dict[str, int] = defaultdict(int)
            for ba, bb in self.bbs.items():
                for i, s in enumerate(bb.stmts):
                    d = self._stmt_def(s)
                    if isinstance(d, Var):
                        defs[d.name].append((ba, i))
                    for u in self._stmt_uses(s):
                        if isinstance(u, Var):
                            usec[u.name] += 1
            addr_taken_names = {v.name for v in self.stack_vars.values() if v.off in self.addr_taken}
            touched: Set[str] = set()
            for name, dl in list(defs.items()):
                if len(dl) != 1 or name in addr_taken_names or name in touched:
                    continue
                ba, i = dl[0]
                bb = self.bbs[ba]
                # indices may have shifted after earlier deletions this round: relocate by identity
                if i >= len(bb.stmts) or self._stmt_def(bb.stmts[i]) is None or self._stmt_def(bb.stmts[i]).name != name:
                    idx = [k for k, st_ in enumerate(bb.stmts) if self._stmt_def(st_) is not None and
                           getattr(self._stmt_def(st_), "name", None) == name]
                    if len(idx) != 1:
                        continue
                    i = idx[0]
                s = bb.stmts[i]
                if not isinstance(s, Assign) or not isinstance(s.dst, Var):
                    continue
                src = s.src
                if isinstance(src, Intr) and src.name == "__undefined":
                    continue
                if s.dst.kind in ("param",):
                    continue
                src_names = {x.name for x in walk(src) if isinstance(x, (Var, Reg))}
                if src_names & touched:
                    continue
                n = usec.get(name, 0)
                if isinstance(src, Const) or (isinstance(src, Var) and src.kind == "param" and src.name not in defs):
                    self._replace_var(name, src)
                    del bb.stmts[i]
                    touched |= {name} | src_names
                    changed = True
                    continue
                if n == 1:
                    j, ok = self._single_use_after(bb, i, name)
                    if ok and self._safe_to_move(bb, i, j, src):
                        self._replace_in_stmt(bb.stmts[j], name, src)
                        del bb.stmts[i]
                        touched |= {name} | src_names
                        for u in self._stmt_uses(bb.stmts[j - 1]):
                            if isinstance(u, (Var, Reg)):
                                touched.add(u.name)
                        changed = True
                elif n == 0 and not has_side_effects(src):
                    del bb.stmts[i]
                    touched |= {name} | src_names
                    changed = True
            if changed:
                for bb in self.bbs.values():
                    for s in bb.stmts:
                        _map_stmt(s, simplify)
            else:
                break

    def _trim_undef_args(self):
        """Drop trailing call arguments that only carry values clobbered by an earlier call (__undefined)."""
        undef = set()
        for bb in self.bbs.values():
            for s in bb.stmts:
                if isinstance(s, Assign) and isinstance(s.dst, Var) and isinstance(s.src, Intr) and s.src.name == "__undefined":
                    undef.add(s.dst.name)

        def fix(e):
            if isinstance(e, CallE) and e.proto is None:
                args = list(e.args)
                while args and isinstance(args[-1], Var) and args[-1].name in undef:
                    args.pop()
                if len(args) != len(e.args):
                    return CallE(e.target, args, e.name, e.size, e.proto, e.addr, e.cc, e.noret)
            return e
        for bb in self.bbs.values():
            for s in bb.stmts:
                _map_stmt(s, fix)

    def _never_redefined(self, v: Var, defs) -> bool:
        return len(defs.get(v.name, [])) == 0 or all(False for _ in [])

    def _single_use_after(self, bb: BB, i: int, name: str):
        for j in range(i + 1, len(bb.stmts)):
            for u in self._stmt_uses(bb.stmts[j]):
                if isinstance(u, Var) and u.name == name:
                    return j, True
            d = self._stmt_def(bb.stmts[j])
        return -1, False

    def _safe_to_move(self, bb: BB, i: int, j: int, src: Expr) -> bool:
        used = {(x.name if isinstance(x, (Var, Reg)) else None) for x in walk(src) if isinstance(x, (Var, Reg))}
        mem = has_mem(src)
        call = isinstance(src, CallE) or ir.has_call(src)
        for k in range(i + 1, j):
            s = bb.stmts[k]
            d = self._stmt_def(s)
            if d is not None and d.name in used:
                return False
            if isinstance(s, Assign) and isinstance(s.dst, Mem) and (mem or call):
                return False
            if isinstance(s, ExprStmt) or (isinstance(s, Assign) and ir.has_call(s.src)):
                if mem or call:
                    return False
            if call and isinstance(s, (Assign, ExprStmt)) and (isinstance(s, ExprStmt) or isinstance(s.dst, Mem)):
                return False
            if call and isinstance(s, Assign) and ir.has_call(s.src):
                return False
        # the use statement itself: if it also contains a call and src is a call, evaluation order is ambiguous
        us = bb.stmts[j]
        if call:
            uses_calls = sum(1 for x in self._stmt_exprs(us) if isinstance(x, CallE))
            if uses_calls > 0:
                return False
        if isinstance(us, Assign) and isinstance(us.dst, Mem) and mem:
            pass
        return True

    def _stmt_exprs(self, s: Stmt):
        if isinstance(s, Assign):
            return list(walk(s.src)) + (list(walk(s.dst.addr)) if isinstance(s.dst, Mem) else [])
        return self._stmt_uses(s)

    def _replace_in_stmt(self, s: Stmt, name: str, repl: Expr):
        def f_(x):
            if isinstance(x, Var) and x.name == name:
                return repl
            return x
        _map_stmt_uses(s, f_)

    def _replace_var(self, name: str, repl: Expr) -> bool:
        for bb in self.bbs.values():
            for s in bb.stmts:
                self._replace_in_stmt(s, name, repl)
        return True

    def _dce_vars(self):
        for _ in range(6):
            live_in, live_out = self._liveness()
            removed = False
            for ba, bb in self.bbs.items():
                cur = set(live_out[ba])
                new = []
                for s in reversed(bb.stmts):
                    d = self._stmt_def(s)
                    if d is not None:
                        k = self._vkey(d)
                        if k is not None and k not in cur and not isinstance(d, Mem):
                            if isinstance(s.src, CallE):
                                new.append(ExprStmt(s.src, s.addr))
                                removed = True
                                for u in self._stmt_uses(s):
                                    uk = self._vkey(u) if isinstance(u, (Reg, Var)) else None
                                    if uk is not None:
                                        cur.add(uk)
                                continue
                            removed = True
                            continue
                        if k is not None:
                            cur.discard(k)
                    for u in self._stmt_uses(s):
                        uk = self._vkey(u) if isinstance(u, (Reg, Var)) else None
                        if uk is not None:
                            cur.add(uk)
                    new.append(s)
                new.reverse()
                bb.stmts = new
            if not removed:
                break


def ends_in_noreturn(stmts) -> bool:
    if not stmts:
        return False
    s = stmts[-1]
    if isinstance(s, ExprStmt) and isinstance(s.e, CallE):
        return bool(s.e.noret)
    if isinstance(s, Assign) and isinstance(s.src, CallE):
        return bool(s.src.noret)
    return False


def _eff_size(e: Expr) -> int:
    """Number of significant bytes produced by an expression (looks through zero-extension)."""
    if isinstance(e, Cast) and e.kind == "zx":
        return e.a.size
    if isinstance(e, CallE):
        return e.size if e.proto is not None else -1          # -1: unknown, register-width result
    if isinstance(e, Const):
        return 0 if e.v < (1 << 32) or sign(e.v, 8) >= -(1 << 31) and e.v >= (1 << 63) else 8
    return e.size or 8


def has_side_effects(e: Expr) -> bool:
    return any(isinstance(x, (CallE, Intr)) and not (isinstance(x, Intr) and x.name == "__undefined") for x in walk(e))


def has_mem(e: Expr) -> bool:
    return any(isinstance(x, Mem) for x in walk(e))


class _FakeCall:
    """Minimal object exposing the Insn attributes lift_call needs for synthetic tail calls."""

    def __init__(self, ins, target):
        self.addr = ins.addr
        self.targets = [target]
        self.ind_slot = None
        self.size = ins.size
        self.cs_insn = ins.cs_insn


def _jcc_code(mn: str) -> Optional[str]:
    from .x86lift import CC_JCC
    return CC_JCC.get(mn)


def _switch_index(lf: X86Lifter, last, st: LState, sw: dict) -> Expr:
    ci = last.cs_insn
    name = sw.get("index_reg")
    if name:
        try:
            return lf.rd_reg(name, st)
        except KeyError:
            pass
    ops = ci.operands
    if ops and ops[0].type == 3 and ops[0].mem.index:
        return lf.rd_reg(ci.reg_name(ops[0].mem.index), st)
    return Intr("__switch_index", [])


def _map_stmt(s: Stmt, fn):
    if isinstance(s, Assign):
        s.src = fn(s.src) if False else s.src.map(fn) if hasattr(s.src, "map") else s.src
        if isinstance(s.dst, Mem):
            s.dst = s.dst.map(fn)
    elif isinstance(s, ExprStmt):
        s.e = s.e.map(fn)
    elif isinstance(s, CJump):
        s.cond = s.cond.map(fn)
    elif isinstance(s, Return) and s.e is not None:
        s.e = s.e.map(fn)
    elif isinstance(s, SwitchJ):
        s.index = s.index.map(fn)


def _apply_top(s: Stmt, fn):
    """Apply fn to each top-level expression of a statement (fn is itself recursive)."""
    if isinstance(s, Assign):
        s.src = fn(s.src)
        s.dst = fn(s.dst) if isinstance(s.dst, Mem) else s.dst
    elif isinstance(s, ExprStmt):
        s.e = fn(s.e)
    elif isinstance(s, CJump):
        s.cond = fn(s.cond)
    elif isinstance(s, Return) and s.e is not None:
        s.e = fn(s.e)
    elif isinstance(s, SwitchJ):
        s.index = fn(s.index)


def _map_stmt_uses(s: Stmt, fn):
    _map_stmt(s, fn)


def _map_mem_first(e: Expr, conv, stack_off, mkvar, dec) -> Expr:
    """Convert stack accesses: Mem(sp0+K) -> Var(K); bare sp0+K (address-of) -> &Var(K)."""
    sp0 = dec.lifter.sp0

    def rec(x: Expr) -> Expr:
        if isinstance(x, Mem):
            off = stack_off(x.addr) if not x.seg else None
            if off is not None:
                return mkvar(off, x.size)
            return Mem(rec(x.addr), x.size, x.seg)
        if isinstance(x, Bin) or x == sp0:
            off = stack_off(x) if (isinstance(x, Bin) and x.op == "+" or x == sp0) else None
            if off is not None:
                dec.addr_taken.add(off)
                return Un("&", mkvar(off, 0), dec.w)
        if isinstance(x, Bin):
            return Bin(x.op, rec(x.a), rec(x.b), x.size)
        if isinstance(x, Un):
            return Un(x.op, rec(x.a), x.size)
        if isinstance(x, Cast):
            return Cast(x.kind, rec(x.a), x.size)
        if isinstance(x, Ite):
            return Ite(rec(x.c), rec(x.a), rec(x.b))
        if isinstance(x, CallE):
            return CallE(rec(x.target), [rec(a) for a in x.args], x.name, x.size, x.proto, x.addr, x.cc, x.noret)
        if isinstance(x, Intr):
            return Intr(x.name, [rec(a) for a in x.args], x.size)
        return x
    return rec(e)


def decompile(db: Database, addr: int) -> Pseudocode:
    ctx = getattr(db, "_decomp_ctx", None)
    if ctx is None or ctx.db is not db:
        ctx = Context(db)
        db._decomp_ctx = ctx
    return Decompiler(db, ctx).run(addr)
