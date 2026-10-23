"""x86 / x86-64 instruction lifter producing decompiler IR."""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from capstone import x86 as cx
import capstone as cs

from ..arch import CALL, CJMP, INDCALL, INDJMP, JMP, RET, Insn
from .ir import (Assign, AsmStmt, Bin, CallE, Cast, Comment, Const, CJump, Expr, ExprStmt, Goto, Intr, Ite, Mem, Reg,
                 Return, Stmt, SwitchJ, Un, mask, simplify, sign)

# ---------------------------------------------------------------------------------------------------------------
_FAM64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"] + [f"r{i}" for i in range(8, 16)]


def _build_regmap(bits: int) -> Dict[str, Tuple[str, int, int]]:
    m: Dict[str, Tuple[str, int, int]] = {}
    legacy = {"ax": ("a", 0), "bx": ("b", 0), "cx": ("c", 0), "dx": ("d", 0)}
    for letter in "abcd":
        fam = ("r" if bits == 64 else "e") + letter + "x"
        m[f"r{letter}x"] = (fam, 8, 0)
        m[f"e{letter}x"] = (fam, 4, 0)
        m[f"{letter}x"] = (fam, 2, 0)
        m[f"{letter}l"] = (fam, 1, 0)
        m[f"{letter}h"] = (fam, 1, 8)
    for base, low8 in (("si", "sil"), ("di", "dil"), ("bp", "bpl"), ("sp", "spl")):
        fam = ("r" if bits == 64 else "e") + base
        m[f"r{base}"] = (fam, 8, 0)
        m[f"e{base}"] = (fam, 4, 0)
        m[base] = (fam, 2, 0)
        m[low8] = (fam, 1, 0)
    for i in range(8, 16):
        fam = f"r{i}"
        m[fam] = (fam, 8, 0)
        m[f"r{i}d"] = (fam, 4, 0)
        m[f"r{i}w"] = (fam, 2, 0)
        m[f"r{i}b"] = (fam, 1, 0)
    m["rip"] = ("rip", 8, 0)
    m["eip"] = ("rip", 4, 0)
    for i in range(16):
        m[f"xmm{i}"] = (f"xmm{i}", 16, 0)
        m[f"ymm{i}"] = (f"xmm{i}", 16, 0)
    return m


REGMAP = {32: _build_regmap(32), 64: _build_regmap(64), 16: _build_regmap(32)}

CC_JCC = {
    "je": "e", "jz": "e", "jne": "ne", "jnz": "ne", "jl": "l", "jnge": "l", "jle": "le", "jng": "le", "jg": "g",
    "jnle": "g", "jge": "ge", "jnl": "ge", "jb": "b", "jnae": "b", "jc": "b", "jbe": "be", "jna": "be", "ja": "a",
    "jnbe": "a", "jae": "ae", "jnb": "ae", "jnc": "ae", "js": "s", "jns": "ns", "jo": "o", "jno": "no", "jp": "p",
    "jpe": "p", "jnp": "np", "jpo": "np",
}
SETCC = {("set" + k[1:]): v for k, v in CC_JCC.items()}
CMOVCC = {("cmov" + k[1:]): v for k, v in CC_JCC.items()}

ARGREGS_MS = ["rcx", "rdx", "r8", "r9"]
ARGREGS_SYSV = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
CALLER_SAVED_MS = ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"]
CALLER_SAVED_SYSV = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]
CALLER_SAVED_32 = ["eax", "ecx", "edx"]


class LState:
    """Per-block lifter state."""

    def __init__(self, spd: int = 0, cc=None):
        self.spd = spd
        self.cc = cc          # (kind, a, b, size)
        self.tmp = 0
        self.known = {}       # register family -> expression of the form sp0 + K


class X86Lifter:
    def __init__(self, db, func, ctx):
        self.db = db
        self.f = func
        self.ctx = ctx
        self.arch = db.image.arch
        self.bits = self.arch.bits
        self.w = self.bits // 8
        self.regmap = REGMAP[self.bits]
        self.sp = "rsp" if self.bits == 64 else "esp"
        self.bp = "rbp" if self.bits == 64 else "ebp"
        self.sp_fam = self.regmap[self.sp][0]
        self.bp_fam = self.regmap[self.bp][0]
        self.sp0 = Reg("sp0", self.w)
        self.fp_off: Optional[int] = None
        self.is_pe = db.image.fmt.startswith("PE")
        self.ms64 = self.bits == 64 and self.is_pe
        self.argregs = ARGREGS_MS if self.ms64 else ARGREGS_SYSV
        self.clobber = (CALLER_SAVED_MS if self.ms64 else CALLER_SAVED_SYSV) if self.bits == 64 else CALLER_SAVED_32
        self.rax = "rax" if self.bits == 64 else "eax"
        self.next_tmp = 0
        self.leave_off = {}

    # -- state helpers ------------------------------------------------------------------------------
    def fresh(self, size: int = 0) -> Reg:
        self.next_tmp += 1
        return Reg(f"t{self.next_tmp}", size or self.w)

    # -- register access -------------------------------------------------------------------------------
    def rd_reg(self, name: str, st: LState) -> Expr:
        fam, size, shift = self.regmap[name]
        full = self.w if fam not in ("rip",) else 8
        if fam.startswith("xmm"):
            return Reg(fam, 16) if size == 16 else Cast("tr", Reg(fam, 16), size)
        if fam == self.sp_fam:
            base: Expr = Bin("+", self.sp0, Const(st.spd & mask(self.w), self.w), self.w)
        elif fam in st.known and size == full and not shift:
            return st.known[fam]
        elif fam == self.bp_fam and self.fp_off is not None:
            base = Bin("+", self.sp0, Const(self.fp_off & mask(self.w), self.w), self.w)
        else:
            base = Reg(fam, full)
        if size == full and not shift:
            return base
        e = base
        if shift:
            e = Bin(">>", e, Const(shift, 1), full)
        return Cast("tr", e, size)

    def wr_reg(self, name: str, val: Expr, st: LState, out: List[Stmt], addr: int):
        fam, size, shift = self.regmap[name]
        full = self.w
        if fam.startswith("xmm"):
            out.append(Assign(Reg(fam, 16), val if val.size == 16 else Cast("zx", val, 16), addr))
            return
        if fam == self.sp_fam:
            # explicit write to the stack pointer: track constant offsets when possible
            e = simplify(val)
            off = self._sp_off(e)
            if off is not None:
                st.spd = off
            return
        if fam == self.bp_fam and self.fp_off is not None:
            return
        st.known.pop(fam, None)
        if size == full and not shift:
            v2 = simplify(val)
            if self._sp_off(v2) is not None:
                st.known[fam] = v2
            out.append(Assign(Reg(fam, full), val, addr))
        elif size == 4 and full == 8:
            out.append(Assign(Reg(fam, 8), Cast("zx", val, 8), addr))
        else:
            keep = ~(mask(size) << shift) & mask(full)
            part = Bin("<<", Cast("zx", val, full), Const(shift, 1), full) if shift else Cast("zx", val, full)
            out.append(Assign(Reg(fam, full), Bin("|", Bin("&", Reg(fam, full), Const(keep, full), full), part, full), addr))

    def _sp_off(self, e: Expr) -> Optional[int]:
        if isinstance(e, Bin) and e.op == "+" and e.a == self.sp0 and isinstance(e.b, Const):
            return sign(e.b.v, e.b.size)
        if e == self.sp0:
            return 0
        return None

    # -- operands -------------------------------------------------------------------------------------------
    def mem_addr(self, ci, op, st: LState) -> Expr:
        m = op.mem
        if m.base == cx.X86_REG_RIP:
            return Const((ci.address + ci.size + m.disp) & mask(8), self.w if self.bits == 64 else 4)
        parts: Optional[Expr] = None
        if m.base:
            parts = self.rd_reg(ci.reg_name(m.base), st)
        if m.index:
            ix = self.rd_reg(ci.reg_name(m.index), st)
            if m.scale != 1:
                ix = Bin("*", ix, Const(m.scale, ix.size), ix.size)
            parts = ix if parts is None else Bin("+", parts, ix, self.w)
        if m.disp or parts is None:
            d = Const(m.disp & mask(self.w), self.w)
            parts = d if parts is None else Bin("+", parts, d, self.w)
        # segment-relative (fs/gs) accesses are kept symbolic
        return simplify(parts)

    def rd(self, ci, op, st: LState, size: Optional[int] = None) -> Expr:
        t = op.type
        sz = size or op.size
        if t == cx.X86_OP_REG:
            return self.rd_reg(ci.reg_name(op.reg), st)
        if t == cx.X86_OP_IMM:
            return Const(op.imm & mask(sz or self.w), sz or self.w)
        if t == cx.X86_OP_MEM:
            seg = ""
            if op.mem.segment in (cx.X86_REG_FS, cx.X86_REG_GS):
                seg = ci.reg_name(op.mem.segment)
            return Mem(self.mem_addr(ci, op, st), sz, seg)
        return Intr("__unknown_operand", [])

    def wr(self, ci, op, val: Expr, st: LState, out: List[Stmt], addr: int):
        if op.type == cx.X86_OP_REG:
            self.wr_reg(ci.reg_name(op.reg), val, st, out, addr)
        elif op.type == cx.X86_OP_MEM:
            seg = ""
            if op.mem.segment in (cx.X86_REG_FS, cx.X86_REG_GS):
                seg = ci.reg_name(op.mem.segment)
            out.append(Assign(Mem(self.mem_addr(ci, op, st), op.size, seg), val, addr))

    # -- flag handling ---------------------------------------------------------------------------------------
    def set_cc(self, kind: str, a: Expr, b: Optional[Expr], size: int, st: LState, out: List[Stmt], addr: int):
        """Snapshot operands into temporaries so a later redefinition of the registers cannot corrupt the condition."""
        ta = self.fresh(size)
        out.append(Assign(ta, a, addr))
        tb = None
        if b is not None:
            tb = self.fresh(size)
            out.append(Assign(tb, b, addr))
        st.cc = (kind, ta, tb, size)

    def cond(self, code: str, st: LState) -> Expr:
        cc = st.cc
        if cc is None:
            return Intr(f"__cond_{code}", [])
        kind, a, b, size = cc
        z = Const(0, size)
        if kind == "sub":
            m = {"e": "==", "ne": "!=", "l": "<", "le": "<=", "g": ">", "ge": ">=", "b": "u<", "be": "u<=", "a": "u>",
                 "ae": "u>="}
            if code in m:
                return Bin(m[code], a, b, 1)
            if code == "s":
                return Bin("<", Bin("-", a, b, size), z, 1)
            if code == "ns":
                return Bin(">=", Bin("-", a, b, size), z, 1)
            return Intr(f"__{code.upper()}_cmp", [a, b], 1)
        if kind == "and":
            r: Expr = Bin("&", a, b, size) if b is not None and not (b == a) else a
            m = {"e": "==", "ne": "!=", "s": "<", "ns": ">=", "l": "<", "ge": ">=", "le": "<=", "g": ">"}
            if code in m:
                return Bin(m[code], r, z, 1)
            if code in ("b",):
                return Const(0, 1)
            if code in ("ae",):
                return Const(1, 1)
            if code == "a":
                return Bin("!=", r, z, 1)
            if code == "be":
                return Bin("==", r, z, 1)
            return Intr(f"__{code.upper()}_test", [r], 1)
        if kind == "res":
            m = {"e": "==", "ne": "!=", "s": "<", "ns": ">=", "l": "<", "ge": ">=", "le": "<=", "g": ">"}
            if code in m:
                return Bin(m[code], a, z, 1)
            if code == "a":
                return Bin("!=", a, z, 1)
            if code == "be":
                return Bin("==", a, z, 1)
            return Intr(f"__{code.upper()}_res", [a], 1)
        if kind == "add":
            # a = result, b = original lhs: carry <=> result < lhs (unsigned)
            m = {"e": "==", "ne": "!=", "s": "<", "ns": ">=", "l": "<", "ge": ">=", "le": "<=", "g": ">"}
            if code in m:
                return Bin(m[code], a, z, 1)
            if code == "b":
                return Bin("u<", a, b, 1)
            if code == "ae":
                return Bin("u>=", a, b, 1)
            return Intr(f"__{code.upper()}_add", [a, b], 1)
        return Intr(f"__cond_{code}", [])

    # -- calls -----------------------------------------------------------------------------------------------------
    def callee_info(self, target: Optional[int], ind_slot: Optional[int]):
        return self.ctx.callee_info(self, target, ind_slot)

    def lift_call(self, ins: Insn, ci, st: LState, out: List[Stmt]):
        a = ins.addr
        target_expr: Expr
        tgt = ins.targets[0] if ins.targets else None
        slot = ins.ind_slot
        if tgt is not None:
            target_expr = Const(tgt, self.w)
        elif ci.operands:
            op = ci.operands[0]
            target_expr = self.rd(ci, op, st, self.w)
        else:
            target_expr = Intr("__unknown_target", [])
        info = self.callee_info(tgt if tgt is not None else None, slot)
        name = info["name"]
        proto = info["proto"]
        cc = info["cc"]
        args: List[Expr] = []
        nargs = info["nargs"]
        sizes = info.get("sizes")
        ret_float = info.get("ret_float", False)
        # register arguments (x64)
        if self.bits == 64:
            nreg = len(self.argregs)
            fi = 0
            for i in range(nargs):
                ptype_float = info.get("float_args", {}).get(i, False)
                if ptype_float:
                    reg = f"xmm{i if self.ms64 else fi}"
                    fi += 1
                    args.append(self.rd_reg(reg, st) if False else Cast("tr", Reg(reg, 16), 8))
                    continue
                if i < nreg and not (self.ms64 is False and False):
                    args.append(self.rd_reg(self.argregs[i], st))
                else:
                    shadow = 0x20 if self.ms64 else 0
                    k = i - (nreg if not self.ms64 else 4)
                    off = st.spd + (shadow if self.ms64 else 0) + 8 * (i - nreg if not self.ms64 else i - 4)
                    args.append(Mem(simplify(Bin("+", self.sp0, Const(off & mask(8), 8), 8)), 8))
        else:
            regs_used = 0
            if cc == "thiscall" and nargs >= 1:
                args.append(self.rd_reg("ecx", st))
                regs_used = 1
            elif cc == "fastcall":
                for r in ("ecx", "edx")[:min(2, nargs)]:
                    args.append(self.rd_reg(r, st))
                    regs_used += 1
            for i in range(nargs - regs_used):
                off = st.spd + 4 * i
                args.append(Mem(simplify(Bin("+", self.sp0, Const(off & mask(4), 4), 4)), 4))
        call = CallE(target_expr, args, name, info["ret_size"], proto, tgt or 0, cc, info.get("noret", False))
        # callee-cleaned stack (stdcall) shrinks the stack here
        if self.bits == 32 and cc in ("stdcall", "fastcall", "thiscall") and nargs:
            popped = 4 * max(0, nargs - (1 if cc == "thiscall" else 2 if cc == "fastcall" else 0))
            st.spd += popped
        if info["void"]:
            out.append(ExprStmt(call, a))
        else:
            if ret_float:
                out.append(Assign(Reg("xmm0", 16), Cast("zx", call, 16) if call.size < 16 else call, a))
            else:
                self.wr_reg(self.rax if call.size >= 4 else {1: "al", 2: "ax"}[call.size], call, st, out, a) \
                    if self.bits == 32 or call.size >= 4 else self.wr_reg({1: "al", 2: "ax"}[call.size], call, st, out, a)
        # clobber caller-saved registers (a no-return callee never gives control back)
        if not info.get("noret"):
            for r in self.clobber:
                if r == self.rax and not info["void"]:
                    continue
                out.append(Assign(Reg(r, self.w), Intr("__undefined", [], self.w), a))
        st.cc = None

    # -- main entry ------------------------------------------------------------------------------------------------
    def lift_insn(self, ins: Insn, st: LState, out: List[Stmt], nxt: Optional[Insn] = None):
        ci = ins.cs_insn
        mn = ci.mnemonic
        ops = ci.operands
        a = ins.addr
        W = self.w

        def R(i, size=None):
            return self.rd(ci, ops[i], st, size)

        def Wr(i, val):
            self.wr(ci, ops[i], val, st, out, a)

        # prefixes: rep/repne for string ops
        if mn.startswith(("rep ", "repe ", "repne ")) or ci.prefix[0] in (cx.X86_PREFIX_REP, cx.X86_PREFIX_REPNE):
            base = mn.split()[-1]
            if base.startswith(("movs", "stos", "lods", "cmps", "scas")):
                self._string_op(ci, base, st, out, a, True)
                return
        if mn.startswith(("movs", "stos", "lods", "cmps", "scas")) and mn not in ("movsx", "movsxd", "movss", "movsd", "movsb_") \
                and not ops or mn in ("movsb", "movsw", "movsq", "stosb", "stosw", "stosd", "stosq", "lodsb", "lodsw", "lodsd",
                                    "scasb", "scasw", "scasd", "cmpsb", "cmpsw", "cmpsd") and ci.operands == []:
            self._string_op(ci, mn, st, out, a, False)
            return
        if mn in ("nop", "endbr64", "endbr32", "pause", "fnop", "int3", "ud2") or mn.startswith("prefetch") or mn in ("lfence", "mfence", "sfence"):
            if mn == "ud2":
                out.append(ExprStmt(Intr("__halt", []), a))
            return
        if mn in ("mov", "movabs"):
            Wr(0, R(1, ops[0].size))
        elif mn in ("movzx",):
            Wr(0, Cast("zx", R(1), ops[0].size))
        elif mn in ("movsx", "movsxd"):
            Wr(0, Cast("sx", R(1), ops[0].size))
        elif mn == "lea":
            Wr(0, Cast("tr", self.mem_addr(ci, ops[1], st), ops[0].size) if ops[0].size < W else self.mem_addr(ci, ops[1], st))
        elif mn in ("add", "sub", "and", "or", "xor", "adc", "sbb"):
            if ops[0].type == cx.X86_OP_REG and self.regmap[ci.reg_name(ops[0].reg)][0] == self.sp_fam and mn in ("add", "sub", "and"):
                # stack-pointer adjustment: only the tracked offset changes, no flag/value statements are needed
                sym = {"add": "+", "sub": "-", "and": "&"}[mn]
                self.wr_reg(ci.reg_name(ops[0].reg), Bin(sym, R(0), R(1, ops[0].size), self.w), st, out, a)
                st.cc = None
                return
            dst, src = R(0), R(1, ops[0].size)
            sz = ops[0].size
            if mn == "xor" and ops[0].type == cx.X86_OP_REG and ops[1].type == cx.X86_OP_REG and ops[0].reg == ops[1].reg:
                Wr(0, Const(0, sz))
                st.cc = ("res", Const(0, sz), None, sz)
                return
            if mn in ("adc", "sbb"):
                res = Intr("__" + mn.upper(), [dst, src], sz)
                Wr(0, res)
                st.cc = None
                return
            op = {"add": "+", "sub": "-", "and": "&", "or": "|", "xor": "^"}[mn]
            if mn == "sub" or mn == "add":
                keep_a = dst
                res = Bin(op, dst, src, sz)
                if ops[0].type == cx.X86_OP_MEM:
                    # read-modify-write memory: capture the value once
                    pass
                Wr(0, res)
                if mn == "sub":
                    self.set_cc("sub", dst, src, sz, st, out, a)
                else:
                    t = self.fresh(sz)
                    out.append(Assign(t, dst, a))
                    # result is recomputed from (t + src); expose as result compare + carry operands
                    st.cc = ("add", Bin("+", t, src, sz), t, sz)
                    if isinstance(src, Const) or True:
                        # snapshot result too, so later register redefinition cannot alter the condition
                        r = self.fresh(sz)
                        out.append(Assign(r, Bin("+", t, src, sz), a))
                        st.cc = ("add", r, t, sz)
            else:
                Wr(0, Bin(op, dst, src, sz))
                self.set_cc("res", R(0, sz) if ops[0].type == cx.X86_OP_REG else Bin(op, dst, src, sz), None, sz, st, out, a)
        elif mn in ("cmp",):
            self.set_cc("sub", R(0), R(1, ops[0].size), ops[0].size, st, out, a)
        elif mn == "test":
            x, y = R(0), R(1, ops[0].size)
            self.set_cc("and", x, y if not (ops[0].type == cx.X86_OP_REG and ops[1].type == cx.X86_OP_REG and ops[0].reg == ops[1].reg) else None,
                        ops[0].size, st, out, a)
        elif mn in ("inc", "dec"):
            sz = ops[0].size
            Wr(0, Bin("+" if mn == "inc" else "-", R(0), Const(1, sz), sz))
            self.set_cc("res", R(0, sz) if ops[0].type == cx.X86_OP_REG else Const(0, sz), None, sz, st, out, a)
        elif mn == "neg":
            sz = ops[0].size
            old = R(0)
            Wr(0, Un("-", old, sz))
            self.set_cc("res", R(0, sz) if ops[0].type == cx.X86_OP_REG else old, None, sz, st, out, a)
        elif mn == "not":
            Wr(0, Un("~", R(0), ops[0].size))
        elif mn in ("shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr", "shld", "shrd"):
            sz = ops[0].size
            cnt = R(1) if len(ops) > 1 else Const(1, 1)
            if mn in ("shl", "sal"):
                res = Bin("<<", R(0), cnt, sz)
            elif mn == "shr":
                res = Bin(">>", R(0), cnt, sz)
            elif mn == "sar":
                res = Bin("sar", R(0), cnt, sz)
            else:
                res = Intr(f"__{mn.upper()}{sz}__", [R(0), cnt] + ([R(2)] if len(ops) > 2 else []), sz)
            Wr(0, res)
            st.cc = None if mn.startswith(("rc", "ro")) else ("res", res, None, sz)
            if st.cc:
                self.set_cc("res", res, None, sz, st, out, a)
        elif mn == "imul":
            sz = ops[0].size
            if len(ops) == 3:
                Wr(0, Bin("*", R(1), R(2, sz), sz))
            elif len(ops) == 2:
                Wr(0, Bin("*", R(0), R(1, sz), sz))
            else:
                # one-operand form: rdx:rax = rax * src
                src = R(0)
                lo = self.rax if sz == W else {4: "eax", 2: "ax", 1: "al"}[sz]
                self.wr_reg(lo if sz != 1 else "ax", Bin("*", self.rd_reg(lo, st), src, sz), st, out, a)
                self.wr_reg({8: "rdx", 4: "edx", 2: "dx"}.get(sz, "edx"),
                            Intr("__MULH__", [self.rd_reg(lo, st), src], sz), st, out, a) if sz != 1 else None
            st.cc = None
        elif mn == "mul":
            sz = ops[0].size
            lo = {8: "rax", 4: "eax", 2: "ax", 1: "al"}[sz]
            src = R(0)
            t = self.fresh(sz)
            out.append(Assign(t, self.rd_reg(lo, st), a))
            self.wr_reg(lo if sz != 1 else "ax", Bin("*", t, src, sz), st, out, a)
            if sz != 1:
                self.wr_reg({8: "rdx", 4: "edx", 2: "dx"}[sz], Intr("__MULH_U__", [t, src], sz), st, out, a)
            st.cc = None
        elif mn in ("div", "idiv"):
            sz = ops[0].size
            lo = {8: "rax", 4: "eax", 2: "ax", 1: "al"}[sz]
            src = R(0)
            t = self.fresh(sz)
            out.append(Assign(t, self.rd_reg(lo, st), a))
            sd = mn == "idiv"
            if sz == 1:
                self.wr_reg("al", Bin("/" if sd else "u/", t, src, 1), st, out, a)
                self.wr_reg("ah", Bin("%" if sd else "u%", t, src, 1), st, out, a)
            else:
                self.wr_reg(lo, Bin("/" if sd else "u/", t, src, sz), st, out, a)
                self.wr_reg({8: "rdx", 4: "edx", 2: "dx"}[sz], Bin("%" if sd else "u%", t, src, sz), st, out, a)
            st.cc = None
        elif mn in ("cdq", "cqo", "cwd"):
            sz = {"cdq": 4, "cqo": 8, "cwd": 2}[mn]
            lo = {4: "eax", 8: "rax", 2: "ax"}[sz]
            dst = {4: "edx", 8: "rdx", 2: "dx"}[sz]
            self.wr_reg(dst, Bin("sar", self.rd_reg(lo, st), Const(sz * 8 - 1, 1), sz), st, out, a)
        elif mn in ("cdqe", "cwde", "cbw"):
            src, dst = {"cdqe": ("eax", "rax"), "cwde": ("ax", "eax"), "cbw": ("al", "ax")}[mn]
            self.wr_reg(dst, Cast("sx", self.rd_reg(src, st), self.regmap[dst][1]), st, out, a)
        elif mn == "push":
            sz = W
            val = R(0, sz)
            st.spd -= sz
            if ops[0].type == cx.X86_OP_REG and self.regmap[ci.reg_name(ops[0].reg)][0] == self.bp_fam and self.fp_off is not None:
                return
            out.append(Assign(Mem(simplify(Bin("+", self.sp0, Const(st.spd & mask(W), W), W)), sz), val, a))
        elif mn == "pop":
            sz = W
            val = Mem(simplify(Bin("+", self.sp0, Const(st.spd & mask(W), W), W)), sz)
            st.spd += sz
            Wr(0, val)
        elif mn == "leave":
            if self.fp_off is not None:
                st.spd = self.fp_off + W
            return
        elif mn in ("call",):
            self.lift_call(ins, ci, st, out)
        elif mn in ("ret", "retn"):
            pass       # handled by terminator logic
        elif mn in SETCC:
            Wr(0, Cast("zx", self.cond(SETCC[mn], st), 1))
        elif mn in CMOVCC:
            sz = ops[0].size
            Wr(0, Ite(self.cond(CMOVCC[mn], st), R(1, sz), R(0)))
        elif mn == "xchg":
            if ops[0].type == cx.X86_OP_REG and ops[1].type == cx.X86_OP_REG and ops[0].reg == ops[1].reg:
                return
            t = self.fresh(ops[0].size)
            out.append(Assign(t, R(0), a))
            Wr(0, R(1, ops[0].size))
            Wr(1, t)
        elif mn == "bswap":
            sz = ops[0].size
            Wr(0, Intr(f"__bswap{sz * 8}", [R(0)], sz))
        elif mn in ("bt", "bts", "btr", "btc"):
            t = Intr("__bt", [R(0), R(1, ops[0].size)], 1)
            st.cc = ("res", t, None, 1)
            if mn != "bt":
                Wr(0, Intr(f"__{mn}", [R(0), R(1, ops[0].size)], ops[0].size))
        elif mn in ("bsf", "bsr", "tzcnt", "lzcnt", "popcnt"):
            Wr(0, Intr(f"__{mn}", [R(1)], ops[0].size))
            self.set_cc("res", R(0), None, ops[0].size, st, out, a)
        elif mn in ("cpuid", "rdtsc", "syscall", "sysenter", "xgetbv", "rdtscp", "int", "hlt", "cli", "sti", "pushfq", "popfq",
                    "pushfd", "popfd", "lock", "in", "out", "cld", "std", "sahf", "lahf", "xlat", "xlatb", "wait", "fwait"):
            if mn == "syscall":
                num, nargs = getattr(self, "_syscall", (None, 6))
                regs = ["rdi", "rsi", "rdx", "r10", "r8", "r9"][:nargs]
                from ..syscalls import lookup
                known = lookup(num, 64) if num is not None else None
                call = Intr(known[0] if known else "__syscall", ([] if known else [self.rd_reg(self.rax, st)]) +
                            [self.rd_reg(r, st) for r in regs], 8)
                self.wr_reg(self.rax, call, st, out, a)
                for r in ("rcx", "r11"):
                    out.append(Assign(Reg(r, 8), Intr("__undefined", [], 8), a))
                return
            if mn == "int" and ops:
                out.append(ExprStmt(Intr("__interrupt", [Const(ops[0].imm, 1)]), a))
            elif mn == "hlt":
                out.append(ExprStmt(Intr("__halt", []), a))
            elif mn in ("pushfq", "pushfd"):
                st.spd -= W
            elif mn in ("popfq", "popfd"):
                st.spd += W
            elif mn == "cpuid":
                out.append(ExprStmt(Intr("__cpuid", [self.rd_reg("eax", st), self.rd_reg("ecx", st)]), a))
                for rn in ("eax", "ebx", "ecx", "edx"):
                    self.wr_reg(rn, Intr("__cpuid_out", []), st, out, a)
            elif mn in ("rdtsc", "rdtscp"):
                t = self.fresh(8)
                out.append(Assign(t, Intr("__rdtsc", [], 8), a))
                self.wr_reg("eax", Cast("tr", t, 4), st, out, a)
                self.wr_reg("edx", Cast("tr", Bin(">>", t, Const(32, 1), 8), 4), st, out, a)
            else:
                out.append(AsmStmt(ins.text, a))
        elif mn.startswith(("movss", "movsd", "movaps", "movups", "movapd", "movupd", "movdqa", "movdqu", "movq", "movd",
                            "cvt", "add", "sub", "mul", "div", "sqrt", "pxor", "xorps", "xorpd", "andps", "andpd",
                            "ucomis", "comis", "punpck", "pshuf", "paddd", "psub", "pand", "por", "pcmp", "vmov",
                            "unpck", "max", "min", "pmov", "movhlps", "movlhps", "movlp", "movhp")):
            self._sse(ci, mn, st, out, a)
        elif mn in ("jmp",):
            pass
        elif mn in CC_JCC or mn.startswith("j") or mn.startswith("loop"):
            pass
        else:
            out.append(AsmStmt(ins.text, a))

    def _string_op(self, ci, mn, st: LState, out: List[Stmt], a: int, rep: bool):
        base = mn.split()[-1]
        sz = {"b": 1, "w": 2, "d": 4, "q": 8}.get(base[-1], 1)
        if base.startswith("movs"):
            dst, src = self.rd_reg("rdi" if self.bits == 64 else "edi", st), self.rd_reg("rsi" if self.bits == 64 else "esi", st)
            n = self.rd_reg("rcx" if self.bits == 64 else "ecx", st) if rep else Const(1, W := self.w)
            out.append(ExprStmt(Intr(f"__movs{sz * 8}", [dst, src, n]), a))
            if rep:
                self.wr_reg("rcx" if self.bits == 64 else "ecx", Const(0, self.w), st, out, a)
        elif base.startswith("stos"):
            reg = {1: "al", 2: "ax", 4: "eax", 8: "rax"}[sz]
            dst = self.rd_reg("rdi" if self.bits == 64 else "edi", st)
            n = self.rd_reg("rcx" if self.bits == 64 else "ecx", st) if rep else Const(1, self.w)
            out.append(ExprStmt(Intr(f"__stos{sz * 8}", [dst, self.rd_reg(reg, st), n]), a))
            if rep:
                self.wr_reg("rcx" if self.bits == 64 else "ecx", Const(0, self.w), st, out, a)
        else:
            out.append(AsmStmt(f"{mn}", a))

    def _sse(self, ci, mn, st, out, a):
        ops = ci.operands
        if mn in ("pxor", "xorps", "xorpd", "vpxor", "vxorps") and len(ops) >= 2 and ops[0].type == ops[1].type == cx.X86_OP_REG \
                and ops[0].reg == ops[1].reg:
            self.wr(ci, ops[0], Const(0, 16), st, out, a)
            return
        if mn.startswith(("movss", "movsd", "movaps", "movups", "movapd", "movupd", "movdqa", "movdqu", "movq", "movd", "vmov")) \
                and len(ops) == 2:
            src = self.rd(ci, ops[1], st, ops[0].size if ops[0].type == cx.X86_OP_MEM else (ops[1].size or 16))
            if ops[0].type == cx.X86_OP_MEM:
                self.wr(ci, ops[0], Cast("tr", src, ops[0].size) if src.size > ops[0].size and ops[0].size else src, st, out, a)
            else:
                self.wr(ci, ops[0], src if src.size == 16 else Cast("zx", src, 16), st, out, a)
            return
        if len(ops) >= 2:
            srcs = [self.rd(ci, o, st, o.size or 8) for o in ops]
            dst = ops[0]
            if mn.startswith(("ucomis", "comis")):
                st.cc = ("sub", Cast("tr", srcs[0], 8), Cast("tr", srcs[1], 8), 8)
                # snapshot to temporaries
                t1, t2 = self.fresh(8), self.fresh(8)
                out.append(Assign(t1, Intr("__tofp", [srcs[0]], 8), a))
                out.append(Assign(t2, Intr("__tofp", [srcs[1]], 8), a))
                st.cc = ("sub", t1, t2, 8)
                return
            val = Intr("__" + mn, srcs, dst.size or 16)
            if dst.type == cx.X86_OP_MEM:
                self.wr(ci, dst, val, st, out, a)
            else:
                self.wr(ci, dst, val if val.size == 16 else Cast("zx", val, 16), st, out, a)
            return
        out.append(AsmStmt(f"{ci.mnemonic} {ci.op_str}", a))
