"""AArch64 instruction lifter producing the same decompiler IR as the x86 lifter."""
from __future__ import annotations

from typing import List, Optional

import capstone as cs
from capstone import arm64 as c

from ..arch import CALL, CJMP, INDCALL, INDJMP, JMP, RET, HALT, Insn
from .ir import (Assign, AsmStmt, Bin, CallE, Cast, Const, CJump, Expr, ExprStmt, Goto, Intr, Ite, Mem, Reg, Return,
                 Stmt, SwitchJ, Un, mask, simplify, sign)
from .x86lift import LState, X86Lifter

ARG_REGS = [f"x{i}" for i in range(8)]
CLOBBER = [f"x{i}" for i in range(0, 18)]
CC_MAP = {"eq": "e", "ne": "ne", "hs": "ae", "cs": "ae", "lo": "b", "cc": "b", "mi": "s", "pl": "ns", "vs": "o", "vc": "no",
          "hi": "a", "ls": "be", "ge": "ge", "lt": "l", "gt": "g", "le": "le"}
CC_ENUM = {c.ARM64_CC_EQ: "eq", c.ARM64_CC_NE: "ne", c.ARM64_CC_HS: "hs", c.ARM64_CC_LO: "lo", c.ARM64_CC_MI: "mi",
           c.ARM64_CC_PL: "pl", c.ARM64_CC_VS: "vs", c.ARM64_CC_VC: "vc", c.ARM64_CC_HI: "hi", c.ARM64_CC_LS: "ls",
           c.ARM64_CC_GE: "ge", c.ARM64_CC_LT: "lt", c.ARM64_CC_GT: "gt", c.ARM64_CC_LE: "le"}
INVERT = {"eq": "ne", "ne": "eq", "hs": "lo", "lo": "hs", "mi": "pl", "pl": "mi", "vs": "vc", "vc": "vs", "hi": "ls", "ls": "hi",
          "ge": "lt", "lt": "ge", "gt": "le", "le": "gt"}


def _ends_noret(out) -> bool:
    from .decompile import ends_in_noreturn
    return ends_in_noreturn(out)


def _nm(ci, reg) -> str:
    """Capstone prints x29/x30 as fp/lr; normalise to x29/x30."""
    n = ci.reg_name(reg)
    return {"fp": "x29", "lr": "x30"}.get(n, n)


class A64Lifter:
    """Mirrors the x86 lifter's public surface (see decompile.Decompiler)."""
    cond = X86Lifter.cond
    set_cc = X86Lifter.set_cc
    fresh = X86Lifter.fresh

    def __init__(self, db, func, ctx):
        self.db, self.f, self.ctx = db, func, ctx
        self.bits = 64
        self.w = 8
        self.sp = "sp"
        self.bp = "x29"
        self.sp_fam = "sp"
        self.bp_fam = "x29"
        self.rax = "x0"
        self.sp0 = Reg("sp0", 8)
        self.fp_off: Optional[int] = None
        self.ms64 = False
        self.argregs = ARG_REGS
        self.clobber = CLOBBER
        self.is_pe = False
        self.next_tmp = 0
        self._adhoc_nargs = 0
        self._vararg_hint = None

    # ---------------------------------------------------------------- registers
    def _rname(self, ci, reg) -> str:
        return _nm(ci, reg)

    def rd_reg(self, name: str, st: LState) -> Expr:
        n = name.lower()
        if n in ("xzr", "wzr"):
            return Const(0, 8 if n == "xzr" else 4)
        if n == "sp" or n == "wsp":
            base = Bin("+", self.sp0, Const(st.spd & mask(8), 8), 8)
            return base if n == "sp" else Cast("tr", base, 4)
        if n == "fp":
            n = "x29"
        if n == "lr":
            n = "x30"
        if n[0] == "w" and n[1:].isdigit():
            full = "x" + n[1:]
            return Cast("tr", self._x(full, st), 4)
        if n[0] == "x" and n[1:].isdigit():
            return self._x(n, st)
        # vector / fp registers
        if n[0] in "vqdshb" and n[1:].isdigit():
            size = {"b": 1, "h": 2, "s": 4, "d": 8, "q": 16, "v": 16}[n[0]]
            r = Reg("v" + n[1:], 16)
            return r if size == 16 else Cast("tr", r, size)
        return Reg(n, 8)

    def _x(self, n: str, st: LState) -> Expr:
        if n in st.known:
            return st.known[n]
        if n == "x29" and self.fp_off is not None:
            return Bin("+", self.sp0, Const(self.fp_off & mask(8), 8), 8)
        return Reg(n, 8)

    def wr_reg(self, name: str, val: Expr, st: LState, out: List[Stmt], addr: int):
        n = name.lower()
        if n in ("xzr", "wzr"):
            return
        if n in ("sp", "wsp"):
            off = self._sp_off(simplify(val))
            if off is not None:
                st.spd = off
            return
        if n == "fp":
            n = "x29"
        if n == "lr":
            n = "x30"
        if n == "x29" and self.fp_off is not None:
            return
        if n[0] == "w" and n[1:].isdigit():
            full = "x" + n[1:]
            st.known.pop(full, None)
            out.append(Assign(Reg(full, 8), Cast("zx", val, 8) if val.size != 8 else val, addr))
            return
        if n[0] == "x" and n[1:].isdigit():
            st.known.pop(n, None)
            v2 = simplify(val)
            if self._sp_off(v2) is not None:
                st.known[n] = v2
            out.append(Assign(Reg(n, 8), val, addr))
            return
        if n[0] in "vqdshb" and n[1:].isdigit():
            out.append(Assign(Reg("v" + n[1:], 16), val if val.size == 16 else Cast("zx", val, 16), addr))
            return
        out.append(Assign(Reg(n, 8), val, addr))

    def _sp_off(self, e: Expr) -> Optional[int]:
        if isinstance(e, Bin) and e.op == "+" and e.a == self.sp0 and isinstance(e.b, Const):
            return sign(e.b.v, e.b.size)
        if e == self.sp0:
            return 0
        return None

    # ---------------------------------------------------------------- operands
    def _reg_op(self, ci, op, st) -> Expr:
        return self.rd_reg(self._rname(ci, op.reg), st)

    def _shifted(self, ci, op, e: Expr, size: int) -> Expr:
        sh = op.shift
        if sh.type != 0 and sh.value:
            names = {c.ARM64_SFT_LSL: "<<", c.ARM64_SFT_LSR: ">>", c.ARM64_SFT_ASR: "sar"}
            if sh.type in names:
                return Bin(names[sh.type], e, Const(sh.value, 1), size)
            if sh.type == c.ARM64_SFT_MSL:
                return Bin("<<", e, Const(sh.value, 1), size)
        ext = op.ext
        if ext:
            kinds = {c.ARM64_EXT_UXTB: ("zx", 1), c.ARM64_EXT_UXTH: ("zx", 2), c.ARM64_EXT_UXTW: ("zx", 4),
                     c.ARM64_EXT_SXTB: ("sx", 1), c.ARM64_EXT_SXTH: ("sx", 2), c.ARM64_EXT_SXTW: ("sx", 4)}
            if ext in kinds:
                k, sz = kinds[ext]
                e = Cast(k, Cast("tr", e, sz), size)
            if sh.value:
                e = Bin("<<", e, Const(sh.value, 1), size)
        return e

    def rd(self, ci, op, st, size=None) -> Expr:
        if op.type == c.ARM64_OP_REG:
            e = self._reg_op(ci, op, st)
            return self._shifted(ci, op, e, e.size or 8)
        if op.type == c.ARM64_OP_IMM:
            e = Const(op.imm & mask(size or 8), size or 8)
            if op.shift.value:
                e = Const((op.imm << op.shift.value) & mask(size or 8), size or 8)
            return e
        return Intr("__unknown_operand", [])

    def mem_addr(self, ci, op, st) -> Expr:
        m = op.mem
        base = self.rd_reg(_nm(ci, m.base), st) if m.base else Const(0, 8)
        if m.index:
            idx = self.rd_reg(_nm(ci, m.index), st)
            idx = self._shifted(ci, op, idx, 8) if (op.shift.value or op.ext) else idx
            if op.ext in (c.ARM64_EXT_SXTW,) and not op.shift.value:
                idx = Cast("sx", Cast("tr", idx, 4), 8)
            base = Bin("+", base, idx, 8)
        if m.disp:
            base = Bin("+", base, Const(m.disp & mask(8), 8), 8)
        return simplify(base)

    # ---------------------------------------------------------------- calls
    def callee_info(self, target, slot):
        return self.ctx.callee_info(self, target, slot)

    def lift_call(self, ins: Insn, ci, st: LState, out: List[Stmt]):
        a = ins.addr
        tgt = ins.targets[0] if ins.targets else None
        if tgt is not None:
            target_expr: Expr = Const(tgt, 8)
        elif ci.operands:
            target_expr = self._reg_op(ci, ci.operands[0], st)
        else:
            target_expr = Intr("__unknown_target", [])
        info = self.callee_info(tgt, None)
        args: List[Expr] = []
        for i in range(info["nargs"]):
            if info.get("float_args", {}).get(i):
                args.append(Cast("tr", Reg(f"v{i}", 16), 8))
            elif i < 8:
                args.append(self.rd_reg(f"x{i}", st))
            else:
                args.append(Mem(simplify(Bin("+", self.sp0, Const((st.spd + 8 * (i - 8)) & mask(8), 8), 8)), 8))
        call = CallE(target_expr, args, info["name"], info["ret_size"], info["proto"], tgt or 0, info["cc"], info.get("noret", False))
        if info["void"]:
            out.append(ExprStmt(call, a))
        elif info.get("ret_float"):
            out.append(Assign(Reg("v0", 16), Cast("zx", call, 16), a))
        else:
            self.wr_reg("x0" if call.size == 8 else "w0", call, st, out, a)
        if not info.get("noret"):
            for r in CLOBBER:
                if r == "x0" and not info["void"]:
                    continue
                out.append(Assign(Reg(r, 8), Intr("__undefined", [], 8), a))
        st.cc = None

    # ---------------------------------------------------------------- instruction lifting
    def lift_insn(self, ins: Insn, st: LState, out: List[Stmt], nxt: Optional[Insn] = None):
        ci = ins.cs_insn
        mn = ci.mnemonic
        ops = ci.operands
        a = ins.addr

        def R(i, size=None):
            return self.rd(ci, ops[i], st, size)

        def W(i, val):
            self.wr_reg(self._rname(ci, ops[i].reg), val, st, out, a)

        def width(i):
            n = self._rname(ci, ops[i].reg).lower()
            return 4 if n.startswith("w") else 8

        if mn in ("nop", "hint", "dmb", "dsb", "isb", "prfm", "yield", "wfi", "wfe", "sev", "bti", "paciasp", "autiasp",
                  "pacibsp", "autibsp", "clrex"):
            return
        if mn in ("bl", "blr", "blraa", "blrab"):
            self.lift_call(ins, ci, st, out)
            return
        if mn in ("mov", "movz", "movn", "movk", "mvn") and len(ops) >= 2:
            sz = width(0)
            if mn == "movk":
                cur = self.rd_reg(self._rname(ci, ops[0].reg), st)
                sh = ops[1].shift.value
                m16 = Const(~(0xFFFF << sh) & mask(sz), sz)
                W(0, Bin("|", Bin("&", cur, m16, sz), Const((ops[1].imm << sh) & mask(sz), sz), sz))
            elif mn == "movn":
                W(0, Const(~(ops[1].imm << ops[1].shift.value) & mask(sz), sz))
            elif mn == "mvn":
                W(0, Un("~", R(1, sz), sz))
            else:
                v = R(1, sz)
                if v.size != sz and not isinstance(v, Const):
                    v = Cast("tr", v, sz) if v.size > sz else Cast("zx", v, sz)
                W(0, v)
            return
        if mn in ("add", "sub", "adds", "subs", "and", "orr", "eor", "ands", "bic", "orn", "eon", "bics", "adc", "sbc") and len(ops) >= 3:
            sz = width(0)
            lhs, rhs = R(1, sz), R(2, sz)
            if len(ops) > 3 and ops[3].type == c.ARM64_OP_IMM and False:
                pass
            if lhs.size != sz and not isinstance(lhs, Const):
                lhs = Cast("tr", lhs, sz)
            if rhs.size != sz and not isinstance(rhs, Const):
                rhs = Cast("tr", rhs, sz) if rhs.size > sz else Cast("zx", rhs, sz)
            op = {"add": "+", "adds": "+", "sub": "-", "subs": "-", "and": "&", "ands": "&", "orr": "|", "eor": "^",
                  "bic": "&", "bics": "&", "orn": "|", "eon": "^", "adc": "+", "sbc": "-"}[mn]
            if mn in ("bic", "bics", "orn", "eon"):
                rhs = Un("~", rhs, sz)
            res = Bin(op, lhs, rhs, sz)
            if mn in ("adds", "subs", "ands", "bics"):
                if mn == "subs":
                    self.set_cc("sub", lhs, rhs, sz, st, out, a)
                else:
                    kind = "and" if mn in ("ands", "bics") else "res"
                    self.set_cc(kind, res if kind == "res" else lhs, rhs if kind == "and" else None, sz, st, out, a)
                W(0, res)
            else:
                W(0, res)
            return
        if mn in ("cmp", "cmn", "tst") and len(ops) >= 2:
            sz = 4 if self._rname(ci, ops[0].reg).lower().startswith("w") else 8
            l, r = R(0, sz), R(1, sz)
            if r.size != sz and not isinstance(r, Const):
                r = Cast("tr", r, sz) if r.size > sz else Cast("zx", r, sz)
            if mn == "cmp":
                self.set_cc("sub", l, r, sz, st, out, a)
            elif mn == "cmn":
                self.set_cc("res", Bin("+", l, r, sz), None, sz, st, out, a)
            else:
                self.set_cc("and", l, r, sz, st, out, a)
            return
        if mn in ("neg", "negs", "ngc") and len(ops) >= 2:
            sz = width(0)
            W(0, Un("-", R(1, sz), sz))
            return
        if mn in ("mul", "madd", "msub", "mneg", "smull", "umull", "smaddl", "umaddl", "smsubl", "umsubl") and len(ops) >= 3:
            sz = width(0)
            long_ = mn in ("smull", "umull", "smaddl", "umaddl", "smsubl", "umsubl")
            def opd(i):
                e = R(i, 8 if long_ else sz)
                if long_:
                    e = Cast("sx" if mn.startswith("s") else "zx", Cast("tr", e, 4), 8)
                return e
            prod = Bin("*", opd(1), opd(2), 8 if long_ else sz)
            if mn in ("mul", "smull", "umull"):
                W(0, prod)
            elif mn == "mneg":
                W(0, Un("-", prod, sz))
            elif mn in ("madd", "smaddl", "umaddl"):
                W(0, Bin("+", R(3, 8 if long_ else sz), prod, 8 if long_ else sz))
            else:
                W(0, Bin("-", R(3, 8 if long_ else sz), prod, 8 if long_ else sz))
            return
        if mn in ("sdiv", "udiv") and len(ops) == 3:
            sz = width(0)
            W(0, Bin("/" if mn == "sdiv" else "u/", R(1, sz), R(2, sz), sz))
            return
        if mn in ("lsl", "lsr", "asr", "ror") and len(ops) == 3:
            sz = width(0)
            opn = {"lsl": "<<", "lsr": ">>", "asr": "sar"}.get(mn)
            if opn:
                W(0, Bin(opn, R(1, sz), R(2, sz), sz))
            else:
                W(0, Intr(f"__ROR{sz * 8}__", [R(1, sz), R(2, sz)], sz))
            return
        if mn in ("sxtw", "sxth", "sxtb", "uxtw", "uxth", "uxtb") and len(ops) == 2:
            sz = width(0)
            n = {"w": 4, "h": 2, "b": 1}[mn[-1]]
            W(0, Cast("sx" if mn[0] == "s" else "zx", Cast("tr", R(1, 8), n), 8 if sz == 8 else 4))
            return
        if mn in ("ubfx", "sbfx", "ubfiz", "sbfiz", "bfi", "bfxil", "bfc", "extr") and len(ops) >= 3:
            sz = width(0)
            if mn in ("ubfx", "sbfx") and len(ops) == 4:
                lsb, wd = ops[2].imm, ops[3].imm
                v = Bin(">>" if mn == "ubfx" else "sar", R(1, sz), Const(lsb, 1), sz)
                if lsb + wd < sz * 8:
                    v = Bin("&", v, Const((1 << wd) - 1, sz), sz) if mn == "ubfx" else Cast("sx", Cast("tr", v, (wd + 7) // 8 or 1), sz)
                W(0, v)
                return
            W(0, Intr(f"__{mn}", [R(i, sz) for i in range(1, len(ops))], sz))
            return
        if mn in ("clz", "rbit", "rev", "rev16", "rev32", "cls") and len(ops) == 2:
            sz = width(0)
            W(0, Intr(f"__{mn}", [R(1, sz)], sz))
            return
        if mn in ("csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cinv", "cneg") and ops:
            sz = width(0)
            code = CC_ENUM.get(ci.cc)
            if code is None:
                out.append(AsmStmt(ins.text, a))
                return
            cond = self.cond(CC_MAP[code], st)
            if mn == "cset":
                W(0, Cast("zx", cond, sz) if sz != 1 else cond)
            elif mn == "csetm":
                W(0, Un("-", Cast("zx", cond, sz), sz))
            elif mn == "csel":
                W(0, Ite(cond, R(1, sz), R(2, sz)))
            elif mn == "csinc":
                W(0, Ite(cond, R(1, sz), Bin("+", R(2, sz), Const(1, sz), sz)))
            elif mn == "csinv":
                W(0, Ite(cond, R(1, sz), Un("~", R(2, sz), sz)))
            elif mn == "csneg":
                W(0, Ite(cond, R(1, sz), Un("-", R(2, sz), sz)))
            elif mn == "cinc":
                W(0, Ite(cond, Bin("+", R(1, sz), Const(1, sz), sz), R(1, sz)))
            elif mn == "cinv":
                W(0, Ite(cond, Un("~", R(1, sz), sz), R(1, sz)))
            else:
                W(0, Ite(cond, Un("-", R(1, sz), sz), R(1, sz)))
            return
        if mn in ("adrp", "adr") and len(ops) == 2:
            W(0, Const(ops[1].imm & mask(8), 8))
            return
        if mn.startswith(("ldr", "ldur", "ldrs", "ldp", "ldnp", "ldxr", "ldar", "ldapr", "ldaxr", "str", "stur", "stp", "stnp", "stxr", "stlr", "stlxr")) \
                and not mn.startswith("strb_"):
            self._lift_mem(ins, ci, mn, ops, st, out, a)
            return
        if mn in ("ret", "retaa", "retab", "b", "br") or mn.startswith("b.") or mn in ("cbz", "cbnz", "tbz", "tbnz"):
            return
        if mn in ("brk", "hlt", "udf"):
            out.append(ExprStmt(Intr("__halt", []), a))
            return
        if mn == "svc":
            out.append(ExprStmt(Intr("__svc", [Const(ops[0].imm if ops else 0, 4)]), a))
            return
        if mn == "mrs" and len(ops) >= 1:
            W(0, Intr("__mrs", [], 8))
            return
        if mn.startswith(("f", "scvtf", "ucvtf", "fmov")) and len(ops) >= 2 and ops[0].type == c.ARM64_OP_REG:
            dst = self._rname(ci, ops[0].reg).lower()
            srcs = [self.rd(ci, o, st, 8) for o in ops[1:] if o.type in (c.ARM64_OP_REG, c.ARM64_OP_IMM, c.ARM64_OP_FP)]
            if mn.startswith("fcmp") or mn.startswith("fccmp"):
                t1, t2 = self.fresh(8), self.fresh(8)
                out.append(Assign(t1, Intr("__tofp", [self.rd(ci, ops[0], st, 8)], 8), a))
                out.append(Assign(t2, Intr("__tofp", [self.rd(ci, ops[1], st, 8)], 8), a))
                st.cc = ("sub", t1, t2, 8)
                return
            self.wr_reg(dst, Intr("__" + mn, srcs, 8), st, out, a)
            return
        out.append(AsmStmt(ins.text, a))

    def _lift_mem(self, ins, ci, mn, ops, st, out, a):
        is_load = mn.startswith("ld")
        pair = mn in ("ldp", "stp", "ldnp", "stnp") or mn.startswith(("ldpsw",))
        nreg = 2 if pair else 1
        mi = nreg
        if len(ops) <= mi or ops[mi].type != c.ARM64_OP_MEM and not (ops[mi].type == c.ARM64_OP_IMM):
            # exclusive/acquire forms with a status register first
            if mn.startswith(("stxr", "stlxr")) and len(ops) >= 3:
                out.append(AsmStmt(ins.text, a))
                return
            out.append(AsmStmt(ins.text, a))
            return
        regs = ops[:nreg]
        mop = ops[mi]
        suffix = mn.rstrip("0123456789")
        sizes = {"b": 1, "h": 2, "w": 4}
        # access size
        rn = self._rname(ci, regs[0].reg).lower()
        if mn.startswith(("ldrb", "strb", "ldurb", "sturb", "ldrsb", "ldursb", "ldarb", "stlrb")):
            sz = 1
        elif mn.startswith(("ldrh", "strh", "ldurh", "sturh", "ldrsh", "ldursh", "ldarh", "stlrh")):
            sz = 2
        elif mn.startswith(("ldrsw", "ldursw", "ldpsw")):
            sz = 4
        else:
            sz = {"w": 4, "x": 8, "s": 4, "d": 8, "q": 16, "b": 1, "h": 2}.get(rn[0], 8)
        signed = mn.startswith(("ldrs", "ldurs", "ldps"))
        # address, with write-back handling
        if mop.type == c.ARM64_OP_IMM:                       # literal (pc-relative) load
            addr = Const(mop.imm & mask(8), 8)
            post = None
        else:
            addr = self.mem_addr(ci, mop, st)
            post = None
            if ci.writeback:
                base_name = _nm(ci, mop.mem.base)
                extra = ops[mi + 1] if len(ops) > mi + 1 and ops[mi + 1].type == c.ARM64_OP_IMM else None
                if extra is not None:                         # post-index: access at base, then base += imm
                    addr = self.rd_reg(base_name, st)
                    post = (base_name, extra.imm)
                else:                                         # pre-index: base += disp, access at new base
                    pre_val = simplify(addr)
                    if base_name.lower() in ("sp", "wsp"):
                        st.spd = self._sp_off(pre_val) if self._sp_off(pre_val) is not None else st.spd
                        addr = Bin("+", self.sp0, Const(st.spd & mask(8), 8), 8)
                    else:
                        self.wr_reg(base_name, pre_val, st, out, a)
                        addr = self.rd_reg(base_name, st)
        for k, rop in enumerate(regs):
            ea = simplify(Bin("+", addr, Const(k * sz, 8), 8)) if k else addr
            m = Mem(ea, sz)
            if not is_load and ((self._rname(ci, rop.reg).lower() in ("x29", "fp") and self.fp_off is not None)
                                or self._rname(ci, rop.reg).lower() in ("x30", "lr")):
                continue                                    # saving the frame pointer / link register is prologue noise
            if is_load:
                v = Cast("sx", m, 8 if rn[0] == "x" or mn.startswith("ldrsw") else 4) if signed and sz < 8 else m
                name = self._rname(ci, rop.reg)
                if name.lower().startswith("w") and sz == 8:
                    v = Cast("tr", v, 4)
                self.wr_reg(name, v, st, out, a)
            else:
                val = self.rd_reg(self._rname(ci, rop.reg), st)
                if val.size > sz:
                    val = Cast("tr", val, sz)
                out.append(Assign(m, val, a))
        if post is not None:
            bn, imm = post
            if bn.lower() in ("sp", "wsp"):
                st.spd += imm
            else:
                self.wr_reg(bn, Bin("+", self.rd_reg(bn, st), Const(imm & mask(8), 8), 8), st, out, a)

    # ---------------------------------------------------------------- decompiler hooks
    def detect_frame_pointer(self, dec):
        """x29 is the frame pointer when set from sp (`mov x29, sp` / `add x29, sp, #n`) exactly once in the entry block."""
        db, f = self.db, self.f
        entry = f.blocks.get(f.start)
        if entry is None:
            return
        spd = 0
        found = None
        sets = 0
        for b in f.blocks.values():
            for a in b.insns:
                ins = db.insn(a)
                if ins is None:
                    continue
                ci = ins.cs_insn
                ops0 = ci.operands
                if ops0 and ops0[0].type == c.ARM64_OP_REG and _nm(ci, ops0[0].reg) == "x29" and                         not ins.mnemonic.startswith(("ldp", "ldr", "ldur", "st", "cmp", "cmn", "tst", "b", "cb", "tb", "ret", "prf")):
                    sets += 1
        if sets != 1:
            return
        for a in entry.insns:
            ins = db.insn(a)
            ci = ins.cs_insn
            ops = ci.operands
            if ins.mnemonic in ("mov", "add") and ops and ops[0].type == c.ARM64_OP_REG and _nm(ci, ops[0].reg) == "x29" \
                    and len(ops) >= 2 and ops[1].type == c.ARM64_OP_REG and _nm(ci, ops[1].reg) == "sp":
                imm = ops[2].imm if ins.mnemonic == "add" and len(ops) > 2 else 0
                found = spd + imm
                break
            sd = self._entry_spd_delta(ci, ins)
            if sd is not None:
                spd += sd
        if found is not None:
            self.fp_off = found

    def _entry_spd_delta(self, ci, ins) -> Optional[int]:
        ops = ci.operands
        mn = ins.mnemonic
        if mn in ("stp", "str") and ci.writeback and ops and ops[-1].type == c.ARM64_OP_MEM and ci.reg_name(ops[-1].mem.base) == "sp":
            return ops[-1].mem.disp
        if mn == "sub" and len(ops) == 3 and ops[0].type == c.ARM64_OP_REG and _nm(ci, ops[0].reg) == "sp" and ops[2].type == c.ARM64_OP_IMM:
            return -ops[2].imm
        return None

    def peek_call_args(self, dec, ins, nxt, insns, i):
        self._adhoc_nargs = 0
        self._vararg_hint = None
        if ins.flow not in (CALL, INDCALL):
            return
        written = set()
        for p in reversed(insns[:i]):
            if p.flow in (CALL, INDCALL):
                break
            try:
                rr, rw = p.cs_insn.regs_access()
            except Exception:
                continue
            for r in rw:
                nm = p.cs_insn.reg_name(r)
                if nm[0] in "xw" and nm[1:].isdigit() and int(nm[1:]) < 8:
                    written.add(int(nm[1:]))
        n = 0
        while n < 8 and n in written:
            n += 1
        self._adhoc_nargs = n
        import re as _re
        name = ""
        if ins.targets:
            name = self.db.names.get(ins.targets[0], "")
        if _re.match(r"^_*(?:v?[sfdn]*printf|syslog|scanf|sscanf|snprintf)", name or ""):
            for p in reversed(insns[:i + 1]):
                for kind, a in p.refs:
                    s = self.db.strings.get(a)
                    if s is not None:
                        self._vararg_hint = len(_re.findall(r"%(?!%)[-+ #0]*[\d*]*(?:\.[\d*]+)?(?:hh|h|ll|l|z|j|t|L)?[diouxXeEfgGcsSpn]", s.text))
                        return

    def terminate(self, dec, bb, blk, last: Insn, st: LState):
        db, f = self.db, self.f
        out = bb.stmts
        fl = last.flow
        addr = last.addr
        nxt = blk.end
        ci = last.cs_insn
        ops = ci.operands
        mn = last.mnemonic
        if fl == RET:
            out.append(Return(Reg("x0", 8), addr))
        elif fl == JMP:
            t = last.targets[0]
            if t in f.blocks:
                out.append(Goto(t, addr))
                bb.succs = [t]
            else:
                tmp: List[Stmt] = []
                from .decompile import _FakeCall
                self.lift_call(_FakeCall(last, t), ci, LState(st.spd, None), tmp)
                out.extend(tmp)
                out.append(Return(Reg("x0", 8), addr))
        elif fl == CJMP:
            t = last.targets[0] if last.targets else nxt
            if t not in f.blocks:
                t = nxt
            if mn.startswith("b."):
                cond = self.cond(CC_MAP.get(mn.split(".")[1], "e"), st)
            elif mn in ("cbz", "cbnz"):
                v = self._reg_op(ci, ops[0], st)
                cond = Bin("==" if mn == "cbz" else "!=", v, Const(0, v.size), 1)
            else:                                            # tbz / tbnz
                v = self._reg_op(ci, ops[0], st)
                bit = ops[1].imm
                test = Bin("&", v, Const(1 << bit, v.size), v.size)
                cond = Bin("==" if mn == "tbz" else "!=", test, Const(0, v.size), 1)
            out.append(CJump(cond, t, nxt, addr))
            bb.succs = [t, nxt] if t != nxt else [t]
        elif fl == INDJMP:
            sw = db.switches.get(addr)
            if sw:
                idx = Intr("__switch_index", [])
                name = sw.get("index_reg")
                if name:
                    idx = self.rd_reg(name, st)
                out.append(SwitchJ(idx, [(k, t) for k, t in enumerate(sw["cases"])], addr))
                bb.succs = sorted(set(sw["targets"]))
            else:
                out.append(ExprStmt(Intr("JUMPOUT", [self._reg_op(ci, ops[0], st) if ops and ops[0].type == c.ARM64_OP_REG else Intr("?", [])]), addr))
                out.append(Return(None, addr))
        elif fl == HALT:
            out.append(Return(None, addr))
        else:
            succ = [t for t, _ in blk.succs]
            if succ:
                out.append(Goto(succ[0], addr))
                bb.succs = [succ[0]]
            elif not _ends_noret(out):
                out.append(Return(None, addr))
