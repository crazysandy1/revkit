"""Jump-table (switch) recovery for indirect jumps.

`resolve_switch(db, jmp_insn, recent)` inspects the straight-line instruction history that led to the
indirect jump (`recent`, oldest first) and returns a dict describing the table, or None.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

import capstone as cs
from capstone import x86 as cx86, arm64 as ca64, arm as carm, mips as cmips

from ..arch import Insn
from ..db import Database

MAX_ENTRIES = 1024


def resolve_switch(db: Database, jmp: Insn, recent: List[Insn]) -> Optional[dict]:
    name = db.image.arch.name
    try:
        if name == "x86":
            return _x86(db, jmp, recent)
        if name == "arm64":
            return _arm64(db, jmp, recent)
        if name in ("arm", "thumb"):
            return _arm(db, jmp, recent)
        if name == "mips":
            return _mips(db, jmp, recent)
    except Exception:
        return None
    return None


def _in_func_range(db: Database, t: int, lo: int, hi: int) -> bool:
    return db.image.is_exec(t) and lo <= t < hi


def _bound(recent: List[Insn], cmp_reg_hint: Optional[str] = None) -> Optional[int]:
    """Find `cmp reg, N ; ja/jae default` and return the number of cases (N+1)."""
    for i in range(len(recent) - 1, 0, -1):
        ins = recent[i]
        if ins.mnemonic in ("ja", "jae", "jnb", "jbe", "jb", "jg", "jge", "jnbe"):
            for j in range(i - 1, max(-1, i - 4), -1):
                c = recent[j]
                if c.mnemonic == "cmp":
                    ops = c.cs_insn.operands
                    if len(ops) == 2 and ops[1].type == cx86.X86_OP_IMM:
                        n = ops[1].imm & 0xFFFFFFFF
                        if ins.mnemonic in ("ja", "jnbe", "jg"):
                            return n + 1
                        if ins.mnemonic in ("jae", "jnb", "jge"):
                            return n
                        if ins.mnemonic in ("jbe",):
                            return n + 1
            # also handle `sub eax, N; cmp eax, M`
    for ins in reversed(recent):
        # ARM/MIPS style bounds are checked in their own helpers
        pass
    return None


def _x86(db: Database, jmp: Insn, recent: List[Insn]) -> Optional[dict]:
    img = db.image
    bits = img.arch.bits
    ci = jmp.cs_insn
    ops = ci.operands
    count = _bound(recent)
    lo = max(0, jmp.addr - 0x20000)
    hi = jmp.addr + 0x20000
    # --- 32-bit absolute table: jmp [index*4 + table] ---
    if jmp.table is not None and bits == 32:
        base = jmp.table["base"]
        n = count or _probe_abs(db, base, 4, lo, hi)
        targets = []
        for k in range(min(n, MAX_ENTRIES)):
            v = img.u(base + 4 * k, 4)
            if v is None or not img.is_exec(v):
                break
            targets.append(v)
        if targets:
            return _info(targets, base, 4, "abs", jmp, index=jmp.table["index"])
        return None
    # --- register jump: jmp rax, preceded by `add rax, base`; entries relative / image-relative ---
    if not ops or ops[0].type != cx86.X86_OP_REG:
        # jmp [reg + idx*8] with a register-held table base (64-bit absolute table)
        if ops and ops[0].type == cx86.X86_OP_MEM:
            m = ops[0].mem
            if m.index and m.base and m.scale in (4, 8):
                tbl = _lea_target(recent, m.base, ci)
                if tbl is not None:
                    esz = m.scale
                    n = count or _probe_abs(db, tbl, esz, lo, hi)
                    targets = []
                    for k in range(min(n, MAX_ENTRIES)):
                        v = img.u(tbl + esz * k, esz)
                        if v is None or not img.is_exec(v):
                            break
                        targets.append(v)
                    if targets:
                        return _info(targets, tbl, esz, "abs", jmp, index=ci.reg_name(m.index))
        return None
    tgt_reg = ops[0].reg
    # find `add tgt_reg, other` that builds the final address, and the load producing tgt_reg
    base_reg = None
    ld = None
    sign_ext = False
    for ins in reversed(recent[:-1]):
        c = ins.cs_insn
        o = c.operands
        if ins.mnemonic in ("cdqe", "movsxd") and ld is None and ins.mnemonic == "cdqe":
            sign_ext = True
        if ins.mnemonic == "add" and len(o) == 2 and o[0].type == cx86.X86_OP_REG and o[0].reg == tgt_reg \
                and o[1].type == cx86.X86_OP_REG and base_reg is None:
            base_reg = o[1].reg
        elif ins.mnemonic in ("movsxd", "mov", "movsx", "movzx") and len(o) == 2 and o[0].type == cx86.X86_OP_REG \
                and _same_family(ci, o[0].reg, tgt_reg) and o[1].type == cx86.X86_OP_MEM:
            ld = ins
            break
    if ld is None:
        return None
    m = ld.cs_insn.operands[1].mem
    esz = ld.cs_insn.operands[1].size or 4
    if esz not in (1, 2, 4, 8):
        esz = 4
    signed = sign_ext or ld.mnemonic in ("movsxd", "movsx")
    if m.base == cx86.X86_REG_RIP:
        tbl = ld.addr + ld.size + m.disp
        off_base = tbl
    else:
        before = recent[:recent.index(ld)]
        tbl_x = None
        for reg in (m.base, m.index):
            if reg:
                x = _lea_target(before, reg, ci)
                if x is not None and img.is_mapped(x):
                    tbl_x = x
                    break
        if tbl_x is None:
            return None
        tbl = tbl_x + m.disp
        off_base = tbl_x
        if base_reg is not None:
            ob = _lea_target(recent[:-1], base_reg, jmp.cs_insn)
            if ob is not None:
                off_base = ob
    n = count or _probe_rel(db, tbl, esz, off_base, signed, lo, hi)
    targets = []
    for k in range(min(n, MAX_ENTRIES)):
        v = img.u(tbl + esz * k, esz)
        if v is None:
            break
        if signed and v >= 1 << (esz * 8 - 1):
            v -= 1 << (esz * 8)
        t = (off_base + v) & ((1 << bits) - 1)
        if not img.is_exec(t):
            break
        targets.append(t)
    if targets:
        idx_name = ci.reg_name(m.index) if m.index and not _is_table_reg(before if m.base != cx86.X86_REG_RIP else [], m.index) else None
        return _info(targets, tbl, esz, "rel", jmp, off_base, index=idx_name)
    return None


def _is_table_reg(before, reg) -> bool:
    return _lea_target(before, reg, None) is not None


def _same_family(ci, a: int, b: int) -> bool:
    na, nb = ci.reg_name(a), ci.reg_name(b)
    fam = lambda n: re.sub(r"^(r|e)", "", n).rstrip("dwl") if n else n
    return fam(na) == fam(nb) or na == nb


def _lea_target(recent: List[Insn], reg: int, ci_ref) -> Optional[int]:
    for ins in reversed(recent):
        c = ins.cs_insn
        o = c.operands
        if ins.mnemonic == "lea" and len(o) == 2 and o[0].type == cx86.X86_OP_REG and o[0].reg == reg \
                and o[1].type == cx86.X86_OP_MEM:
            m = o[1].mem
            if m.base == cx86.X86_REG_RIP:
                return ins.addr + ins.size + m.disp
            if m.base == 0 and m.index == 0:
                return m.disp & 0xFFFFFFFF
        if ins.mnemonic == "mov" and len(o) == 2 and o[0].type == cx86.X86_OP_REG and o[0].reg == reg \
                and o[1].type == cx86.X86_OP_IMM:
            return o[1].imm & 0xFFFFFFFFFFFFFFFF
    return None


def _probe_abs(db, base, esz, lo, hi) -> int:
    n = 0
    while n < 512:
        v = db.image.u(base + esz * n, esz)
        if v is None or not db.image.is_exec(v) or not (lo <= v < hi):
            break
        n += 1
    return n


def _probe_rel(db, base, esz, off_base, signed, lo, hi) -> int:
    n = 0
    bits = db.image.arch.bits
    while n < 512:
        v = db.image.u(base + esz * n, esz)
        if v is None:
            break
        if signed and v >= 1 << (esz * 8 - 1):
            v -= 1 << (esz * 8)
        t = (off_base + v) & ((1 << bits) - 1)
        if not db.image.is_exec(t) or not (lo <= t < hi):
            break
        n += 1
    return n


def _info(targets, tbl, esz, kind, jmp, base=None, index=None) -> dict:
    seen, uniq = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    d = {"targets": uniq, "cases": list(targets), "table": tbl, "entry_size": esz, "kind": kind,
         "count": len(targets)}
    if base is not None:
        d["base"] = base
    if index:
        d["index_reg"] = index
    return d


# ---------------------------------------------------------------------------
def _arm64(db: Database, jmp: Insn, recent: List[Insn]) -> Optional[dict]:
    """clang/gcc pattern: adrp+add table; ldr{b,h,w} idx; adr base; add x, base, w, {sxtb|uxtb|lsl} #2; br."""
    img = db.image
    tbl = None
    width = 1
    shift = 2
    base = None
    regs: Dict[int, int] = {}
    count = None
    for ins in recent:
        c = ins.cs_insn
        o = c.operands
        mn = c.mnemonic
        if mn == "adrp" and len(o) == 2:
            regs[o[0].reg] = o[1].imm
        elif mn == "add" and len(o) == 3 and o[1].type == ca64.ARM64_OP_REG and o[1].reg in regs \
                and o[2].type == ca64.ARM64_OP_IMM:
            regs[o[0].reg] = regs[o[1].reg] + o[2].imm
            tbl = regs[o[0].reg]
        elif mn == "adr" and len(o) == 2:
            base = o[1].imm
        elif mn in ("ldrb", "ldrh", "ldrsb", "ldrsh", "ldr", "ldrsw") and len(o) == 2 and o[1].type == ca64.ARM64_OP_MEM:
            width = {"ldrb": 1, "ldrsb": 1, "ldrh": 2, "ldrsh": 2, "ldr": 4, "ldrsw": 4}[mn]
            if o[1].mem.base in regs:
                tbl = regs[o[1].mem.base]
        elif mn == "cmp" and len(o) == 2 and o[1].type == ca64.ARM64_OP_IMM:
            count = o[1].imm + 1
    for ins in recent:
        c = ins.cs_insn
        if c.mnemonic == "add" and len(c.operands) == 3 and c.operands[2].shift.value:
            shift = c.operands[2].shift.value
    if tbl is None or base is None:
        return None
    n = count or 64
    targets = []
    for k in range(min(n, MAX_ENTRIES)):
        v = img.u(tbl + width * k, width)
        if v is None:
            break
        t = base + (v << shift)
        if not img.is_exec(t):
            break
        targets.append(t)
    return _info(targets, tbl, width, "rel", jmp, base) if targets else None


def _arm(db: Database, jmp: Insn, recent: List[Insn]) -> Optional[dict]:
    return None


def _mips(db: Database, jmp: Insn, recent: List[Insn]) -> Optional[dict]:
    img = db.image
    tbl = None
    count = None
    for ins in recent:
        for kind, a in ins.refs:
            if kind == "offset" and img.is_mapped(a) and not img.is_exec(a):
                tbl = a
        c = ins.cs_insn
        if c.mnemonic == "sltiu" and len(c.operands) == 3:
            count = c.operands[2].imm
    if tbl is None:
        return None
    n = count or 32
    targets = []
    for k in range(min(n, MAX_ENTRIES)):
        v = img.u(tbl + 4 * k, 4)
        if v is None or not img.is_exec(v):
            break
        targets.append(v)
    return _info(targets, tbl, 4, "abs", jmp) if targets else None
