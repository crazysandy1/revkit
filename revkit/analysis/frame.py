"""Stack-frame analysis: SP tracking, frame size, calling convention and argument count estimation."""
from __future__ import annotations

from ..arch import CALL, RET
from ..db import Database, Function


def analyze_frames(db: Database):
    for f in db.functions.values():
        try:
            _frame(db, f)
        except Exception:
            f.sp_delta_known = False


def _frame(db: Database, f: Function):
    arch = db.arch
    spec = db.image.arch
    if spec.name != "x86":
        f.callconv = "aapcs" if spec.name in ("arm", "arm64") else ""
        return
    w = spec.bits // 8
    # propagate SP delta along CFG (entry delta 0)
    delta = {f.start: 0}
    order = sorted(f.blocks)
    work = [f.start]
    min_delta = 0
    ret_pop = 0
    known = True
    seen = set()
    while work:
        b = f.blocks.get(work.pop())
        if b is None or b.start in seen:
            continue
        seen.add(b.start)
        d = delta[b.start]
        for ia in b.insns:
            ins = db.insn(ia)
            if ins is None:
                continue
            if ins.stack_delta is not None and ins.flow != RET:
                d += ins.stack_delta
            elif ins.mnemonic == "leave":
                known = known and d <= 0
            elif ins.flow == RET:
                ret_pop = max(ret_pop, (ins.stack_delta or w) - w)
            min_delta = min(min_delta, d)
        for t, _ in b.succs:
            if t not in delta:
                delta[t] = d
                work.append(t)
    f.frame_size = -min_delta
    f.args_size = ret_pop
    f.sp_delta_known = known
    # frame pointer detection
    first = [db.insn(a) for a in f.blocks[f.start].insns[:4]] if f.start in f.blocks else []
    fp = arch.fp
    uses_fp = any(i and i.mnemonic == "mov" and i.op_str.replace(" ", "") == f"{fp},{arch.sp}" for i in first)
    if uses_fp:
        f.flags.add("frame_pointer")
    else:
        f.flags.add("no_frame")
    # calling convention
    if spec.bits == 64:
        f.callconv = "ms_x64" if db.image.fmt.startswith("PE") else "sysv_x64"
    else:
        cc = "cdecl"
        if ret_pop:
            cc = "stdcall"
        reads_ecx_first = False
        written = set()
        for ia in sorted(f.blocks[f.start].insns)[:12] if f.start in f.blocks else []:
            ins = db.insn(ia)
            if ins is None:
                break
            ops = [o.strip() for o in ins.op_str.split(",")]
            if ins.mnemonic in ("mov", "lea", "xor", "pop", "movzx", "movsx") and ops and ops[0] in ("ecx", "edx", "eax"):
                written.add(ops[0])
            src = ",".join(ops[1:]) if len(ops) > 1 else ""
            if "ecx" in src and "ecx" not in written:
                reads_ecx_first = True
            if "edx" in src and "edx" not in written:
                cc = "fastcall" if ret_pop or reads_ecx_first else cc
        if reads_ecx_first and cc == "stdcall":
            cc = "thiscall"
        elif reads_ecx_first and cc == "cdecl":
            cc = "thiscall"
        f.callconv = cc
