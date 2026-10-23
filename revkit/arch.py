"""Processor abstraction: instruction decoding + control-flow / reference semantics (Capstone based)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import capstone as cs
from capstone import x86 as cx86, arm as carm, arm64 as ca64, mips as cmips, ppc as cppc, riscv as criscv

from .image import ArchSpec, Image

# flow kinds
NORMAL, CALL, JMP, CJMP, RET, INDJMP, INDCALL, HALT = "normal", "call", "jmp", "cjmp", "ret", "indjmp", "indcall", "halt"


@dataclass
class Insn:
    addr: int
    size: int
    mnemonic: str
    op_str: str
    raw: bytes
    flow: str = NORMAL
    targets: List[int] = field(default_factory=list)      # direct control-flow targets
    refs: List[Tuple[str, int]] = field(default_factory=list)   # ("data"|"offset"|"read"|"write", addr)
    ind_slot: Optional[int] = None    # memory slot used for indirect call/jmp ([rip+x] / [abs])
    delay_slot: bool = False
    imms: List[int] = field(default_factory=list)
    stack_delta: Optional[int] = None  # best-effort known change to SP (x86/x64)
    table: Optional[dict] = None       # indirect jump through an indexed table: {base, scale, index, entry_size}
    cs_insn: object = None

    @property
    def end(self) -> int:
        return self.addr + self.size

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {self.op_str}".strip()

    @property
    def falls_through(self) -> bool:
        return self.flow not in (JMP, RET, INDJMP, HALT)


class Arch:
    """Decoder for one ArchSpec. Instances are cheap and cached by `get_arch`."""
    # subclasses fill these in
    sp = "sp"
    fp = "fp"
    ra: Optional[str] = None
    max_insn = 15
    insn_align = 1
    nop_bytes: bytes = b"\x90"

    def __init__(self, spec: ArchSpec):
        self.spec = spec
        self.md = self._make_md(spec)
        self.md.detail = True
        self.md.skipdata = False

    def _make_md(self, spec) -> cs.Cs:  # pragma: no cover
        raise NotImplementedError

    # -- public API ----------------------------------------------------
    def decode(self, img: Image, addr: int) -> Optional[Insn]:
        buf = img.read(addr, self.max_insn)
        if not buf:
            return None
        return self.decode_bytes(buf, addr)

    def decode_bytes(self, buf: bytes, addr: int) -> Optional[Insn]:
        for ci in self.md.disasm(buf, addr, 1):
            return self._wrap(ci)
        return None

    def disasm(self, buf: bytes, addr: int) -> List[Insn]:
        return [self._wrap(ci) for ci in self.md.disasm(buf, addr)]

    def _wrap(self, ci) -> Insn:
        ins = Insn(ci.address, ci.size, ci.mnemonic, ci.op_str, bytes(ci.bytes), cs_insn=ci)
        self.classify(ins, ci)
        return ins

    def classify(self, ins: Insn, ci) -> None:  # pragma: no cover
        raise NotImplementedError

    def new_block_state(self) -> dict:
        """Per-basic-block scratch used to resolve split address materialisation (adrp+add, lui+addiu...)."""
        return {}

    def track_refs(self, ins: Insn, state: dict, img: Image) -> None:
        """Update `state` and append resolved constant references to ins.refs (default: no-op)."""

    def is_nop(self, ins: Insn) -> bool:
        return ins.mnemonic in ("nop", "fnop")

    def looks_like_prologue(self, buf: bytes) -> bool:
        return False

    def reg_names(self) -> List[str]:
        return []


# =====================================================================
# x86 / x86-64
# =====================================================================
class X86(Arch):
    nop_bytes = b"\x90"
    _PREFIXES = (b"\x55\x8b\xec", b"\x55\x89\xe5", b"\x53\x83\xec", b"\x83\xec", b"\x57\x56",
                 b"\x41\x57\x41\x56", b"\x40\x53\x48\x83\xec", b"\x48\x83\xec", b"\x48\x89\x5c\x24",
                 b"\x48\x8b\xc4", b"\x55\x48\x89\xe5", b"\x53\x48\x83\xec", b"\xf3\x0f\x1e\xfa",
                 b"\x56\x57\x53", b"\x48\x81\xec", b"\x55\x57\x56", b"\x40\x55", b"\x40\x56", b"\x40\x57",
                 b"\x4c\x8b\xdc", b"\x55\x53", b"\x8b\xff\x55")

    def __init__(self, spec):
        super().__init__(spec)
        self.sp = {16: "sp", 32: "esp", 64: "rsp"}[spec.bits]
        self.fp = {16: "bp", 32: "ebp", 64: "rbp"}[spec.bits]
        self.ip = {16: "ip", 32: "eip", 64: "rip"}[spec.bits]

    def _make_md(self, spec):
        mode = {16: cs.CS_MODE_16, 32: cs.CS_MODE_32, 64: cs.CS_MODE_64}[spec.bits]
        return cs.Cs(cs.CS_ARCH_X86, mode)

    def classify(self, ins, ci):
        grp = set(ci.groups)
        ops = ci.operands
        mn = ci.mnemonic
        is_call = cs.CS_GRP_CALL in grp
        is_jmp = cs.CS_GRP_JUMP in grp
        is_ret = cs.CS_GRP_RET in grp or mn in ("iret", "iretd", "iretq", "sysret", "sysexit")
        bits = self.spec.bits
        if mn in ("hlt", "ud2", "int3") and mn != "int3":
            ins.flow = HALT
        if is_ret:
            ins.flow = RET
        elif is_call or is_jmp:
            if ops and ops[0].type == cx86.X86_OP_IMM:
                ins.targets = [ops[0].imm & ((1 << bits) - 1)]
                ins.flow = CALL if is_call else (JMP if mn in ("jmp", "ljmp") else CJMP)
            else:
                ins.flow = INDCALL if is_call else INDJMP
                if ops and ops[0].type == cx86.X86_OP_MEM:
                    m = ops[0].mem
                    if m.index != 0 and m.base == 0 and bits == 32 and m.disp:
                        ins.table = {"base": m.disp & 0xFFFFFFFF, "scale": m.scale, "index": ci.reg_name(m.index)}
                    else:
                        slot = self._mem_abs(ci, ops[0])
                        if slot is not None:
                            ins.ind_slot = slot
        if mn in ("loop", "loope", "loopne", "jcxz", "jecxz", "jrcxz") and ops and ops[0].type == cx86.X86_OP_IMM:
            ins.flow, ins.targets = CJMP, [ops[0].imm]
        # data references / immediates
        for op in ops:
            if op.type == cx86.X86_OP_MEM:
                a = self._mem_abs(ci, op)
                if a is not None and ins.flow not in (CALL, JMP, CJMP):
                    kind = "read"
                    if mn == "lea":
                        kind = "offset"
                    elif op.access & cs.CS_AC_WRITE and not op.access & cs.CS_AC_READ:
                        kind = "write"
                    ins.refs.append((kind, a))
            elif op.type == cx86.X86_OP_IMM and ins.flow not in (CALL, JMP, CJMP):
                ins.imms.append(op.imm & ((1 << bits) - 1) if op.imm < 0 else op.imm)
                if bits >= 32 and not (mn in ("ret", "retn", "enter", "int")):
                    ins.refs.append(("offset", op.imm & ((1 << bits) - 1)))
        # stack delta
        sp = self.sp
        w = bits // 8
        if mn == "push":
            ins.stack_delta = -w
        elif mn == "pop":
            ins.stack_delta = w
        elif mn == "call":
            ins.stack_delta = 0
        elif mn in ("ret", "retn"):
            ins.stack_delta = w + (ops[0].imm if ops and ops[0].type == cx86.X86_OP_IMM else 0)
        elif mn in ("sub", "add") and len(ops) == 2 and ops[0].type == cx86.X86_OP_REG \
                and ci.reg_name(ops[0].reg) == sp and ops[1].type == cx86.X86_OP_IMM:
            ins.stack_delta = -ops[1].imm if mn == "sub" else ops[1].imm
        elif mn == "leave":
            ins.stack_delta = None
        if mn in ("pushal", "pushad"):
            ins.stack_delta = -32
        elif mn in ("popal", "popad"):
            ins.stack_delta = 32
        elif mn in ("pushfq", "pushf", "pushfd"):
            ins.stack_delta = -w
        elif mn in ("popfq", "popf", "popfd"):
            ins.stack_delta = w

    def _mem_abs(self, ci, op) -> Optional[int]:
        m = op.mem
        bits = self.spec.bits
        if m.base == cx86.X86_REG_RIP:
            return (ci.address + ci.size + m.disp) & ((1 << 64) - 1)
        if m.base == 0 and m.index == 0 and m.segment in (0, cx86.X86_REG_DS, cx86.X86_REG_CS):
            return m.disp & ((1 << bits) - 1)
        if m.base == 0 and m.index != 0 and bits == 32 and m.disp and m.segment == 0:
            return m.disp & 0xFFFFFFFF    # table-base [reg*N + disp32]
        return None

    def looks_like_prologue(self, buf: bytes) -> bool:
        return any(buf.startswith(p) for p in self._PREFIXES)

    def is_nop(self, ins):
        if ins.mnemonic in ("nop", "fnop", "pause"):
            return True
        if ins.mnemonic == "xchg" and ins.op_str in ("ax, ax", "eax, eax", "rax, rax"):
            return True
        if ins.mnemonic == "mov" and ins.op_str in ("edi, edi", "esi, esi"):
            return True
        if ins.mnemonic == "lea" and ins.op_str.replace(" ", "") in ("esi,[esi]", "edi,[edi]", "esi,[esi+0]"):
            return True
        return False

    def reg_names(self):
        if self.spec.bits == 64:
            return ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"] + [f"r{i}" for i in range(8, 16)] + ["rip"]
        return ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]


# =====================================================================
# ARM (A32/T32) / ARM64
# =====================================================================
class ARM(Arch):
    sp, fp, ra = "sp", "r11", "lr"
    insn_align = 2
    max_insn = 4
    nop_bytes = b"\x00\xf0\x20\xe3"

    def __init__(self, spec):
        super().__init__(spec)
        self.thumb = spec.name == "thumb" or spec.mode == "thumb"
        if self.thumb:
            self.nop_bytes = b"\x00\xbf"
        else:
            self.insn_align = 4

    def _make_md(self, spec):
        thumb = spec.name == "thumb" or spec.mode == "thumb"
        mode = (cs.CS_MODE_THUMB if thumb else cs.CS_MODE_ARM) | (cs.CS_MODE_BIG_ENDIAN if spec.big_endian else 0)
        return cs.Cs(cs.CS_ARCH_ARM, mode)

    def classify(self, ins, ci):
        mn = ci.mnemonic
        base = mn.split(".")[0]
        grp = set(ci.groups)
        ops = ci.operands
        cc = ci.cc
        conditional = cc not in (carm.ARM_CC_AL, carm.ARM_CC_INVALID, 0) if hasattr(carm, "ARM_CC_AL") else False
        writes_pc = False
        for op in ops[:1]:
            if op.type == carm.ARM_OP_REG and op.reg == carm.ARM_REG_PC:
                writes_pc = True
        if base in ("pop", "ldm", "ldmia", "ldmfd", "ldmdb") and any(
                o.type == carm.ARM_OP_REG and o.reg == carm.ARM_REG_PC for o in ops):
            ins.flow = CJMP if conditional and False else RET
            return
        if base == "bx" and ops and ops[0].type == carm.ARM_OP_REG:
            ins.flow = RET if ops[0].reg == carm.ARM_REG_LR else INDJMP
            return
        if base in ("bl", "blx"):
            if ops and ops[0].type == carm.ARM_OP_IMM:
                ins.flow, ins.targets = CALL, [ops[0].imm]
            else:
                ins.flow = INDCALL
            return
        if base in ("b", "cbz", "cbnz") or (cs.CS_GRP_JUMP in grp and ops and ops[-1].type == carm.ARM_OP_IMM):
            tgt = ops[-1].imm if ops and ops[-1].type == carm.ARM_OP_IMM else None
            if tgt is not None:
                ins.targets = [tgt]
                ins.flow = CJMP if (conditional or base in ("cbz", "cbnz")) else JMP
            else:
                ins.flow = INDJMP
            return
        if base in ("mov", "ldr", "add") and writes_pc:
            ins.flow = INDJMP if base != "ldr" else INDJMP
            if base == "mov" and len(ops) > 1 and ops[1].type == carm.ARM_OP_REG and ops[1].reg == carm.ARM_REG_LR:
                ins.flow = RET
            return
        for op in ops:
            if op.type == carm.ARM_OP_IMM:
                ins.imms.append(op.imm & 0xFFFFFFFF)
        # pc-relative literal loads
        if base in ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "vldr") and len(ops) >= 2 and ops[1].type == carm.ARM_OP_MEM \
                and ops[1].mem.base == carm.ARM_REG_PC:
            pc = ci.address + (4 if self.thumb else 8)
            if self.thumb:
                pc &= ~3
            ins.refs.append(("data", (pc + ops[1].mem.disp) & 0xFFFFFFFF))
        if base == "adr" and len(ops) >= 2 and ops[1].type == carm.ARM_OP_IMM:
            ins.refs.append(("offset", ops[1].imm & 0xFFFFFFFF))
        if base == "add" and len(ops) == 3 and ops[1].type == carm.ARM_OP_REG and ops[1].reg == carm.ARM_REG_PC \
                and ops[2].type == carm.ARM_OP_IMM:
            pc = ci.address + (4 if self.thumb else 8)
            ins.refs.append(("offset", (pc + ops[2].imm) & 0xFFFFFFFF))
        if base in ("push", "stmdb", "stmfd"):
            ins.stack_delta = -4 * (len(ops) - (1 if base != "push" else 0))
        elif base == "sub" and len(ops) >= 2 and ops[0].type == carm.ARM_OP_REG and ops[0].reg == carm.ARM_REG_SP \
                and ops[-1].type == carm.ARM_OP_IMM:
            ins.stack_delta = -ops[-1].imm

    def track_refs(self, ins, state, img):
        ci = ins.cs_insn
        mn = ci.mnemonic.split(".")[0]
        ops = ci.operands
        if mn in ("movw",) and len(ops) == 2 and ops[1].type == carm.ARM_OP_IMM:
            state[ops[0].reg] = ops[1].imm & 0xFFFF
        elif mn == "movt" and len(ops) == 2 and ops[1].type == carm.ARM_OP_IMM and ops[0].reg in state:
            v = state[ops[0].reg] | ((ops[1].imm & 0xFFFF) << 16)
            ins.refs.append(("offset", v))
            state[ops[0].reg] = v

    def looks_like_prologue(self, buf):
        if self.thumb:
            return buf[:2] in (b"\x2d\xe9",) or (len(buf) >= 2 and buf[1] == 0xB5)   # push {..,lr}
        return len(buf) >= 4 and buf[2:4] == b"\x2d\xe9"       # stmfd sp!, {...lr}

    def reg_names(self):
        return [f"r{i}" for i in range(13)] + ["sp", "lr", "pc"]


class ARM64(Arch):
    sp, fp, ra = "sp", "x29", "x30"
    insn_align = 4
    max_insn = 4
    nop_bytes = b"\x1f\x20\x03\xd5"

    def _make_md(self, spec):
        return cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM | (cs.CS_MODE_BIG_ENDIAN if spec.big_endian else 0))

    def classify(self, ins, ci):
        mn = ci.mnemonic
        ops = ci.operands
        if mn in ("ret", "retaa", "retab", "eret"):
            ins.flow = RET
        elif mn in ("bl",):
            ins.flow, ins.targets = CALL, [ops[0].imm]
        elif mn in ("blr", "blraa", "blrab", "blraaz", "blrabz"):
            ins.flow = INDCALL
        elif mn in ("br", "braa", "brab", "braaz", "brabz"):
            ins.flow = INDJMP
        elif mn == "b":
            ins.flow, ins.targets = JMP, [ops[0].imm]
        elif mn.startswith("b.") or mn in ("cbz", "cbnz", "tbz", "tbnz"):
            ins.flow, ins.targets = CJMP, [ops[-1].imm]
        elif mn in ("brk", "hlt"):
            ins.flow = HALT
        for op in ops:
            if op.type == ca64.ARM64_OP_IMM and ins.flow == NORMAL:
                ins.imms.append(op.imm)
        if mn in ("adr",) and ops and ops[-1].type == ca64.ARM64_OP_IMM:
            ins.refs.append(("offset", ops[-1].imm))
        if mn in ("ldr", "ldrsw", "ldrb", "ldrh") and len(ops) == 2 and ops[1].type == ca64.ARM64_OP_IMM:
            ins.refs.append(("data", ops[1].imm))   # literal pool form
        if mn == "stp" and ops and ops[-1].type == ca64.ARM64_OP_MEM and ops[-1].mem.base == ca64.ARM64_REG_SP:
            ins.stack_delta = ops[-1].mem.disp if ci.writeback else None
        elif mn == "sub" and len(ops) == 3 and ops[0].type == ca64.ARM64_OP_REG and ops[0].reg == ca64.ARM64_REG_SP \
                and ops[2].type == ca64.ARM64_OP_IMM:
            ins.stack_delta = -ops[2].imm

    def new_block_state(self):
        return {}

    def track_refs(self, ins, state, img):
        ci = ins.cs_insn
        mn = ci.mnemonic
        ops = ci.operands
        if mn == "adrp" and len(ops) == 2 and ops[1].type == ca64.ARM64_OP_IMM:
            state[ops[0].reg] = ops[1].imm
        elif mn == "add" and len(ops) == 3 and ops[1].type == ca64.ARM64_OP_REG and ops[1].reg in state \
                and ops[2].type == ca64.ARM64_OP_IMM:
            v = state[ops[1].reg] + ops[2].imm
            ins.refs.append(("offset", v))
            state[ops[0].reg] = v
        elif mn in ("ldr", "ldrb", "ldrh", "ldrsw", "str", "strb", "strh") and len(ops) >= 2 \
                and ops[-1].type == ca64.ARM64_OP_MEM and ops[-1].mem.base in state:
            ins.refs.append(("data", state[ops[-1].mem.base] + ops[-1].mem.disp))
        elif ops and ops[0].type == ca64.ARM64_OP_REG and mn in ("mov", "movz", "movk"):
            state.pop(ops[0].reg, None)

    def looks_like_prologue(self, buf):
        if len(buf) < 4:
            return False
        w = int.from_bytes(buf[:4], "big" if self.spec.big_endian else "little")
        return (w & 0xFFC003E0) == 0xA98003E0 or (w & 0xFF0003FF) == 0xD10003FF or w == 0xD503233F  # stp x,x,[sp,#-n]!; sub sp; paciasp

    def reg_names(self):
        return [f"x{i}" for i in range(31)] + ["sp"]


# =====================================================================
# MIPS / PPC / RISC-V / SPARC / M68K / others via generic capstone groups
# =====================================================================
class GenericArch(Arch):
    """Group-driven classification for architectures without bespoke handling."""
    CS_ARCH = None
    BR_OPS = ()

    def __init__(self, spec, cs_arch, cs_mode, align=4, max_insn=4, sp="sp", fp="fp", ra=None, nop=b""):
        self._cs_arch, self._cs_mode = cs_arch, cs_mode
        super().__init__(spec)
        self.insn_align, self.max_insn, self.sp, self.fp, self.ra = align, max_insn, sp, fp, ra
        self.nop_bytes = nop

    def _make_md(self, spec):
        return cs.Cs(self._cs_arch, self._cs_mode)

    def classify(self, ins, ci):
        grp = set(ci.groups)
        ops = ci.operands
        imm_ops = [o for o in ops if o.type == cs.CS_OP_IMM]
        mn = ci.mnemonic
        direct = imm_ops[-1].imm if imm_ops else None
        if cs.CS_GRP_RET in grp or cs.CS_GRP_IRET in grp:
            ins.flow = RET
        elif cs.CS_GRP_CALL in grp:
            if direct is not None:
                ins.flow, ins.targets = CALL, [direct]
            else:
                ins.flow = INDCALL
        elif cs.CS_GRP_JUMP in grp or cs.CS_GRP_BRANCH_RELATIVE in grp:
            if direct is not None:
                ins.targets = [direct]
                unconditional = mn in ("j", "b", "ba", "bra", "jmp", "jra", "bral", "jr") or mn.startswith("c.j") and mn != "c.jal"
                ins.flow = JMP if unconditional else CJMP
            else:
                ins.flow = INDJMP
        for o in imm_ops:
            if ins.flow == NORMAL:
                ins.imms.append(o.imm & ((1 << self.spec.bits) - 1))

    def is_nop(self, ins):
        return ins.mnemonic in ("nop", "c.nop")


class MIPS(GenericArch):
    def __init__(self, spec):
        mode = (cs.CS_MODE_MIPS64 if spec.bits == 64 else cs.CS_MODE_MIPS32) | \
               (cs.CS_MODE_BIG_ENDIAN if spec.big_endian else cs.CS_MODE_LITTLE_ENDIAN)
        super().__init__(spec, cs.CS_ARCH_MIPS, mode, 4, 4, "sp", "fp", "ra", b"\0\0\0\0")

    def classify(self, ins, ci):
        mn = ci.mnemonic
        ops = ci.operands
        grp = set(ci.groups)
        if mn == "jr" and ops and ops[0].type == cmips.MIPS_OP_REG and ops[0].reg == cmips.MIPS_REG_RA:
            ins.flow, ins.delay_slot = RET, True
            return
        if mn in ("jal", "bal", "bgezal", "bltzal") and ops and ops[-1].type == cmips.MIPS_OP_IMM:
            ins.flow, ins.targets, ins.delay_slot = CALL, [ops[-1].imm], True
            return
        if mn in ("jalr",):
            ins.flow, ins.delay_slot = INDCALL, True
            return
        if mn in ("jr",):
            ins.flow, ins.delay_slot = INDJMP, True
            return
        if mn in ("j", "b") and ops and ops[-1].type == cmips.MIPS_OP_IMM:
            ins.flow, ins.targets, ins.delay_slot = JMP, [ops[-1].imm], True
            return
        if cs.CS_GRP_JUMP in grp and ops and ops[-1].type == cmips.MIPS_OP_IMM:
            ins.flow, ins.targets, ins.delay_slot = CJMP, [ops[-1].imm], True
            return
        for o in ops:
            if o.type == cmips.MIPS_OP_IMM:
                ins.imms.append(o.imm & 0xFFFFFFFF)

    def track_refs(self, ins, state, img):
        ci = ins.cs_insn
        mn = ci.mnemonic
        ops = ci.operands
        if mn == "lui" and len(ops) == 2 and ops[1].type == cmips.MIPS_OP_IMM:
            state[ops[0].reg] = (ops[1].imm & 0xFFFF) << 16
        elif mn in ("addiu", "ori", "addi", "daddiu") and len(ops) == 3 and ops[1].reg in state \
                and ops[2].type == cmips.MIPS_OP_IMM:
            v = (state[ops[1].reg] + (ops[2].imm if mn != "ori" else ops[2].imm & 0xFFFF)) & 0xFFFFFFFF
            ins.refs.append(("offset", v))
            state[ops[0].reg] = v
        elif mn in ("lw", "sw", "lb", "lbu", "lh", "lhu", "sb", "sh") and len(ops) == 2 and \
                ops[1].type == cmips.MIPS_OP_MEM and ops[1].mem.base in state:
            ins.refs.append(("data", (state[ops[1].mem.base] + ops[1].mem.disp) & 0xFFFFFFFF))

    def looks_like_prologue(self, buf):
        if len(buf) < 4:
            return False
        w = int.from_bytes(buf[:4], "big" if self.spec.big_endian else "little")
        return (w & 0xFFFF0000) == 0x27BD0000 and (w & 0x8000) != 0   # addiu sp, sp, -N

    def reg_names(self):
        return ["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3"] + [f"t{i}" for i in range(8)] + \
               [f"s{i}" for i in range(8)] + ["gp", "sp", "fp", "ra"]


class PPC(GenericArch):
    def __init__(self, spec):
        mode = (cs.CS_MODE_64 if spec.bits == 64 else cs.CS_MODE_32) | \
               (cs.CS_MODE_BIG_ENDIAN if spec.big_endian else cs.CS_MODE_LITTLE_ENDIAN)
        super().__init__(spec, cs.CS_ARCH_PPC, mode, 4, 4, "r1", "r31", "lr", b"\x60\0\0\0")

    def classify(self, ins, ci):
        mn = ci.mnemonic
        imm = [o for o in ci.operands if o.type == cppc.PPC_OP_IMM]
        grp = set(ci.groups)
        if mn == "blr":
            ins.flow = RET
        elif mn in ("blrl", "bctrl"):
            ins.flow = INDCALL
        elif mn == "bctr":
            ins.flow = INDJMP
        elif mn in ("bl", "bla") and imm:
            ins.flow, ins.targets = CALL, [imm[-1].imm]
        elif mn in ("b", "ba") and imm:
            ins.flow, ins.targets = JMP, [imm[-1].imm]
        elif cs.CS_GRP_JUMP in grp or (mn.startswith("b") and mn.endswith(("lr", "ctr"))):
            ins.flow = CJMP
            ins.targets = [imm[-1].imm] if imm else []
        else:
            for o in imm:
                ins.imms.append(o.imm & 0xFFFFFFFF)

    def track_refs(self, ins, state, img):
        ci = ins.cs_insn
        mn = ci.mnemonic
        ops = ci.operands
        if mn == "lis" and len(ops) == 2 and ops[1].type == cppc.PPC_OP_IMM:
            state[ops[0].reg] = (ops[1].imm & 0xFFFF) << 16
        elif mn in ("addi", "ori") and len(ops) == 3 and ops[1].type == cppc.PPC_OP_REG and ops[1].reg in state \
                and ops[2].type == cppc.PPC_OP_IMM:
            v = (state[ops[1].reg] + ops[2].imm) & 0xFFFFFFFF
            ins.refs.append(("offset", v))
            state[ops[0].reg] = v

    def looks_like_prologue(self, buf):
        return buf[:4] in (b"\x94\x21\xff\xe0", b"\x94\x21\xff\xf0", b"\x7c\x08\x02\xa6") or buf[:2] == b"\x94\x21"


class RISCV(GenericArch):
    def __init__(self, spec):
        mode = (cs.CS_MODE_RISCV64 if spec.bits == 64 else cs.CS_MODE_RISCV32) | cs.CS_MODE_RISCVC
        super().__init__(spec, cs.CS_ARCH_RISCV, mode, 2, 4, "sp", "s0", "ra", b"\x13\0\0\0")

    def classify(self, ins, ci):
        mn = ci.mnemonic
        ops = ci.operands
        regs = [o for o in ops if o.type == criscv.RISCV_OP_REG]
        imm = [o for o in ops if o.type == criscv.RISCV_OP_IMM]
        names = [ci.reg_name(o.reg) for o in regs]
        if mn in ("ret", "c.jr") and (mn == "ret" or names[:1] == ["ra"]):
            ins.flow = RET
        elif mn == "jalr" or mn == "c.jalr":
            if mn == "jalr" and names[:2] == ["zero", "ra"]:
                ins.flow = RET
            elif mn == "jalr" and names[:1] == ["zero"]:
                ins.flow = INDJMP
            else:
                ins.flow = INDCALL
        elif mn == "c.jr":
            ins.flow = INDJMP
        elif mn in ("jal", "c.jal"):
            if imm:
                if names[:1] == ["zero"] or mn == "c.j":
                    ins.flow = JMP
                else:
                    ins.flow = CALL
                ins.targets = [imm[-1].imm]
        elif mn in ("j", "c.j"):
            ins.flow, ins.targets = JMP, [imm[-1].imm]
        elif mn.startswith(("b", "c.b")) and imm and mn not in ("bset", "bclr", "binv", "bext"):
            ins.flow, ins.targets = CJMP, [imm[-1].imm]
        else:
            for o in imm:
                ins.imms.append(o.imm)

    def track_refs(self, ins, state, img):
        ci = ins.cs_insn
        mn = ci.mnemonic
        ops = ci.operands
        if mn == "auipc" and len(ops) == 2 and ops[1].type == criscv.RISCV_OP_IMM:
            state[ops[0].reg] = ci.address + (ops[1].imm << 12)
        elif mn == "lui" and len(ops) == 2 and ops[1].type == criscv.RISCV_OP_IMM:
            state[ops[0].reg] = ops[1].imm << 12
        elif mn == "addi" and len(ops) == 3 and ops[1].type == criscv.RISCV_OP_REG and ops[1].reg in state \
                and ops[2].type == criscv.RISCV_OP_IMM:
            v = state[ops[1].reg] + ops[2].imm
            ins.refs.append(("offset", v))
            state[ops[0].reg] = v

    def looks_like_prologue(self, buf):
        if len(buf) < 4:
            return False
        w = int.from_bytes(buf[:4], "little")
        return (w & 0xFFFFF) == 0x10113 and (w >> 31)      # addi sp, sp, -N


class Sparc(GenericArch):
    def __init__(self, spec):
        super().__init__(spec, cs.CS_ARCH_SPARC, cs.CS_MODE_BIG_ENDIAN | (cs.CS_MODE_V9 if spec.bits == 64 else 0), 4, 4,
                         "o6", "i6", "i7", b"\x01\0\0\0")

    def classify(self, ins, ci):
        super().classify(ins, ci)
        if ins.flow in (JMP, CJMP, CALL, RET, INDJMP, INDCALL):
            ins.delay_slot = True
        if ci.mnemonic in ("retl", "ret", "restore") and ci.mnemonic != "restore":
            ins.flow = RET

    def looks_like_prologue(self, buf):
        return buf[:2] == b"\x9d\xe3"   # save %sp, -N, %sp


class M68K(GenericArch):
    def __init__(self, spec):
        super().__init__(spec, cs.CS_ARCH_M68K, cs.CS_MODE_M68K_040 | cs.CS_MODE_BIG_ENDIAN, 2, 10, "a7", "a6", None, b"\x4e\x71")

    def looks_like_prologue(self, buf):
        return buf[:2] == b"\x4e\x56"   # link a6, #n


class MOS6502(GenericArch):
    def __init__(self, spec):
        super().__init__(spec, cs.CS_ARCH_MOS65XX, cs.CS_MODE_LITTLE_ENDIAN | getattr(cs, "CS_MODE_MOS65XX_6502", 0), 1, 3, "s", "s", None, b"\xea")


class SysZ(GenericArch):
    def __init__(self, spec):
        super().__init__(spec, cs.CS_ARCH_SYSZ, cs.CS_MODE_BIG_ENDIAN, 2, 6, "r15", "r11", "r14", b"\x07\x00")


_CACHE: Dict[str, Arch] = {}
_FACTORIES: Dict[str, object] = {}


def register_arch(name: str, factory) -> None:
    """Register a processor module: `factory(spec: ArchSpec) -> Arch` (subclass `Arch`/`GenericArch`)."""
    _FACTORIES[name] = factory
    _CACHE.clear()


def get_arch(spec: ArchSpec) -> Arch:
    key = spec.key
    if key in _CACHE:
        return _CACHE[key]
    if spec.name in _FACTORIES:
        a = _FACTORIES[spec.name](spec)
        _CACHE[key] = a
        return a
    n = spec.name
    if n == "x86":
        a = X86(spec)
    elif n in ("arm", "thumb"):
        a = ARM(spec)
    elif n == "arm64":
        a = ARM64(spec)
    elif n == "mips":
        a = MIPS(spec)
    elif n == "ppc":
        a = PPC(spec)
    elif n == "riscv":
        a = RISCV(spec)
    elif n == "sparc":
        a = Sparc(spec)
    elif n == "m68k":
        a = M68K(spec)
    elif n == "mos65xx":
        a = MOS6502(spec)
    elif n == "sysz":
        a = SysZ(spec)
    else:
        raise ValueError(f"unsupported architecture {spec.name}")
    _CACHE[key] = a
    return a


SUPPORTED = ["x86 (16/32/64)", "arm", "thumb", "arm64", "mips (32/64, BE/LE)", "ppc (32/64)", "riscv (32/64)",
             "sparc", "m68k", "mos65xx", "sysz"]
