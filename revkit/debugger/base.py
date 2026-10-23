"""Debugger session interface shared by all back-ends (native Windows, remote GDB RSP, emulator stub)."""
from __future__ import annotations

import ast
import operator
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


class DebugError(Exception):
    pass


@dataclass
class Breakpoint:
    id: int
    addr: int                       # runtime address
    kind: str = "sw"                # sw | hw-exec | hw-write | hw-rw
    size: int = 1
    condition: str = ""
    enabled: bool = True
    hits: int = 0
    temporary: bool = False
    static_addr: Optional[int] = None
    orig: bytes = b""
    slot: Optional[int] = None      # debug register slot for hw breakpoints

    def to_dict(self):
        return {"id": self.id, "addr": self.addr, "static_addr": self.static_addr, "kind": self.kind, "size": self.size,
                "condition": self.condition, "enabled": self.enabled, "hits": self.hits, "temporary": self.temporary}


@dataclass
class Module:
    name: str
    base: int
    size: int = 0
    path: str = ""

    def to_dict(self):
        return {"name": self.name, "base": self.base, "size": self.size, "path": self.path}


@dataclass
class DebugEvent:
    kind: str                       # breakpoint | step | exception | exit | module_load | module_unload | thread_create |
    #                                 thread_exit | output | started | signal | stopped
    tid: int = 0
    addr: int = 0
    info: Dict[str, object] = field(default_factory=dict)

    def to_dict(self):
        return {"kind": self.kind, "tid": self.tid, "addr": self.addr, **self.info}


class DebugSession:
    """Abstract debugger. Addresses taken/returned by the public API are *runtime* addresses unless noted."""
    arch: str = ""
    bits: int = 64

    def __init__(self, proj=None):
        self.proj = proj
        self.breakpoints: Dict[int, Breakpoint] = {}
        self._next_bp = 1
        self.modules: List[Module] = []
        self.listeners: List[Callable[[DebugEvent], None]] = []
        self.main_base: Optional[int] = None
        self.state = "idle"          # idle | running | stopped | exited
        self.last_event: Optional[DebugEvent] = None

    # ----- lifecycle -----------------------------------------------------------------------------------------
    def launch(self, path: str, args: Optional[List[str]] = None, cwd: Optional[str] = None) -> DebugEvent:
        raise NotImplementedError

    def attach(self, pid: int) -> DebugEvent:
        raise NotImplementedError

    def detach(self):
        raise NotImplementedError

    def kill(self):
        raise NotImplementedError

    # ----- execution control ---------------------------------------------------------------------------------
    def cont(self, timeout: Optional[float] = None) -> DebugEvent:
        raise NotImplementedError

    def step_into(self) -> DebugEvent:
        raise NotImplementedError

    def step_over(self) -> DebugEvent:
        ins = self.current_insn()
        if ins is not None and ins.flow in ("call", "indcall"):
            return self.run_to(ins.end)
        return self.step_into()

    def step_out(self) -> DebugEvent:
        ret = self.return_address()
        if ret is None:
            raise DebugError("cannot determine the return address")
        return self.run_to(ret)

    def run_to(self, addr: int, timeout: Optional[float] = None) -> DebugEvent:
        bp = self.add_breakpoint(addr, temporary=True)
        try:
            ev = self.cont(timeout)
        finally:
            if bp.id in self.breakpoints:
                self.remove_breakpoint(bp.id)
        if ev.kind == "breakpoint" and ev.info.get("id") == bp.id:
            ev.kind = "step"
            ev.info.pop("id", None)
        return ev

    def pause(self):
        raise NotImplementedError

    # ----- breakpoints ---------------------------------------------------------------------------------------
    def add_breakpoint(self, addr: int, kind: str = "sw", size: int = 1, condition: str = "", temporary: bool = False) -> Breakpoint:
        raise NotImplementedError

    def remove_breakpoint(self, bid: int):
        raise NotImplementedError

    def set_breakpoint_enabled(self, bid: int, enabled: bool):
        raise NotImplementedError

    # ----- state ---------------------------------------------------------------------------------------------
    def registers(self, tid: Optional[int] = None) -> Dict[str, int]:
        raise NotImplementedError

    def set_register(self, name: str, value: int, tid: Optional[int] = None):
        raise NotImplementedError

    def read_memory(self, addr: int, size: int) -> bytes:
        raise NotImplementedError

    def write_memory(self, addr: int, data: bytes):
        raise NotImplementedError

    def threads(self) -> List[dict]:
        return []

    def select_thread(self, tid: int):
        raise NotImplementedError

    def memory_map(self) -> List[dict]:
        return []

    # ----- derived helpers (back-end independent) ------------------------------------------------------------
    def pc(self) -> int:
        regs = self.registers()
        for n in ("rip", "eip", "pc"):
            if n in regs:
                return regs[n]
        raise DebugError("no program counter register")

    def sp(self) -> int:
        regs = self.registers()
        for n in ("rsp", "esp", "sp"):
            if n in regs:
                return regs[n]
        raise DebugError("no stack pointer register")

    def current_insn(self):
        if self.proj is None:
            return None
        a = self.pc()
        buf = self.read_memory(a, 16)
        return self.proj.db.arch.decode_bytes(buf, a)

    def disasm(self, addr: Optional[int] = None, count: int = 8) -> List[dict]:
        a = self.pc() if addr is None else addr
        out = []
        arch = self.proj.db.arch
        for _ in range(count):
            buf = self.read_memory(a, 16)
            ins = arch.decode_bytes(buf, a)
            if ins is None:
                break
            out.append({"addr": a, "static": self.to_static(a), "bytes": ins.raw.hex(" "), "text": ins.text})
            a += ins.size
        return out

    def stack(self, depth: int = 32) -> List[dict]:
        """Raw stack words plus return-address candidates annotated with static function names."""
        sp = self.sp()
        w = self.bits // 8
        out = []
        data = self.read_memory(sp, w * depth)
        for i in range(0, len(data) - w + 1, w):
            v = int.from_bytes(data[i:i + w], "little")
            entry = {"addr": sp + i, "value": v}
            f = self._function_for_runtime(v)
            if f:
                entry["symbol"] = f
            out.append(entry)
        return out

    def backtrace(self, max_frames: int = 32) -> List[dict]:
        """Frame-pointer based unwind with return-address validation; falls back to stack scanning."""
        frames = [{"pc": self.pc(), "sp": self.sp(), "symbol": self._function_for_runtime(self.pc())}]
        regs = self.registers()
        w = self.bits // 8
        fp = regs.get("rbp") or regs.get("ebp") or regs.get("x29") or 0
        seen = set()
        while fp and fp not in seen and len(frames) < max_frames:
            seen.add(fp)
            try:
                nxt = int.from_bytes(self.read_memory(fp, w), "little")
                ret = int.from_bytes(self.read_memory(fp + w, w), "little")
            except DebugError:
                break
            if not self._looks_like_code(ret):
                break
            frames.append({"pc": ret, "sp": fp + 2 * w, "symbol": self._function_for_runtime(ret)})
            if nxt <= fp:
                break
            fp = nxt
        if len(frames) == 1:
            for e in self.stack(64):
                if self._looks_like_code(e["value"]) and self._after_call(e["value"]):
                    frames.append({"pc": e["value"], "sp": e["addr"] + w, "symbol": self._function_for_runtime(e["value"])})
                    if len(frames) >= max_frames:
                        break
        return frames

    def return_address(self) -> Optional[int]:
        for fr in self.backtrace(4)[1:2]:
            return fr["pc"]
        return None

    def _looks_like_code(self, v: int) -> bool:
        for m in self.modules:
            if m.base <= v < m.base + max(m.size, 1):
                return True
        return False

    def _after_call(self, v: int) -> bool:
        try:
            b = self.read_memory(v - 7, 7)
        except DebugError:
            return False
        return b[2:3] == b"\xe8" or b[1:3] == b"\xff\x15" or b[5:7] in (b"\xff\xd0", b"\xff\xd1", b"\xff\xd2") or b[-2:-1] == b"\xff" or b[-5:-4] == b"\xe8" or b[-6:-4] == b"\xff\x15"

    # ----- address translation -------------------------------------------------------------------------------
    def to_static(self, addr: int) -> Optional[int]:
        if self.proj is None or self.main_base is None:
            return None
        base = self.proj.image.imagebase
        sz = max(s.end for s in self.proj.image.segments) - base
        if self.main_base <= addr < self.main_base + sz:
            return addr - self.main_base + base
        return None

    def to_runtime(self, static: int) -> int:
        if self.main_base is None:
            return static
        return static - self.proj.image.imagebase + self.main_base

    def _function_for_runtime(self, v: int) -> Optional[str]:
        s = self.to_static(v)
        if s is not None and self.proj is not None:
            f = self.proj.db.function_at(s)
            if f:
                off = s - f.start
                return self.proj.db.display_name(f.start) + (f"+{off:#x}" if off else "")
        for m in self.modules:
            if m.base <= v < m.base + max(m.size, 1):
                return f"{m.name}+{v - m.base:#x}"
        return None

    # ----- expression evaluation -----------------------------------------------------------------------------
    def evaluate(self, expr: str) -> int:
        regs = {k.lower(): v for k, v in self.registers().items()}
        return safe_eval(expr, regs, self.read_memory, self.bits // 8, {m.name.lower().split(".")[0]: m.base for m in self.modules})

    def _fire(self, ev: DebugEvent):
        self.last_event = ev
        for l in list(self.listeners):
            try:
                l(ev)
            except Exception:
                pass


# ---------------------------------------------------------------------------------------------------------------
_BIN = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.BitAnd: operator.and_,
        ast.BitOr: operator.or_, ast.BitXor: operator.xor, ast.LShift: operator.lshift, ast.RShift: operator.rshift,
        ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod}
_CMP = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt, ast.LtE: operator.le, ast.Gt: operator.gt,
        ast.GtE: operator.ge}


def safe_eval(expr: str, regs: Dict[str, int], read_mem, ptr: int, symbols: Optional[Dict[str, int]] = None) -> int:
    """Evaluate a restricted expression: registers, hex/dec numbers, + - * & | ^ << >>, comparisons, and
    byte(addr)/word/dword/qword/ptr(addr) memory reads. No attribute access, calls to other names, or builtins."""
    tree = ast.parse(expr.strip(), mode="eval").body
    syms = symbols or {}

    def ev(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, int):
            return n.value
        if isinstance(n, ast.Name):
            k = n.id.lower()
            if k in regs:
                return regs[k]
            if k in syms:
                return syms[k]
            raise ValueError(f"unknown name {n.id!r}")
        if isinstance(n, ast.BinOp) and type(n.op) in _BIN:
            return _BIN[type(n.op)](ev(n.left), ev(n.right))
        if isinstance(n, ast.UnaryOp):
            v = ev(n.operand)
            return -v if isinstance(n.op, ast.USub) else ~v if isinstance(n.op, ast.Invert) else (not v) if isinstance(n.op, ast.Not) else v
        if isinstance(n, ast.Compare) and len(n.ops) == 1 and type(n.ops[0]) in _CMP:
            return int(_CMP[type(n.ops[0])](ev(n.left), ev(n.comparators[0])))
        if isinstance(n, ast.BoolOp):
            vals = [ev(v) for v in n.values]
            return int(all(vals)) if isinstance(n.op, ast.And) else int(any(vals))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and len(n.args) == 1 and not n.keywords:
            sizes = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "ptr": ptr}
            if n.func.id in sizes:
                sz = sizes[n.func.id]
                return int.from_bytes(read_mem(ev(n.args[0]), sz), "little")
        raise ValueError(f"unsupported expression element: {type(n).__name__}")
    return ev(tree)
