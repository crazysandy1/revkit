"""Decompiler IR: expressions, statements, algebraic simplification and C pretty printing."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

MASKS = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF, 16: (1 << 128) - 1}


def mask(size: int) -> int:
    return MASKS.get(size, (1 << (size * 8)) - 1)


def sign(v: int, size: int) -> int:
    v &= mask(size)
    return v - (1 << (size * 8)) if v >> (size * 8 - 1) else v


# --------------------------------------------------------------------------- expressions
class Expr:
    __slots__ = ()
    size: int = 0

    def key(self):
        raise NotImplementedError

    def __eq__(self, o):
        return isinstance(o, Expr) and self.key() == o.key()

    def __hash__(self):
        return hash(self.key())

    def children(self) -> List["Expr"]:
        return []

    def map(self, fn) -> "Expr":
        """Rebuild bottom-up applying fn to each rebuilt node."""
        return fn(self)

    def __repr__(self):
        return fmt(self)


class Const(Expr):
    __slots__ = ("v", "size", "sym")

    def __init__(self, v: int, size: int = 4, sym: str = ""):
        self.v = v & mask(size) if size else v
        self.size = size
        self.sym = sym

    def key(self):
        return ("c", self.v, self.size)


class Reg(Expr):
    """Architectural register (full-width family name), before variable recovery."""
    __slots__ = ("name", "size")

    def __init__(self, name: str, size: int):
        self.name, self.size = name, size

    def key(self):
        return ("r", self.name, self.size)


class Var(Expr):
    """Recovered variable (local, argument, stack slot)."""
    __slots__ = ("name", "size", "kind", "ty", "off", "ptr")

    def __init__(self, name: str, size: int, kind: str = "local", ty: str = "", off: Optional[int] = None):
        self.name, self.size, self.kind, self.ty, self.off = name, size, kind, ty, off
        self.ptr = False

    def key(self):
        return ("v", self.name)


class Mem(Expr):
    __slots__ = ("addr", "size", "seg")

    def __init__(self, addr: Expr, size: int, seg: str = ""):
        self.addr, self.size, self.seg = addr, size, seg

    def key(self):
        return ("m", self.addr.key(), self.size, self.seg)

    def children(self):
        return [self.addr]

    def map(self, fn):
        return fn(Mem(self.addr.map(fn), self.size, self.seg))


class Bin(Expr):
    __slots__ = ("op", "a", "b", "size")

    def __init__(self, op: str, a: Expr, b: Expr, size: int = 0):
        self.op, self.a, self.b = op, a, b
        self.size = size or (a.size if op not in CMP_OPS else 1)

    def key(self):
        return ("b", self.op, self.a.key(), self.b.key(), self.size)

    def children(self):
        return [self.a, self.b]

    def map(self, fn):
        return fn(Bin(self.op, self.a.map(fn), self.b.map(fn), self.size))


class Un(Expr):
    __slots__ = ("op", "a", "size")

    def __init__(self, op: str, a: Expr, size: int = 0):
        self.op, self.a = op, a
        self.size = size or (a.size if op != "!" else 1)

    def key(self):
        return ("u", self.op, self.a.key(), self.size)

    def children(self):
        return [self.a]

    def map(self, fn):
        return fn(Un(self.op, self.a.map(fn), self.size))


class Cast(Expr):
    """kind: 'sx' sign-extend, 'zx' zero-extend, 'tr' truncate."""
    __slots__ = ("kind", "a", "size")

    def __init__(self, kind: str, a: Expr, size: int):
        self.kind, self.a, self.size = kind, a, size

    def key(self):
        return ("x", self.kind, self.a.key(), self.size)

    def children(self):
        return [self.a]

    def map(self, fn):
        return fn(Cast(self.kind, self.a.map(fn), self.size))


class Ite(Expr):
    __slots__ = ("c", "a", "b", "size")

    def __init__(self, c: Expr, a: Expr, b: Expr):
        self.c, self.a, self.b = c, a, b
        self.size = a.size

    def key(self):
        return ("i", self.c.key(), self.a.key(), self.b.key())

    def children(self):
        return [self.c, self.a, self.b]

    def map(self, fn):
        return fn(Ite(self.c.map(fn), self.a.map(fn), self.b.map(fn)))


class CallE(Expr):
    __slots__ = ("target", "args", "name", "size", "proto", "addr", "cc", "noret")

    def __init__(self, target: Expr, args: List[Expr], name: str = "", size: int = 8, proto=None, addr: int = 0,
                 cc: str = "", noret: bool = False):
        self.target, self.args, self.name, self.size, self.proto, self.addr, self.cc, self.noret = \
            target, args, name, size, proto, addr, cc, noret

    def key(self):
        return ("call", self.target.key(), tuple(a.key() for a in self.args), self.addr)

    def children(self):
        return [self.target] + list(self.args)

    def map(self, fn):
        return fn(CallE(self.target.map(fn), [a.map(fn) for a in self.args], self.name, self.size, self.proto,
                        self.addr, self.cc, self.noret))


class Intr(Expr):
    """Opaque intrinsic / unmodelled operation."""
    __slots__ = ("name", "args", "size")

    def __init__(self, name: str, args: List[Expr], size: int = 0):
        self.name, self.args, self.size = name, args, size

    def key(self):
        return ("intr", self.name, tuple(a.key() for a in self.args), self.size)

    def children(self):
        return list(self.args)

    def map(self, fn):
        return fn(Intr(self.name, [a.map(fn) for a in self.args], self.size))


CMP_OPS = {"==", "!=", "<", "<=", ">", ">=", "u<", "u<=", "u>", "u>=", "&&", "||"}
NEG_CMP = {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=", ">=": "<",
           "u<": "u>=", "u<=": "u>", "u>": "u<=", "u>=": "u<"}
COMMUT = {"+", "*", "&", "|", "^", "==", "!="}


# --------------------------------------------------------------------------- statements
class Stmt:
    addr: int = 0


class Assign(Stmt):
    def __init__(self, dst: Expr, src: Expr, addr: int = 0):
        self.dst, self.src, self.addr = dst, src, addr

    def __repr__(self):
        return f"{fmt(self.dst)} = {fmt(self.src)}"


class ExprStmt(Stmt):
    def __init__(self, e: Expr, addr: int = 0):
        self.e, self.addr = e, addr

    def __repr__(self):
        return fmt(self.e)


class Goto(Stmt):
    def __init__(self, target: int, addr: int = 0):
        self.target, self.addr = target, addr


class CJump(Stmt):
    def __init__(self, cond: Expr, t: int, f: int, addr: int = 0):
        self.cond, self.t, self.f, self.addr = cond, t, f, addr


class Return(Stmt):
    def __init__(self, e: Optional[Expr] = None, addr: int = 0):
        self.e, self.addr = e, addr


class SwitchJ(Stmt):
    def __init__(self, index: Expr, cases: List[Tuple[int, int]], addr: int = 0):
        self.index, self.cases, self.addr = index, cases, addr   # cases: (value, target block)


class Comment(Stmt):
    def __init__(self, text: str, addr: int = 0):
        self.text, self.addr = text, addr


class AsmStmt(Stmt):
    def __init__(self, text: str, addr: int = 0):
        self.text, self.addr = text, addr


# --------------------------------------------------------------------------- simplifier
def simplify(e: Expr) -> Expr:
    return e.map(_simp1)


def _is_c(e) -> bool:
    return isinstance(e, Const)


def _simp1(e: Expr) -> Expr:
    if isinstance(e, Cast):
        a = e.a
        if e.kind == "tr":
            if a.size == e.size:
                return a
            if isinstance(a, Const):
                return Const(a.v, e.size)
            if isinstance(a, Cast) and a.kind in ("zx", "sx"):
                if a.a.size == e.size:
                    return a.a
                if a.a.size > e.size:
                    return simplify(Cast("tr", a.a, e.size))
                if a.a.size < e.size:
                    return Cast(a.kind, a.a, e.size)
            if isinstance(a, Cast) and a.kind == "tr":
                return Cast("tr", a.a, e.size)
            if isinstance(a, Bin) and a.op in ("+", "-", "*", "&", "|", "^", "<<") and not isinstance(a.a, Mem):
                # truncation distributes over ring ops: tr(a op b) = tr(a) op tr(b)
                if a.op != "<<":
                    return simplify(Bin(a.op, Cast("tr", a.a, e.size), Cast("tr", a.b, e.size), e.size))
            if isinstance(a, CallE) and a.proto is None:
                return CallE(a.target, a.args, a.name, e.size, a.proto, a.addr, a.cc, a.noret)
            if isinstance(a, Mem) and a.size >= e.size:
                return e   # keep: reading part of memory
        if e.kind in ("zx", "sx"):
            if a.size == e.size:
                return a
            if isinstance(a, Const):
                v = a.v if e.kind == "zx" else sign(a.v, a.size)
                return Const(v, e.size)
            if isinstance(a, Cast) and a.kind == e.kind and a.a.size <= a.size:
                return Cast(e.kind, a.a, e.size)
            if e.kind == "sx" and isinstance(a, Cast) and a.kind == "zx" and a.a.size < a.size:
                return Cast("zx", a.a, e.size)
        return e
    if isinstance(e, Un):
        a = e.a
        if e.op == "!" and isinstance(a, Bin) and a.op in NEG_CMP:
            return Bin(NEG_CMP[a.op], a.a, a.b, 1)
        if e.op == "!" and isinstance(a, Un) and a.op == "!":
            return a.a
        if e.op == "-" and isinstance(a, Const):
            return Const(-a.v, e.size)
        if e.op == "~" and isinstance(a, Const):
            return Const(~a.v, e.size)
        if e.op == "-" and isinstance(a, Un) and a.op == "-":
            return a.a
        if e.op == "~" and isinstance(a, Un) and a.op == "~":
            return a.a
        return e
    if isinstance(e, Bin):
        a, b, op = e.a, e.b, e.op
        sz = e.size
        if _is_c(a) and _is_c(b):
            r = _fold(op, a, b, sz)
            if r is not None:
                return r
        if op in COMMUT and _is_c(a) and not _is_c(b):
            a, b = b, a
            e = Bin(op, a, b, sz)
        if op == "+":
            if _is_c(b) and b.v == 0:
                return a
            if isinstance(a, Bin) and a.op == "+" and _is_c(a.b) and _is_c(b):
                return simplify(Bin("+", a.a, Const(a.b.v + b.v, sz), sz))
            if isinstance(a, Bin) and a.op == "-" and _is_c(a.b) and _is_c(b):
                return simplify(Bin("+", a.a, Const(b.v - a.b.v, sz), sz))
            if isinstance(b, Un) and b.op == "-":
                return Bin("-", a, b.a, sz)
        if op == "-":
            if _is_c(b) and b.v == 0:
                return a
            if _is_c(b):
                return simplify(Bin("+", a, Const(-b.v, sz), sz))
            if a == b:
                return Const(0, sz)
        if op == "*":
            if _is_c(b) and b.v == 1:
                return a
            if _is_c(b) and b.v == 0:
                return Const(0, sz)
            if isinstance(a, Bin) and a.op == "*" and _is_c(a.b) and _is_c(b):
                return simplify(Bin("*", a.a, Const(a.b.v * b.v, sz), sz))
        if op == "<<" and _is_c(b):
            if b.v == 0:
                return a
            if isinstance(a, Bin) and a.op == "<<" and _is_c(a.b):
                return simplify(Bin("<<", a.a, Const(a.b.v + b.v, sz), sz))
        if op in (">>", "sar") and _is_c(b) and b.v == 0:
            return a
        if op == "&":
            if _is_c(b):
                if b.v == mask(sz):
                    return a
                if b.v == 0:
                    return Const(0, sz)
                if isinstance(a, Cast) and a.kind == "zx" and a.a.size * 8 <= 64 and b.v == mask(a.a.size):
                    return a
            if a == b:
                return a
        if op == "|":
            if _is_c(b) and b.v == 0:
                return a
            if a == b:
                return a
        if op == "^":
            if a == b:
                return Const(0, sz)
            if _is_c(b) and b.v == 0:
                return a
            if _is_c(b) and b.v == mask(sz):
                return Un("~", a, sz)
        if op in ("==", "!=") and isinstance(a, Bin) and a.op in CMP_OPS and _is_c(b) and b.v in (0, 1):
            truth = (b.v == 1) == (op == "==")
            return a if truth else simplify(Un("!", a, 1))
        if op in ("==", "!=") and isinstance(a, Bin) and a.op == "-" and _is_c(b) and b.v == 0 and False:
            return Bin(op, a.a, a.b, 1)
        if op in ("==", "!=") and isinstance(a, Bin) and a.op == "+" and _is_c(a.b) and _is_c(b):
            return simplify(Bin(op, a.a, Const(b.v - a.b.v, a.size), 1))
        if op in ("==", "!=", "<", ">", "<=", ">=", "u<", "u>", "u<=", "u>=") and isinstance(a, Cast) and a.kind == "zx" \
                and _is_c(b) and b.v < (1 << (a.a.size * 8)):
            return Bin(op, a.a, Const(b.v, a.a.size), 1)
        return e
    if isinstance(e, Ite):
        if isinstance(e.c, Const):
            return e.a if e.c.v else e.b
    return e


def _fold(op: str, a: Const, b: Const, sz: int) -> Optional[Const]:
    x, y = a.v, b.v
    sx, sy = sign(x, a.size), sign(y, b.size)
    try:
        if op == "+":
            return Const(x + y, sz)
        if op == "-":
            return Const(x - y, sz)
        if op == "*":
            return Const(x * y, sz)
        if op == "&":
            return Const(x & y, sz)
        if op == "|":
            return Const(x | y, sz)
        if op == "^":
            return Const(x ^ y, sz)
        if op == "<<":
            return Const(x << y, sz) if y < 128 else Const(0, sz)
        if op == ">>":
            return Const(x >> y, sz)
        if op == "sar":
            return Const(sx >> min(y, 127), sz)
        if op == "==":
            return Const(int(x == y), 1)
        if op == "!=":
            return Const(int(x != y), 1)
        if op == "<":
            return Const(int(sx < sy), 1)
        if op == "<=":
            return Const(int(sx <= sy), 1)
        if op == ">":
            return Const(int(sx > sy), 1)
        if op == ">=":
            return Const(int(sx >= sy), 1)
        if op == "u<":
            return Const(int(x < y), 1)
        if op == "u<=":
            return Const(int(x <= y), 1)
        if op == "u>":
            return Const(int(x > y), 1)
        if op == "u>=":
            return Const(int(x >= y), 1)
        if op == "/" and sy:
            return Const(int(sx / sy) if (sx < 0) != (sy < 0) else sx // sy, sz)
        if op == "u/" and y:
            return Const(x // y, sz)
        if op == "%" and sy:
            return Const(sx - sy * int(sx / sy), sz)
        if op == "u%" and y:
            return Const(x % y, sz)
    except (OverflowError, ValueError):
        return None
    return None


# --------------------------------------------------------------------------- printing
_PREC = {"||": 1, "&&": 2, "|": 3, "^": 4, "&": 5, "==": 6, "!=": 6, "<": 7, "<=": 7, ">": 7, ">=": 7,
         "u<": 7, "u<=": 7, "u>": 7, "u>=": 7, "<<": 8, ">>": 8, "sar": 8, "+": 9, "-": 9, "*": 10, "/": 10,
         "%": 10, "u/": 10, "u%": 10}
_CTYPE = {1: "char", 2: "__int16", 4: "int", 8: "__int64", 16: "__int128"}
_UTYPE = {1: "unsigned __int8", 2: "unsigned __int16", 4: "unsigned int", 8: "unsigned __int64", 16: "unsigned __int128"}
_MTYPE = {1: "_BYTE", 2: "_WORD", 4: "_DWORD", 8: "_QWORD", 16: "_OWORD"}
OPSYM = {"u<": "<", "u<=": "<=", "u>": ">", "u>=": ">=", "sar": ">>", "u/": "/", "u%": "%"}


def ctype(size: int, signed: bool = True) -> str:
    return (_CTYPE if signed else _UTYPE).get(size, f"_BYTE[{size}]")


class Namer:
    """Hooks the printer uses to turn addresses into names."""

    def __init__(self, db=None):
        self.db = db

    def addr_name(self, v: int) -> Optional[str]:
        if self.db is None:
            return None
        n = self.db.names.get(v)
        if n:
            return n
        if v in self.db.functions or v in self.db.data:
            return self.db.display_name(v)
        return None

    def string_at(self, v: int) -> Optional[str]:
        if self.db is None:
            return None
        s = self.db.strings.get(v)
        return s.text if s else None


_DEFAULT_NAMER = Namer()


def fmt(e: Expr, namer: Namer = _DEFAULT_NAMER, parent: int = 0) -> str:
    if isinstance(e, Const):
        v = e.v
        if e.sym:
            return e.sym
        if e.size >= 4 and v >= 0x10000 or e.size == 8 and v > 0xFFFF:
            n = namer.addr_name(v)
            if n:
                return f"&{n}" if not (namer.db and v in namer.db.functions) else n
            s = namer.string_at(v)
            if s is not None:
                return '"' + _cesc(s) + '"'
        sv = sign(v, e.size) if e.size else v
        if sv < 0 and sv > -0x10000:
            return str(sv)
        if v < 10:
            return str(v)
        return hex(v) + ("u" if False else "")
    if isinstance(e, (Reg, Var)):
        return e.name
    if isinstance(e, Mem):
        return _fmt_mem(e, namer)
    if isinstance(e, Cast):
        if e.kind == "tr":
            return _paren(f"({ctype(e.size)}){fmt(e.a, namer, 11)}", parent, 11)
        if e.kind == "zx":
            return _paren(f"({ctype(e.size, False)}){fmt(e.a, namer, 11)}", parent, 11)
        return _paren(f"({ctype(e.size)}){fmt(e.a, namer, 11)}", parent, 11)
    if isinstance(e, Un):
        if e.op == "!":
            return _paren("!" + fmt(e.a, namer, 11), parent, 11)
        return _paren(e.op + fmt(e.a, namer, 11), parent, 11)
    if isinstance(e, Bin):
        p = _PREC.get(e.op, 6)
        sym = OPSYM.get(e.op, e.op)
        if e.op == "+" and isinstance(e.b, Const) and e.b.size and sign(e.b.v, e.b.size) < 0:
            return _paren(f"{fmt(e.a, namer, p)} - {fmt(Const(-sign(e.b.v, e.b.size), e.b.size), namer, p + 1)}", parent, p)
        a = fmt(e.a, namer, p)
        b = fmt(e.b, namer, p + 1)
        if e.op in ("u<", "u<=", "u>", "u>="):
            a = _ufmt(e.a, namer)
        if e.op in ("u/", "u%"):
            a = _ufmt(e.a, namer)
        if e.op == ">>" and not isinstance(e.a, Const):
            a = _ufmt(e.a, namer)
        return _paren(f"{a} {sym} {b}", parent, p)
    if isinstance(e, Ite):
        return _paren(f"{fmt(e.c, namer, 1)} ? {fmt(e.a, namer, 1)} : {fmt(e.b, namer, 1)}", parent, 0)
    if isinstance(e, CallE):
        if isinstance(e.target, Const):
            nm = e.name or namer.addr_name(e.target.v) or f"sub_{e.target.v:X}"
        else:
            nm = e.name or ("(" + fmt(e.target, namer, 0) + ")") if not isinstance(e.target, (Var, Reg)) else (e.name or f"{fmt(e.target, namer)}")
        return f"{nm}({', '.join(fmt(a, namer, 0) for a in e.args)})"
    if isinstance(e, Intr):
        return f"{e.name}({', '.join(fmt(a, namer, 0) for a in e.args)})"
    return "?"


def _ufmt(e: Expr, namer) -> str:
    """Format e as an unsigned operand without stacking redundant casts."""
    if isinstance(e, Const):
        return fmt(e, namer, 11)
    if isinstance(e, Cast) and e.kind in ("tr", "sx"):
        return f"({ctype(max(e.size, 1), False)}){fmt(e.a, namer, 11)}"
    if isinstance(e, Cast) and e.kind == "zx":
        return fmt(e, namer, 11)
    return f"({ctype(max(e.size, 1), False)}){fmt(e, namer, 11)}"


def _paren(s: str, parent: int, mine: int) -> str:
    return f"({s})" if parent > mine else s


def _fmt_mem(e: Mem, namer: Namer) -> str:
    a = e.addr
    if isinstance(a, Var) and a.kind == "stack":
        return a.name
    t = _MTYPE.get(e.size, f"_BYTE[{e.size}]")
    # global variable access
    if isinstance(a, Const):
        n = namer.addr_name(a.v)
        if n:
            return n
    if isinstance(a, Bin) and a.op == "+" and isinstance(a.b, Const) and a.b.size:
        off = sign(a.b.v, a.b.size)
        if off < 0:
            return f"*({t} *)({fmt(a.a, namer, 9)} - {hex(-off)})" if -off >= 10 else f"*({t} *)({fmt(a.a, namer, 9)} - {-off})"
    s = fmt(a, namer, 0)
    if isinstance(a, (Var, Reg)):
        return f"*({t} *){s}"
    return f"*({t} *)({s})" if not s.startswith("(") else f"*({t} *){s}"


def _cesc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


def walk(e: Expr):
    yield e
    for c in e.children():
        yield from walk(c)


def uses(e: Expr) -> List[Expr]:
    return [x for x in walk(e) if isinstance(x, (Reg, Var))]


def has_mem(e: Expr) -> bool:
    return any(isinstance(x, Mem) for x in walk(e))


def has_call(e: Expr) -> bool:
    return any(isinstance(x, (CallE,)) for x in walk(e))
