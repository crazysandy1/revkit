"""C type system: declaration parser, layout engine, enums/structs/typedefs, prototype library."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .image import ArchSpec


class TypeError_(Exception):
    pass


# ---------------------------------------------------------------------------
# type model
# ---------------------------------------------------------------------------
@dataclass
class T:
    pass


@dataclass
class Prim(T):
    name: str
    size: int
    signed: bool = True
    kind: str = "int"      # int, float, void, bool, char


@dataclass
class Ptr(T):
    target: T
    size: int = 8


@dataclass
class Arr(T):
    elem: T
    count: Optional[int]


@dataclass
class Field:
    name: str
    type: T
    offset: int = 0
    bits: Optional[int] = None
    bit_offset: int = 0


@dataclass
class Struct(T):
    name: str
    fields: List[Field] = field(default_factory=list)
    union: bool = False
    size: int = 0
    align: int = 1
    complete: bool = False
    packed: int = 0


@dataclass
class Enum(T):
    name: str
    members: List[Tuple[str, int]] = field(default_factory=list)
    size: int = 4
    flags: bool = False


@dataclass
class Func(T):
    ret: T
    params: List[Tuple[str, T]] = field(default_factory=list)
    cc: str = ""
    varargs: bool = False


@dataclass
class Named(T):
    """Reference to a typedef / tagged type, resolved through the manager."""
    name: str
    tag: str = ""        # "", "struct", "union", "enum"


CC_WORDS = {"__cdecl": "cdecl", "__stdcall": "stdcall", "__fastcall": "fastcall", "__thiscall": "thiscall",
            "__vectorcall": "vectorcall", "__usercall": "usercall", "__userpurge": "userpurge",
            "WINAPI": "stdcall", "CALLBACK": "stdcall", "APIENTRY": "stdcall", "NTAPI": "stdcall",
            "__ms_abi": "ms", "__sysv_abi": "sysv"}
QUALS = {"const", "volatile", "restrict", "__restrict", "__restrict__", "_Atomic", "__unaligned", "__ptr64",
         "__ptr32", "extern", "static", "inline", "__inline", "__forceinline", "register", "auto", "_Noreturn",
         "__noreturn", "__extension__", "_In_", "_Out_", "_Inout_", "_In_opt_", "_Out_opt_", "_Inout_opt_",
         "_Reserved_", "__in", "__out", "__inout", "__in_opt", "__out_opt", "FAR", "NEAR", "IN", "OUT", "OPTIONAL",
         "_Success_", "_Must_inspect_result_", "_Check_return_", "__declspec_dummy"}

_TOKEN = re.compile(r"""
    (?P<ws>\s+|//[^\n]*|/\*.*?\*/)
  | (?P<num>0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*)
  | (?P<id>[A-Za-z_$][A-Za-z_0-9$]*)
  | (?P<str>"(?:\\.|[^"\\])*")
  | (?P<chr>'(?:\\.|[^'\\])+')
  | (?P<op><<|>>|\.\.\.|[{}()\[\];,*=:+\-/%&|^~<>!?.#])
""", re.X | re.S)


def tokenize(src: str) -> List[str]:
    toks, pos = [], 0
    while pos < len(src):
        m = _TOKEN.match(src, pos)
        if not m:
            raise TypeError_(f"unexpected character {src[pos]!r} in declaration")
        pos = m.end()
        if m.lastgroup != "ws":
            toks.append(m.group())
    return toks


# ---------------------------------------------------------------------------
class TypeManager:
    def __init__(self, arch: ArchSpec, model: str = ""):
        self.arch = arch
        self.ptr = arch.bits // 8
        if not model:
            model = "ilp32" if arch.bits <= 32 else "lp64"
        self.model = model        # ilp32 | lp64 | llp64
        self.typedefs: Dict[str, T] = {}
        self.structs: Dict[str, Struct] = {}
        self.unions: Dict[str, Struct] = {}
        self.enums: Dict[str, Enum] = {}
        self.enum_consts: Dict[str, Tuple[str, int]] = {}
        self.protos: Dict[str, Func] = {}
        self.user_sources: List[str] = []
        self.macros: Dict[str, int] = {}
        self._install_builtin_prims()

    # -- primitives -----------------------------------------------------
    def _install_builtin_prims(self):
        lsz = 8 if self.model == "lp64" else 4
        self.prims = {
            "void": Prim("void", 0, False, "void"), "_Bool": Prim("_Bool", 1, False, "bool"),
            "char": Prim("char", 1, True, "char"), "signed char": Prim("signed char", 1, True, "char"),
            "unsigned char": Prim("unsigned char", 1, False, "char"),
            "short": Prim("short", 2), "unsigned short": Prim("unsigned short", 2, False),
            "int": Prim("int", 4), "unsigned int": Prim("unsigned int", 4, False),
            "long": Prim("long", lsz), "unsigned long": Prim("unsigned long", lsz, False),
            "long long": Prim("long long", 8), "unsigned long long": Prim("unsigned long long", 8, False),
            "float": Prim("float", 4, True, "float"), "double": Prim("double", 8, True, "float"),
            "long double": Prim("long double", 16 if self.model != "llp64" else 8, True, "float"),
            "__int128": Prim("__int128", 16), "unsigned __int128": Prim("unsigned __int128", 16, False),
        }
        for n, base in {"__int8": "char", "__int16": "short", "__int32": "int", "__int64": "long long",
                        "int8_t": "signed char", "uint8_t": "unsigned char", "int16_t": "short",
                        "uint16_t": "unsigned short", "int32_t": "int", "uint32_t": "unsigned int",
                        "int64_t": "long long", "uint64_t": "unsigned long long", "bool": "_Bool",
                        "wchar_t": "unsigned short" if self.model == "llp64" else "int"}.items():
            self.typedefs[n] = self.prims[base]
        sz = "unsigned long long" if self.arch.bits == 64 else "unsigned int"
        ss = "long long" if self.arch.bits == 64 else "int"
        for n in ("size_t", "uintptr_t", "uintmax_t", "ULONG_PTR", "DWORD_PTR", "SIZE_T"):
            self.typedefs[n] = self.prims[sz]
        for n in ("ssize_t", "ptrdiff_t", "intptr_t", "LONG_PTR", "SSIZE_T", "off_t"):
            self.typedefs[n] = self.prims[ss]

    def load_stdlib(self, platform: str = "any"):
        """Load the bundled prototype libraries. `platform` is "windows", "posix" or "any" (both, Windows wins)."""
        here = os.path.join(os.path.dirname(__file__), "typelibs")
        order = ["base.h", "libc.h"]
        if platform in ("posix", "any"):
            order.append("posix.h")
        if platform in ("windows", "any"):
            order.append("windows.h")
        for fn in order:
            p = os.path.join(here, fn)
            if os.path.exists(p):
                with open(p, encoding="utf8") as f:
                    self.parse_decls(f.read(), user=False)

    # -- parsing entry points ---------------------------------------------
    def parse_decls(self, src: str, user: bool = True) -> List[str]:
        """Parse a block of C declarations. Returns names declared. Raises TypeError_ with context."""
        src = self._preprocess(src)
        p = _Parser(self, tokenize(src))
        names = p.parse_translation_unit()
        if user:
            self.user_sources.append(src)
            if getattr(self, "on_user_source", None):
                self.on_user_source(src)
        return names

    def _preprocess(self, src: str) -> str:
        out = []
        for line in src.splitlines():
            s = line.strip()
            if s.startswith("#"):
                pm = re.match(r"#\s*pragma\s+pack\s*\(\s*(?:push\s*,\s*)?(\d*)\s*\)", s)
                if pm:
                    out.append(f"__rk_pack({pm.group(1) or 0});")
                    continue
                if re.match(r"#\s*pragma\s+pack\s*\(\s*pop\s*\)", s):
                    out.append("__rk_pack(0);")
                    continue
                m = re.match(r"#\s*define\s+(\w+)\s+(\(?-?(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*\)?)\s*(?://.*|/\*.*)?$", s)
                if m:
                    v = m.group(2).strip("()")
                    self.macros[m.group(1)] = int(v.rstrip("uUlL"), 0)
                continue
            out.append(line)
        return "\n".join(out)

    def parse_type(self, text: str) -> T:
        p = _Parser(self, tokenize(text))
        t = p.parse_type_name()
        if p.pos != len(p.toks):
            raise TypeError_(f"trailing tokens in type: {' '.join(p.toks[p.pos:])}")
        return t

    def parse_prototype(self, text: str, name: str = "") -> Func:
        text = text.strip().rstrip(";")
        p = _Parser(self, tokenize(text))
        spec = p.parse_specifiers()
        n, t = p.parse_declarator(spec.type, allow_abstract=True)
        if isinstance(t, Func):
            if spec.cc and not t.cc:
                t.cc = spec.cc
            return t
        raise TypeError_("declaration is not a function prototype")

    def export_user(self) -> dict:
        return {"sources": self.user_sources}

    def import_user(self, d: dict):
        for s in d.get("sources", []):
            self.parse_decls(s, user=True)

    # -- resolution ---------------------------------------------------------
    def resolve(self, t: T, depth: int = 0) -> T:
        while isinstance(t, Named):
            if depth > 64:
                raise TypeError_("typedef cycle")
            depth += 1
            if t.tag == "struct":
                t = self.structs.setdefault(t.name, Struct(t.name))
            elif t.tag == "union":
                t = self.unions.setdefault(t.name, Struct(t.name, union=True))
            elif t.tag == "enum":
                t = self.enums.setdefault(t.name, Enum(t.name))
            else:
                if t.name not in self.typedefs:
                    raise TypeError_(f"unknown type name {t.name!r}")
                t = self.typedefs[t.name]
        return t

    def sizeof(self, t: T) -> int:
        t = self.resolve(t)
        if isinstance(t, Prim):
            return t.size
        if isinstance(t, Ptr):
            return self.ptr
        if isinstance(t, Arr):
            if t.count is None:
                return 0
            return t.count * self.sizeof(t.elem)
        if isinstance(t, Struct):
            self.layout(t)
            return t.size
        if isinstance(t, Enum):
            return t.size
        if isinstance(t, Func):
            return 1
        raise TypeError_("sizeof: unsupported type")

    def alignof(self, t: T) -> int:
        t = self.resolve(t)
        if isinstance(t, Prim):
            return min(max(t.size, 1), 8 if self.arch.bits == 64 or self.model == "lp64" else 4) if t.size else 1
        if isinstance(t, Ptr):
            return self.ptr
        if isinstance(t, Arr):
            return self.alignof(t.elem)
        if isinstance(t, Struct):
            self.layout(t)
            return t.align
        if isinstance(t, Enum):
            return t.size
        return 1

    def layout(self, s: Struct, pack: int = 0):
        if s.complete and getattr(s, "_laid", False):
            return
        pack = s.packed or pack
        off, maxalign, maxsize = 0, 1, 0
        bit_unit_off, bit_pos, bit_unit_size = None, 0, 0
        for f in s.fields:
            ft = self.resolve(f.type)
            size = self.sizeof(ft) if not isinstance(ft, Struct) or ft.complete else 0
            al = self.alignof(ft)
            if pack:
                al = min(al, pack)
            if f.bits is not None:
                # pack bitfields into units of the declared type
                if bit_unit_off is None or bit_unit_size != size or bit_pos + f.bits > size * 8:
                    off = (off + al - 1) // al * al
                    bit_unit_off, bit_pos, bit_unit_size = off, 0, size
                    off += size
                f.offset = bit_unit_off
                f.bit_offset = bit_pos
                bit_pos += f.bits
                maxalign = max(maxalign, al)
                maxsize = max(maxsize, off)
                continue
            bit_unit_off = None
            if s.union:
                f.offset = 0
                maxsize = max(maxsize, size)
            else:
                off = (off + al - 1) // al * al
                f.offset = off
                off += size
                maxsize = off
            maxalign = max(maxalign, al)
        s.align = maxalign
        s.size = (maxsize + maxalign - 1) // maxalign * maxalign if maxsize else 0
        s.complete = True
        s._laid = True

    # -- formatting ----------------------------------------------------------
    def format(self, t: T, name: str = "") -> str:
        return _fmt(t, name)

    def struct_to_c(self, s: Struct) -> str:
        self.layout(s)
        kw = "union" if s.union else "struct"
        lines = [f"{kw} {s.name} {{"]
        for f in s.fields:
            decl = _fmt(f.type, f.name)
            if f.bits is not None:
                decl += f" : {f.bits}"
            lines.append(f"    {decl};  // +{f.offset:#x}")
        lines.append(f"}}; // size {s.size:#x}")
        return "\n".join(lines)

    def lookup_proto(self, name: str) -> Optional[Func]:
        for cand in (name, name.lstrip("_"), name.split("@")[0].lstrip("_"), name.rstrip("AW") if name[-1:] in "AW" else None):
            if cand and cand in self.protos:
                return self.protos[cand]
        return None


def _fmt(t: T, name: str = "") -> str:
    """Format type `t` as a C declaration of `name`."""
    prefix_parts = []
    inner = name
    while True:
        if isinstance(t, Ptr):
            inner = "*" + inner
            if isinstance(t.target, (Arr, Func)):
                inner = f"({inner})"
            t = t.target
        elif isinstance(t, Arr):
            inner = f"{inner}[{'' if t.count is None else t.count}]"
            t = t.elem
        elif isinstance(t, Func):
            params = ", ".join(_fmt(pt, pn) for pn, pt in t.params) or "void"
            if t.varargs:
                params += ", ..."
            cc = f"__{t.cc} " if t.cc else ""
            inner = f"{inner}({params})"
            if cc:
                inner = f"({cc}{inner})" if False else inner
            t = t.ret
        else:
            break
    if isinstance(t, Prim):
        base = t.name
    elif isinstance(t, Struct):
        base = f"{'union' if t.union else 'struct'} {t.name}"
    elif isinstance(t, Enum):
        base = f"enum {t.name}"
    elif isinstance(t, Named):
        base = (t.tag + " " if t.tag else "") + t.name
    else:
        base = "?"
    return f"{base} {inner}".rstrip() if inner else base


# ---------------------------------------------------------------------------
@dataclass
class _Spec:
    type: T
    cc: str = ""
    typedef: bool = False


class _Parser:
    def __init__(self, tm: TypeManager, toks: List[str]):
        self.tm = tm
        self.toks = toks
        self.pos = 0
        self.pack = 0

    # -- token helpers --------------------------------------------------------
    def peek(self, k=0) -> Optional[str]:
        return self.toks[self.pos + k] if self.pos + k < len(self.toks) else None

    def next(self) -> str:
        if self.pos >= len(self.toks):
            raise TypeError_("unexpected end of declaration")
        t = self.toks[self.pos]
        self.pos += 1
        return t

    def accept(self, s: str) -> bool:
        if self.peek() == s:
            self.pos += 1
            return True
        return False

    def expect(self, s: str):
        t = self.next()
        if t != s:
            raise TypeError_(f"expected {s!r} but found {t!r}")

    def skip_balanced(self):
        """Skip a parenthesised group starting at '('."""
        depth = 0
        while True:
            t = self.next()
            if t == "(":
                depth += 1
            elif t == ")":
                depth -= 1
                if depth == 0:
                    return

    def skip_attrs(self) -> str:
        cc = ""
        while True:
            t = self.peek()
            if t in ("__attribute__", "__declspec", "__pragma", "_Alignas", "__asm", "__asm__", "_Static_assert"):
                self.next()
                if self.peek() == "(":
                    self.skip_balanced()
            elif t in QUALS:
                self.next()
            elif t in CC_WORDS:
                cc = CC_WORDS[self.next()]
            else:
                return cc

    # -- top level -------------------------------------------------------------
    def parse_translation_unit(self) -> List[str]:
        names = []
        while self.peek() is not None:
            if self.accept(";"):
                continue
            names += self.parse_external_decl()
        return names

    def parse_external_decl(self) -> List[str]:
        names = []
        if self.peek() == "__rk_pack":
            self.next()
            self.expect("(")
            self.pack = int(self.next())
            self.expect(")")
            self.accept(";")
            return names
        spec = self.parse_specifiers()
        if self.accept(";"):
            return names
        while True:
            name, t = self.parse_declarator(spec.type)
            cc = spec.cc
            if self.peek() in ("__attribute__", "__asm", "__asm__"):
                self.skip_attrs()
            if isinstance(t, Func) and cc and not t.cc:
                t.cc = cc
            if spec.typedef:
                self.tm.typedefs[name] = t
            elif isinstance(t, Func):
                self.tm.protos[name] = t
            # variable declarations are accepted and ignored
            if name:
                names.append(name)
            if self.accept("="):   # skip initialisers
                depth = 0
                while self.peek() is not None and not (depth == 0 and self.peek() in (",", ";")):
                    tk = self.next()
                    depth += tk in "({"
                    depth -= tk in ")}"
            if self.accept(","):
                continue
            if self.peek() == "{":          # function body: skip
                depth = 0
                while True:
                    tk = self.next()
                    if tk == "{":
                        depth += 1
                    elif tk == "}":
                        depth -= 1
                        if depth == 0:
                            break
                return names
            self.expect(";")
            return names

    # -- specifiers -------------------------------------------------------------
    def starts_type(self, t: Optional[str]) -> bool:
        if t is None:
            return False
        if t in self.tm.typedefs or t in ("struct", "union", "enum", "typedef", "unsigned", "signed", "short", "long",
                                         "int", "char", "float", "double", "void", "_Bool", "const", "volatile") or t in QUALS:
            return True
        return t in self.tm.prims

    def parse_specifiers(self) -> _Spec:
        cc = ""
        typedef = False
        words: List[str] = []
        base: Optional[T] = None
        while True:
            cc = self.skip_attrs() or cc
            t = self.peek()
            if t is None:
                break
            if t == "typedef":
                typedef = True
                self.next()
            elif t in ("struct", "union"):
                self.next()
                base = self.parse_struct(t == "union")
            elif t == "enum":
                self.next()
                base = self.parse_enum()
            elif t in ("unsigned", "signed", "short", "long", "int", "char", "float", "double", "void", "_Bool",
                       "__int8", "__int16", "__int32", "__int64", "__int128") and base is None:
                words.append(self.next())
            elif base is None and not words and t in self.tm.typedefs:
                self.next()
                base = Named(t)
            elif base is None and not words and t not in CC_WORDS and re.match(r"^[A-Za-z_]\w*$", t) \
                    and self.peek(1) is not None and self.peek(1) not in ("(", ")", ",", ";", "[", "=") \
                    and t not in QUALS and not self._is_decl_name_position():
                # unknown identifier used as a type name: treat as opaque typedef to int-sized unknown
                self.next()
                base = Named(t)
                self.tm.typedefs.setdefault(t, Prim(t, self.tm.ptr, False))
            else:
                break
        if base is None:
            base = self._prim_from_words(words) if words else self.tm.prims["int"]
            if not words:
                if self.peek() is None or typedef:
                    raise TypeError_("missing type specifier")
        cc = self.skip_attrs() or cc
        return _Spec(base, cc, typedef)

    def _is_decl_name_position(self) -> bool:
        return False

    def _prim_from_words(self, words: List[str]) -> T:
        w = list(words)
        uns = "unsigned" in w
        w = [x for x in w if x not in ("unsigned", "signed")]
        longs = w.count("long")
        w = [x for x in w if x not in ("long", "int")]
        if w and w[0] in ("__int8", "__int16", "__int32", "__int64", "__int128"):
            base = {"__int8": "char", "__int16": "short", "__int32": "int", "__int64": "long long",
                    "__int128": "__int128"}[w[0]]
            name = base
        elif w and w[0] in ("char", "short", "float", "double", "void", "_Bool"):
            name = w[0]
            if name == "double" and longs:
                name = "long double"
        elif longs >= 2:
            name = "long long"
        elif longs == 1:
            name = "long"
        else:
            name = "int"
        if uns:
            name = "unsigned " + name
        if name not in self.tm.prims:
            raise TypeError_(f"unsupported type specifier combination {' '.join(words)!r}")
        return self.tm.prims[name]

    def _eat_attrs_packed(self) -> bool:
        """Consume __attribute__/__declspec groups; report whether `packed` was among them."""
        packed = False
        while self.peek() in ("__attribute__", "__declspec", "_Alignas"):
            self.next()
            if self.peek() == "(":
                start = self.pos
                self.skip_balanced()
                if "packed" in self.toks[start:self.pos] or "__packed__" in self.toks[start:self.pos]:
                    packed = True
        return packed

    def parse_struct(self, union: bool) -> T:
        packed_attr = self._eat_attrs_packed()
        self.skip_attrs()
        name = ""
        if self.peek() and re.match(r"^[A-Za-z_]\w*$", self.peek()):
            name = self.next()
        packed_attr = self._eat_attrs_packed() or packed_attr
        self.skip_attrs()
        tag = "union" if union else "struct"
        if self.peek() != "{":
            if not name:
                raise TypeError_("anonymous struct without body")
            return Named(name, tag)
        self.expect("{")
        if not name:
            name = f"__anon_{len(self.tm.structs) + len(self.tm.unions)}"
        store = self.tm.unions if union else self.tm.structs
        s = store.get(name)
        if s is None or s.complete:
            s = Struct(name, union=union)
            store[name] = s
        s.fields = []
        if packed_attr:
            s.packed = 1
        while not self.accept("}"):
            fs = self.parse_specifiers()
            if self.accept(";"):          # anonymous struct/union member
                rt = self.tm.resolve(fs.type)
                if isinstance(rt, Struct):
                    s.fields.append(Field("", fs.type))
                continue
            while True:
                if self.peek() == ":":
                    fname, ft = "", fs.type
                else:
                    fname, ft = self.parse_declarator(fs.type)
                bits = None
                if self.accept(":"):
                    bits = self.const_expr()
                s.fields.append(Field(fname, ft, 0, bits))
                if not self.accept(","):
                    break
            self.expect(";")
        if self.peek() == "__attribute__":
            save = self.pos
            self.next()
            toks = []
            depth = 0
            while True:
                tk = self.next()
                toks.append(tk)
                depth += tk == "("
                depth -= tk == ")"
                if depth == 0:
                    break
            if "packed" in toks or "__packed__" in toks:
                s.packed = 1
        s.packed = s.packed or self.pack
        # flatten anonymous members into layout with real offsets
        self.tm.layout(s)
        return Named(name, tag)

    def parse_enum(self) -> T:
        self.skip_attrs()
        name = ""
        if self.peek() and re.match(r"^[A-Za-z_]\w*$", self.peek()) and self.peek() != "{":
            name = self.next()
        if self.peek() != "{":
            return Named(name, "enum")
        self.expect("{")
        if not name:
            name = f"__anon_enum_{len(self.tm.enums)}"
        e = Enum(name)
        val = 0
        while not self.accept("}"):
            n = self.next()
            if self.accept("="):
                val = self.const_expr()
            e.members.append((n, val))
            self.tm.enum_consts[n] = (name, val)
            val += 1
            if not self.accept(","):
                self.expect("}")
                break
        vals = [v for _, v in e.members]
        if vals and (min(vals) < -(1 << 31) or max(vals) >= (1 << 32)):
            e.size = 8
        e.flags = bool(vals) and all(v == 0 or (v & (v - 1)) == 0 for v in vals) and len(vals) > 2
        self.tm.enums[name] = e
        return Named(name, "enum")

    # -- declarators -------------------------------------------------------------
    def parse_type_name(self) -> T:
        spec = self.parse_specifiers()
        _, t = self.parse_declarator(spec.type, allow_abstract=True)
        return t

    def parse_declarator(self, base: T, allow_abstract: bool = True) -> Tuple[str, T]:
        cc = self.skip_attrs()
        while self.peek() == "*":
            self.next()
            self.skip_attrs()
            base = Ptr(base, self.tm.ptr)
        cc = self.skip_attrs() or cc
        inner_range = None
        name = ""
        t = self.peek()
        if t == "(" and self._is_nested_declarator():
            start = self.pos + 1
            self.skip_balanced()
            inner_range = (start, self.pos - 1)
        elif t is not None and re.match(r"^[A-Za-z_$]\w*$", t) and t not in QUALS and t not in CC_WORDS:
            name = self.next()
        self.skip_attrs()
        suffixes = []
        while True:
            if self.peek() == "[":
                self.next()
                n = None if self.peek() == "]" else self.const_expr()
                self.expect("]")
                suffixes.append(("arr", n))
            elif self.peek() == "(":
                self.next()
                suffixes.append(("fn",) + self.parse_params())
            else:
                break
        for s in reversed(suffixes):
            if s[0] == "arr":
                base = Arr(base, s[1])
            else:
                base = Func(base, s[1], cc, s[2])
                cc = ""
        if inner_range is not None:
            sub = _Parser(self.tm, self.toks[inner_range[0]:inner_range[1]])
            name, base = sub.parse_declarator(base)
        elif cc and isinstance(base, Func) and not base.cc:
            base.cc = cc
        return name, base

    def _is_nested_declarator(self) -> bool:
        n = self.peek(1)
        if n in ("*", "(", "^"):
            return True
        if n in CC_WORDS or n in ("__attribute__",):
            return True
        if n is not None and re.match(r"^[A-Za-z_]\w*$", n) and not self.starts_type(n):
            return True
        return False

    def parse_params(self) -> Tuple[List[Tuple[str, T]], bool]:
        params: List[Tuple[str, T]] = []
        varargs = False
        if self.accept(")"):
            return params, False
        if self.peek() == "void" and self.peek(1) == ")":
            self.next()
            self.next()
            return params, False
        while True:
            if self.accept("..."):
                varargs = True
                self.expect(")")
                break
            spec = self.parse_specifiers()
            name, t = self.parse_declarator(spec.type)
            rt = t
            if isinstance(rt, Arr):
                t = Ptr(rt.elem, self.tm.ptr)
            elif isinstance(rt, Func):
                t = Ptr(rt, self.tm.ptr)
            params.append((name, t))
            if self.accept(","):
                continue
            self.expect(")")
            break
        return params, varargs

    # -- constant expressions ------------------------------------------------------
    def const_expr(self) -> int:
        return self._or()

    def _or(self):
        v = self._xor()
        while self.peek() == "|":
            self.next()
            v |= self._xor()
        return v

    def _xor(self):
        v = self._and()
        while self.peek() == "^":
            self.next()
            v ^= self._and()
        return v

    def _and(self):
        v = self._shift()
        while self.peek() == "&":
            self.next()
            v &= self._shift()
        return v

    def _shift(self):
        v = self._add()
        while self.peek() in ("<<", ">>"):
            op = self.next()
            r = self._add()
            v = v << r if op == "<<" else v >> r
        return v

    def _add(self):
        v = self._mul()
        while self.peek() in ("+", "-"):
            op = self.next()
            r = self._mul()
            v = v + r if op == "+" else v - r
        return v

    def _mul(self):
        v = self._unary()
        while self.peek() in ("*", "/", "%"):
            op = self.next()
            r = self._unary()
            v = v * r if op == "*" else (v // r if op == "/" else v % r)
        return v

    def _unary(self):
        t = self.peek()
        if t == "-":
            self.next()
            return -self._unary()
        if t == "+":
            self.next()
            return self._unary()
        if t == "~":
            self.next()
            return ~self._unary()
        if t == "(":
            self.next()
            if self.starts_type(self.peek()):
                ty = self.parse_type_name()
                self.expect(")")
                return self._unary()
            v = self._or()
            self.expect(")")
            return v
        if t == "sizeof":
            self.next()
            self.expect("(")
            ty = self.parse_type_name()
            self.expect(")")
            return self.tm.sizeof(ty)
        t = self.next()
        if re.match(r"^(0[xX][0-9a-fA-F]+|\d+)[uUlL]*$", t):
            return int(t.rstrip("uUlL"), 0)
        if t.startswith("'"):
            return ord(t[1:-1].encode().decode("unicode_escape")[0])
        if t in self.tm.enum_consts:
            return self.tm.enum_consts[t][1]
        if t in self.tm.macros:
            return self.tm.macros[t]
        raise TypeError_(f"cannot evaluate constant expression at {t!r}")
