"""Analysis database: derived analysis state + authoritative user edits, with undo/redo and persistence.

Design: *user edits* (names, comments, types, bookmarks, patches, operand formats, function overrides,
triage notes) are the source of truth and are stored in SQLite tables. *Analysis results* (instruction
map, functions, xrefs) are derived data and cached as a versioned blob; when the cache is missing or its
version differs, analysis is re-run and user edits are re-applied. That keeps migrations trivial.
"""
from __future__ import annotations

import json
import marshal
import os
import sqlite3
import time
import zlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from .arch import Arch, Insn, get_arch, CALL, JMP, CJMP, RET, NORMAL, INDJMP, INDCALL, HALT
from .image import Image, ArchSpec

DB_VERSION = 3
CACHE_VERSION = 5

# xref kinds
X_CALL, X_JUMP, X_FLOW, X_READ, X_WRITE, X_OFFSET, X_DATA = "call", "jump", "flow", "read", "write", "offset", "data"


@dataclass
class Block:
    start: int
    end: int                        # exclusive end of last instruction
    insns: List[int] = field(default_factory=list)       # instruction start addresses
    succs: List[Tuple[int, str]] = field(default_factory=list)   # (target, "true"|"false"|"jump"|"fall"|"switch")


@dataclass
class Function:
    start: int
    name: str = ""
    end: int = 0
    blocks: Dict[int, Block] = field(default_factory=dict)
    chunks: List[Tuple[int, int]] = field(default_factory=list)
    flags: set = field(default_factory=set)   # thunk, noreturn, library, import, user, no_frame, leaf, switch
    frame_size: int = 0
    max_sp: int = 0
    callconv: str = ""
    source: str = "auto"       # auto, symtab, pdata, eh_frame, prologue, user, pointer, ...
    thunk_target: Optional[int] = None
    args_size: int = 0
    sp_delta_known: bool = True

    @property
    def size(self) -> int:
        return sum(e - s for s, e in self.chunks) if self.chunks else self.end - self.start

    def contains(self, addr: int) -> bool:
        return any(s <= addr < e for s, e in self.chunks) if self.chunks else self.start <= addr < self.end


@dataclass
class DataItem:
    addr: int
    size: int
    kind: str          # byte/word/dword/qword/ptr/string/wstring/array/struct/float/double/align/unknown
    value: object = None
    type: str = ""


class Database:
    def __init__(self, image: Image):
        self.image = image
        self.arch: Arch = get_arch(image.arch)
        self.insns: Dict[int, int] = {}             # insn start -> size
        self.data: Dict[int, DataItem] = {}
        self.functions: Dict[int, Function] = {}
        self.xrefs_from: Dict[int, List[Tuple[int, str]]] = defaultdict(list)
        self.xrefs_to: Dict[int, List[Tuple[int, str]]] = defaultdict(list)
        self.names: Dict[int, str] = {}
        self.name_user: Dict[int, bool] = {}
        self._name_rev: Dict[str, int] = {}
        self.comments: Dict[int, str] = {}
        self.rep_comments: Dict[int, str] = {}
        self.anterior: Dict[int, str] = {}
        self.posterior: Dict[int, str] = {}
        self.func_comments: Dict[int, str] = {}
        self.bookmarks: Dict[int, Tuple[int, str]] = {}
        self.opreprs: Dict[Tuple[int, int], str] = {}
        self.var_names: Dict[Tuple[int, str], Tuple[str, str]] = {}   # (func, location) -> (name, type)
        self.applied_types: Dict[int, str] = {}      # addr -> C type declaration
        self.func_protos: Dict[int, str] = {}        # func -> prototype string
        self.triage: Dict[str, dict] = {}            # finding id -> {status, note, user, ts}
        self.meta: Dict[str, object] = {}
        self.noreturn: set = set()
        self.signatures_applied: Dict[int, str] = {}
        self.switches: Dict[int, dict] = {}          # jmp addr -> {table, targets, ...}
        self.strings: Dict[int, "StrItem"] = {}
        self.audit: List[dict] = []
        self.listeners: List[Callable[[str, dict], None]] = []
        from .types import TypeManager
        self.types = TypeManager(image.arch)
        self.analyzed = False
        self.path: Optional[str] = None
        self._undo: List[Tuple[str, Callable, Callable]] = []
        self._redo: List[Tuple[str, Callable, Callable]] = []
        self._recording = True
        self._icache: Dict[int, Insn] = {}
        self.user_funcs: set = set()
        self.user_nofunc: set = set()
        self.user_func_end: Dict[int, int] = {}
        self.user_undefined: set = set()
        self.user_code: set = set()
        self.user_data: Dict[int, DataItem] = {}
        self.rev = 0
        self.pending_user_types: dict = {"sources": []}
        self.oplog: List[dict] = []          # journal of user edits (for team sync)
        self._journaling = True

    # ------------------------------------------------------------------
    # edit journal (collaboration)
    # ------------------------------------------------------------------
    def journal(self, kind: str, **kw):
        if self._journaling and self._recording:
            import uuid
            self.oplog.append({"id": uuid.uuid4().hex[:16], "kind": kind, "ts": time.time(), **kw})

    def apply_op(self, op: dict):
        """Apply a journalled edit (typically received from a team server) without journaling it again."""
        k = op["kind"]
        was = self._journaling
        self._journaling = False
        try:
            if k == "name":
                self.set_name(op["addr"], op["name"], user=True, force=True)
            elif k == "comment":
                self.set_comment(op["addr"], op["text"], op.get("repeatable", False))
            elif k == "fcomment":
                self.set_func_comment(op["addr"], op["text"])
            elif k == "anterior":
                self.set_anterior(op["addr"], op["text"])
            elif k == "posterior":
                self.set_posterior(op["addr"], op["text"])
            elif k == "bookmark":
                if op.get("remove"):
                    self.remove_bookmark(op["slot"])
                else:
                    self.set_bookmark(op["slot"], op["addr"], op.get("desc", ""))
            elif k == "opfmt":
                self.set_operand_repr(op["addr"], op["op"], op["fmt"])
            elif k == "type":
                self.apply_type(op["addr"], op["decl"])
            elif k == "var":
                self.rename_var(op["func"], op["loc"], op["name"], op.get("type", ""))
            elif k == "types_src":
                self.types.parse_decls(op["src"])
            elif k == "triage":
                self.triage[op["finding"]] = op["data"]
            elif k == "make_function":
                from . import edit
                edit.make_function(self, op["addr"])
            elif k == "delete_function":
                from . import edit
                edit.delete_function(self, op["addr"])
            elif k == "undefine":
                from . import edit
                edit.undefine(self, op["addr"], op.get("size", 1))
            elif k == "func_end":
                from . import edit
                edit.set_function_end(self, op["addr"], op["end"])
            elif k == "make_code":
                from . import edit
                edit.make_code(self, op["addr"])
            else:
                raise ValueError(f"unknown op kind {k}")
        finally:
            self._journaling = was

    # ------------------------------------------------------------------
    # events / undo
    # ------------------------------------------------------------------
    def emit(self, kind: str, **kw):
        self.rev += 1
        for l in list(self.listeners):
            try:
                l(kind, kw)
            except Exception:
                pass

    def _rec(self, desc: str, undo: Callable, redo: Callable, user: str = ""):
        if self._recording:
            self._undo.append((desc, undo, redo))
            self._redo.clear()
            self.audit.append({"ts": time.time(), "op": desc, "user": user or os.environ.get("USERNAME", "")})

    def undo(self) -> Optional[str]:
        if not self._undo:
            return None
        desc, u, r = self._undo.pop()
        self._recording = False
        try:
            u()
        finally:
            self._recording = True
        self._redo.append((desc, u, r))
        self.emit("undo", desc=desc)
        return desc

    def redo(self) -> Optional[str]:
        if not self._redo:
            return None
        desc, u, r = self._redo.pop()
        self._recording = False
        try:
            r()
        finally:
            self._recording = True
        self._undo.append((desc, u, r))
        self.emit("redo", desc=desc)
        return desc

    # ------------------------------------------------------------------
    # instruction access
    # ------------------------------------------------------------------
    def insn(self, addr: int) -> Optional[Insn]:
        i = self._icache.get(addr)
        if i is None:
            i = self.arch.decode(self.image, addr)
            if i is not None:
                if len(self._icache) > 800000:
                    self._icache.clear()
                self._icache[addr] = i
        return i

    def is_code(self, addr: int) -> bool:
        return addr in self.insns

    def item_start(self, addr: int) -> Optional[int]:
        """Start address of the code/data item covering `addr` (None if unexplored)."""
        for back in range(0, 16):
            a = addr - back
            if a in self.insns and a + self.insns[a] > addr:
                return a
            d = self.data.get(a)
            if d is not None and a + d.size > addr:
                return a
            if back > 0 and (a in self.insns or a in self.data):
                break
        return None

    def next_item(self, addr: int) -> Optional[int]:
        """Address after the item at addr, skipping to the next mapped address."""
        if addr in self.insns:
            return addr + self.insns[addr]
        d = self.data.get(addr)
        if d:
            return addr + d.size
        return addr + 1

    def function_at(self, addr: int) -> Optional[Function]:
        f = self.functions.get(addr)
        if f:
            return f
        return self._func_for(addr)

    def _func_for(self, addr: int) -> Optional[Function]:
        if not hasattr(self, "_fidx") or self._fidx_rev != self.rev_funcs:
            self._rebuild_fidx()
        import bisect
        i = bisect.bisect_right(self._fidx_starts, addr) - 1
        # chunk index: scan back a little in case of overlapping chunks
        for j in range(i, max(-1, i - 8), -1):
            s, e, f = self._fidx[j]
            if s <= addr < e:
                return f
        return None

    rev_funcs = 0

    def _rebuild_fidx(self):
        ranges = []
        for f in self.functions.values():
            for s, e in (f.chunks or [(f.start, f.end)]):
                ranges.append((s, e, f))
        ranges.sort(key=lambda r: r[0])
        self._fidx = ranges
        self._fidx_starts = [r[0] for r in ranges]
        self._fidx_rev = self.rev_funcs

    def touch_functions(self):
        self.rev_funcs += 1

    # ------------------------------------------------------------------
    # xrefs
    # ------------------------------------------------------------------
    def add_xref(self, frm: int, to: int, kind: str):
        t = (to, kind)
        lst = self.xrefs_from[frm]
        if t not in lst:
            lst.append(t)
            self.xrefs_to[to].append((frm, kind))

    def refs_from(self, addr: int) -> List[Tuple[int, str]]:
        return list(self.xrefs_from.get(addr, ()))

    def refs_to(self, addr: int) -> List[Tuple[int, str]]:
        return list(self.xrefs_to.get(addr, ()))

    def code_refs_to(self, addr: int):
        return [(a, k) for a, k in self.xrefs_to.get(addr, ()) if k in (X_CALL, X_JUMP, X_FLOW)]

    def callers(self, func_addr: int) -> List[int]:
        out = []
        for a, k in self.xrefs_to.get(func_addr, ()):
            if k == X_CALL:
                f = self.function_at(a)
                out.append(f.start if f else a)
        return sorted(set(out))

    def callees(self, func_addr: int) -> List[int]:
        f = self.functions.get(func_addr)
        if not f:
            return []
        out = set()
        for b in f.blocks.values():
            for ia in b.insns:
                for to, k in self.xrefs_from.get(ia, ()):
                    if k == X_CALL:
                        out.add(to)
        return sorted(out)

    # ------------------------------------------------------------------
    # names
    # ------------------------------------------------------------------
    def get_name(self, addr: int) -> Optional[str]:
        return self.names.get(addr)

    def addr_of(self, name: str) -> Optional[int]:
        return self._name_rev.get(name)

    def display_name(self, addr: int) -> str:
        n = self.names.get(addr)
        if n:
            return n
        f = self.functions.get(addr)
        if f and f.name:
            return f.name
        return self.default_name(addr)

    def default_name(self, addr: int) -> str:
        if addr in self.functions:
            return f"sub_{addr:X}"
        if addr in self.insns:
            return f"loc_{addr:X}"
        d = self.data.get(addr)
        if d is not None:
            return {"string": "a", "wstring": "w", "byte": "byte_", "word": "word_", "dword": "dword_",
                    "qword": "qword_", "ptr": "off_"}.get(d.kind, "unk_") + (f"{addr:X}" if d.kind not in ("string", "wstring") else f"{addr:X}")
        return f"unk_{addr:X}"

    def set_name(self, addr: int, name: str, user: bool = True, force: bool = False) -> bool:
        """Name an address. Returns False when the name is taken (unless force) or invalid."""
        if name and not _valid_name(name):
            return False
        old = self.names.get(addr)
        old_user = self.name_user.get(addr, False)
        if name:
            other = self._name_rev.get(name)
            if other is not None and other != addr:
                if not force:
                    return False
                name = self._unique(name, addr)
        if old == name:
            return True
        if not user and old and old_user:
            return False   # never overwrite user names with automatic ones
        self._apply_name(addr, name, user)
        f = self.functions.get(addr)
        if f is not None:
            f.name = name or ""
        self._rec(f"name {addr:#x} {old or ''}->{name}",
                  lambda: self._apply_name(addr, old or "", old_user),
                  lambda: self._apply_name(addr, name, user))
        if user:
            self.journal("name", addr=addr, name=name)
        self.emit("name", addr=addr, name=name)
        return True

    def _apply_name(self, addr, name, user):
        old = self.names.pop(addr, None)
        if old is not None and self._name_rev.get(old) == addr:
            del self._name_rev[old]
        if name:
            self.names[addr] = name
            self.name_user[addr] = user
            self._name_rev[name] = addr
        else:
            self.name_user.pop(addr, None)
        f = self.functions.get(addr)
        if f is not None:
            f.name = name

    def _unique(self, name: str, addr: int) -> str:
        n, i = name, 1
        while n in self._name_rev and self._name_rev[n] != addr:
            n = f"{name}_{i}"
            i += 1
        return n

    # ------------------------------------------------------------------
    # comments / bookmarks / operand repr / types
    # ------------------------------------------------------------------
    def _set_dict(self, store: Dict, key, value, label: str):
        old = store.get(key)
        if value in (None, ""):
            store.pop(key, None)
        else:
            store[key] = value

        def restore(v):
            def _():
                if v in (None, ""):
                    store.pop(key, None)
                else:
                    store[key] = v
            return _
        self._rec(f"{label} {key}", restore(old), restore(value if value else None))
        self.emit(label, key=key)

    def set_comment(self, addr: int, text: str, repeatable: bool = False):
        self._set_dict(self.rep_comments if repeatable else self.comments, addr, text,
                       "rcomment" if repeatable else "comment")
        self.journal("comment", addr=addr, text=text, repeatable=repeatable)

    def get_comment(self, addr: int, repeatable: bool = False) -> str:
        return (self.rep_comments if repeatable else self.comments).get(addr, "")

    def set_anterior(self, addr: int, text: str):
        self._set_dict(self.anterior, addr, text, "anterior")
        self.journal("anterior", addr=addr, text=text)

    def set_posterior(self, addr: int, text: str):
        self._set_dict(self.posterior, addr, text, "posterior")
        self.journal("posterior", addr=addr, text=text)

    def set_func_comment(self, addr: int, text: str):
        self._set_dict(self.func_comments, addr, text, "fcomment")
        self.journal("fcomment", addr=addr, text=text)

    def set_bookmark(self, slot: int, addr: int, desc: str = ""):
        self._set_dict(self.bookmarks, slot, (addr, desc), "bookmark")
        self.journal("bookmark", slot=slot, addr=addr, desc=desc)

    def remove_bookmark(self, slot: int):
        self._set_dict(self.bookmarks, slot, None, "bookmark")
        self.journal("bookmark", slot=slot, remove=True)

    def set_operand_repr(self, addr: int, opidx: int, fmt: str):
        self._set_dict(self.opreprs, (addr, opidx), fmt, "opfmt")
        self.journal("opfmt", addr=addr, op=opidx, fmt=fmt)

    def apply_type(self, addr: int, decl: str):
        """Apply a C declaration (e.g. 'struct foo' or 'int[16]') to a data address or prototype to a function."""
        if addr in self.functions:
            self.types.parse_prototype(decl, name=self.display_name(addr))   # validate
            self._set_dict(self.func_protos, addr, decl, "proto")
        else:
            self.types.parse_type(decl)
            self._set_dict(self.applied_types, addr, decl, "type")
        self.journal("type", addr=addr, decl=decl)

    def rename_var(self, func: int, loc: str, name: str, type_: str = ""):
        old = self.var_names.get((func, loc))
        self._set_dict(self.var_names, (func, loc), (name, type_ or (old[1] if old else "")), "var")
        self.journal("var", func=func, loc=loc, name=name, type=type_)

    # ------------------------------------------------------------------
    # patching
    # ------------------------------------------------------------------
    def patch_bytes(self, addr: int, data: bytes):
        old = self.image.read(addr, len(data))
        if len(old) != len(data):
            raise ValueError("patch range not fully mapped")
        self._write(addr, data)
        self._rec(f"patch {addr:#x} ({len(data)}b)", lambda: self._write(addr, old), lambda: self._write(addr, data))
        self.emit("patch", addr=addr, size=len(data))

    def _write(self, addr, data):
        self.image.write(addr, data)
        self._icache.clear()
        # re-decode patched instructions lazily: drop code items in the range so analysis can be re-run on them
        for a in range(addr - 15, addr + len(data)):
            sz = self.insns.get(a)
            if sz and a + sz > addr:
                pass

    def patch_assemble(self, addr: int, asm: str, pad_nop: bool = True) -> bytes:
        """Assemble `asm` at addr using Keystone, pad to the size of the overwritten instruction(s)."""
        from .assembler import assemble
        code = assemble(self.image.arch, asm, addr)
        n = len(code)
        covered = 0
        cur = addr
        while covered < n:
            i = self.insn(cur)
            if i is None:
                break
            covered += i.size
            cur += i.size
        if pad_nop and covered > n:
            nop = self.arch.nop_bytes or b"\x90"
            pad = covered - n
            code += (nop * (pad // len(nop) + 1))[:pad]
        self.patch_bytes(addr, code)
        return code

    # ------------------------------------------------------------------
    # imports
    # ------------------------------------------------------------------
    def import_slots(self) -> Dict[int, object]:
        if getattr(self, "_imp_slots_n", -1) != len(self.image.imports):
            self._imp_slots = {i.addr: i for i in self.image.imports}
            self._imp_stubs = {i.stub: i for i in self.image.imports if i.stub}
            self._imp_slots_n = len(self.image.imports)
        return self._imp_slots

    def import_at(self, addr: int):
        """Import record for an IAT/GOT slot, PLT stub, or thunk function address."""
        self.import_slots()
        i = self._imp_slots.get(addr) or self._imp_stubs.get(addr)
        if i is not None:
            return i
        f = self.functions.get(addr)
        if f is not None and f.thunk_target is not None:
            return self._imp_slots.get(f.thunk_target)
        return None

    # ------------------------------------------------------------------
    # structural edits with undo (snapshot based)
    # ------------------------------------------------------------------
    def _structure_snapshot(self):
        return (dict(self.insns), dict(self.data), dict(self.functions),
                {k: list(v) for k, v in self.xrefs_from.items()}, {k: list(v) for k, v in self.xrefs_to.items()},
                dict(self.strings), dict(self.switches), dict(self.names), dict(self.name_user), set(self.noreturn),
                set(self.user_funcs), set(self.user_nofunc), set(self.user_undefined), set(self.user_code),
                dict(self.user_data), dict(self.user_func_end))

    def _structure_restore(self, snap):
        (self.insns, self.data, self.functions, xf, xt, self.strings, self.switches, names, nu, self.noreturn,
         self.user_funcs, self.user_nofunc, self.user_undefined, self.user_code, self.user_data, self.user_func_end) = (
            dict(snap[0]), dict(snap[1]), dict(snap[2]), snap[3], snap[4], dict(snap[5]), dict(snap[6]), snap[7], snap[8],
            set(snap[9]), set(snap[10]), set(snap[11]), set(snap[12]), set(snap[13]), dict(snap[14]), dict(snap[15]))
        self.xrefs_from = defaultdict(list, {k: list(v) for k, v in xf.items()})
        self.xrefs_to = defaultdict(list, {k: list(v) for k, v in xt.items()})
        self.names = dict(names)
        self.name_user = dict(nu)
        self._name_rev = {n: a for a, n in self.names.items()}
        self._icache.clear()
        self.touch_functions()

    def structural_edit(self, label: str, fn: Callable[[], object]):
        before = self._structure_snapshot()
        was = self._recording
        self._recording = False
        try:
            r = fn()
        finally:
            self._recording = was
        after = self._structure_snapshot()
        self._rec(label, lambda: self._structure_restore(before), lambda: self._structure_restore(after))
        self.emit("structure", label=label)
        return r

    # ------------------------------------------------------------------
    # iteration helpers
    # ------------------------------------------------------------------
    def sorted_functions(self) -> List[Function]:
        return [self.functions[a] for a in sorted(self.functions)]

    def head_addrs(self) -> List[int]:
        return sorted(set(self.insns) | set(self.data))

    # ------------------------------------------------------------------
    # persistence
    # ------------------------------------------------------------------
    def save(self, path: Optional[str] = None):
        path = path or self.path
        if not path:
            raise ValueError("no database path")
        tmp = path + ".tmp"
        if os.path.exists(tmp):
            os.remove(tmp)
        con = sqlite3.connect(tmp)
        c = con.cursor()
        c.executescript("""
        CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE blob(k TEXT PRIMARY KEY, v BLOB);
        CREATE TABLE names(addr INTEGER PRIMARY KEY, name TEXT, user INTEGER);
        CREATE TABLE comments(addr INTEGER, kind TEXT, text TEXT, PRIMARY KEY(addr, kind));
        CREATE TABLE bookmarks(slot INTEGER PRIMARY KEY, addr INTEGER, descr TEXT);
        CREATE TABLE opreprs(addr INTEGER, op INTEGER, fmt TEXT, PRIMARY KEY(addr, op));
        CREATE TABLE vars(func INTEGER, loc TEXT, name TEXT, type TEXT, PRIMARY KEY(func, loc));
        CREATE TABLE types(addr INTEGER PRIMARY KEY, decl TEXT);
        CREATE TABLE protos(addr INTEGER PRIMARY KEY, decl TEXT);
        CREATE TABLE patches(addr INTEGER, orig BLOB, new BLOB);
        CREATE TABLE userfuncs(addr INTEGER PRIMARY KEY, kind TEXT, extra TEXT);
        CREATE TABLE triage(id TEXT PRIMARY KEY, data TEXT);
        CREATE TABLE audit(ts REAL, user TEXT, op TEXT);
        """)
        c.execute("INSERT INTO meta VALUES('db_version',?)", (str(DB_VERSION),))
        c.execute("INSERT INTO meta VALUES('cache_version',?)", (str(CACHE_VERSION),))
        c.execute("INSERT INTO meta VALUES('image',?)", (json.dumps(self._image_meta()),))
        c.execute("INSERT INTO meta VALUES('analyzed',?)", (json.dumps(self.analyzed),))
        c.execute("INSERT INTO meta VALUES('meta',?)", (json.dumps(self.meta, default=str),))
        # original input is embedded so that the database is self-contained
        c.execute("INSERT INTO blob VALUES('input',?)", (zlib.compress(self.image.raw, 6),))
        c.executemany("INSERT INTO names VALUES(?,?,?)",
                      [(a, n, int(self.name_user.get(a, False))) for a, n in self.names.items() if self.name_user.get(a)])
        for kind, d in (("reg", self.comments), ("rep", self.rep_comments), ("ant", self.anterior),
                        ("post", self.posterior), ("func", self.func_comments)):
            c.executemany("INSERT INTO comments VALUES(?,?,?)", [(a, kind, t) for a, t in d.items()])
        c.executemany("INSERT INTO bookmarks VALUES(?,?,?)", [(s, a, d) for s, (a, d) in self.bookmarks.items()])
        c.executemany("INSERT INTO opreprs VALUES(?,?,?)", [(a, o, f) for (a, o), f in self.opreprs.items()])
        c.executemany("INSERT INTO vars VALUES(?,?,?,?)", [(f, l, n, t) for (f, l), (n, t) in self.var_names.items()])
        c.executemany("INSERT INTO types VALUES(?,?)", list(self.applied_types.items()))
        c.executemany("INSERT INTO protos VALUES(?,?)", list(self.func_protos.items()))
        c.executemany("INSERT INTO patches VALUES(?,?,?)", self.image.patched_ranges())
        uf = [(a, "func", "") for a in self.user_funcs] + [(a, "undef", "") for a in self.user_undefined] + \
             [(a, "code", "") for a in self.user_code] + [(a, "nofunc", "") for a in self.user_nofunc] + \
             [(a, "funcend", str(e)) for a, e in self.user_func_end.items()]
        uf += [(a, "data", json.dumps({"size": d.size, "kind": d.kind, "type": d.type})) for a, d in self.user_data.items()]
        c.executemany("INSERT INTO userfuncs VALUES(?,?,?)", uf)
        c.executemany("INSERT INTO triage VALUES(?,?)", [(k, json.dumps(v)) for k, v in self.triage.items()])
        c.executemany("INSERT INTO audit VALUES(?,?,?)", [(e["ts"], e["user"], e["op"]) for e in self.audit])
        c.execute("INSERT INTO blob VALUES('types',?)", (zlib.compress(json.dumps(self.types.export_user()).encode()),))
        if self.analyzed:
            c.execute("INSERT INTO blob VALUES('analysis',?)", (zlib.compress(marshal.dumps(self._export_analysis()), 6),))
        con.commit()
        con.close()
        os.replace(tmp, path)
        self.path = path

    def _image_meta(self) -> dict:
        im = self.image
        return {"path": im.path, "fmt": im.fmt, "arch": im.arch.to_dict(), "sha256": im.sha256,
                "loader": getattr(im, "loader_args", {})}

    def _export_analysis(self) -> dict:
        return {
            "insns": self.insns,
            "data": {a: (d.size, d.kind, d.value if isinstance(d.value, (int, str, float, type(None))) else str(d.value), d.type)
                     for a, d in self.data.items()},
            "functions": {a: {"name": f.name, "end": f.end, "chunks": f.chunks, "flags": sorted(f.flags),
                              "frame": f.frame_size, "cc": f.callconv, "src": f.source, "thunk": f.thunk_target,
                              "args": f.args_size, "maxsp": f.max_sp,
                              "blocks": {b.start: (b.end, b.insns, b.succs) for b in f.blocks.values()}}
                          for a, f in self.functions.items()},
            "xrefs": [(a, t, k) for a, lst in self.xrefs_from.items() for t, k in lst],
            "auto_names": {a: n for a, n in self.names.items() if not self.name_user.get(a)},
            "noreturn": sorted(self.noreturn),
            "switches": {a: {k: v for k, v in s.items()} for a, s in self.switches.items()},
            "strings": {a: (s.length, s.encoding, s.text) for a, s in self.strings.items()},
            "sigs": self.signatures_applied,
        }

    def _import_analysis(self, d: dict):
        self.insns = dict(d["insns"])
        self.data = {a: DataItem(a, t[0], t[1], t[2], t[3]) for a, t in d["data"].items()}
        self.functions = {}
        for a, fd in d["functions"].items():
            f = Function(a, fd["name"], fd["end"], {}, [tuple(c) for c in fd["chunks"]], set(fd["flags"]),
                         fd["frame"], fd.get("maxsp", 0), fd["cc"], fd["src"], fd["thunk"], fd.get("args", 0))
            for bs, (be, ins, succ) in fd["blocks"].items():
                f.blocks[bs] = Block(bs, be, list(ins), [tuple(s) for s in succ])
            self.functions[a] = f
        self.xrefs_from.clear()
        self.xrefs_to.clear()
        for a, t, k in d["xrefs"]:
            self.xrefs_from[a].append((t, k))
            self.xrefs_to[t].append((a, k))
        for a, n in d["auto_names"].items():
            self._apply_name(a, n, False)
        self.noreturn = set(d["noreturn"])
        self.switches = {a: dict(s) for a, s in d["switches"].items()}
        from .analysis.strings import StrItem
        self.strings = {a: StrItem(a, l, e, t) for a, (l, e, t) in d["strings"].items()}
        self.signatures_applied = dict(d.get("sigs", {}))
        self.touch_functions()

    @staticmethod
    def open(path: str, reanalyze: bool = False) -> "Database":
        from .loaders import load_file
        con = sqlite3.connect(path)
        c = con.cursor()
        meta = dict(c.execute("SELECT k,v FROM meta").fetchall())
        im = json.loads(meta["image"])
        raw = zlib.decompress(c.execute("SELECT v FROM blob WHERE k='input'").fetchone()[0])
        import tempfile
        la = im.get("loader") or {}
        with tempfile.TemporaryDirectory() as td:
            tp = os.path.join(td, os.path.basename(im["path"]) or "input.bin")
            with open(tp, "wb") as f:
                f.write(raw)
            image = load_file(tp, **la)
        image.path = im["path"]
        db = Database(image)
        db.path = path
        db._recording = False
        row = c.execute("SELECT v FROM blob WHERE k='types'").fetchone()
        db.pending_user_types = json.loads(zlib.decompress(row[0])) if row else {"sources": []}
        for a, n, u in c.execute("SELECT addr,name,user FROM names"):
            db._apply_name(a, n, bool(u))
        for a, k, t in c.execute("SELECT addr,kind,text FROM comments"):
            {"reg": db.comments, "rep": db.rep_comments, "ant": db.anterior, "post": db.posterior,
             "func": db.func_comments}[k][a] = t
        for s, a, d in c.execute("SELECT slot,addr,descr FROM bookmarks"):
            db.bookmarks[s] = (a, d)
        for a, o, f in c.execute("SELECT addr,op,fmt FROM opreprs"):
            db.opreprs[(a, o)] = f
        for f, l, n, t in c.execute("SELECT func,loc,name,type FROM vars"):
            db.var_names[(f, l)] = (n, t)
        db.applied_types = dict(c.execute("SELECT addr,decl FROM types").fetchall())
        db.func_protos = dict(c.execute("SELECT addr,decl FROM protos").fetchall())
        for a, o, n in c.execute("SELECT addr,orig,new FROM patches"):
            image.write(a, n)
        for a, kind, extra in c.execute("SELECT addr,kind,extra FROM userfuncs"):
            if kind == "func":
                db.user_funcs.add(a)
            elif kind == "undef":
                db.user_undefined.add(a)
            elif kind == "code":
                db.user_code.add(a)
            elif kind == "nofunc":
                db.user_nofunc.add(a)
            elif kind == "funcend":
                db.user_func_end[a] = int(extra)
            elif kind == "data":
                x = json.loads(extra)
                db.user_data[a] = DataItem(a, x["size"], x["kind"], None, x.get("type", ""))
        db.triage = {k: json.loads(v) for k, v in c.execute("SELECT id,data FROM triage")}
        db.audit = [{"ts": t, "user": u, "op": o} for t, u, o in c.execute("SELECT ts,user,op FROM audit")]
        db.meta = json.loads(meta.get("meta", "{}"))
        cache = c.execute("SELECT v FROM blob WHERE k='analysis'").fetchone()
        ok = cache and int(meta.get("cache_version", 0)) == CACHE_VERSION and not reanalyze
        if ok:
            db._import_analysis(marshal.loads(zlib.decompress(cache[0])))
            db.analyzed = True
            # user function renames override the cache
            for a in list(db.names):
                if db.name_user.get(a) and a in db.functions:
                    db.functions[a].name = db.names[a]
        con.close()
        db._recording = True
        if not ok and json.loads(meta.get("analyzed", "false")):
            from .analysis.auto import analyze
            analyze(db)
        return db


@dataclass
class _Str:
    pass


def _valid_name(n: str) -> bool:
    if not n or len(n) > 1024:
        return False
    if n[0].isdigit():
        return False
    return all(ch.isalnum() or ch in "_$@?.:<>~`'!*&()[]-+ ,=" for ch in n)
