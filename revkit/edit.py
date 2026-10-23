"""Interactive structural edits: make code/function/data/string, undefine, delete function (all undoable)."""
from __future__ import annotations

from typing import List, Optional

from .analysis.auto import Analyzer, Options
from .db import Database, DataItem
from .image import CODE


def _analyzer(db: Database) -> Analyzer:
    a = Analyzer(db, Options())
    a.fstarts = {s: f.source for s, f in db.functions.items() if s not in db.user_nofunc}
    for s in db.user_funcs:
        a.fstarts[s] = "user"
    a._nr_funcs = set(db.noreturn)
    return a


def _rebuild(db: Database, a: Analyzer):
    a.explore_all()
    db.functions.clear()
    a.owner.clear()
    a.fstarts = {s: src for s, src in a.fstarts.items() if s in db.insns and s not in db.user_nofunc}
    a.build_functions()
    a.infer_noreturn()
    a.resolve_imports_and_thunks()
    from .analysis.frame import analyze_frames
    analyze_frames(db)
    db.touch_functions()


def _clear_range(db: Database, addr: int, size: int):
    end = addr + size
    for a in list(db.insns):
        if a < end and a + db.insns[a] > addr:
            del db.insns[a]
            for to, k in db.xrefs_from.pop(a, []):
                db.xrefs_to[to] = [(f, kk) for f, kk in db.xrefs_to.get(to, []) if f != a]
    for a in list(db.data):
        d = db.data[a]
        if a < end and a + d.size > addr:
            del db.data[a]
            db.strings.pop(a, None)
    for a in list(db.user_data):
        if addr <= a < end:
            del db.user_data[a]
    db._icache.clear()


def make_code(db: Database, addr: int) -> bool:
    """Convert the bytes at addr into code and follow its flow."""
    if not db.image.is_mapped(addr):
        raise ValueError(f"{addr:#x} is not mapped")

    def op():
        _clear_range(db, addr, 1)
        db.user_undefined.discard(addr)
        db.user_code.add(addr)
        a = _analyzer(db)
        a.queue.append(addr)
        _rebuild(db, a)
        return addr in db.insns
    r = db.structural_edit(f"make_code {addr:#x}", op)
    db.journal("make_code", addr=addr)
    return r


def make_function(db: Database, addr: int) -> bool:
    def op():
        _clear_range(db, addr, 1)
        db.user_nofunc.discard(addr)
        db.user_undefined.discard(addr)
        db.user_funcs.add(addr)
        a = _analyzer(db)
        a.fstarts[addr] = "user"
        a.queue.append(addr)
        _rebuild(db, a)
        return addr in db.functions
    r = db.structural_edit(f"make_function {addr:#x}", op)
    db.journal("make_function", addr=addr)
    return r


def delete_function(db: Database, addr: int) -> bool:
    f = db.functions.get(addr)
    if f is None:
        return False

    def op():
        db.user_funcs.discard(addr)
        db.user_nofunc.add(addr)
        a = _analyzer(db)
        a.fstarts.pop(addr, None)
        _rebuild(db, a)
        return True
    r = db.structural_edit(f"delete_function {addr:#x}", op)
    db.journal("delete_function", addr=addr)
    return r


def set_function_end(db: Database, start: int, end: int) -> bool:
    """Fix the end address of a function: code at or beyond `end` is no longer part of it."""
    if start not in db.functions:
        raise ValueError(f"no function at {start:#x}")
    if end <= start:
        raise ValueError("end must be above the function start")

    def op():
        db.user_func_end[start] = end
        a = _analyzer(db)
        a.fstarts[start] = a.fstarts.get(start, "user")
        _rebuild(db, a)
        return True
    r = db.structural_edit(f"set_function_end {start:#x}..{end:#x}", op)
    db.journal("func_end", addr=start, end=end)
    return r


def undefine(db: Database, addr: int, size: int = 1) -> None:
    def op():
        _clear_range(db, addr, size)
        for k in range(size):
            db.user_undefined.add(addr + k) if size <= 64 else None
        db.user_undefined.add(addr)
        for s in list(db.functions):
            if addr <= s < addr + size:
                db.user_nofunc.add(s)
        a = _analyzer(db)
        a.fstarts = {s: src for s, src in a.fstarts.items() if not (addr <= s < addr + size)}
        _rebuild(db, a)
    db.structural_edit(f"undefine {addr:#x}+{size}", op)
    db.journal("undefine", addr=addr, size=size)


_KIND_SIZE = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "float": 4, "double": 8, "ptr": None}


def make_data(db: Database, addr: int, kind: str, count: int = 1, type_: str = "") -> DataItem:
    if kind not in _KIND_SIZE:
        raise ValueError(f"unknown data kind {kind!r}")
    esz = _KIND_SIZE[kind] or db.image.ptr_size
    size = esz * count

    def op():
        _clear_range(db, addr, size)
        d = DataItem(addr, size, kind if count == 1 else "array", db.image.u(addr, esz) if count == 1 else None,
                     type_ or (f"{kind}[{count}]" if count > 1 else kind))
        db.data[addr] = d
        db.user_data[addr] = d
        a = _analyzer(db)
        _rebuild(db, a)
        return d
    return db.structural_edit(f"make_data {addr:#x} {kind}x{count}", op)


def make_string(db: Database, addr: int, encoding: str = "ascii", max_len: int = 4096) -> Optional[str]:
    img = db.image
    step = 2 if encoding == "utf16" else 1
    out = bytearray()
    a = addr
    while len(out) < max_len:
        chunk = img.read(a, step)
        if len(chunk) < step:
            return None
        if chunk == bytes(step):
            break
        out += chunk
        a += step
    size = len(out) + step
    text = out.decode("utf-16-le" if encoding == "utf16" else "latin1", "replace")

    def op():
        from .analysis.strings import StrItem
        _clear_range(db, addr, size)
        db.strings[addr] = StrItem(addr, size, encoding, text)
        d = DataItem(addr, size, "wstring" if encoding == "utf16" else "string", text)
        db.data[addr] = d
        db.user_data[addr] = d
    db.structural_edit(f"make_string {addr:#x}", op)
    return text


def apply_struct(db: Database, addr: int, decl: str) -> int:
    """Apply a C type to addr and make it a data item of the right size (e.g. 'struct foo', 'int[8]')."""
    t = db.types.parse_type(decl)
    size = db.types.sizeof(t)

    def op():
        _clear_range(db, addr, max(size, 1))
        d = DataItem(addr, max(size, 1), "struct", None, decl)
        db.data[addr] = d
        db.user_data[addr] = d
        db.applied_types[addr] = decl
    db.structural_edit(f"apply_type {addr:#x} {decl}", op)
    return size
