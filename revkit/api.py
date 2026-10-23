"""High-level project API: the single entry point used by the CLI, web server, scripts and plugins."""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Callable, Dict, Iterable, List, Optional, Tuple, Union

from . import edit as _edit
from . import graphs, patching, search as _search
from .analysis import Options, analyze
from .analysis.signatures import SigDB, apply_sigs, load_all
from .arch import Insn
from .db import Database, Function
from .image import Image
from .listing import Line, Listing, hexdump, render_insn, to_text
from .loaders import load_file

Addr = Union[int, str]


class RevkitError(Exception):
    pass


class Project:
    """A binary + its analysis database. Create with `Project.load` (binary) or `Project.open` (saved database)."""

    def __init__(self, db: Database):
        self.db = db
        self.listing = Listing(db)
        self.hooks: Dict[str, List[Callable]] = {}
        db.listeners.append(self._dispatch)

    # ------------------------------------------------------------------ construction
    @classmethod
    def load(cls, path: str, analyze_now: bool = True, fmt: Optional[str] = None, arch: Optional[str] = None,
             base: int = 0, entry: Optional[int] = None, options: Optional[Options] = None,
             progress: Optional[Callable[[str], None]] = None, slice_cpu: Optional[int] = None,
             unpack: bool = False) -> "Project":
        """`unpack=True` runs the program's unpacking stub in the emulator first and analyses/decompiles the unpacked code.
        If nothing unpacks (the file is not packed, or the packer defeats emulation) the original image is analysed and
        `info()["unpack"]` says so."""
        if not os.path.isfile(path):
            raise RevkitError(f"file not found: {path}")
        img = load_file(path, fmt=fmt, arch=arch, base=base, entry=entry, slice_cpu=slice_cpu, unpack=unpack)
        img.loader_args = {k: v for k, v in dict(fmt=fmt, arch=arch, base=base, entry=entry, slice_cpu=slice_cpu,
                                                 unpack=unpack).items() if v not in (None, 0, False)}
        db = Database(img)
        _init_types(db)
        p = cls(db)
        if analyze_now:
            p.analyze(options, progress)
        return p

    @classmethod
    def open(cls, path: str, reanalyze: bool = False) -> "Project":
        db = Database.open(path, reanalyze)
        _init_types(db, keep_user=True)
        return cls(db)

    # ------------------------------------------------------------------ basics
    @property
    def image(self) -> Image:
        return self.db.image

    def analyze(self, options: Optional[Options] = None, progress=None) -> dict:
        st = analyze(self.db, options, progress)
        self._fire("analyzed", st)
        return st

    def save(self, path: Optional[str] = None) -> str:
        path = path or self.db.path or (self.image.path + ".rkdb")
        self.db.save(path)
        return path

    def resolve(self, ref: Addr) -> int:
        """Accept an int, hex string, decimal string, or a name."""
        if isinstance(ref, int):
            return ref
        s = ref.strip()
        a = self.db.addr_of(s)
        if a is not None:
            return a
        for f in self.db.functions.values():
            if f.name == s:
                return f.start
        low = s.lower()
        if low.startswith("sub_") or low.startswith("loc_"):
            try:
                return int(low[4:], 16)
            except ValueError:
                pass
        try:
            return int(s, 0)
        except ValueError:
            pass
        try:
            return int(s, 16)
        except ValueError:
            raise RevkitError(f"cannot resolve {ref!r} to an address")

    def info(self) -> dict:
        im, db = self.image, self.db
        return {
            "path": im.path, "format": im.fmt, "arch": im.arch.to_dict(), "arch_key": im.arch.key, "sha256": im.sha256,
            "md5": im.md5, "size": len(im.raw), "imagebase": im.imagebase,
            "entry_points": [{"addr": a, "kind": k, "name": db.display_name(a)} for a, k in im.entry_points],
            "segments": len(im.segments), "functions": len(db.functions), "instructions": len(db.insns),
            "strings": len(db.strings), "imports": len(im.imports), "exports": len(im.exports),
            "libraries": im.libraries, "compiler": im.info.get("compiler"), "warnings": im.warnings,
            "analyzed": db.analyzed, "stats": db.meta.get("analysis_stats"), "pdb": im.info.get("pdb"),
            "unpack": getattr(im, "unpack_result", None) or im.info.get("unpacked"),
            "loader_info": {k: v for k, v in im.info.items() if isinstance(v, (str, int, bool, float))},
        }

    # ------------------------------------------------------------------ inventories
    def segments(self) -> List[dict]:
        return [{"name": s.name, "start": s.start, "end": s.end, "size": s.size, "perms": s.perms, "kind": s.kind,
                 "file_offset": s.file_offset} for s in self.image.segments]

    def functions(self, pattern: Optional[str] = None) -> List[dict]:
        import re
        db = self.db
        rx = re.compile(pattern, re.I) if pattern else None
        out = []
        for a in sorted(db.functions):
            f = db.functions[a]
            nm = db.display_name(a)
            if rx and not rx.search(nm):
                continue
            out.append({"addr": a, "name": nm, "size": f.size, "blocks": len(f.blocks), "flags": sorted(f.flags),
                        "callconv": f.callconv, "frame": f.frame_size, "source": f.source,
                        "callers": len(db.callers(a)), "callees": len(db.callees(a)),
                        "complexity": graphs.cyclomatic_complexity(f) if f.blocks else 0})
        return out

    def function(self, ref: Addr) -> Function:
        a = self.resolve(ref)
        f = self.db.function_at(a)
        if f is None:
            raise RevkitError(f"no function at {a:#x}")
        return f

    def names(self) -> List[dict]:
        db = self.db
        out = [{"addr": a, "name": n, "user": db.name_user.get(a, False)} for a, n in sorted(db.names.items())]
        return out

    def strings(self, min_len: int = 0, pattern: Optional[str] = None) -> List[dict]:
        import re
        rx = re.compile(pattern, re.I) if pattern else None
        out = []
        for a in sorted(self.db.strings):
            s = self.db.strings[a]
            if len(s.text) < min_len or (rx and not rx.search(s.text)):
                continue
            out.append({"addr": a, "text": s.text, "length": s.length, "encoding": s.encoding,
                        "xrefs": [x for x, k in self.db.xrefs_to.get(a, ())]})
        return out

    def imports(self) -> List[dict]:
        db = self.db
        out = []
        for i in self.image.imports:
            xr = {x for x, k in db.xrefs_to.get(i.addr, ())}
            if i.stub:
                xr |= {x for x, k in db.xrefs_to.get(i.stub, ())}
            out.append({"addr": i.addr, "stub": i.stub, "module": i.module, "name": i.display, "ordinal": i.ordinal,
                        "xrefs": sorted(xr)})
        return out

    def exports(self) -> List[dict]:
        return [{"addr": e.addr, "name": e.name, "ordinal": e.ordinal, "forwarder": e.forwarder} for e in self.image.exports]

    # ------------------------------------------------------------------ views
    def disasm(self, start: Addr, count: int = 40, back: int = 0) -> List[Line]:
        return self.listing.lines(self.resolve(start), count, back)

    def disasm_function(self, ref: Addr) -> str:
        f = self.function(ref)
        return to_text(self.db, f.start, f.end)

    def listing_text(self, with_bytes: bool = False) -> str:
        return to_text(self.db, with_bytes=with_bytes)

    def hexdump(self, addr: Addr, length: int = 256, width: int = 16) -> List[dict]:
        return hexdump(self.image, self.resolve(addr), length, width)

    def decompile(self, ref: Addr):
        from .decompiler import decompile
        return decompile(self.db, self.function(ref).start)

    def decompile_text(self, ref: Addr) -> str:
        return self.decompile(ref).text

    def cfg(self, ref: Addr) -> dict:
        return graphs.cfg(self.db, self.function(ref))

    def cfg_dot(self, ref: Addr) -> str:
        return graphs.cfg_dot(self.db, self.function(ref))

    def callgraph_dot(self, root: Optional[Addr] = None) -> str:
        return graphs.call_graph_dot(self.db, self.resolve(root) if root is not None else None)

    def proximity(self, ref: Addr, depth: int = 2) -> dict:
        return graphs.proximity(self.db, self.function(ref).start, depth)

    # ------------------------------------------------------------------ xrefs
    def xrefs_to(self, ref: Addr) -> List[dict]:
        a = self.resolve(ref)
        return [{"from": f, "kind": k, "function": (self.db.function_at(f).start if self.db.function_at(f) else None),
                 "text": self._text(f)} for f, k in sorted(self.db.xrefs_to.get(a, ()))]

    def xrefs_from(self, ref: Addr) -> List[dict]:
        a = self.resolve(ref)
        return [{"to": t, "kind": k, "name": self.db.display_name(t)} for t, k in self.db.xrefs_from.get(a, ())]

    def callers(self, ref: Addr) -> List[int]:
        return self.db.callers(self.function(ref).start)

    def callees(self, ref: Addr) -> List[int]:
        return self.db.callees(self.function(ref).start)

    def _text(self, a: int) -> str:
        i = self.db.insn(a) if a in self.db.insns else None
        return render_insn(self.db, i) if i else ""

    # ------------------------------------------------------------------ search
    def search_bytes(self, pattern: str, **kw) -> List[int]:
        return _search.search_bytes(self.db, pattern, **kw)

    def search_text(self, q: str, **kw):
        return _search.search_text(self.db, q, **kw)

    def search_imm(self, value: int, **kw):
        return _search.search_immediate(self.db, value, **kw)

    def search_names(self, q: str, **kw):
        return _search.search_names(self.db, q, **kw)

    def search_strings(self, q: str, **kw):
        return _search.search_strings(self.db, q, **kw)

    # ------------------------------------------------------------------ annotation
    def rename(self, ref: Addr, name: str) -> bool:
        a = self.resolve(ref)
        ok = self.db.set_name(a, name, user=True)
        if not ok:
            raise RevkitError(f"cannot name {a:#x} {name!r}: invalid or already used")
        return ok

    def comment(self, ref: Addr, text: str, repeatable: bool = False):
        self.db.set_comment(self.resolve(ref), text, repeatable)

    def func_comment(self, ref: Addr, text: str):
        self.db.set_func_comment(self.function(ref).start, text)

    def bookmark(self, slot: int, ref: Addr, desc: str = ""):
        self.db.set_bookmark(slot, self.resolve(ref), desc)

    def set_type(self, ref: Addr, decl: str):
        self.db.apply_type(self.resolve(ref), decl)

    def add_types(self, c_source: str) -> List[str]:
        names = self.db.types.parse_decls(c_source)
        self.db.journal("types_src", src=c_source)
        self.db.emit("types")
        return names

    def op_format(self, ref: Addr, opidx: int, fmt: str):
        self.db.set_operand_repr(self.resolve(ref), opidx, fmt)

    def rename_var(self, func: Addr, old: str, new: str, type_: str = ""):
        self.db.rename_var(self.function(func).start, old, new, type_)

    # structural
    def make_code(self, ref: Addr) -> bool:
        return _edit.make_code(self.db, self.resolve(ref))

    def make_function(self, ref: Addr) -> bool:
        return _edit.make_function(self.db, self.resolve(ref))

    def delete_function(self, ref: Addr) -> bool:
        return _edit.delete_function(self.db, self.resolve(ref))

    def set_function_end(self, ref: Addr, end: Addr) -> bool:
        return _edit.set_function_end(self.db, self.function(ref).start, self.resolve(end))

    def undefine(self, ref: Addr, size: int = 1):
        _edit.undefine(self.db, self.resolve(ref), size)

    def make_data(self, ref: Addr, kind: str = "dword", count: int = 1):
        return _edit.make_data(self.db, self.resolve(ref), kind, count)

    def make_string(self, ref: Addr, encoding: str = "ascii"):
        return _edit.make_string(self.db, self.resolve(ref), encoding)

    def apply_struct(self, ref: Addr, decl: str) -> int:
        return _edit.apply_struct(self.db, self.resolve(ref), decl)

    def undo(self):
        return self.db.undo()

    def redo(self):
        return self.db.redo()

    # ------------------------------------------------------------------ patching
    def patch_bytes(self, ref: Addr, data: Union[bytes, str]):
        if isinstance(data, str):
            data = bytes.fromhex(data.replace(" ", ""))
        self.db.patch_bytes(self.resolve(ref), data)

    def patch_asm(self, ref: Addr, asm: str) -> bytes:
        return self.db.patch_assemble(self.resolve(ref), asm)

    def nop(self, ref: Addr, size: int):
        return patching.nop_range(self.db, self.resolve(ref), size)

    def invert_branch(self, ref: Addr):
        return patching.invert_branch(self.db, self.resolve(ref))

    def force_jump(self, ref: Addr):
        return patching.force_jump(self.db, self.resolve(ref))

    def patches(self) -> List[dict]:
        return patching.list_patches(self.db)

    def revert_patch(self, ref: Addr, size: Optional[int] = None) -> bool:
        return patching.revert_patch(self.db, self.resolve(ref), size)

    def write_patched(self, out_path: str) -> dict:
        return patching.write_patched_file(self.db, out_path)

    # ------------------------------------------------------------------ signatures
    def apply_signatures(self, paths: Optional[List[str]] = None) -> Dict[int, str]:
        sdbs: List[SigDB] = []
        for p in paths or []:
            sdbs.append(SigDB.load(p) if p.endswith(".rsig") else SigDB.import_pat(open(p, encoding="latin1").read(), os.path.basename(p)))
        if not paths:
            sdbs = load_all(self.db)
        return apply_sigs(self.db, sdbs)

    def import_names(self, path: str) -> int:
        """Import names from a MAP/CSV/TSV (`addr name` per line), a JSON object {addr: name} / [{addr, name}], or a names/Python
        script containing set_name(addr, "name") calls. Returns the number of names applied."""
        import re
        with open(path, encoding="utf8", errors="replace") as f:
            text = f.read()
        pairs = []
        t = text.lstrip()
        if t.startswith(("{", "[")):
            data = json.loads(text)
            if isinstance(data, dict):
                pairs = [(k, v) for k, v in data.items() if isinstance(v, str)]
            else:
                pairs = [(d["addr"], d["name"]) for d in data]
        else:
            for m in re.finditer(r"set_name\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*[\"']([^\"']+)[\"']", text):
                pairs.append((m.group(1), m.group(2)))
            if not pairs:
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith((";", "#", "//")):
                        continue
                    parts = re.split(r"[,\t ]+", line)
                    if len(parts) >= 2 and re.fullmatch(r"(0x)?[0-9a-fA-F]+", parts[0]):
                        pairs.append((parts[0], parts[1]))
        n = 0
        for a, name in pairs:
            try:
                addr = a if isinstance(a, int) else int(str(a), 16)
                if self.image.is_mapped(addr) and self.db.set_name(addr, name, user=True):
                    n += 1
            except (ValueError, TypeError):
                continue
        return n

    def load_pdb(self, path: str) -> int:
        """Apply public symbols from a Microsoft PDB to a PE image. Returns the number of symbols applied."""
        from .pdb import load_pdb_symbols
        n = 0
        for addr, name in load_pdb_symbols(path, self.image):
            if self.db.set_name(addr, name, user=False, force=True):
                n += 1
        self.db.emit("pdb", count=n)
        return n

    def unpack(self, **kw):
        from .emulate import unpack
        return unpack(self, **kw)

    def make_signatures(self, out_path: str, name: str = "user", only_named: bool = True) -> int:
        s = SigDB(name)
        n = s.add_database(self.db, only_named)
        s.save(out_path)
        return n

    # ------------------------------------------------------------------ events
    def on(self, event: str, cb: Callable):
        self.hooks.setdefault(event, []).append(cb)

    def _dispatch(self, kind: str, kw: dict):
        for cb in list(self.hooks.get(kind, ())):
            try:
                cb(kw)
            except Exception:
                pass
        for cb in list(self.hooks.get("*", ())):
            try:
                cb(kind, kw)
            except Exception:
                pass

    def _fire(self, kind: str, payload=None):
        self._dispatch(kind, payload if isinstance(payload, dict) else {"data": payload})

    # ------------------------------------------------------------------ extras (lazy imports)
    def decompile_all(self, progress=None) -> Dict[int, str]:
        out = {}
        for a in sorted(self.db.functions):
            try:
                out[a] = self.decompile(a).text
            except Exception as e:
                out[a] = f"// decompilation failed: {e}"
            if progress:
                progress(a)
        return out

    def run_script(self, path_or_code: str, args: Optional[List[str]] = None):
        from .scripting import run_script
        return run_script(self, path_or_code, args)

    def triage(self):
        from .vulns import scan
        return scan(self)

    def explain(self, ref: Addr, use_llm: bool = False):
        from .explain import explain_function
        return explain_function(self, self.function(ref).start, use_llm)

    def packer_report(self):
        from .packers import analyze_packing
        return analyze_packing(self)

    def report(self, fmt: str = "markdown") -> str:
        from .report import build_report
        return build_report(self, fmt)

    def diff(self, other: "Project"):
        from .bindiff import diff_projects
        return diff_projects(self, other)

    def debugger(self, **kw):
        from .debugger import create_session
        return create_session(self, **kw)


def _init_types(db: Database, keep_user: bool = False):
    user = (db.pending_user_types if keep_user else None)
    plat = "windows" if db.image.fmt.startswith("PE") else "posix"
    model = "llp64" if db.image.fmt.startswith("PE") and db.image.arch.bits == 64 else None
    from .types import TypeManager
    tm = TypeManager(db.image.arch, model or "")
    tm.load_stdlib(plat)
    if user and user.get("sources"):
        for s in user["sources"]:
            try:
                tm.parse_decls(s, user=True)
            except Exception:
                pass
    elif not keep_user and db.types.user_sources:
        for s in db.types.user_sources:
            tm.parse_decls(s, user=True)
    db.types = tm


def open_database(path: str, **kw) -> Project:
    """idalib-style helper: open a binary or a saved .rkdb database headlessly."""
    if path.endswith(".rkdb"):
        return Project.open(path)
    return Project.load(path, **kw)
