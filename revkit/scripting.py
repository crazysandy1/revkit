"""Python scripting: a native `proj` API plus a familiar scripting-style compatibility layer (rk / rkutil / rkapi)."""
from __future__ import annotations

import builtins
import io
import os
import sys
import traceback
import types as _types
from contextlib import redirect_stdout, redirect_stderr
from typing import Any, Dict, Iterator, List, Optional

BADADDR = 0xFFFFFFFFFFFFFFFF


class ScriptResult:
    def __init__(self, ok: bool, output: str, error: str = "", value: Any = None):
        self.ok, self.output, self.error, self.value = ok, output, error, value

    def to_dict(self):
        return {"ok": self.ok, "output": self.output, "error": self.error,
                "value": repr(self.value) if self.value is not None else None}


def build_namespace(proj) -> Dict[str, Any]:
    """Globals available to scripts. `proj` is the revkit Project; the rk modules are shims over it."""
    compat = IdaCompat(proj)
    ns: Dict[str, Any] = {
        "proj": proj, "db": proj.db, "image": proj.image, "BADADDR": BADADDR,
        "rk": compat.rk, "rkutil": compat.rkutil, "rkapi": compat.rkapi, "kernwin": compat.kernwin, "decomp": compat.decomp,
        "__name__": "__main__",
    }
    return ns


def run_script(proj, path_or_code: str, args: Optional[List[str]] = None) -> ScriptResult:
    """Run a script file or a code string against `proj`. Captures stdout/stderr."""
    if os.path.isfile(path_or_code):
        with open(path_or_code, encoding="utf8") as f:
            code = f.read()
        fname = path_or_code
    else:
        code, fname = path_or_code, "<script>"
    ns = build_namespace(proj)
    ns["ARGS"] = list(args or [])
    out, err = io.StringIO(), io.StringIO()
    old_argv = sys.argv
    sys.argv = [fname] + list(args or [])
    try:
        with redirect_stdout(out), redirect_stderr(err):
            try:
                exec(compile(code, fname, "exec"), ns)
                return ScriptResult(True, out.getvalue() + err.getvalue(), value=ns.get("result"))
            except SystemExit:
                return ScriptResult(True, out.getvalue() + err.getvalue())
            except Exception:
                return ScriptResult(False, out.getvalue(), traceback.format_exc())
    finally:
        sys.argv = old_argv


class IdaCompat:
    def __init__(self, proj):
        self.p = proj
        self.rk = self._idc()
        self.rkutil = self._rkutil()
        self.rkapi = self._rkapi()
        self.decomp = self._decomp()
        self.kernwin = self._kernwin()

    # ------------------------------------------------------------------ rk
    def _idc(self):
        p, db, img = self.p, self.p.db, self.p.image
        m = _types.SimpleNamespace(BADADDR=BADADDR)

        def need(ea):
            return p.resolve(ea) if not isinstance(ea, int) else ea
        m.here = m.get_screen_ea = lambda: getattr(p, "cursor", img.entry_points[0][0] if img.entry_points else img.min_addr)
        m.jumpto = lambda ea: setattr(p, "cursor", need(ea)) or True
        m.get_func_name = lambda ea: (db.display_name(db.function_at(need(ea)).start) if db.function_at(need(ea)) else "")
        m.get_name = lambda ea, flags=0: db.names.get(need(ea), "") or (db.default_name(need(ea)) if need(ea) in db.functions or need(ea) in db.data else "")
        m.get_name_ea_simple = m.get_name_ea = lambda *a: (db.addr_of(a[-1]) if db.addr_of(a[-1]) is not None else BADADDR)
        m.set_name = lambda ea, name, flags=0: db.set_name(need(ea), name, True)
        m.get_item_size = lambda ea: db.insns.get(need(ea)) or (db.data[need(ea)].size if need(ea) in db.data else 1)
        m.get_bytes = lambda ea, n, use_dbg=False: img.read(need(ea), n)
        m.get_wide_byte = m.get_db_byte = lambda ea: (img.u(need(ea), 1) if img.u(need(ea), 1) is not None else 0)
        m.get_wide_word = lambda ea: img.u(need(ea), 2) or 0
        m.get_wide_dword = lambda ea: img.u(need(ea), 4) or 0
        m.get_qword = lambda ea: img.u(need(ea), 8) or 0
        m.patch_byte = lambda ea, v: db.patch_bytes(need(ea), bytes([v & 0xFF])) or True
        m.patch_word = lambda ea, v: db.patch_bytes(need(ea), (v & 0xFFFF).to_bytes(2, "little")) or True
        m.patch_dword = lambda ea, v: db.patch_bytes(need(ea), (v & 0xFFFFFFFF).to_bytes(4, "little")) or True
        m.get_segm_name = lambda ea: (img.segment_at(need(ea)).name if img.segment_at(need(ea)) else "")
        m.get_segm_start = lambda ea: (img.segment_at(need(ea)).start if img.segment_at(need(ea)) else BADADDR)
        m.get_segm_end = lambda ea: (img.segment_at(need(ea)).end if img.segment_at(need(ea)) else BADADDR)
        m.set_cmt = lambda ea, text, rpt=0: db.set_comment(need(ea), text, bool(rpt)) or True
        m.get_cmt = lambda ea, rpt=0: db.get_comment(need(ea), bool(rpt))
        m.set_func_cmt = lambda ea, text, rpt=0: db.set_func_comment(need(ea), text) or True

        def disasm_line(ea, flags=0):
            from .listing import render_insn
            i = db.insn(need(ea))
            return render_insn(db, i) if i else ""
        m.generate_disasm_line = disasm_line
        m.GetDisasm = disasm_line
        m.print_insn_mnem = lambda ea: (db.insn(need(ea)).mnemonic if db.insn(need(ea)) else "")
        m.GetMnem = m.print_insn_mnem
        m.print_operand = lambda ea, n: (lambda i: [s.strip() for s in i.op_str.split(",")][n] if i and n < len(i.op_str.split(",")) else "")(db.insn(need(ea)))

        def next_head(ea, maxea=BADADDR):
            heads = p.listing._heads if p.listing._heads else sorted(set(db.insns) | set(db.data))
            p.listing._refresh()
            import bisect
            h = p.listing._heads
            i = bisect.bisect_right(h, need(ea))
            return h[i] if i < len(h) and h[i] < maxea else BADADDR

        def prev_head(ea, minea=0):
            import bisect
            p.listing._refresh()
            h = p.listing._heads
            i = bisect.bisect_left(h, need(ea)) - 1
            return h[i] if i >= 0 and h[i] >= minea else BADADDR
        m.next_head, m.prev_head = next_head, prev_head
        m.get_next_func = lambda ea: next((a for a in sorted(db.functions) if a > need(ea)), BADADDR)
        m.get_prev_func = lambda ea: next((a for a in sorted(db.functions, reverse=True) if a < need(ea)), BADADDR)
        m.find_func_end = lambda ea: (db.function_at(need(ea)).end if db.function_at(need(ea)) else BADADDR)

        def func_attr(ea, attr):
            f = db.function_at(need(ea))
            if not f:
                return BADADDR
            return {"FUNCATTR_START": f.start, "FUNCATTR_END": f.end, "FUNCATTR_FRSIZE": f.frame_size}.get(attr, BADADDR) if isinstance(attr, str) else \
                {0: f.start, 4: f.end, 8: f.frame_size}.get(attr, BADADDR)
        m.get_func_attr = func_attr
        m.FUNCATTR_START, m.FUNCATTR_END, m.FUNCATTR_FRSIZE = 0, 4, 8
        m.get_entry_qty = lambda: len(img.exports) + len(img.entry_points)
        m.add_func = lambda ea, end=BADADDR: p.make_function(ea)
        m.del_func = lambda ea: p.delete_function(ea)
        m.create_insn = lambda ea: p.make_code(ea)
        m.del_items = lambda ea, flags=0, n=1: p.undefine(ea, n) or True
        m.create_byte = lambda ea: p.make_data(ea, "byte") and True
        m.create_dword = lambda ea: p.make_data(ea, "dword") and True
        m.create_qword = lambda ea: p.make_data(ea, "qword") and True
        m.create_strlit = lambda ea, end=BADADDR: p.make_string(ea) is not None
        m.add_bookmark = lambda ea, slot, desc: p.bookmark(slot, ea, desc)
        m.msg = lambda s: sys.stdout.write(s)
        m.get_inf_attr = lambda *a: img.min_addr
        m.set_color = lambda *a: None
        m.auto_wait = lambda: True
        m.qexit = lambda code=0: (_ for _ in ()).throw(SystemExit(code))
        return m

    # ------------------------------------------------------------------ rkutil
    def _rkutil(self):
        p, db, img = self.p, self.p.db, self.p.image
        m = _types.SimpleNamespace()

        def Functions(start=None, end=None):
            for a in sorted(db.functions):
                if (start is None or a >= start) and (end is None or a < end):
                    yield a

        def Segments():
            for s in img.segments:
                yield s.start

        class _XR:
            def __init__(self, frm, to, typ, iscode):
                self.frm, self.to, self.type, self.iscode, self.user = frm, to, typ, iscode, 0

        codekinds = {"call": 17, "jump": 19, "flow": 21}

        def XrefsTo(ea, flags=0):
            for f, k in sorted(db.xrefs_to.get(ea, ())):
                yield _XR(f, ea, codekinds.get(k, 1), k in codekinds)

        def XrefsFrom(ea, flags=0):
            for t, k in db.xrefs_from.get(ea, ()):
                yield _XR(ea, t, codekinds.get(k, 1), k in codekinds)

        def FuncItems(ea):
            f = db.function_at(ea)
            if f:
                for b in sorted(f.blocks.values(), key=lambda x: x.start):
                    yield from b.insns

        def Heads(start=None, end=None):
            p.listing._refresh()
            for a in p.listing._heads:
                if (start is None or a >= start) and (end is None or a < end):
                    yield a

        class _Str:
            def __init__(self, it):
                self.ea, self.length, self.type, self._t = it.addr, it.length, 0 if it.encoding != "utf16" else 1, it.text

            def __str__(self):
                return self._t

        def Strings():
            return [_Str(db.strings[a]) for a in sorted(db.strings)]

        m.Functions, m.Segments, m.XrefsTo, m.XrefsFrom, m.FuncItems, m.Heads, m.Strings = \
            Functions, Segments, XrefsTo, XrefsFrom, FuncItems, Heads, Strings
        m.Names = lambda: [(a, n) for a, n in sorted(db.names.items())]
        m.Entries = lambda: [(i, e.addr, i, e.name) for i, e in enumerate(img.exports)] + \
                            [(len(img.exports) + i, a, 0, "start") for i, (a, k) in enumerate(img.entry_points)]
        m.CodeRefsTo = lambda ea, flow=0: [f for f, k in sorted(db.xrefs_to.get(ea, ())) if k in codekinds]
        m.DataRefsTo = lambda ea: [f for f, k in sorted(db.xrefs_to.get(ea, ())) if k not in codekinds]
        m.CodeRefsFrom = lambda ea, flow=0: [t for t, k in db.xrefs_from.get(ea, ()) if k in codekinds]
        m.DataRefsFrom = lambda ea: [t for t, k in db.xrefs_from.get(ea, ()) if k not in codekinds]
        m.Chunks = lambda ea: [(s, e) for s, e in (db.function_at(ea).chunks if db.function_at(ea) else [])]
        return m

    # ------------------------------------------------------------------ rkapi
    def _rkapi(self):
        p, db = self.p, self.p.db
        m = _types.SimpleNamespace(BADADDR=BADADDR)

        class _Func:
            def __init__(self, f):
                self.start_ea, self.end_ea, self.flags = f.start, f.end, 0
                self.frsize = f.frame_size

            @property
            def size(self):
                return self.end_ea - self.start_ea

        m.get_func = lambda ea: (_Func(db.function_at(ea)) if db.function_at(ea) else None)
        m.get_func_name = lambda ea: db.display_name(ea)
        m.decompile = lambda ea, *a: self.decomp.decompile(ea)
        m.get_item_head = lambda ea: db.item_start(ea) or ea
        m.get_imagebase = lambda: p.image.imagebase
        m.is_code = lambda f: True
        m.get_screen_ea = lambda: getattr(p, "cursor", 0)
        m.ask_yn = lambda *a, **k: 1
        m.msg = lambda s: sys.stdout.write(s)
        return m

    def _decomp(self):
        p = self.p
        m = _types.SimpleNamespace()

        class _CFunc:
            def __init__(self, pc):
                self.pc = pc
                self.text = pc.text
                self.entry_ea = pc.function

            def __str__(self):
                return self.text

            def get_pseudocode(self):
                return [t for t, _ in self.pc.lines]

        m.decompile = lambda ea, *a, **k: _CFunc(p.decompile(ea))
        return m

    def _kernwin(self):
        m = _types.SimpleNamespace()
        m.msg = lambda s: sys.stdout.write(s)
        m.info = lambda s: print(s)
        m.warning = lambda s: print("WARNING:", s)
        m.ask_yn = lambda *a, **k: 1
        return m
