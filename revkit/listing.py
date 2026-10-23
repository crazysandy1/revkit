"""Disassembly listing renderer: turns database items into display lines (names, xrefs, comments, operand formats)."""
from __future__ import annotations

import bisect
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .arch import CALL, CJMP, JMP, Insn, INDCALL, INDJMP, RET
from .db import Database, Function, X_CALL, X_JUMP, X_OFFSET, X_READ, X_WRITE

_NUM = re.compile(r"(?<![\w$.])(-?(?:0x[0-9a-fA-F]+|\d+))(?![\w.])")
_RIP = re.compile(r"\[(?:rip|eip)\s*([+-]\s*0x[0-9a-fA-F]+|[+-]\s*\d+)?\]")


@dataclass
class Line:
    addr: int
    kind: str                 # code | data | label | comment | header | footer | blank | unknown | align | xref
    text: str = ""
    bytes: str = ""
    comment: str = ""
    func: Optional[int] = None
    size: int = 0
    xrefs: List[Tuple[int, str]] = field(default_factory=list)

    def to_dict(self):
        return {"addr": self.addr, "kind": self.kind, "text": self.text, "bytes": self.bytes,
                "comment": self.comment, "func": self.func, "size": self.size}


def fmt_imm(v: int, fmt: str, db: Database, bits: int = 32) -> Optional[str]:
    mask = (1 << bits) - 1
    u = v & mask
    if fmt == "hex":
        return hex(u) if v >= 0 else hex(u)
    if fmt == "dec":
        return str(v if v < 0 else u)
    if fmt == "sdec":
        return str(u - (1 << bits) if u >> (bits - 1) else u)
    if fmt == "oct":
        return "0o" + format(u, "o")
    if fmt == "bin":
        return "0b" + format(u, "b")
    if fmt == "char":
        if 0 <= u < 0x110000 and 32 <= u < 127:
            return repr(chr(u))
        return None
    if fmt == "neg":
        return str(-(u if u < (1 << (bits - 1)) else u - (1 << bits)))
    if fmt == "offset":
        n = db.names.get(u)
        return f"offset {n}" if n else None
    if fmt.startswith("enum:"):
        ename = fmt[5:]
        e = db.types.enums.get(ename)
        if e:
            for n, val in e.members:
                if val == u or val == v:
                    return n
            # flag-style decomposition
            if e.flags:
                parts, rest = [], u
                for n, val in e.members:
                    if val and rest & val == val:
                        parts.append(n)
                        rest &= ~val
                if parts and rest == 0:
                    return " | ".join(parts)
        return None
    return None


def _split_operands(op_str: str) -> List[Tuple[int, int]]:
    spans, depth, start = [], 0, 0
    for i, ch in enumerate(op_str):
        if ch in "[({":
            depth += 1
        elif ch in "])}":
            depth -= 1
        elif ch == "," and depth == 0:
            spans.append((start, i))
            start = i + 1
    spans.append((start, len(op_str)))
    return spans


def render_operands(db: Database, ins: Insn) -> str:
    """Operand text with symbolic names, RIP-relative resolution and user operand formats applied."""
    ops = ins.op_str
    img = db.image
    bits = img.arch.bits
    # branch targets -> names
    if ins.flow in (CALL, JMP, CJMP) and ins.targets:
        t = ins.targets[0]
        return db.display_name(t) if (t in db.names or t in db.functions or t in db.insns) else ops
    # indirect through slot: call [rip+x] -> call cs:name
    if ins.ind_slot is not None:
        n = db.names.get(ins.ind_slot)
        if n:
            pre = ""
            m = re.match(r"^((?:byte|word|dword|qword|xmmword|tbyte)\s+ptr\s+)", ops)
            return f"{m.group(1) if m else ''}cs:{n}" if img.arch.name == "x86" and bits == 64 else \
                f"{m.group(1) if m else ''}ds:{n}"
    # rip-relative data reference
    if bits == 64 and img.arch.name == "x86" and ("rip" in ops):
        for kind, a in ins.refs:
            n = db.names.get(a) or (db.default_name(a) if a in db.data or a in db.insns else None)
            if n:
                if ins.mnemonic == "lea":
                    ops = _RIP.sub(lambda m: "", ops)
                    ops = re.sub(r",\s*$", "", ops)
                    ops = re.sub(r"(,\s*)(?:\w+\s+ptr\s+)?\s*$", r"\1", ops)
                    parts = [p.strip() for p in ops.split(",") if p.strip()]
                    return (parts[0] if parts else "") + ", " + n if parts else n
                ops = re.sub(r"\[(?:rip)\s*[+-]\s*(?:0x[0-9a-fA-F]+|\d+)\s*\]", f"cs:{n}", ops)
                ops = re.sub(r"\[rip\]", f"cs:{n}", ops)
                break
    # absolute 32-bit memory / immediate that is a known name
    out = ops
    spans = _split_operands(ops)
    pieces = []
    for idx, (s, e) in enumerate(spans):
        seg = ops[s:e]
        fmt = db.opreprs.get((ins.addr, idx))
        def repl(m, idx=idx, fmt=fmt):
            tok = m.group(1)
            try:
                v = int(tok, 0)
            except ValueError:
                return tok
            if fmt:
                r = fmt_imm(v, fmt, db, min(bits, 64) if bits else 32)
                if r is not None:
                    return r
            if v >= 0x1000 and (v in db.names) and "[" not in seg.replace(tok, "", 1)[:0] + "":
                # immediates that equal a named address print as offsets
                if ins.mnemonic not in ("ret", "retn", "enter", "int", "sub", "add", "and", "or", "xor", "shl", "shr", "sar", "cmp", "test") or bits == 32 and ins.mnemonic in ("add", "sub", "cmp") and False:
                    return f"offset {db.names[v]}"
            return tok
        pieces.append(_NUM.sub(repl, seg))
    out = ",".join(pieces)
    return out


def render_insn(db: Database, ins: Insn) -> str:
    ops = render_operands(db, ins)
    return f"{ins.mnemonic:<8}{ops}".rstrip() if ops else ins.mnemonic


class Listing:
    """Ordered view over every addressable item of a database (code, data, unexplored bytes)."""

    def __init__(self, db: Database):
        self.db = db
        self._rev = -1
        self._heads: List[int] = []

    def _refresh(self):
        db = self.db
        if self._rev != (db.rev, len(db.insns), len(db.data)):
            heads = set(db.insns) | set(db.data)
            self._heads = sorted(heads)
            self._rev = (db.rev, len(db.insns), len(db.data))

    # -- item iteration ------------------------------------------------------------------
    def item_at_or_before(self, addr: int) -> Optional[int]:
        self._refresh()
        i = bisect.bisect_right(self._heads, addr) - 1
        if i < 0:
            return None
        return self._heads[i]

    def lines(self, start: int, count: int = 64, back: int = 0) -> List[Line]:
        """Render `count` lines beginning at the item containing `start` (after `back` lines of context above)."""
        self._refresh()
        db, img = self.db, self.db.image
        # locate item start
        a = start
        h = self.item_at_or_before(start)
        if h is not None:
            sz = db.insns.get(h) or (db.data[h].size if h in db.data else 1)
            if h + sz > start:
                a = h
        if back:
            idx = bisect.bisect_left(self._heads, a)
            idx = max(0, idx - back)
            if self._heads:
                a = min(a, self._heads[idx])
        out: List[Line] = []
        guard = 0
        while len(out) < count and guard < count * 40:
            guard += 1
            seg = img.segment_at(a)
            if seg is None:
                nxt = self._next_mapped(a)
                if nxt is None:
                    break
                a = nxt
                continue
            out.extend(self._render_item(a, seg))
            a = self._next_addr(a)
        return out[:count] if len(out) > count else out

    def _next_mapped(self, a: int) -> Optional[int]:
        for s in self.db.image.segments:
            if s.start > a:
                return s.start
        return None

    def _next_addr(self, a: int) -> int:
        db = self.db
        if a in db.insns:
            return a + db.insns[a]
        d = db.data.get(a)
        if d is not None:
            return a + max(d.size, 1)
        # unexplored: run of bytes up to next head or 16 bytes
        self._refresh()
        i = bisect.bisect_right(self._heads, a)
        limit = self._heads[i] if i < len(self._heads) else 1 << 64
        seg = db.image.segment_at(a)
        return min(a + 16, limit, seg.end) if seg else a + 1

    def _render_item(self, a: int, seg) -> List[Line]:
        db, img = self.db, self.db.image
        out: List[Line] = []
        f = db.function_at(a)
        fa = f.start if f else None
        if a in db.functions:
            out.extend(self._func_header(db.functions[a]))
        elif a in db.names and (a in db.insns or a in db.data) and not db.names[a].startswith("__imp_") or \
                (a in db.insns and a in db.xrefs_to and any(k in (X_JUMP, X_CALL) for _, k in db.xrefs_to[a])):
            pass
        if a in db.anterior:
            for ln in db.anterior[a].splitlines():
                out.append(Line(a, "comment", f"; {ln}", func=fa))
        # xref summary + label
        if a in db.insns and a not in db.functions:
            refs = [r for r in db.xrefs_to.get(a, ()) if r[1] in (X_JUMP, X_CALL)]
            if refs:
                out.append(self._xref_line(a, refs, "CODE", fa))
                out.append(Line(a, "label", f"{db.display_name(a)}:", func=fa))
            elif a in db.names:
                out.append(Line(a, "label", f"{db.names[a]}:", func=fa))
        elif a in db.data:
            refs = db.xrefs_to.get(a, ())
            if refs:
                out.append(self._xref_line(a, list(refs), "DATA", fa))
        if a in db.insns:
            ins = db.insn(a)
            cmt = db.comments.get(a, "")
            rc = db.rep_comments.get(a, "")
            auto = self._auto_comment(ins)
            text = render_insn(db, ins)
            ln = Line(a, "code", text, ins.raw.hex(" "), "; ".join(x for x in (cmt, rc and f"{rc}", auto) if x), fa, ins.size)
            out.append(ln)
            if a in db.switches:
                sw = db.switches[a]
                out.append(Line(a, "comment", f"; jump table at {sw['table']:#x}, {sw['count']} cases", func=fa))
        elif a in db.data:
            out.append(self._data_line(a, db.data[a], fa))
        else:
            n = min(16, self._next_addr(a) - a)
            raw = img.read(a, n)
            nm = db.names.get(a)
            if nm:
                out.append(Line(a, "label", f"{nm}:", func=fa))
            out.append(Line(a, "unknown", "db " + ", ".join(f"0x{b:02X}" for b in raw), raw.hex(" "),
                            db.comments.get(a, ""), fa, n))
        if a in db.posterior:
            for ln in db.posterior[a].splitlines():
                out.append(Line(a, "comment", f"; {ln}", func=fa))
        if a in db.insns and f and (a + db.insns[a]) == f.end and not any(x[0] <= a < x[1] and x[1] > a + db.insns[a] for x in f.chunks):
            out.append(Line(a, "footer", f"{db.display_name(f.start)} endp", func=fa))
        return out

    def _xref_line(self, a: int, refs, kind: str, fa) -> Line:
        db = self.db
        parts = []
        for frm, k in refs[:6]:
            ff = db.function_at(frm)
            if ff is not None:
                off = frm - ff.start
                where = db.display_name(ff.start) + (f"+{off:X}" if off else "")
            else:
                where = f"{frm:X}"
            tag = {"call": "p", "jump": "j", "read": "r", "write": "w", "offset": "o", "data": "r"}.get(k, "?")
            parts.append(f"{where}{tag}")
        more = f" ... and {len(refs) - 6} more" if len(refs) > 6 else ""
        return Line(a, "xref", f"; {kind} XREF: " + ", ".join(parts) + more, func=fa, xrefs=list(refs))

    def _func_header(self, f: Function) -> List[Line]:
        db = self.db
        a = f.start
        out = [Line(a, "blank", "", func=a),
               Line(a, "comment", "; " + "=" * 20 + " S U B R O U T I N E " + "=" * 20, func=a)]
        attrs = []
        if "frame_pointer" in f.flags:
            attrs.append("bp-based frame")
        if "thunk" in f.flags:
            attrs.append("thunk")
        if "library" in f.flags:
            attrs.append("library function")
        if a in db.noreturn:
            attrs.append("noreturn")
        if f.callconv:
            attrs.append(f.callconv)
        if attrs:
            out.append(Line(a, "comment", "; Attributes: " + ", ".join(attrs), func=a))
        if a in db.func_comments:
            for ln in db.func_comments[a].splitlines():
                out.append(Line(a, "comment", f"; {ln}", func=a))
        proto = db.func_protos.get(a)
        if proto:
            out.append(Line(a, "comment", f"; {proto}", func=a))
        refs = [r for r in db.xrefs_to.get(a, ()) if r[1] in (X_CALL, X_JUMP, X_OFFSET)]
        if refs:
            out.append(self._xref_line(a, refs, "CODE", a))
        out.append(Line(a, "header", f"{db.display_name(a)} proc near", func=a))
        return out

    def _data_line(self, a: int, d, fa) -> Line:
        db, img = self.db, self.db.image
        nm = db.names.get(a) or db.default_name(a)
        cmt = db.comments.get(a, "")
        raw = img.read(a, min(d.size, 16))
        if d.kind == "string":
            txt = d.value if isinstance(d.value, str) else raw.decode("latin1")
            body = f"db '{_esc(txt)}',0"
        elif d.kind == "wstring":
            txt = d.value if isinstance(d.value, str) else ""
            body = f"du '{_esc(txt)}',0"
        elif d.kind == "ptr":
            v = img.ptr(a)
            tgt = db.names.get(v) if v is not None else None
            body = f"{'dq' if img.ptr_size == 8 else 'dd'} offset {tgt}" if tgt else \
                   f"{'dq' if img.ptr_size == 8 else 'dd'} {v:#x}" if v is not None else "dq ?"
        else:
            sz = d.size
            v = img.u(a, sz) if sz in (1, 2, 4, 8) else None
            mn = {1: "db", 2: "dw", 4: "dd", 8: "dq"}.get(sz, "db")
            if v is None:
                body = "db " + ", ".join(f"0x{b:02X}" for b in raw)
            else:
                fmt = db.opreprs.get((a, 0))
                body = f"{mn} {fmt_imm(v, fmt, db, sz * 8) or hex(v)}" if fmt else f"{mn} {v:#x}"
        t = db.applied_types.get(a)
        if t:
            cmt = (cmt + "; " if cmt else "") + t
        return Line(a, "data", f"{nm} {body}", raw.hex(" "), cmt, fa, d.size)

    def _auto_comment(self, ins: Insn) -> str:
        db = self.db
        # call-site prototype hints and string references
        if ins.flow in (CALL, INDCALL):
            tgt = ins.targets[0] if ins.targets else ins.ind_slot
            if tgt is not None:
                name = db.names.get(tgt)
                f = db.functions.get(tgt)
                if f and f.name:
                    name = f.name
                if name:
                    proto = db.types.lookup_proto(name.replace("__imp_", ""))
                    if proto is not None:
                        return db.types.format(proto, name.replace("__imp_", ""))[:140]
        for kind, a in ins.refs:
            s = db.strings.get(a)
            if s is not None:
                t = s.text if len(s.text) <= 60 else s.text[:57] + "..."
                return f'"{_esc(t)}"'
        return ""


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


def hexdump(img, addr: int, length: int = 256, width: int = 16) -> List[dict]:
    rows = []
    start = addr - (addr % width)
    for off in range(0, length, width):
        a = start + off
        b = img.read(a, width)
        if not b and img.segment_at(a) is None:
            continue
        ascii_ = "".join(chr(c) if 32 <= c < 127 else "." for c in b)
        rows.append({"addr": a, "hex": b.hex(" "), "ascii": ascii_, "bytes": list(b)})
    return rows


def to_text(db: Database, start: Optional[int] = None, end: Optional[int] = None, with_bytes: bool = False) -> str:
    """Complete textual listing between start and end (defaults to everything)."""
    lst = Listing(db)
    out = []
    for seg in db.image.segments:
        if seg.name == "HEADER":
            continue
        lo = max(seg.start, start) if start is not None else seg.start
        hi = min(seg.end, end) if end is not None else seg.end
        if lo >= hi:
            continue
        out.append(f"; Segment: {seg.name}  [{seg.start:#x}-{seg.end:#x}]  perms={seg.perms}")
        a = lo
        while a < hi:
            lines = lst._render_item(a, seg)
            for ln in lines:
                if ln.kind == "blank":
                    out.append("")
                    continue
                pre = f"{seg.name}:{ln.addr:08X}  "
                if ln.kind in ("code", "data", "unknown"):
                    b = (ln.bytes + " ") if with_bytes else ""
                    txt = f"{pre}{b:<24}{ln.text}" if with_bytes else f"{pre}    {ln.text}"
                    if ln.comment:
                        txt = f"{txt:<70} ; {ln.comment}"
                    out.append(txt)
                else:
                    out.append(f"{pre}{ln.text}")
            a = lst._next_addr(a)
    return "\n".join(out)
