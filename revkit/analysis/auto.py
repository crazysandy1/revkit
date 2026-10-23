"""Automatic analysis: recursive-descent disassembly, function discovery, CFG, xrefs, naming, strings.

The pipeline is iterative: after functions are built we infer which ones never return and, if that
discovers new no-return functions, the code is re-explored so fall-through after calls to them is not
followed (this is how disassemblers avoid decoding data that follows `exit()` / `abort()`).
"""
from __future__ import annotations

import bisect
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from ..arch import (CALL, CJMP, HALT, INDCALL, INDJMP, JMP, NORMAL, RET, Insn)
from ..db import (Block, Database, DataItem, Function, X_CALL, X_DATA, X_JUMP, X_OFFSET, X_READ, X_WRITE)
from ..image import CODE, Image
from .strings import StrItem, auto_name, find_strings

NORETURN_NAMES = {
    "exit", "_exit", "abort", "_Exit", "quick_exit", "__stack_chk_fail", "__assert_fail", "__assert", "__fortify_fail",
    "ExitProcess", "ExitThread", "TerminateProcess_", "FatalExit", "FatalAppExitA", "FatalAppExitW", "RaiseException_",
    "longjmp", "_longjmp", "siglongjmp", "__longjmp_chk", "pthread_exit", "__cxa_throw", "__cxa_rethrow",
    "__cxa_bad_cast", "__cxa_bad_typeid", "_Unwind_Resume", "__chk_fail", "err", "errx", "verr", "verrx", "_abort",
    "terminate", "__libc_fatal", "__stack_chk_fail_local", "__security_check_cookie_fail", "RtlExitUserProcess",
    "ZwTerminateProcess_", "exit_group", "__builtin_trap", "__GI_abort", "_invalid_parameter_noinfo_noreturn",
    "_invoke_watson", "__fastfail", "quick_exit", "_CxxThrowException", "std::terminate", "__imp_ExitProcess",
    "__imp_exit", "__imp__exit", "__imp_abort",
}
PAD_BYTES = {0x00, 0xCC, 0x90, 0xFF}
BAD_X86 = {"in", "out", "insb", "insw", "insd", "outsb", "outsw", "outsd", "cli", "sti", "hlt", "arpl", "int1",
           "into", "lcall", "ljmp", "lret", "iret", "iretd", "iretq", "salc", "aaa", "aas", "aam", "aad", "daa",
           "das", "bound", "wait", "fwait", "enter", "pushal", "popal", "pushad", "popad", "lds", "les"}


@dataclass
class Options:
    min_string: int = 4
    prologue_scan: bool = True
    pointer_scan: bool = True
    strings: bool = True
    signatures: bool = True
    max_passes: int = 3
    utf16: bool = True
    frames: bool = True
    trial_limit: int = 400
    max_insns: int = 5_000_000


class Analyzer:
    def __init__(self, db: Database, opts: Optional[Options] = None, progress: Optional[Callable[[str], None]] = None):
        self.db = db
        self.img: Image = db.image
        self.arch = db.arch
        self.o = opts or Options()
        self.progress = progress or (lambda m: None)
        self.fstarts: Dict[int, str] = {}
        self.queue: deque = deque()
        self.owner: Dict[int, int] = {}
        self.cand: Set[int] = set()
        self.problems: List[Tuple[int, str]] = []
        self.stats: Dict[str, object] = {}
        self._ms = time.time()
        self.import_slot = {i.addr: i for i in self.img.imports}
        self.import_stub = {i.stub: i for i in self.img.imports if i.stub}
        self.noreturn_names = set(NORETURN_NAMES)

    # ------------------------------------------------------------------
    def log(self, msg: str):
        self.progress(msg)

    def run(self) -> Dict[str, object]:
        t0 = time.time()
        db = self.db
        db._recording = False
        try:
            for p in range(self.o.max_passes):
                self.log(f"pass {p + 1}: exploring code")
                self.reset_derived()
                self.name_symbols()
                self.seed()
                self.explore_all()
                self.discover_gaps()
                self.build_functions()
                new = self.infer_noreturn()
                self.stats["passes"] = p + 1
                if not new:
                    break
            self.log("naming and cross-references")
            self.resolve_imports_and_thunks()
            self.classify_data()
            if self.o.strings:
                self.find_strings()
            self.finish_names()
            if self.o.signatures:
                try:
                    from .signatures import apply_builtin
                    self.stats["signatures"] = apply_builtin(db)
                except Exception as e:  # signature DB problems must not break analysis
                    self.problems.append((0, f"signatures: {e}"))
            if self.o.frames:
                from .frame import analyze_frames
                analyze_frames(db)
            db.analyzed = True
            db.touch_functions()
        finally:
            db._recording = True
        self.stats.update(functions=len(db.functions), instructions=len(db.insns), strings=len(db.strings),
                          xrefs=sum(len(v) for v in db.xrefs_from.values()), problems=len(self.problems),
                          seconds=round(time.time() - t0, 2))
        db.meta["analysis_stats"] = self.stats
        db.meta["problems"] = self.problems[:2000]
        db.emit("analyzed")
        return self.stats

    # ------------------------------------------------------------------
    def reset_derived(self):
        db = self.db
        db.insns.clear()
        db.data.clear()
        db.functions.clear()
        db.xrefs_from.clear()
        db.xrefs_to.clear()
        db.switches.clear()
        db.strings.clear()
        for a in [a for a, u in db.name_user.items() if not u]:
            db._apply_name(a, "", False)
        for a in [a for a in list(db.names) if not db.name_user.get(a)]:
            db._apply_name(a, "", False)
        self.fstarts.clear()
        self.queue.clear()
        self.owner.clear()
        self.cand.clear()
        self.problems.clear()
        for a, d in db.user_data.items():
            db.data[a] = d
        db.noreturn = set(getattr(self, "_nr_funcs", set()))

    # ------------------------------------------------------------------
    def name_symbols(self):
        db, img = self.db, self.img
        plat_pe = img.fmt.startswith("PE")
        for sym in img.symbols:
            if sym.kind in ("func", "object") and sym.name:
                db.set_name(sym.addr, sym.name, user=False, force=True)
        for e in img.exports:
            if e.name and e.addr and not db.names.get(e.addr):
                db.set_name(e.addr, e.name, user=False, force=True)
        for imp in img.imports:
            if plat_pe:
                db.set_name(imp.addr, f"__imp_{imp.display}", user=False, force=True)
            else:
                db.set_name(imp.addr, f"{imp.display}_ptr", user=False, force=True)
                if imp.stub:
                    db.set_name(imp.stub, imp.display, user=False, force=True)
        for i, (a, kind) in enumerate(img.entry_points):
            if kind == "entry":
                if not db.names.get(a):
                    db.set_name(a, "start", user=False, force=True)
            elif kind == "tls_callback":
                db.set_name(a, f"TlsCallback_{i}", user=False, force=True)

    def seed(self):
        db, img = self.db, self.img
        for a, kind in img.entry_points:
            self.add_func(a, kind)
        for a, src in img.func_hints.items():
            self.add_func(a, src)
        for a in db.user_funcs:
            self.add_func(a, "user")
        for a in db.user_code:
            self.queue.append(a)
        for a in list(self.fstarts):
            self.queue.append(a)

    def add_func(self, addr: int, src: str, check: bool = True) -> bool:
        if addr in self.db.user_undefined:
            return False
        if check and not self.img.is_exec(addr):
            return False
        if addr not in self.fstarts:
            self.fstarts[addr] = src
            self.queue.append(addr)
            return True
        return False

    # ------------------------------------------------------------------
    def explore_all(self):
        while self.queue:
            a = self.queue.popleft()
            if a in self.db.insns or a in self.db.user_undefined:
                continue
            self.explore(a)
            if len(self.db.insns) > self.o.max_insns:
                self.problems.append((a, "instruction limit reached"))
                self.queue.clear()
                break

    def is_noreturn_target(self, target: int) -> bool:
        db = self.db
        if target in db.noreturn:
            return True
        imp = self.import_stub.get(target) or self.import_slot.get(target)
        if imp is not None and imp.name in self.noreturn_names:
            return True
        n = db.names.get(target)
        return bool(n and n in self.noreturn_names)

    def explore(self, start: int):
        db, img, arch = self.db, self.img, self.arch
        state = arch.new_block_state()
        recent: List[Insn] = []
        addr = start
        align = arch.insn_align
        first = True
        while True:
            if addr in db.insns:
                break
            if addr in db.user_undefined or addr in db.data:
                break
            if not img.is_exec(addr):
                if first:
                    self.problems.append((addr, "code target not in executable memory"))
                break
            if align > 1 and addr % align:
                self.problems.append((addr, f"misaligned code address"))
                break
            ins = db.insn(addr)
            first = False
            if ins is None or ins.size == 0:
                self.problems.append((addr, "invalid instruction"))
                break
            # overlap with an already decoded instruction (jump into the middle)
            if self._overlaps(addr, ins.size):
                self.problems.append((addr, "overlapping instruction"))
                break
            if self.arch.spec.name == "x86" and ins.mnemonic == "int3":
                db.insns[addr] = ins.size
                break
            db.insns[addr] = ins.size
            recent.append(ins)
            if len(recent) > 40:
                del recent[0]
            arch.track_refs(ins, state, img)
            self._handle_refs(ins)
            fl = ins.flow
            nxt = ins.end
            if ins.delay_slot:
                ds = db.insn(nxt)
                if ds is not None and nxt not in db.insns:
                    db.insns[nxt] = ds.size
                    arch.track_refs(ds, state, img)
                    self._handle_refs(ds)
                    nxt = ds.end
            if fl == CALL:
                tgt = ins.targets[0]
                if tgt == ins.end and img.arch.name == "x86":     # call $+5 (get-pc idiom)
                    db.add_xref(addr, tgt, X_OFFSET)
                    addr = nxt
                    continue
                db.add_xref(addr, tgt, X_CALL)
                self.add_func(tgt, "call")
                if self.is_noreturn_target(tgt):
                    break
                addr = nxt
                continue
            if fl == INDCALL:
                if ins.ind_slot is not None:
                    db.add_xref(addr, ins.ind_slot, X_CALL)
                    imp = self.import_slot.get(ins.ind_slot)
                    if imp is not None and imp.name in self.noreturn_names:
                        break
                    else:
                        p = img.ptr(ins.ind_slot)
                        if p and imp is None and img.is_exec(p):
                            self.cand.add(p)
                addr = nxt
                continue
            if fl == JMP:
                tgt = ins.targets[0]
                db.add_xref(addr, tgt, X_JUMP)
                self.queue.append(tgt)
                break
            if fl == CJMP:
                for t in ins.targets:
                    db.add_xref(addr, t, X_JUMP)
                    self.queue.append(t)
                addr = nxt
                continue
            if fl == INDJMP:
                if ins.ind_slot is not None:
                    db.add_xref(addr, ins.ind_slot, X_JUMP)
                else:
                    self._switch(ins, recent)
                break
            if fl in (RET, HALT):
                break
            addr = nxt

    def _overlaps(self, addr: int, size: int) -> bool:
        insns = self.db.insns
        for back in range(1, 16):
            s = insns.get(addr - back)
            if s is not None and s > back:
                return True
        for fw in range(1, size):
            if (addr + fw) in insns:
                return True
        return False

    def _handle_refs(self, ins: Insn):
        db, img = self.db, self.img
        for kind, tgt in ins.refs:
            if not img.is_mapped(tgt):
                continue
            if kind == "read":
                db.add_xref(ins.addr, tgt, X_READ)
            elif kind == "write":
                db.add_xref(ins.addr, tgt, X_WRITE)
            elif kind == "offset":
                db.add_xref(ins.addr, tgt, X_OFFSET)
                if img.is_exec(tgt):
                    self.cand.add(tgt)
            else:
                db.add_xref(ins.addr, tgt, X_READ)

    def _switch(self, ins: Insn, recent: List[Insn]):
        try:
            from .switch import resolve_switch
        except ImportError:
            return
        info = resolve_switch(self.db, ins, recent)
        if info and info["targets"]:
            self.db.switches[ins.addr] = info
            for t in info["targets"]:
                self.db.add_xref(ins.addr, t, X_JUMP)
                self.queue.append(t)
            if info.get("table"):
                tb, n, esz = info["table"], info["count"], info["entry_size"]
                self.db.add_xref(ins.addr, tb, X_READ)
                for k in range(n):
                    a = tb + k * esz
                    self.db.data[a] = DataItem(a, esz, "ptr" if info.get("kind") == "abs" and esz == self.img.ptr_size else "dword", None)

    # ------------------------------------------------------------------
    # gap / candidate discovery
    # ------------------------------------------------------------------
    def trial(self, p: int) -> bool:
        """Decide whether `p` begins plausible code without committing anything."""
        db, img, arch = self.db, self.img, self.arch
        a, n = p, 0
        is_x86 = arch.spec.name == "x86"
        while n < self.o.trial_limit:
            if a in db.insns:
                return n >= 1
            if a in db.data or not img.is_exec(a):
                return False
            ins = db.insn(a)
            if ins is None:
                return False
            if is_x86 and ins.mnemonic in BAD_X86:
                return False
            if is_x86 and ins.mnemonic == "add" and ins.raw[:2] == b"\x00\x00":
                return False          # add [rax], al: zeroed memory decodes as this
            for t in ins.targets:
                if not img.is_mapped(t):
                    return False
            n += 1
            if ins.flow in (RET, JMP, INDJMP, HALT):
                return n >= 2 or ins.flow == RET and n >= 1
            a = ins.end
        return False

    def _is_pad(self, a: int) -> bool:
        b = self.img.read(a, 1)
        if not b:
            return True
        v = b[0]
        spec = self.arch.spec.name
        if spec == "x86":
            return v in (0x00, 0xCC, 0x90)
        return v == 0x00 and self.img.read(a, self.arch.insn_align) == bytes(self.arch.insn_align)

    def discover_gaps(self):
        for _ in range(6):
            added = self._process_candidates()
            if self.o.prologue_scan:
                added += self._scan_gaps()
            if self.o.pointer_scan:
                added += self._scan_pointers()
            self.explore_all()
            if not added:
                break

    def _process_candidates(self) -> int:
        n = 0
        for c in sorted(self.cand):
            if c in self.db.insns or c in self.fstarts:
                continue
            if self.arch.spec.name == "x86" or self.trial(c):
                if self.trial(c):
                    self.add_func(c, "pointer")
                    n += 1
        self.cand.clear()
        return n

    def _scan_gaps(self) -> int:
        db, img, arch = self.db, self.img, self.arch
        added = 0
        starts = sorted(db.insns)          # snapshot; newly explored code is detected through `db.insns` membership
        step = arch.insn_align
        for seg in img.segments:
            if not seg.executable:
                continue
            lo, hi = seg.start, seg.end
            pos = lo
            while pos < hi:
                if pos in db.insns:
                    pos += db.insns[pos]
                    continue
                j = bisect.bisect_left(starts, pos)
                gap_end = starts[j] if j < len(starts) and starts[j] < hi else hi
                p = pos
                found_first = False
                while p < gap_end:
                    if p in db.insns:                       # code appeared here while exploring an earlier candidate
                        p += db.insns[p]
                        found_first = False
                        continue
                    if self._is_pad(p):
                        p += step if step > 1 else 1
                        continue
                    pi = db.insn(p)
                    if pi is not None and arch.is_nop(pi):
                        p += pi.size                        # multi-byte NOP padding between functions
                        continue
                    ok = False
                    buf = img.read(p, 8)
                    if (not found_first) or arch.looks_like_prologue(buf):
                        if arch.insn_align == 1 or p % arch.insn_align == 0:
                            ok = self.trial(p)
                    found_first = True
                    if ok:
                        self.add_func(p, "prologue")
                        self.explore_all()
                        added += 1
                        found_first = False
                    else:
                        p += step
                pos = max(gap_end, pos + 1)
        return added

    def _scan_pointers(self) -> int:
        """Find tables of code pointers (vtables, callback arrays, relocation-targeted pointers)."""
        db, img = self.db, self.img
        ps = img.ptr_size
        added = 0
        reloc_addrs = {a for a, k, ad in img.relocations}
        for seg in img.segments:
            if (seg.executable and "w" not in seg.perms) or seg.name == "HEADER":
                continue
            data = seg.data
            n = len(data) // ps
            run = []
            fmt = "big" if img.arch.big_endian else "little"
            base = seg.start
            for k in range(n + 1):
                v = int.from_bytes(data[k * ps:(k + 1) * ps], fmt) if k < n else None
                a = base + k * ps
                if seg.executable and (a in db.insns or self._covered_by_insn(a)):
                    v = None
                if v is not None and img.is_exec(v) and v not in db.data and (
                        v in self.fstarts or v in db.insns or a in reloc_addrs
                        or self.arch.looks_like_prologue(img.read(v, 8))):
                    run.append((a, v))
                    continue
                if len(run) >= 2 or (len(run) == 1 and run[0][0] in reloc_addrs):
                    for ra, rv in run:
                        if rv not in db.insns and rv not in self.fstarts and self.trial(rv):
                            self.add_func(rv, "pointer")
                            added += 1
                        db.add_xref(ra, rv, X_OFFSET)
                        db.data.setdefault(ra, DataItem(ra, ps, "ptr", rv))
                run = []
        return added

    # ------------------------------------------------------------------
    # function construction
    # ------------------------------------------------------------------
    def build_functions(self):
        db = self.db
        self.owner.clear()
        order = sorted(a for a in self.fstarts if a in db.insns)
        strong = {a for a in order if self.fstarts[a] in ("symtab", "pdata", "eh_frame", "export", "user", "entry", "func_starts")}
        starts_set = set(order)
        # strong seeds first so that tail-merged regions pick the authoritative owner
        for a in sorted(strong) + [a for a in order if a not in strong]:
            if a in self.owner and self.owner[a] != a:
                # start lies inside another function's chunk (shared tail): keep as separate function entry
                pass
            self._build_function(a, starts_set)
        # code not claimed by any function (e.g. reached only via jumps from data) becomes orphan chunks
        for a in sorted(db.insns):
            if a not in self.owner and a not in db.user_undefined:
                if a in self.fstarts:
                    continue
                if a in db.user_nofunc:
                    self._claim_flow(a)         # analyst deleted this function: keep its code, but do not re-create it
                    continue
                self._build_function(a, starts_set, orphan=True)
                starts_set.add(a)
        db.touch_functions()

    def _claim_flow(self, start: int):
        db = self.db
        stack, seen = [start], set()
        while stack:
            a = stack.pop()
            while a in db.insns and a not in seen and a not in self.owner:
                seen.add(a)
                self.owner[a] = -1
                ins = db.insn(a)
                if ins is None:
                    break
                nxt = ins.end
                if ins.delay_slot and nxt in db.insns:
                    self.owner[nxt] = -1
                    nxt = nxt + db.insns[nxt]
                if ins.flow == CJMP:
                    stack.extend(t for t in ins.targets)
                    a = nxt
                    continue
                if ins.flow == JMP:
                    stack.extend(ins.targets)
                    break
                if ins.flow in (RET, HALT, INDJMP):
                    break
                a = nxt

    def _build_function(self, start: int, starts: Set[int], orphan: bool = False):
        db = self.db
        if start in db.functions or start not in db.insns:
            return
        f = Function(start, db.names.get(start, ""), source=self.fstarts.get(start, "orphan" if orphan else "auto"))
        owned: List[int] = []
        seen: Set[int] = set()
        stack = [start]
        tails: Set[int] = set()
        limit = db.user_func_end.get(start)
        leaders: Set[int] = {start}
        has_ret = has_halt = False
        while stack:
            a = stack.pop()
            while a in db.insns and a not in seen:
                if a != start and (a in starts or (a in self.owner and self.owner[a] != start)):
                    tails.add(a)       # tail call / shared code
                    break
                if limit is not None and a >= limit:
                    tails.add(a)       # analyst fixed the end of this function
                    break
                seen.add(a)
                owned.append(a)
                self.owner[a] = start
                ins = db.insn(a)
                if ins is None:
                    break
                nxt = ins.end
                if ins.delay_slot:
                    ds = db.insn(nxt)
                    if ds is not None and nxt in db.insns:
                        seen.add(nxt)
                        owned.append(nxt)
                        self.owner[nxt] = start
                        nxt = ds.end
                fl = ins.flow
                if fl == CJMP:
                    for t in ins.targets:
                        leaders.add(t)
                        stack.append(t)
                    leaders.add(nxt)
                    a = nxt
                    continue
                if fl == JMP:
                    t = ins.targets[0]
                    if t in starts and t != start:
                        tails.add(t)
                    else:
                        leaders.add(t)
                        stack.append(t)
                    break
                if fl == INDJMP:
                    sw = db.switches.get(a)
                    if sw:
                        for t in sw["targets"]:
                            leaders.add(t)
                            stack.append(t)
                    elif ins.ind_slot is None:
                        f.flags.add("indirect_jump")
                    break
                if fl == RET:
                    has_ret = True
                    break
                if fl == HALT:
                    has_halt = True
                    break
                if fl == CALL and self.is_noreturn_target(ins.targets[0]):
                    break
                if fl == INDCALL and ins.ind_slot is not None and (self.import_slot.get(ins.ind_slot) and
                                                                    self.import_slot[ins.ind_slot].name in self.noreturn_names):
                    break
                a = nxt
        if not owned:
            return
        owned_sorted = sorted(set(owned))
        # blocks
        leaders |= {start}
        blocks: Dict[int, Block] = {}
        cur: Optional[Block] = None
        prev_end = None
        oset = set(owned_sorted)
        for a in owned_sorted:
            sz = db.insns[a]
            if cur is None or a in leaders or prev_end != a:
                cur = Block(a, a + sz, [a])
                blocks[a] = cur
            else:
                cur.insns.append(a)
                cur.end = a + sz
            prev_end = a + sz
        for b in blocks.values():
            last_a = b.insns[-1]
            ins = db.insn(last_a)
            last_real = ins
            if ins is not None and len(b.insns) >= 2:
                pv = db.insn(b.insns[-2])
                if pv is not None and pv.delay_slot:
                    last_real = pv
            if last_real is None:
                continue
            fl = last_real.flow
            end = b.end
            if fl == CJMP:
                for t in last_real.targets:
                    if t in blocks:
                        b.succs.append((t, "true"))
                if end in blocks:
                    b.succs.append((end, "false"))
            elif fl == JMP:
                t = last_real.targets[0]
                if t in blocks:
                    b.succs.append((t, "jump"))
            elif fl == INDJMP and last_a in db.switches:
                for t in db.switches[last_a]["targets"]:
                    if t in blocks:
                        b.succs.append((t, "switch"))
            elif fl in (RET, HALT, INDJMP):
                pass
            elif fl == CALL and self.is_noreturn_target(last_real.targets[0]):
                pass
            elif end in blocks:
                b.succs.append((end, "fall"))
        # tail calls: keep as jump xrefs; mark function
        if tails:
            f.flags.add("tailcalls")
        # chunks
        chunks: List[Tuple[int, int]] = []
        for b in sorted(blocks.values(), key=lambda x: x.start):
            if chunks and chunks[-1][1] == b.start:
                chunks[-1] = (chunks[-1][0], b.end)
            else:
                chunks.append((b.start, b.end))
        f.blocks = blocks
        f.chunks = chunks
        f.end = max(e for _, e in chunks)
        if has_halt and not has_ret:
            f.flags.add("halts")
        f.flags.add("returns" if has_ret or "tailcalls" in f.flags else "noret_candidate")
        if orphan:
            f.flags.add("orphan")
        db.functions[start] = f

    # ------------------------------------------------------------------
    def infer_noreturn(self) -> bool:
        """Fixpoint: functions with no return path are no-return. Returns True if the set grew."""
        db = self.db
        known = set(getattr(self, "_nr_funcs", set()))
        cur = set(known)
        changed = True
        while changed:
            changed = False
            for a, f in db.functions.items():
                if a in cur or "orphan" in f.flags:
                    continue
                if self._no_return_path(f, cur):
                    cur.add(a)
                    changed = True
        # also thunks to known no-return imports
        for a, f in db.functions.items():
            if a in cur:
                continue
            if len(f.blocks) == 1 and len(next(iter(f.blocks.values())).insns) == 1:
                i = db.insn(f.start)
                if i and i.flow == INDJMP and i.ind_slot in self.import_slot and \
                        self.import_slot[i.ind_slot].name in self.noreturn_names:
                    cur.add(a)
        new = cur - known
        self._nr_funcs = cur
        db.noreturn = set(cur)
        return bool(new)

    def _no_return_path(self, f: Function, nr: Set[int]) -> bool:
        db = self.db
        if not f.blocks:
            return False
        for b in f.blocks.values():
            last = db.insn(b.insns[-1])
            if last is None:
                return False
            if len(b.insns) >= 2:
                pv = db.insn(b.insns[-2])
                if pv is not None and pv.delay_slot:
                    last = pv
            fl = last.flow
            if fl == RET:
                return False
            if fl == INDJMP and last.addr not in db.switches:
                return False
            if fl == JMP:
                t = last.targets[0]
                if t not in f.blocks and t not in nr and not self.is_noreturn_target(t):
                    return False
            elif fl == CALL:
                if not (last.targets[0] in nr or self.is_noreturn_target(last.targets[0])) and not b.succs:
                    return False
            elif fl == INDCALL:
                imp = self.import_slot.get(last.ind_slot)
                if not (imp is not None and imp.name in self.noreturn_names) and not b.succs:
                    return False
            elif fl == NORMAL and not b.succs:
                return False
        return True

    # ------------------------------------------------------------------
    def resolve_imports_and_thunks(self):
        db, img = self.db, self.img
        db_import_slots = self.import_slot
        # import slots are pointer data items
        ps = img.ptr_size
        for imp in img.imports:
            db.data[imp.addr] = DataItem(imp.addr, ps, "ptr", None, "import")
        for a, f in db.functions.items():
            if len(f.blocks) != 1:
                continue
            b = next(iter(f.blocks.values()))
            if len(b.insns) > 3:
                continue
            tgt = None
            slot = None
            for ia in b.insns:
                ins = db.insn(ia)
                if ins.flow == INDJMP and ins.ind_slot is not None:
                    slot = ins.ind_slot
                elif ins.flow == JMP:
                    tgt = ins.targets[0]
                elif ins.flow == CJMP or ins.flow == RET:
                    pass
            # ARM/AArch64 PLT: adrp+ldr+br - use import.stub mapping
            imp = self.import_stub.get(a)
            if imp is None and slot is not None:
                imp = db_import_slots.get(slot)
            if imp is None and slot is None and tgt is None:
                # indirect jump via loaded pointer (arm64 PLT): resolve via ref data
                for ia in b.insns:
                    ins = db.insn(ia)
                    for kind, t in ins.refs:
                        if t in db_import_slots:
                            imp = db_import_slots[t]
            if imp is not None:
                f.flags |= {"thunk", "import", "library"}
                f.thunk_target = imp.addr
                if not db.names.get(a) or not db.name_user.get(a, False):
                    db.set_name(a, imp.display, user=False, force=True)
                f.name = db.names.get(a, imp.display)
            elif tgt is not None and tgt != a:
                f.flags.add("thunk")
                f.thunk_target = tgt
                tn = db.names.get(tgt)
                if tn and not db.names.get(a):
                    db.set_name(a, f"j_{tn}", user=False, force=True)
                    f.name = db.names.get(a, "")
        # function names from symbol table already set; propagate to Function objects
        for a, f in db.functions.items():
            n = db.names.get(a)
            if n:
                f.name = n

    def classify_data(self):
        """Create typed data items for referenced addresses outside code."""
        db, img = self.db, self.img
        ps = img.ptr_size
        for tgt, refs in list(db.xrefs_to.items()):
            if tgt in db.insns or tgt in db.data or not img.is_mapped(tgt):
                continue
            seg = img.segment_at(tgt)
            if seg.executable and seg.kind == CODE and tgt in db.functions:
                continue
            kinds = {k for _, k in refs}
            if self._covered_by_insn(tgt):
                continue
            size = ps
            kind = "ptr"
            v = img.u(tgt, ps)
            if v is not None and (img.is_mapped(v) or v in db.functions):
                kind = "ptr"
                if img.is_exec(v):
                    self.cand.add(v)
            else:
                kind = {1: "byte", 2: "word", 4: "dword", 8: "qword"}.get(size, "dword")
            db.data[tgt] = DataItem(tgt, size, kind, v)

    def _covered_by_insn(self, a: int) -> bool:
        db = self.db
        for back in range(1, 16):
            s = db.insns.get(a - back)
            if s is not None and s > back:
                return True
        return False

    def find_strings(self):
        db, img = self.db, self.img
        covered = set()
        for a, sz in db.insns.items():
            covered.update(range(a, a + sz)) if sz < 16 else None
        items = find_strings(img, self.o.min_string, covered, self.o.utf16, force=set(db.xrefs_to))
        taken = set(db.names.values())
        for it in items:
            if it.addr in db.insns or self._covered_by_insn(it.addr):
                continue
            existing = db.data.get(it.addr)
            if existing and existing.kind not in ("ptr", "byte", "word", "dword", "qword", "unknown") and existing.kind != "string":
                continue
            db.strings[it.addr] = it
            db.data[it.addr] = DataItem(it.addr, it.length, "wstring" if it.encoding == "utf16" else "string", it.text)
            # offset-ref into the middle of a string keeps a data xref; naming only for referenced strings
            if db.xrefs_to.get(it.addr) and it.addr not in db.names:
                n = auto_name(it.text, taken)
                taken.add(n)
                db.set_name(it.addr, n, user=False, force=True)

    def finish_names(self):
        db = self.db
        for a, f in db.functions.items():
            if "thunk" in f.flags and f.thunk_target is not None and f.name == "":
                pass
        # loc_ names are produced on the fly by display_name


def analyze(db: Database, options: Optional[Options] = None, progress=None) -> Dict[str, object]:
    return Analyzer(db, options, progress).run()
