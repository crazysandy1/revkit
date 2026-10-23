"""CPU emulation (Unicorn) for running isolated functions: string decryptors, hash/checksum routines, unpacking stubs.

Only the loaded image is mapped; nothing from the host is executed. Calls to unmapped/imported code are stubbed (return 0)
so that decoder routines can run without a process. Memory writes are tracked so decoded buffers can be extracted.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from unicorn import (Uc, UC_ARCH_ARM, UC_ARCH_ARM64, UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED,
                     UC_HOOK_MEM_WRITE, UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED, UC_MODE_32, UC_MODE_64,
                     UC_MODE_ARM, UC_MODE_THUMB, UcError)
from unicorn import x86_const as x, arm64_const as a64, arm_const as arm

import threading

UC_LOCK = threading.RLock()      # Unicorn's setup path is not reliably thread-safe on all hosts; serialise it
STACK_BASE = 0x7FF00000
STACK_SIZE = 0x100000
HEAP_BASE = 0x60000000
HEAP_SIZE = 0x400000
RET_SENTINEL = 0x5E5E0000


class EmuError(Exception):
    pass


class EmuResult:
    def __init__(self):
        self.ok = False
        self.error = ""
        self.insns = 0
        self.regs: Dict[str, int] = {}
        self.writes: List[Tuple[int, int, bytes]] = []     # (addr, size, data after execution)
        self.stub_calls: List[int] = []
        self.trace: List[int] = []
        self.oep: Optional[int] = None
        self.dump: Dict[int, bytes] = {}

    def to_dict(self):
        return {"ok": self.ok, "error": self.error, "insns": self.insns, "regs": self.regs,
                "writes": [{"addr": a, "size": s, "hex": d.hex()} for a, s, d in self.writes],
                "stub_calls": self.stub_calls}


def _uc(proj):
    a = proj.image.arch
    if a.name == "x86":
        return Uc(UC_ARCH_X86, {16: UC_MODE_32, 32: UC_MODE_32, 64: UC_MODE_64}[a.bits])
    if a.name == "arm64":
        return Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    if a.name in ("arm", "thumb"):
        return Uc(UC_ARCH_ARM, UC_MODE_THUMB if a.name == "thumb" or a.mode == "thumb" else UC_MODE_ARM)
    raise EmuError(f"emulation not supported for {a.name}")


def emulate(proj, entry: int, args: Optional[List[int]] = None, max_insns: int = 200000, memory: Optional[Dict[int, bytes]] = None,
            regs: Optional[Dict[str, int]] = None, stop_at: Optional[int] = None, trace: bool = False,
            unpack_mode: bool = False) -> EmuResult:
    """Run the code at `entry` with integer `args` (ABI-conforming) until it returns, hits `stop_at`, or runs out of budget."""
    with UC_LOCK:
        img = proj.image
        uc = _uc(proj)
        res = EmuResult()
        pg = 0x1000
        for s in img.segments:
            lo = s.start & ~(pg - 1)
            hi = (s.end + pg - 1) & ~(pg - 1)
            try:
                uc.mem_map(lo, hi - lo)
            except UcError:
                pass                       # overlapping header/section pages
            uc.mem_write(s.start, bytes(s.data))
        uc.mem_map(STACK_BASE, STACK_SIZE)
        uc.mem_map(HEAP_BASE, HEAP_SIZE)
        uc.mem_map(RET_SENTINEL, pg)
        for addr, data in (memory or {}).items():
            lo = addr & ~(pg - 1)
            try:
                uc.mem_map(lo, ((addr + len(data) + pg - 1) & ~(pg - 1)) - lo)
            except UcError:
                pass
            uc.mem_write(addr, data)
        a = img.arch
        bits = a.bits
        sp = STACK_BASE + STACK_SIZE - 0x1000
        if a.name == "x86":
            if bits == 64:
                win = img.fmt.startswith("PE")
                order = [x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9] if win else \
                    [x.UC_X86_REG_RDI, x.UC_X86_REG_RSI, x.UC_X86_REG_RDX, x.UC_X86_REG_RCX, x.UC_X86_REG_R8, x.UC_X86_REG_R9]
                for r, v in zip(order, args or []):
                    uc.reg_write(r, v & (2 ** 64 - 1))
                extra = (args or [])[len(order):]
                sp -= 8 * len(extra) + 0x28
                for i, v in enumerate(extra):
                    uc.mem_write(sp + 8 + (0x20 if win else 0) + 8 * i, (v & (2 ** 64 - 1)).to_bytes(8, "little"))
                sp -= 8
                uc.mem_write(sp, RET_SENTINEL.to_bytes(8, "little"))
                uc.reg_write(x.UC_X86_REG_RSP, sp)
            else:
                sp -= 4 * len(args or []) + 4
                uc.mem_write(sp, RET_SENTINEL.to_bytes(4, "little"))
                for i, v in enumerate(args or []):
                    uc.mem_write(sp + 4 + 4 * i, (v & 0xFFFFFFFF).to_bytes(4, "little"))
                uc.reg_write(x.UC_X86_REG_ESP, sp)
        elif a.name == "arm64":
            for i, v in enumerate((args or [])[:8]):
                uc.reg_write(a64.UC_ARM64_REG_X0 + i, v)
            uc.reg_write(a64.UC_ARM64_REG_SP, sp)
            uc.reg_write(a64.UC_ARM64_REG_X30, RET_SENTINEL)
        else:
            for i, v in enumerate((args or [])[:4]):
                uc.reg_write(arm.UC_ARM_REG_R0 + i, v)
            uc.reg_write(arm.UC_ARM_REG_SP, sp)
            uc.reg_write(arm.UC_ARM_REG_LR, RET_SENTINEL | (1 if a.name == "thumb" else 0))
        for k, v in (regs or {}).items():
            uc.reg_write(_regid(a, k), v)

    written: Dict[int, int] = {}
    count = [0]
    ret_stub = {"x86_64": x.UC_X86_REG_RAX}

    def on_write(uc_, access, address, size, value, ud):
        for i in range(size):
            written[address + i] = 1

    def on_unmapped(uc_, access, address, size, value, ud):
        try:
            lo = address & ~(pg - 1)
            uc_.mem_map(lo, pg)
            return True
        except UcError:
            return False

    def on_code(uc_, address, size, ud):
        count[0] += 1
        if trace and len(res.trace) < 100000:
            res.trace.append(address)
        if stop_at is not None and address == stop_at:
            uc_.emu_stop()
        if unpack_mode and address in written and not (STACK_BASE <= address < STACK_BASE + STACK_SIZE):
            res.oep = address                    # first instruction fetched from memory the program wrote itself
            uc_.emu_stop()
        # stub: calls into imports / unmapped code just return 0
        if address in imp_stubs:
            res.stub_calls.append(address)
            _do_return(uc_, a, bits)

    imp_stubs = {i.stub for i in img.imports if i.stub}
    imp_stubs |= {f.start for f in proj.db.functions.values() if "import" in f.flags}
    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, on_unmapped)
    uc.hook_add(UC_HOOK_CODE, on_code)
    try:
        start = entry | 1 if (a.name == "thumb" or a.mode == "thumb") else entry
        uc.emu_start(start, RET_SENTINEL, count=max_insns)
        res.ok = True
    except UcError as e:
        res.error = str(e)
        res.ok = False
        if "UC_ERR_FETCH_UNMAPPED" in str(e) or "FETCH_PROT" in str(e):
            # returning to the sentinel counts as a normal exit on some targets
            res.ok = False
    res.insns = count[0]
    if unpack_mode:
        res.dump = {}
        for s in img.segments:
            try:
                res.dump[s.start] = bytes(uc.mem_read(s.start, s.size))
            except UcError:
                pass
    if a.name == "x86":
        names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip"] + [f"r{i}" for i in range(8, 16)] \
            if bits == 64 else ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]
    elif a.name == "arm64":
        names = [f"x{i}" for i in range(31)] + ["sp"]
    else:
        names = [f"r{i}" for i in range(13)] + ["sp", "lr", "pc"]
    for n in names:
        try:
            res.regs[n] = uc.reg_read(_regid(a, n))
        except Exception:
            pass
    # coalesce written bytes into runs
    addrs = sorted(written)
    i = 0
    while i < len(addrs):
        j = i
        while j + 1 < len(addrs) and addrs[j + 1] == addrs[j] + 1:
            j += 1
        lo, hi = addrs[i], addrs[j] + 1
        if not (STACK_BASE <= lo < STACK_BASE + STACK_SIZE):
            try:
                res.writes.append((lo, hi - lo, bytes(uc.mem_read(lo, min(hi - lo, 1 << 16)))))
            except UcError:
                pass
        i = j + 1
    return res


class _ImageOnly:
    """Minimal stand-in for a Project so emulation can run before any analysis exists."""

    def __init__(self, image):
        self.image = image
        self.db = type("_D", (), {"functions": {}})()


def unpack_image(img, max_insns: int = 20_000_000, rounds: int = 4) -> dict:
    """Unpack `img` in place by emulation. Layered packers are handled by repeating up to `rounds` times: each round runs from
    the current entry point until memory written by the program is executed, then the image bytes and entry point are replaced.
    Returns {"ok", "layers", "oeps", "insns"}; the image is left untouched when no layer unpacks."""
    from .image import Segment
    shim = _ImageOnly(img)
    layers, oeps, total = 0, [], 0
    for _ in range(rounds):
        ep = img.entry_points[0][0] if img.entry_points else img.min_addr
        r = emulate(shim, ep, [], max_insns=max_insns, unpack_mode=True)
        total += r.insns
        if r.oep is None or not r.dump:
            break
        for s in img.segments:
            d = r.dump.get(s.start)
            if d is not None and len(d) == s.size:
                s.data[:] = d
        img.entry_points = [(r.oep, "entry")] + [e for e in img.entry_points[1:]]
        img.func_hints = {}
        oeps.append(r.oep)
        layers += 1
        if not img.is_exec(r.oep):
            break
    if layers:
        img.info["unpacked"] = {"layers": layers, "oeps": oeps}
        img.warnings.append(f"image was unpacked by emulation ({layers} layer(s)); imports resolved by the packer stub are not "
                            "reconstructed and the file bytes no longer match the loaded memory")
        for s in img.segments:
            s.orig = bytes(s.data)           # unpacked bytes become the baseline for patch diffs
    return {"ok": layers > 0, "layers": layers, "oeps": oeps, "insns": total}


def unpack(proj, entry: Optional[int] = None, max_insns: int = 20_000_000, dump_path: Optional[str] = None) -> dict:
    """Emulate from the entry point until the program executes memory it wrote itself (typical for packers/crypters that
    decode a payload in place), then return the original entry point and the unpacked image bytes.

    The dump is a flat snapshot of every segment of the image (written back at its linked address); load it with
    `Project.load(dump, arch=..., base=<lowest address>, entry=<oep>)`. Only the emulated copy is executed."""
    ep = entry if entry is not None else proj.image.entry_points[0][0]
    r = emulate(proj, ep, [], max_insns=max_insns, unpack_mode=True)
    out = {"ok": r.oep is not None, "oep": r.oep, "insns": r.insns, "error": r.error, "stub_calls": len(r.stub_calls)}
    if r.oep is not None and r.dump:
        lo = min(r.dump)
        hi = max(a + len(d) for a, d in r.dump.items())
        buf = bytearray(hi - lo)
        for a, d in r.dump.items():
            buf[a - lo:a - lo + len(d)] = d
        out["base"] = lo
        out["size"] = len(buf)
        out["changed_bytes"] = sum(1 for a, d in r.dump.items() for i, b in enumerate(d)
                                   if b != (proj.image.read(a + i, 1) or b"\0")[0]) if hi - lo < 4_000_000 else None
        if dump_path:
            with open(dump_path, "wb") as f:
                f.write(buf)
            out["dump"] = dump_path
    return out


def _do_return(uc, a, bits):
    if a.name == "x86":
        if bits == 64:
            rsp = uc.reg_read(x.UC_X86_REG_RSP)
            ret = int.from_bytes(uc.mem_read(rsp, 8), "little")
            uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(x.UC_X86_REG_RAX, 0)
            uc.reg_write(x.UC_X86_REG_RIP, ret)
        else:
            esp = uc.reg_read(x.UC_X86_REG_ESP)
            ret = int.from_bytes(uc.mem_read(esp, 4), "little")
            uc.reg_write(x.UC_X86_REG_ESP, esp + 4)
            uc.reg_write(x.UC_X86_REG_EAX, 0)
            uc.reg_write(x.UC_X86_REG_EIP, ret)
    elif a.name == "arm64":
        uc.reg_write(a64.UC_ARM64_REG_X0, 0)
        uc.reg_write(a64.UC_ARM64_REG_PC, uc.reg_read(a64.UC_ARM64_REG_X30))
    else:
        uc.reg_write(arm.UC_ARM_REG_R0, 0)
        uc.reg_write(arm.UC_ARM_REG_PC, uc.reg_read(arm.UC_ARM_REG_LR))


def _regid(a, name: str) -> int:
    n = name.lower()
    if a.name == "x86":
        return getattr(x, f"UC_X86_REG_{n.upper()}")
    if a.name == "arm64":
        return a64.UC_ARM64_REG_SP if n == "sp" else getattr(a64, f"UC_ARM64_REG_{n.upper()}")
    return getattr(arm, f"UC_ARM_REG_{n.upper()}")


def decode_strings(proj, decoder: int, max_calls: int = 200, buf_size: int = 256) -> List[dict]:
    """Emulate `decoder(src_ptr)` / `decoder(dst, src)` style routines for every call site with constant pointer arguments.

    Heuristic: the first constant argument that points into the image is the encoded buffer; the decoder is assumed to decode in
    place or write into a scratch buffer provided as the other argument. Results are candidates for analyst review.
    """
    from .decompiler import decompile
    out: List[dict] = []
    db = proj.db
    callers = {c for c in db.callers(decoder)}
    for caller in sorted(callers):
        try:
            pc = decompile(db, caller)
        except Exception:
            continue
        for c in pc.calls:
            t = c["target"]
            if not (hasattr(t, "v") and t.v == decoder):
                continue
            consts = [a.v for a in c["args"] if hasattr(a, "v") and proj.image.is_mapped(a.v)]
            if not consts:
                continue
            scratch = HEAP_BASE + 0x1000
            args = []
            for a in c["args"]:
                args.append(a.v if hasattr(a, "v") else scratch)
            before = {x_: proj.image.read(x_, buf_size) for x_ in consts}
            r = emulate(proj, decoder, args, max_insns=500000, memory={scratch: bytes(buf_size)})
            cand = []
            for addr, size, data in r.writes:
                txt = _printable(data)
                if txt and len(txt) >= 3:
                    cand.append((addr, txt))
            if cand:
                out.append({"call": c["addr"], "caller": caller, "args": [hex(a) for a in args], "decoded": cand,
                            "insns": r.insns, "ok": r.ok})
        if len(out) >= max_calls:
            break
    return out


def _printable(data: bytes) -> str:
    end = data.find(b"\x00")
    chunk = data[:end] if end >= 0 else data
    if len(chunk) >= 3 and all(32 <= b < 127 or b in (9, 10, 13) for b in chunk):
        return chunk.decode("ascii")
    return ""
