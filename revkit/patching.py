"""Binary patching helpers and patched-file export (original is never modified)."""
from __future__ import annotations

import hashlib
import os
import struct
from typing import Dict, List, Optional, Tuple

from .arch import CJMP, JMP
from .db import Database


def nop_range(db: Database, addr: int, size: int) -> bytes:
    nop = db.arch.nop_bytes or b"\x90"
    if db.image.arch.name == "x86":
        data = b"\x90" * size
    else:
        if size % len(nop):
            raise ValueError(f"size must be a multiple of {len(nop)} for this architecture")
        data = nop * (size // len(nop))
    db.patch_bytes(addr, data)
    return data


def invert_branch(db: Database, addr: int) -> bytes:
    """Invert a conditional branch (x86 Jcc, ARM64 b.cond, MIPS beq/bne, PPC etc. not supported)."""
    ins = db.insn(addr)
    if ins is None or ins.flow != CJMP:
        raise ValueError("not a conditional branch")
    name = db.image.arch.name
    raw = bytearray(ins.raw)
    if name == "x86":
        if 0x70 <= raw[0] <= 0x7F:
            raw[0] ^= 1
        elif raw[0] == 0x0F and 0x80 <= raw[1] <= 0x8F:
            raw[1] ^= 1
        else:
            raise ValueError("unsupported x86 conditional branch encoding (loop/jcxz)")
    elif name == "arm64":
        w = int.from_bytes(raw, "little")
        if (w & 0xFF000010) == 0x54000000:       # b.cond
            w ^= 1
        elif (w & 0x7E000000) == 0x34000000:      # cbz/cbnz
            w ^= 1 << 24
        else:
            raise ValueError("unsupported arm64 branch")
        raw = bytearray(w.to_bytes(4, "little"))
    elif name == "mips":
        w = int.from_bytes(raw, "big" if db.image.arch.big_endian else "little")
        op = w >> 26
        if op in (4, 5):
            w ^= (4 ^ 5) << 26
        else:
            raise ValueError("unsupported mips branch")
        raw = bytearray(w.to_bytes(4, "big" if db.image.arch.big_endian else "little"))
    else:
        raise ValueError(f"invert_branch not implemented for {name}")
    db.patch_bytes(addr, bytes(raw))
    return bytes(raw)


def force_jump(db: Database, addr: int) -> bytes:
    """Turn a conditional branch into an unconditional one (x86 only)."""
    ins = db.insn(addr)
    if ins is None or ins.flow != CJMP or db.image.arch.name != "x86":
        raise ValueError("force_jump supports x86 Jcc only")
    raw = bytearray(ins.raw)
    if 0x70 <= raw[0] <= 0x7F:
        raw[0] = 0xEB
    elif raw[0] == 0x0F and 0x80 <= raw[1] <= 0x8F:
        disp = int.from_bytes(raw[2:6], "little", signed=True) + 1       # jmp rel32 is one byte shorter
        raw = bytearray(b"\xe9" + disp.to_bytes(4, "little", signed=True) + b"\x90")
    else:
        raise ValueError("unsupported encoding")
    db.patch_bytes(addr, bytes(raw))
    return bytes(raw)


def list_patches(db: Database) -> List[dict]:
    return [{"addr": a, "original": o.hex(), "patched": n.hex(), "size": len(n)} for a, o, n in db.image.patched_ranges()]


def revert_patch(db: Database, addr: int, size: Optional[int] = None) -> bool:
    """Restore original bytes of every patched run overlapping [addr, addr+size) (default: the instruction at addr)."""
    img = db.image
    if size is None:
        ins = db.insn(addr) if addr in db.insns else None
        size = ins.size if ins else 1
    hit = False
    for a, o, n in img.patched_ranges():
        if a < addr + size and addr < a + len(n):
            db.patch_bytes(a, o)
            hit = True
    return hit


def write_patched_file(db: Database, out_path: str, fix_pe_checksum: bool = True) -> dict:
    """Write a copy of the input with all patches applied at their file offsets. Returns a provenance record."""
    img = db.image
    raw = bytearray(img.raw)
    applied = []
    for a, orig, new in img.patched_ranges():
        for i, b in enumerate(new):
            off = img.file_offset(a + i)
            if off is None:
                raise ValueError(f"{a + i:#x} has no file backing (BSS/synthetic); cannot patch the file")
            # fat Mach-O: image slices keep absolute file offsets already
            if off >= len(raw):
                raise ValueError(f"file offset {off:#x} out of range")
            raw[off] = b
        applied.append({"addr": a, "original": orig.hex(), "patched": new.hex()})
    if fix_pe_checksum and img.fmt.startswith("PE") and applied:
        _pe_checksum(raw)
    with open(out_path, "wb") as f:
        f.write(raw)
    return {"input_sha256": img.sha256, "output_sha256": hashlib.sha256(bytes(raw)).hexdigest(),
            "patches": applied, "output": os.path.abspath(out_path)}


def _pe_checksum(raw: bytearray):
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    ck_off = e_lfanew + 24 + 64
    struct.pack_into("<I", raw, ck_off, 0)
    data = bytes(raw) + (b"\0" if len(raw) % 2 else b"")
    s = 0
    for i in range(0, len(data), 2):
        s += data[i] | (data[i + 1] << 8)
        s = (s & 0xFFFFFFFF) + (s >> 32)
    s = (s & 0xFFFF) + (s >> 16)
    s = (s + (s >> 16)) & 0xFFFF
    struct.pack_into("<I", raw, ck_off, (s + len(raw)) & 0xFFFFFFFF)
