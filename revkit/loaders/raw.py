"""Headerless formats: raw binary, DOS COM, Intel HEX, Motorola S-record."""
from __future__ import annotations

from typing import Optional

from ..image import ArchSpec, Image, Segment, CODE

ARCH_ALIASES = {
    "x86": ("x86", 32, False), "i386": ("x86", 32, False), "x86_64": ("x86", 64, False), "x64": ("x86", 64, False),
    "amd64": ("x86", 64, False), "x86_16": ("x86", 16, False), "8086": ("x86", 16, False),
    "arm": ("arm", 32, False), "thumb": ("thumb", 32, False), "arm64": ("arm64", 64, False),
    "aarch64": ("arm64", 64, False), "mips": ("mips", 32, True), "mipsel": ("mips", 32, False),
    "mips64": ("mips", 64, True), "ppc": ("ppc", 32, True), "ppc64": ("ppc", 64, True),
    "riscv32": ("riscv", 32, False), "riscv64": ("riscv", 64, False), "riscv": ("riscv", 64, False),
    "sparc": ("sparc", 32, True), "m68k": ("m68k", 32, True), "6502": ("mos65xx", 16, False),
    "sysz": ("sysz", 64, True), "s390x": ("sysz", 64, True),
}


def parse_arch(spec: str) -> ArchSpec:
    k = spec.lower().strip()
    if k not in ARCH_ALIASES:
        raise ValueError(f"unknown architecture {spec!r}; choices: {', '.join(sorted(ARCH_ALIASES))}")
    n, b, be = ARCH_ALIASES[k]
    return ArchSpec(n, b, be)


def load_raw(path: str, raw: bytes, arch: ArchSpec, base: int = 0, entry: Optional[int] = None) -> Image:
    img = Image(path, "RAW", arch, raw)
    img.imagebase = base
    img.add_segment(Segment("raw", base, base + max(len(raw), 1), "rwx", CODE, 0, bytearray(raw)))
    img.entry_points.append((base if entry is None else entry, "entry"))
    return img


def load_com(path: str, raw: bytes) -> Image:
    if not (0 < len(raw) <= 65280):
        raise ValueError("DOS COM image must be 1..65280 bytes")
    img = Image(path, "DOS-COM", ArchSpec("x86", 16), raw)
    img.imagebase = 0x100
    img.add_segment(Segment("com", 0x100, 0x100 + len(raw), "rwx", CODE, 0, bytearray(raw)))
    img.entry_points.append((0x100, "entry"))
    return img


def load_ihex(path: str, raw: bytes, arch: ArchSpec) -> Image:
    regions = {}
    ext = 0
    start = None
    for line in raw.decode("ascii", "replace").splitlines():
        line = line.strip()
        if not line.startswith(":"):
            continue
        b = bytes.fromhex(line[1:])
        n, addr, typ = b[0], (b[1] << 8) | b[2], b[3]
        data = b[4:4 + n]
        if (sum(b) & 0xFF) != 0:
            raise ValueError("Intel HEX checksum error")
        if typ == 0:
            for i, v in enumerate(data):
                regions[ext + addr + i] = v
        elif typ == 2:
            ext = int.from_bytes(data, "big") << 4
        elif typ == 4:
            ext = int.from_bytes(data, "big") << 16
        elif typ in (3, 5):
            start = int.from_bytes(data, "big") if typ == 5 else ((data[0] << 8 | data[1]) << 4) + (data[2] << 8 | data[3])
    return _from_sparse(path, raw, arch, regions, start, "IHEX")


def load_srec(path: str, raw: bytes, arch: ArchSpec) -> Image:
    regions = {}
    start = None
    for line in raw.decode("ascii", "replace").splitlines():
        line = line.strip()
        if not line.startswith("S") or len(line) < 4:
            continue
        t = line[1]
        b = bytes.fromhex(line[2:])
        if (sum(b) & 0xFF) != 0xFF:
            raise ValueError("S-record checksum error")
        alen = {"1": 2, "2": 3, "3": 4, "7": 4, "8": 3, "9": 2}.get(t)
        if alen is None:
            continue
        addr = int.from_bytes(b[1:1 + alen], "big")
        if t in "123":
            for i, v in enumerate(b[1 + alen:-1]):
                regions[addr + i] = v
        elif t in "789":
            start = addr
    return _from_sparse(path, raw, arch, regions, start, "SREC")


def _from_sparse(path, raw, arch, regions, start, fmt):
    if not regions:
        raise ValueError(f"{fmt}: no data records")
    img = Image(path, fmt, arch, raw)
    addrs = sorted(regions)
    runs, rs, prev = [], addrs[0], addrs[0]
    for a in addrs[1:]:
        if a != prev + 1:
            runs.append((rs, prev + 1))
            rs = a
        prev = a
    runs.append((rs, prev + 1))
    for i, (s, e) in enumerate(runs):
        img.add_segment(Segment(f"seg{i}", s, e, "rwx", CODE, None, bytearray(regions[a] for a in range(s, e))))
    img.imagebase = runs[0][0]
    img.entry_points.append((start if start is not None else runs[0][0], "entry"))
    return img
