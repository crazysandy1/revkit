"""In-memory model of a loaded program image (segments, symbols, imports)."""
from __future__ import annotations

import bisect
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

CODE, DATA, BSS = "CODE", "DATA", "BSS"


@dataclass
class ArchSpec:
    """Processor description: family name, bitness, endianness, sub-mode."""
    name: str            # x86, arm, thumb, arm64, mips, ppc, riscv, sparc, m68k, 6502...
    bits: int = 32
    big_endian: bool = False
    mode: str = ""       # free-form sub-mode e.g. "thumb", "micromips"

    @property
    def key(self) -> str:
        return f"{self.name}{self.bits}{'be' if self.big_endian else 'le'}{self.mode}"

    def to_dict(self):
        return {"name": self.name, "bits": self.bits, "big_endian": self.big_endian, "mode": self.mode}

    @staticmethod
    def from_dict(d):
        return ArchSpec(d["name"], d["bits"], d["big_endian"], d.get("mode", ""))


@dataclass
class Segment:
    name: str
    start: int
    end: int                 # exclusive
    perms: str = "r"         # subset of "rwx"
    kind: str = DATA
    file_offset: Optional[int] = None
    data: bytearray = field(default_factory=bytearray)
    orig: bytes = b""        # pristine bytes (for patch diff)

    def __post_init__(self):
        size = self.end - self.start
        if len(self.data) < size:
            self.data = bytearray(self.data) + bytearray(size - len(self.data))
        if not self.orig:
            self.orig = bytes(self.data)

    @property
    def size(self) -> int:
        return self.end - self.start

    def contains(self, a: int) -> bool:
        return self.start <= a < self.end

    @property
    def executable(self) -> bool:
        return "x" in self.perms


@dataclass
class Import:
    addr: int            # address of the IAT/GOT slot (or stub) that holds / resolves the import
    module: str
    name: str
    ordinal: Optional[int] = None
    stub: Optional[int] = None   # address of a PLT-style thunk, when known

    @property
    def display(self) -> str:
        return self.name or f"ord{self.ordinal}"


@dataclass
class Export:
    addr: int
    name: str
    ordinal: Optional[int] = None
    forwarder: str = ""


@dataclass
class Symbol:
    addr: int
    name: str
    size: int = 0
    kind: str = "unknown"   # func, object, section, file, unknown
    source: str = "symtab"


class Image:
    """A loaded program: address space + metadata produced by a loader."""

    def __init__(self, path: str, fmt: str, arch: ArchSpec, raw: bytes = b""):
        self.path = path
        self.fmt = fmt
        self.arch = arch
        self.raw = raw
        self.sha256 = hashlib.sha256(raw).hexdigest() if raw else ""
        self.md5 = hashlib.md5(raw).hexdigest() if raw else ""
        self.segments: List[Segment] = []
        self.entry_points: List[Tuple[int, str]] = []
        self.imports: List[Import] = []
        self.exports: List[Export] = []
        self.symbols: List[Symbol] = []
        self.relocations: List[Tuple[int, str, int]] = []  # (addr, kind, addend)
        self.func_hints: Dict[int, str] = {}   # addr -> source (eh_frame, pdata, symtab, func_starts)
        self.imagebase: int = 0
        self.info: Dict[str, object] = {}      # loader-specific metadata (compiler, PDB, etc.)
        self.libraries: List[str] = []
        self.warnings: List[str] = []
        self._starts: List[int] = []

    # ---- segments -----------------------------------------------------
    def add_segment(self, seg: Segment) -> Segment:
        self.segments.append(seg)
        self.segments.sort(key=lambda s: s.start)
        self._starts = [s.start for s in self.segments]
        return seg

    def split_by_sections(self, sections) -> None:
        """Replace each segment by sub-segments following `sections` = [(name, start, end, is_code)].

        Real files put data sections (.rodata, __cstring, __const) inside executable segments; only sections that really
        contain instructions may be treated as code. Bytes of a segment not covered by any section keep the segment's
        permissions minus execute."""
        new: List[Segment] = []
        for seg in self.segments:
            cuts = sorted((max(s, seg.start), min(e, seg.end), n, c) for n, s, e, c in sections
                          if s < seg.end and e > seg.start and e > s)
            if not cuts:
                new.append(seg)
                continue
            pos = seg.start
            nx = seg.perms.replace("x", "")
            def piece(lo, hi, name, perms, kind):
                off = lo - seg.start
                d = seg.data[off:off + (hi - lo)]
                fo = seg.file_offset + off if seg.file_offset is not None else None
                new.append(Segment(name, lo, hi, perms or "r", kind, fo, bytearray(d)))
            for lo, hi, name, is_code in cuts:
                if lo < pos:
                    lo = pos
                    if hi <= lo:
                        continue
                if lo > pos:
                    piece(pos, lo, seg.name, nx, DATA)
                piece(lo, hi, name, (nx + "x") if is_code else nx, CODE if is_code else DATA)
                pos = hi
            if pos < seg.end:
                piece(pos, seg.end, seg.name, nx, DATA)
        self.segments = sorted(new, key=lambda s: s.start)
        self._starts = [s.start for s in self.segments]

    def segment_at(self, addr: int) -> Optional[Segment]:
        i = bisect.bisect_right(self._starts, addr) - 1
        if i >= 0:
            s = self.segments[i]
            if s.start <= addr < s.end:
                return s
        return None

    def is_mapped(self, addr: int) -> bool:
        return self.segment_at(addr) is not None

    def is_exec(self, addr: int) -> bool:
        s = self.segment_at(addr)
        return bool(s and s.executable)

    def read(self, addr: int, n: int) -> bytes:
        """Read up to n bytes starting at addr, crossing contiguous segments."""
        out = bytearray()
        while n > 0:
            s = self.segment_at(addr)
            if not s:
                break
            off = addr - s.start
            take = min(n, s.size - off)
            out += s.data[off:off + take]
            addr += take
            n -= take
        return bytes(out)

    def read_exact(self, addr: int, n: int) -> Optional[bytes]:
        b = self.read(addr, n)
        return b if len(b) == n else None

    def write(self, addr: int, data: bytes) -> None:
        for i, byte in enumerate(data):
            s = self.segment_at(addr + i)
            if not s:
                raise ValueError(f"address {addr + i:#x} not mapped")
            s.data[addr + i - s.start] = byte

    def original(self, addr: int, n: int) -> bytes:
        out = bytearray()
        for i in range(n):
            s = self.segment_at(addr + i)
            if not s:
                break
            out.append(s.orig[addr + i - s.start])
        return bytes(out)

    def u(self, addr: int, size: int) -> Optional[int]:
        b = self.read_exact(addr, size)
        if b is None:
            return None
        return int.from_bytes(b, "big" if self.arch.big_endian else "little")

    def ptr(self, addr: int) -> Optional[int]:
        return self.u(addr, self.arch.bits // 8)

    @property
    def ptr_size(self) -> int:
        return self.arch.bits // 8

    def iter_addrs(self) -> Iterator[int]:
        for s in self.segments:
            yield from range(s.start, s.end)

    def file_offset(self, addr: int) -> Optional[int]:
        s = self.segment_at(addr)
        if s is None or s.file_offset is None:
            return None
        return s.file_offset + (addr - s.start)

    def addr_from_offset(self, off: int) -> Optional[int]:
        for s in self.segments:
            if s.file_offset is not None and s.file_offset <= off < s.file_offset + s.size:
                return s.start + (off - s.file_offset)
        return None

    @property
    def min_addr(self) -> int:
        return self.segments[0].start if self.segments else 0

    @property
    def max_addr(self) -> int:
        return max((s.end for s in self.segments), default=0)

    def patched_ranges(self) -> List[Tuple[int, bytes, bytes]]:
        """Return (addr, original, current) runs where bytes differ from the pristine image."""
        runs = []
        for s in self.segments:
            i, n = 0, s.size
            while i < n:
                if s.data[i] != s.orig[i]:
                    j = i
                    while j < n and s.data[j] != s.orig[j]:
                        j += 1
                    runs.append((s.start + i, bytes(s.orig[i:j]), bytes(s.data[i:j])))
                    i = j
                else:
                    i += 1
        return runs
