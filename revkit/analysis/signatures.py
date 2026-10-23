"""Signature-based library function recognition.

Signature = first 32 bytes (with wildcards) + CRC16 of the next <=255 bytes (relocation/position-dependent
bytes zeroed) + total function size. Signatures are created from (a) analysed binaries whose function names are
known, (b) ELF relocatable objects / ar archives where relocation positions are exact, and (c) imported from
text `.pat` text files. Matching masks position-dependent bytes of the *target* function the same way,
so the same routine linked at different addresses still matches.

NOTE: this is our own signature container (".rsig", gzip JSON). Vendor binary signature formats are NOT read; `.pat`
files can be imported (best effort; CRC window semantics follow our definition).
"""
from __future__ import annotations

import gzip
import io
import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from ..arch import CALL, JMP, CJMP
from ..db import Database, Function

PREFIX = 32
CRC_MAX = 255


def crc16(data: bytes) -> int:
    """CRC16 as used by text-format (reflected 0x8408, init 0xFFFF, byte-swapped complement)."""
    if not data:
        return 0
    crc = 0xFFFF
    for b in data:
        d = b
        for _ in range(8):
            if (crc ^ d) & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
            d >>= 1
    crc = (~crc) & 0xFFFF
    return ((crc << 8) | (crc >> 8)) & 0xFFFF


@dataclass
class Sig:
    name: str
    size: int
    pre: bytes              # first <=32 bytes (wild positions zeroed)
    pre_mask: bytes         # 0xFF = must match
    crc: int
    crc_len: int
    crc_mask: bytes = b""   # wild bitmap for the crc window (0xFF = fixed byte) – needed to reproduce the zeroing
    lib: str = ""

    def to_json(self):
        return {"n": self.name, "s": self.size, "p": self.pre.hex(), "m": self.pre_mask.hex(), "c": self.crc,
                "cl": self.crc_len, "cm": self.crc_mask.hex(), "l": self.lib}

    @staticmethod
    def from_json(d):
        return Sig(d["n"], d["s"], bytes.fromhex(d["p"]), bytes.fromhex(d["m"]), d["c"], d["cl"],
                   bytes.fromhex(d.get("cm", "")), d.get("l", ""))


def wild_mask_from_decode(db: Database, f: Function, nbytes: int) -> Tuple[bytes, bytes]:
    """Return (bytes, mask) for the first `nbytes` of the function's first chunk; position-dependent bytes
    (direct call/jump displacements, rip-relative displacements, absolute addresses) are masked out."""
    img = db.image
    start = f.start
    end = min(f.chunks[0][1] if f.chunks else f.end, start + nbytes)
    raw = img.read(start, end - start)
    mask = bytearray(b"\xff" * len(raw))
    a = start
    while a < end:
        ins = db.insn(a)
        if ins is None:
            break
        sz = ins.size
        rel = None
        # direct branch displacement: last 1/4 bytes of the instruction hold the displacement
        if ins.flow in (CALL, JMP, CJMP) and ins.targets and db.image.arch.name == "x86":
            n = 4 if sz >= 5 and not (ins.flow in (JMP, CJMP) and sz == 2) else 1
            if sz in (2,):
                n = 1
            rel = (sz - n, n)
        elif db.image.arch.name == "x86" and ("rip" in ins.op_str):
            m = re.search(r"\[rip\s*[+-]\s*0x[0-9a-fA-F]+\]|\[rip\]", ins.op_str)
            if m and sz >= 5:
                # disp32 sits before any trailing immediate; locate by search of the encoded displacement
                try:
                    disp = (ins.refs[0][1] - ins.end) if ins.refs else None
                except Exception:
                    disp = None
                if disp is not None:
                    enc = (disp & 0xFFFFFFFF).to_bytes(4, "little")
                    p = ins.raw.find(enc)
                    if p >= 0:
                        rel = (p, 4)
        elif ins.refs and db.image.arch.bits == 32 and db.image.arch.name == "x86":
            for kind, t in ins.refs:
                enc = (t & 0xFFFFFFFF).to_bytes(4, "little")
                p = ins.raw.find(enc)
                if p >= 0:
                    rel = (p, 4)
                    break
        elif db.image.arch.name in ("arm64", "arm", "mips", "ppc", "riscv", "thumb") and ins.flow in (CALL, JMP, CJMP):
            rel = (0, sz)   # fixed-width ISAs encode the displacement in the whole word: wildcard it all
        if rel is not None:
            for k in range(rel[0], min(rel[0] + rel[1], len(mask) - (a - start))):
                if (a - start) + k < len(mask):
                    mask[(a - start) + k] = 0
        a += sz
    return raw, bytes(mask)


class SigDB:
    def __init__(self, name: str = "user"):
        self.name = name
        self.arch_key = ""
        self.sigs: List[Sig] = []
        self._index: Optional[Dict[bytes, List[Sig]]] = None
        self._wild: List[Sig] = []

    # -- building ---------------------------------------------------------------
    @staticmethod
    def make_sig(name: str, raw: bytes, mask: bytes, size: int, lib: str = "") -> Optional[Sig]:
        if len(raw) < 6:
            return None
        pre = bytes(b if m else 0 for b, m in zip(raw[:PREFIX], mask[:PREFIX]))
        pre_mask = bytes(mask[:PREFIX])
        window_raw = raw[PREFIX:PREFIX + CRC_MAX]
        window_mask = mask[PREFIX:PREFIX + CRC_MAX]
        zeroed = bytes(b if m else 0 for b, m in zip(window_raw, window_mask))
        return Sig(name, size, pre, pre_mask, crc16(zeroed), len(window_raw), bytes(window_mask), lib)

    def add_database(self, db: Database, only_named: bool = True, min_size: int = 8, lib: str = "") -> int:
        """Create signatures from every named function of an analysed database (e.g. a library with symbols)."""
        self.arch_key = db.image.arch.key
        n = 0
        for a, f in db.functions.items():
            nm = db.names.get(a)
            if only_named and (not nm or nm.startswith(("sub_", "loc_", "j_"))):
                continue
            if "thunk" in f.flags and "import" in f.flags:
                continue
            size = f.chunks[0][1] - f.chunks[0][0] if f.chunks else f.end - f.start
            if size < min_size:
                continue
            raw, mask = wild_mask_from_decode(db, f, PREFIX + CRC_MAX)
            s = self.make_sig(nm or f.name, raw, mask, size, lib or self.name)
            if s:
                self.sigs.append(s)
                n += 1
        self._index = None
        return n

    def add_elf_object(self, path: str, lib: str = "") -> int:
        """Signatures from an ELF relocatable object, masking exactly the bytes covered by relocations."""
        from elftools.elf.elffile import ELFFile
        from elftools.elf.relocation import RelocationSection
        from elftools.elf.sections import SymbolTableSection
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            n = 0
            relocs: Dict[int, List[int]] = defaultdict(list)
            for sec in elf.iter_sections():
                if isinstance(sec, RelocationSection):
                    target = elf.get_section(sec["sh_info"])
                    for r in sec.iter_relocations():
                        relocs[sec["sh_info"]].append(r["r_offset"])
            sizes = {"EM_X86_64": 4, "EM_386": 4}
            self.arch_key = self.arch_key or {"EM_X86_64": "x8664le", "EM_386": "x8632le"}.get(elf["e_machine"], "")
            for sec in elf.iter_sections():
                if not isinstance(sec, SymbolTableSection):
                    continue
                for sym in sec.iter_symbols():
                    if sym["st_info"]["type"] != "STT_FUNC" or not isinstance(sym["st_shndx"], int):
                        continue
                    tsec = elf.get_section(sym["st_shndx"])
                    data = tsec.data()
                    off, size = sym["st_value"], sym["st_size"]
                    if size < 8:
                        continue
                    raw = data[off:off + size][:PREFIX + CRC_MAX]
                    mask = bytearray(b"\xff" * len(raw))
                    width = 4
                    for ro in relocs.get(sym["st_shndx"], ()):
                        if off <= ro < off + size:
                            for k in range(width):
                                if ro - off + k < len(mask):
                                    mask[ro - off + k] = 0
                    s = self.make_sig(sym.name, raw, bytes(mask), size, lib or os.path.basename(path))
                    if s:
                        self.sigs.append(s)
                        n += 1
        self._index = None
        return n

    def add_archive(self, path: str, lib: str = "") -> int:
        """Signatures from a Unix `ar` archive of ELF objects."""
        import tempfile
        with open(path, "rb") as fh:
            data = fh.read()
        if data[:8] != b"!<arch>\n":
            raise ValueError("not an ar archive")
        pos, total = 8, 0
        names = b""
        while pos + 60 <= len(data):
            hdr = data[pos:pos + 60]
            name = hdr[:16].decode("latin1").strip()
            size = int(hdr[48:58].decode().strip())
            body = data[pos + 60:pos + 60 + size]
            pos += 60 + size + (size & 1)
            if body[:4] == b"\x7fELF":
                with tempfile.NamedTemporaryFile(delete=False, suffix=".o") as tf:
                    tf.write(body)
                try:
                    total += self.add_elf_object(tf.name, lib or os.path.basename(path))
                finally:
                    os.unlink(tf.name)
        return total

    # -- persistence ---------------------------------------------------------------
    def save(self, path: str):
        blob = json.dumps({"name": self.name, "arch": self.arch_key, "sigs": [s.to_json() for s in self.sigs]}).encode()
        with gzip.open(path, "wb") as f:
            f.write(blob)

    @staticmethod
    def load(path: str) -> "SigDB":
        with gzip.open(path, "rb") as f:
            d = json.loads(f.read().decode())
        db = SigDB(d["name"])
        db.arch_key = d.get("arch", "")
        db.sigs = [Sig.from_json(x) for x in d["sigs"]]
        return db

    def export_pat(self) -> str:
        """text-format .pat text: pattern(32 bytes, '..' wildcard) crc_len(2) crc16(4) total(4) :0000 name"""
        out = []
        for s in self.sigs:
            pat = "".join(f"{b:02X}" if m else ".." for b, m in zip(s.pre, s.pre_mask)).ljust(PREFIX * 2, ".")
            out.append(f"{pat} {min(s.crc_len, 255):02X} {s.crc:04X} {s.size:04X} :0000 {s.name}")
        out.append("---")
        return "\n".join(out) + "\n"

    @staticmethod
    def import_pat(text: str, name: str = "pat") -> "SigDB":
        db = SigDB(name)
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("---", ";", "#")):
                continue
            parts = line.split()
            if len(parts) < 6 or len(parts[0]) % 2:
                continue
            pat, crc_len, crc, total = parts[0], int(parts[1], 16), int(parts[2], 16), int(parts[3], 16)
            nm = next((parts[i + 1] for i, p in enumerate(parts) if p.startswith(":") and i + 1 < len(parts)), None)
            if not nm:
                continue
            pre = bytearray()
            mask = bytearray()
            for i in range(0, len(pat), 2):
                t = pat[i:i + 2]
                if t == "..":
                    pre.append(0)
                    mask.append(0)
                else:
                    pre.append(int(t, 16))
                    mask.append(0xFF)
            db.sigs.append(Sig(nm, total, bytes(pre), bytes(mask), crc, crc_len, b"\xff" * crc_len, name))
        return db

    # -- matching ------------------------------------------------------------------
    def _build(self):
        idx: Dict[bytes, List[Sig]] = defaultdict(list)
        wild: List[Sig] = []
        for s in self.sigs:
            head = s.pre[:3]
            if len(s.pre_mask) >= 3 and all(m == 0xFF for m in s.pre_mask[:3]):
                idx[head].append(s)
            else:
                wild.append(s)
        self._index, self._wild = idx, wild

    def match(self, db: Database, f: Function) -> Optional[Sig]:
        if self._index is None:
            self._build()
        raw, tmask = wild_mask_from_decode(db, f, PREFIX + CRC_MAX)
        size = f.chunks[0][1] - f.chunks[0][0] if f.chunks else f.end - f.start
        cands = list(self._index.get(raw[:3], ())) + self._wild
        for s in cands:
            if s.size != size:
                continue
            ok = True
            for i, (pb, pm) in enumerate(zip(s.pre, s.pre_mask)):
                if pm and i < len(raw) and tmask[i] and raw[i] != pb:
                    ok = False
                    break
            if not ok:
                continue
            window = raw[PREFIX:PREFIX + s.crc_len]
            wm = s.crc_mask or b"\xff" * len(window)
            zeroed = bytes(b if (k < len(wm) and wm[k]) else 0 for k, b in enumerate(window))
            if len(window) == s.crc_len and crc16(zeroed) == s.crc:
                return s
        return None


def sig_dirs() -> List[str]:
    dirs = [os.path.join(os.path.dirname(os.path.dirname(__file__)), "sigs"),
            os.path.join(os.path.expanduser("~"), ".revkit", "sigs")]
    env = os.environ.get("REVKIT_SIGS")
    if env:
        dirs += env.split(os.pathsep)
    return [d for d in dirs if os.path.isdir(d)]


def load_all(db: Database) -> List[SigDB]:
    out = []
    key = db.image.arch.key
    for d in sig_dirs():
        for fn in sorted(os.listdir(d)):
            p = os.path.join(d, fn)
            try:
                if fn.endswith(".rsig"):
                    s = SigDB.load(p)
                elif fn.endswith(".pat"):
                    with open(p, encoding="latin1") as fh:
                        s = SigDB.import_pat(fh.read(), fn)
                else:
                    continue
            except Exception:
                continue
            if s.arch_key and s.arch_key != key:
                continue
            out.append(s)
    return out


def apply_sigs(db: Database, sigdbs: List[SigDB], overwrite_auto: bool = True) -> Dict[int, str]:
    applied: Dict[int, str] = {}
    for a, f in sorted(db.functions.items()):
        if db.name_user.get(a, False) or "import" in f.flags:
            continue
        n = db.names.get(a)
        if n and not n.startswith(("sub_", "j_")) and not overwrite_auto and a not in applied:
            continue
        for sdb in sigdbs:
            s = sdb.match(db, f)
            if s is not None:
                db.set_name(a, s.name, user=False, force=True)
                f.name = db.names.get(a, s.name)
                f.flags.add("library")
                db.signatures_applied[a] = f"{s.lib}:{s.name}"
                applied[a] = s.name
                break
    return applied


def apply_builtin(db: Database) -> int:
    dbs = load_all(db)
    if not dbs:
        return 0
    return len(apply_sigs(db, dbs))
