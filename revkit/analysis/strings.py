"""String discovery (ASCII, UTF-16LE, UTF-8 multibyte) over non-code regions."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set

from ..image import Image, Segment


@dataclass
class StrItem:
    addr: int
    length: int        # size in bytes including terminator when present
    encoding: str      # ascii | utf16 | utf8
    text: str

    def to_dict(self):
        return {"addr": self.addr, "length": self.length, "encoding": self.encoding, "text": self.text}


_ASCII = re.compile(rb"[\x20-\x7e\t\r\n]{%d,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e\t\r\n]\x00){%d,}")
_UTF8 = re.compile(rb"(?:[\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf4][\x80-\xbf]{3}){%d,}")


def find_strings(img: Image, min_len: int = 4, skip: Optional[Set[int]] = None, utf16: bool = True,
                 utf8: bool = True, force: Optional[Set[int]] = None) -> List[StrItem]:
    """Find strings in every segment. `skip` is a set of addresses (e.g. decoded instruction bytes) to ignore."""
    out: List[StrItem] = []
    a_re = re.compile(_ASCII.pattern % min_len)
    w_re = re.compile(_UTF16.pattern % min_len)
    u_re = re.compile(_UTF8.pattern % min_len)
    for seg in img.segments:
        data = bytes(seg.data)
        if not data or seg.name == "HEADER":
            continue
        taken = bytearray(len(data))
        if utf16:
            for m in w_re.finditer(data):
                s, e = m.start(), m.end()
                if _overlaps_skip(seg.start + s, e - s, skip):
                    continue
                term = e + 2 <= len(data) and data[e:e + 2] == b"\x00\x00"
                if not term and s > 0 and e - s < 12:
                    continue
                text = data[s:e].decode("utf-16-le", "replace")
                out.append(StrItem(seg.start + s, (e - s) + (2 if term else 0), "utf16", text))
                taken[s:e] = b"\x01" * (e - s)
        for m in a_re.finditer(data):
            s, e = m.start(), m.end()
            if taken[s] or _overlaps_skip(seg.start + s, e - s, skip):
                continue
            # require NUL terminator or end of segment, otherwise very likely code / data noise
            term = e < len(data) and data[e] == 0
            if not term and e != len(data):
                if e - s < 8:
                    continue
            if _low_quality(data[s:e]) and not (force and (seg.start + s) in force):
                continue
            out.append(StrItem(seg.start + s, (e - s) + (1 if term else 0), "ascii", data[s:e].decode("ascii")))
            taken[s:e] = b"\x01" * (e - s)
        if utf8:
            for m in u_re.finditer(data):
                s, e = m.start(), m.end()
                chunk = data[s:e]
                if taken[s] or all(b < 0x80 for b in chunk):
                    continue
                if _overlaps_skip(seg.start + s, e - s, skip):
                    continue
                term = e < len(data) and data[e] == 0
                if not term:
                    continue
                try:
                    out.append(StrItem(seg.start + s, (e - s) + 1, "utf8", chunk.decode("utf-8")))
                except UnicodeDecodeError:
                    continue
    out.sort(key=lambda x: x.addr)
    return out


def _overlaps_skip(addr: int, n: int, skip) -> bool:
    if not skip:
        return False
    return addr in skip or (addr + n - 1) in skip


def _low_quality(b: bytes) -> bool:
    """Reject runs like 'UUUUUU' or 'AAAA' / code-looking noise with very low symbol variety."""
    if len(b) < 6:
        return len(set(b)) < 3
    if len(set(b)) <= 2:
        return True
    alnum = sum(chr(ch).isalnum() or chr(ch) in " _-./:\\%" for ch in b)
    return alnum / len(b) < 0.6


def auto_name(text: str, taken) -> str:
    """Auto-generated string label: 'a' + CamelCase of the leading alphanumerics."""
    words = re.findall(r"[A-Za-z0-9]+", text)[:6]
    base = "a" + "".join(w[:1].upper() + w[1:] for w in words)
    base = base[:28] if base != "a" else "aStr"
    n, i = base, 1
    while n in taken:
        n = f"{base}_{i}"
        i += 1
    return n
