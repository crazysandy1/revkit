"""Minimal Microsoft PDB (MSF 7.00) reader: extracts public symbols (S_PUB32) and maps them to image addresses.

Supports the common "big MSF" layout used by modern MSVC/LLD toolchains. Type information, line numbers and private
symbols are not read. Names are returned as stored (decorated); no demangling is performed.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Tuple

MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
S_PUB32 = 0x110E
S_GPROC32, S_LPROC32 = 0x1110, 0x1127


class PdbError(Exception):
    pass


def _streams(data: bytes) -> List[bytes]:
    if not data.startswith(MAGIC):
        raise PdbError("not a PDB 7.00 (MSF) file")
    block_size, free_map, nblocks, dir_size, _ = struct.unpack_from("<IIIII", data, 32)
    nbp = (dir_size + block_size - 1) // block_size
    ptr_blocks = (nbp * 4 + block_size - 1) // block_size
    # block map pointers (list of blocks containing the directory's block list)
    bm = struct.unpack_from(f"<{ptr_blocks}I", data, 52)
    dir_block_list = b"".join(data[b * block_size:(b + 1) * block_size] for b in bm)
    dir_blocks = struct.unpack_from(f"<{nbp}I", dir_block_list, 0)
    directory = b"".join(data[b * block_size:(b + 1) * block_size] for b in dir_blocks)[:dir_size]
    nstreams = struct.unpack_from("<I", directory, 0)[0]
    sizes = struct.unpack_from(f"<{nstreams}I", directory, 4)
    pos = 4 + 4 * nstreams
    out: List[bytes] = []
    for sz in sizes:
        if sz == 0xFFFFFFFF:
            out.append(b"")
            continue
        n = (sz + block_size - 1) // block_size
        blocks = struct.unpack_from(f"<{n}I", directory, pos)
        pos += 4 * n
        out.append(b"".join(data[b * block_size:(b + 1) * block_size] for b in blocks)[:sz])
    return out


def public_symbols(path: str) -> List[Tuple[int, int, str]]:
    """Returns [(section_index_1based, offset, name)]."""
    with open(path, "rb") as f:
        data = f.read()
    streams = _streams(data)
    if len(streams) < 4:
        raise PdbError("PDB has no DBI stream")
    dbi = streams[3]
    if len(dbi) < 64:
        raise PdbError("DBI stream too short")
    sym_stream = struct.unpack_from("<H", dbi, 20)[0]
    if sym_stream >= len(streams) or not streams[sym_stream]:
        raise PdbError("no symbol record stream")
    recs = streams[sym_stream]
    out = []
    pos = 0
    while pos + 4 <= len(recs):
        ln, typ = struct.unpack_from("<HH", recs, pos)
        if ln < 2:
            break
        body = recs[pos + 4:pos + 2 + ln]
        if typ == S_PUB32 and len(body) >= 10:
            flags, off, seg = struct.unpack_from("<IIH", body, 0)
            name = body[10:].split(b"\0")[0].decode("latin1")
            out.append((seg, off, name))
        elif typ in (S_GPROC32, S_LPROC32) and len(body) >= 35:
            off, seg = struct.unpack_from("<IH", body, 28)
            name = body[35:].split(b"\0")[0].decode("latin1")
            out.append((seg, off, name))
        pos += 2 + ln
        pos = (pos + 3) & ~3 if False else pos
    return out


def load_pdb_symbols(path: str, image) -> List[Tuple[int, str]]:
    """Map PDB public symbols to virtual addresses using the PE section table kept in the image."""
    secs = image.info.get("pe_sections")
    if not secs:
        raise PdbError("image has no PE section table (is this a PE file?)")
    res = []
    for seg, off, name in public_symbols(path):
        if 1 <= seg <= len(secs):
            res.append((image.imagebase + secs[seg - 1] + off, name))
    return res
