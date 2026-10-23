"""PE/COFF loader built on pefile."""
from __future__ import annotations

import pefile

from ..image import ArchSpec, Image, Segment, Export, Import, Symbol, CODE, DATA, BSS

MACHINES = {
    0x14C: ArchSpec("x86", 32),
    0x8664: ArchSpec("x86", 64),
    0x1C0: ArchSpec("arm", 32),
    0x1C4: ArchSpec("thumb", 32),
    0xAA64: ArchSpec("arm64", 64),
}


def sniff(raw: bytes) -> bool:
    return raw[:2] == b"MZ" and len(raw) > 0x40


def load(path: str, raw: bytes) -> Image:
    pe = pefile.PE(data=raw, fast_load=False)
    arch = MACHINES.get(pe.FILE_HEADER.Machine)
    if arch is None:
        raise ValueError(f"unsupported PE machine {pe.FILE_HEADER.Machine:#x}")
    img = Image(path, "PE" if pe.OPTIONAL_HEADER.Magic == 0x10B else "PE+", arch, raw)
    base = pe.OPTIONAL_HEADER.ImageBase
    img.imagebase = base
    img.info["pe_sections"] = [sec.VirtualAddress for sec in pe.sections]
    img.info["subsystem"] = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "?")
    img.info["timestamp"] = pe.FILE_HEADER.TimeDateStamp
    img.info["characteristics"] = pe.FILE_HEADER.Characteristics
    img.info["dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    img.info["dll_characteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics
    img.info["checksum"] = pe.OPTIONAL_HEADER.CheckSum
    img.info["is_dotnet"] = bool(
        len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress)

    # headers segment
    hsize = pe.OPTIONAL_HEADER.SizeOfHeaders
    img.add_segment(Segment("HEADER", base, base + max(hsize, 0x1000) if hsize else base + 0x1000, "r", DATA,
                            0, bytearray(raw[:hsize])))
    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode("latin1")
        vsize = max(s.Misc_VirtualSize, s.SizeOfRawData)
        vsize = (vsize + 0xFFF) & ~0xFFF if vsize else 0x1000
        c = s.Characteristics
        perms = ("r" if c & 0x40000000 else "") + ("w" if c & 0x80000000 else "") + ("x" if c & 0x20000000 else "")
        perms = perms or "r"
        kind = CODE if c & 0x20 or c & 0x20000000 else (BSS if c & 0x80 and not s.SizeOfRawData else DATA)
        data = bytearray(raw[s.PointerToRawData:s.PointerToRawData + min(s.SizeOfRawData, vsize)])
        start = base + s.VirtualAddress
        img.add_segment(Segment(name, start, start + vsize, perms, kind,
                                s.PointerToRawData if s.SizeOfRawData else None, data))

    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if ep:
        img.entry_points.append((base + ep, "entry"))
    # TLS callbacks
    try:
        tls = pe.DIRECTORY_ENTRY_TLS.struct
        cb = tls.AddressOfCallBacks
        ps = arch.bits // 8
        while cb:
            v = img.u(cb, ps)
            if not v:
                break
            img.entry_points.append((v, "tls_callback"))
            cb += ps
    except AttributeError:
        pass

    # imports
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        mod = entry.dll.decode("latin1") if entry.dll else "?"
        img.libraries.append(mod)
        for imp in entry.imports:
            name = imp.name.decode("latin1") if imp.name else ""
            img.imports.append(Import(imp.address, mod, name, imp.ordinal))
    for entry in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
        mod = entry.dll.decode("latin1") if entry.dll else "?"
        img.libraries.append(mod + " (delay)")
        for imp in entry.imports:
            name = imp.name.decode("latin1") if imp.name else ""
            img.imports.append(Import(imp.address, mod, name, imp.ordinal))
    # exports
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = e.name.decode("latin1") if e.name else ""
            addr = base + e.address if e.address else 0
            img.exports.append(Export(addr, name, e.ordinal, e.forwarder.decode("latin1") if e.forwarder else ""))
            if name and not e.forwarder:
                img.symbols.append(Symbol(addr, name, 0, "func", "export"))
                img.func_hints.setdefault(addr, "export")
    # x64 exception directory (.pdata RUNTIME_FUNCTION table) = authoritative function starts.
    # Parsed by hand: pefile validates UNWIND_INFO and rejects directories with unusual unwind data.
    try:
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if arch.bits == 64 and dd.VirtualAddress and dd.Size:
            data = pe.get_data(dd.VirtualAddress, dd.Size)
            import struct as _st
            for k in range(0, len(data) - 11, 12):
                begin, end, unwind = _st.unpack_from("<III", data, k)
                if begin == 0 and end == 0:
                    break
                if begin and begin < end:
                    img.func_hints.setdefault(base + begin, "pdata")
    except Exception as e:  # pragma: no cover - malformed directory
        img.warnings.append(f"exception directory not parsed: {e}")
    # debug / PDB
    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        ent = getattr(d, "entry", None)
        if ent is not None and hasattr(ent, "PdbFileName"):
            img.info["pdb"] = ent.PdbFileName.rstrip(b"\0").decode("latin1")
            img.info["pdb_guid"] = getattr(ent, "Signature_Data1", None)
    # relocations
    if hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        for blk in pe.DIRECTORY_ENTRY_BASERELOC:
            for r in blk.entries:
                if r.type:
                    img.relocations.append((r.rva + base, str(r.type), 0))
    # COFF symbols (rare in images)
    try:
        for s in pe.get_symbols() if hasattr(pe, "get_symbols") else []:
            pass
    except Exception:
        pass
    # rich header presence + version info
    try:
        if pe.RICH_HEADER:
            img.info["rich_header"] = True
    except Exception:
        pass
    try:
        for fi in pe.FileInfo or []:
            for e in fi:
                if hasattr(e, "StringTable"):
                    for st in e.StringTable:
                        img.info["version_info"] = {k.decode("latin1"): v.decode("latin1")
                                                    for k, v in st.entries.items()}
    except Exception:
        pass
    pe.close()
    return img
