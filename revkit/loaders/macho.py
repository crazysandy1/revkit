"""Mach-O loader (thin and fat) written directly against the file format."""
from __future__ import annotations

import struct
from typing import List, Optional

from ..image import ArchSpec, Image, Segment, Export, Import, Symbol, CODE, DATA, BSS

MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64 = 0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE
FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF
CPU = {7: ("x86", 32), 0x01000007: ("x86", 64), 12: ("arm", 32), 0x0100000C: ("arm64", 64),
       18: ("ppc", 32), 0x01000012: ("ppc", 64)}
LC_SEGMENT, LC_SYMTAB, LC_UNIXTHREAD, LC_DYSYMTAB, LC_LOAD_DYLIB = 1, 2, 5, 0xB, 0xC
LC_SEGMENT_64, LC_FUNCTION_STARTS, LC_MAIN = 0x19, 0x26, 0x80000028
LC_REEXPORT_DYLIB, LC_LOAD_WEAK_DYLIB, LC_LAZY_LOAD_DYLIB = 0x8000001F, 0x80000018, 0x20
LC_DYLD_INFO, LC_DYLD_INFO_ONLY, LC_UUID, LC_ID_DYLIB = 0x22, 0x80000022, 0x1B, 0xD
LC_BUILD_VERSION, LC_CODE_SIGNATURE = 0x32, 0x1D


def sniff(raw: bytes) -> bool:
    if len(raw) < 8:
        return False
    m = struct.unpack(">I", raw[:4])[0]
    if m in (FAT_MAGIC, FAT_MAGIC_64):
        # Java class files share CAFEBABE; discriminate via arch count
        n = struct.unpack(">I", raw[4:8])[0]
        return n < 20
    return struct.unpack("<I", raw[:4])[0] in (MH_MAGIC, MH_MAGIC_64)


def fat_slices(raw: bytes):
    m = struct.unpack(">I", raw[:4])[0]
    if m not in (FAT_MAGIC, FAT_MAGIC_64):
        return [(0, len(raw), None)]
    n = struct.unpack(">I", raw[4:8])[0]
    out = []
    for i in range(n):
        if m == FAT_MAGIC:
            cpu, sub, off, size, align = struct.unpack(">iiIII", raw[8 + 20 * i:28 + 20 * i])
        else:
            cpu, sub, off, size, align, _ = struct.unpack(">iiQQII", raw[8 + 32 * i:40 + 32 * i])
        out.append((off, size, cpu & 0xFFFFFFFF))
    return out


def load(path: str, raw: bytes, slice_cpu: Optional[int] = None) -> Image:
    slices = fat_slices(raw)
    sel = slices[0]
    prefer = [s for s in slices if s[2] in (0x0100000C, 0x01000007)]
    if slice_cpu is not None:
        sel = next((s for s in slices if s[2] == slice_cpu), sel)
    elif prefer:
        sel = prefer[0]
    off0, size0, _ = sel
    blob = raw[off0:off0 + size0]
    magic = struct.unpack("<I", blob[:4])[0]
    is64 = magic in (MH_MAGIC_64,)
    if magic not in (MH_MAGIC, MH_MAGIC_64):
        raise ValueError("unsupported Mach-O byte order or magic")
    hdr = struct.unpack("<IiiIIIIi"[: 8 if is64 else 7], blob[: 32 if is64 else 28]) if False else None
    if is64:
        _, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, _r = struct.unpack("<IiiIIIII", blob[:32])
        p = 32
    else:
        _, cputype, cpusub, ftype, ncmds, sizeofcmds, flags = struct.unpack("<IiiIIII", blob[:28])
        p = 28
    arch_t = CPU.get(cputype & 0xFFFFFFFF)
    if arch_t is None:
        raise ValueError(f"unsupported Mach-O cputype {cputype:#x}")
    arch = ArchSpec(arch_t[0], arch_t[1], arch_t[0] == "ppc")
    img = Image(path, "Mach-O64" if is64 else "Mach-O", arch, raw)
    img.info["filetype"] = ftype
    img.info["flags"] = flags
    img.info["fat_slices"] = [(hex(c) if c is not None else None) for _, _, c in slices]
    segs: List[Segment] = []
    symoff = nsyms = stroff = strsize = 0
    entry_off: Optional[int] = None
    unix_pc: Optional[int] = None
    fstarts = None
    indirect = (0, 0)
    dyld = None
    text_vm = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", blob[p:p + 8])
        body = blob[p:p + cmdsize]
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            if cmd == LC_SEGMENT_64:
                segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _f = struct.unpack("<16sQQQQiiII", body[8:72])
                sp = 72
                sect_sz = 80
            else:
                segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _f = struct.unpack("<16sIIIIiiII", body[8:56])
                sp = 56
                sect_sz = 68
            name = segname.rstrip(b"\0").decode()
            if name == "__PAGEZERO" or vmsize == 0:
                p += cmdsize
                continue
            perms = ("r" if initprot & 1 else "") + ("w" if initprot & 2 else "") + ("x" if initprot & 4 else "")
            data = bytearray(blob[fileoff:fileoff + filesize])
            seg = Segment(name, vmaddr, vmaddr + vmsize, perms or "r", CODE if initprot & 4 else DATA,
                          off0 + fileoff, data)
            segs.append(seg)
            if name == "__TEXT":
                text_vm = vmaddr
            sects = []
            for i in range(nsects):
                sb = body[sp + i * sect_sz: sp + (i + 1) * sect_sz]
                if cmd == LC_SEGMENT_64:
                    sectname, _sn, addr, size, offset, align, reloff, nreloc, sflags, r1, r2, r3 = struct.unpack("<16s16sQQIIIIIIII", sb)
                else:
                    sectname, _sn, addr, size, offset, align, reloff, nreloc, sflags, r1, r2 = struct.unpack("<16s16sIIIIIIIII", sb[:68 - 4]) + (0,)
                sects.append((sectname.rstrip(b"\0").decode(), addr, size, sflags, r1, r2))
            img.info.setdefault("sections", []).extend([(f"{name},{s[0]}", s[1], s[2], s[3]) for s in sects])
            seg.__dict__["_sects"] = sects
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack("<IIII", body[8:24])
        elif cmd == LC_DYSYMTAB:
            vals = struct.unpack("<" + "I" * 18, body[8:80])
            indirect = (vals[12], vals[13])  # indirectsymoff, nindirectsyms
        elif cmd == LC_MAIN:
            entry_off = struct.unpack("<Q", body[8:16])[0]
        elif cmd == LC_UNIXTHREAD:
            # flavor,count then regs; PC position depends on arch
            try:
                flavor, count = struct.unpack("<II", body[8:16])
                regs = body[16:]
                if arch.name == "x86" and arch.bits == 64:
                    unix_pc = struct.unpack("<Q", regs[16 * 8:17 * 8])[0]
                elif arch.name == "x86":
                    unix_pc = struct.unpack("<I", regs[10 * 4:11 * 4])[0]
                elif arch.name == "arm64":
                    unix_pc = struct.unpack("<Q", regs[32 * 8:33 * 8])[0]
            except struct.error:
                pass
        elif cmd == LC_FUNCTION_STARTS:
            fstarts = struct.unpack("<II", body[8:16])
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB):
            noff = struct.unpack("<I", body[8:12])[0]
            img.libraries.append(body[noff:].split(b"\0")[0].decode("latin1"))
        elif cmd == LC_ID_DYLIB:
            noff = struct.unpack("<I", body[8:12])[0]
            img.info["install_name"] = body[noff:].split(b"\0")[0].decode("latin1")
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            dyld = struct.unpack("<" + "I" * 10, body[8:48])
        elif cmd == LC_UUID:
            img.info["uuid"] = body[8:24].hex()
        elif cmd == LC_CODE_SIGNATURE:
            img.info["code_signed"] = True
        p += cmdsize
    for s in segs:
        img.add_segment(s)
    code_secs = []
    for s in segs:
        for sname, addr, size, sflags, r1, r2 in s.__dict__.get("_sects", []):
            code = bool(sflags & 0x80000000 or sflags & 0x400 or (sflags & 0xFF) == 8)   # PURE/SOME_INSTRUCTIONS, SYMBOL_STUBS
            code_secs.append((f"{s.name},{sname}", addr, addr + size, code))
    if code_secs:
        img.split_by_sections(code_secs)
    img.imagebase = text_vm or (segs[0].start if segs else 0)
    if entry_off is not None and text_vm is not None:
        img.entry_points.append((text_vm + entry_off, "entry"))
    elif unix_pc:
        img.entry_points.append((unix_pc, "entry"))

    # symbols
    syms = []
    if nsyms:
        nsz = 16 if is64 else 12
        strtab = blob[stroff:stroff + strsize]
        for i in range(nsyms):
            b = blob[symoff + i * nsz: symoff + (i + 1) * nsz]
            if is64:
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack("<IBBHQ", b)
            else:
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack("<IBBHI", b)
            name = strtab[n_strx:].split(b"\0")[0].decode("latin1") if n_strx < len(strtab) else ""
            syms.append((name, n_type, n_sect, n_desc, n_value))
        for name, n_type, n_sect, n_desc, n_value in syms:
            if n_type & 0xE0 or not name:   # debug stabs
                continue
            if (n_type & 0xE) == 0xE and img.is_mapped(n_value):   # N_SECT
                kind = "func" if img.is_exec(n_value) else "object"
                img.symbols.append(Symbol(n_value, name, 0, kind))
                if kind == "func":
                    img.func_hints.setdefault(n_value, "symtab")
                if n_type & 1:
                    img.exports.append(Export(n_value, name))
    # stubs -> imports through indirect symbol table
    if indirect[1] and syms:
        ptr = 8 if is64 else 4
        for seg in segs:
            for sname, addr, size, sflags, r1, r2 in seg.__dict__.get("_sects", []):
                typ = sflags & 0xFF
                if typ in (6, 7, 8) :  # non-lazy ptr, lazy ptr, symbol stubs ("S_SYMBOL_STUBS"=8)
                    esz = r2 if typ == 8 and r2 else ptr
                    cnt = size // esz if esz else 0
                    for k in range(cnt):
                        idx = struct.unpack("<I", blob[indirect[0] + (r1 + k) * 4: indirect[0] + (r1 + k) * 4 + 4])[0]
                        if idx >= len(syms) or idx & 0x80000000:
                            continue
                        nm = syms[idx][0].lstrip("_") and syms[idx][0]
                        a = addr + k * esz
                        imp = Import(a, "", nm)
                        if typ == 8:
                            imp.stub = a
                            img.func_hints.setdefault(a, "stub")
                        img.imports.append(imp)
    if fstarts and fstarts[1] and text_vm is not None:
        data = blob[fstarts[0]:fstarts[0] + fstarts[1]]
        a, i = text_vm, 0
        while i < len(data):
            v, shift = 0, 0
            while i < len(data):
                b = data[i]
                i += 1
                v |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            if v == 0:
                break
            a += v
            img.func_hints.setdefault(a, "func_starts")
    if dyld:
        _parse_binds(img, blob, dyld, segs, is64)
    return img


def _uleb(d, i):
    v = s = 0
    while True:
        b = d[i]
        i += 1
        v |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            return v, i


def _sleb(d, i):
    v = s = 0
    while True:
        b = d[i]
        i += 1
        v |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            if b & 0x40:
                v -= 1 << s
            return v, i


def _parse_binds(img: Image, blob: bytes, dyld, segs, is64: bool):
    rebase_off, rebase_sz, bind_off, bind_sz, weak_off, weak_sz, lazy_off, lazy_sz, export_off, export_sz = dyld
    ptr = 8 if is64 else 4
    seglist = sorted(segs, key=lambda s: s.start)
    # Mach-O segment indices follow load-command order (including __PAGEZERO as index 0)
    order = [None] + seglist if seglist and seglist[0].name != "__PAGEZERO" else seglist
    for off, sz, lazy in ((bind_off, bind_sz, False), (lazy_off, lazy_sz, True)):
        if not sz:
            continue
        d = blob[off:off + sz]
        i = 0
        name, segi, segoff, dylib = "", 0, 0, 0
        while i < len(d):
            op, imm = d[i] & 0xF0, d[i] & 0x0F
            i += 1
            if op == 0x00 and not lazy:
                continue
            if op == 0x10:
                dylib = imm
            elif op == 0x20:
                dylib, i = _uleb(d, i)
            elif op == 0x30:
                dylib = -imm if imm else 0
            elif op == 0x40:
                end = d.index(b"\0", i)
                name = d[i:end].decode("latin1")
                i = end + 1
            elif op == 0x50:
                pass
            elif op == 0x60:
                _, i = _sleb(d, i)
            elif op == 0x70:
                segi = imm
                segoff, i = _uleb(d, i)
            elif op == 0x80:
                v, i = _uleb(d, i)
                segoff += v
            elif op in (0x90, 0xA0, 0xB0, 0xC0):
                s = order[segi] if segi < len(order) else None
                addr = (s.start + segoff) if s else 0
                if op == 0x90:
                    cnt, step = 1, ptr
                elif op == 0xA0:
                    cnt, step = 1, ptr
                    segoff += ptr
                elif op == 0xB0:
                    cnt, step = 1, ptr
                    segoff += imm * ptr + ptr
                else:
                    cnt, i = _uleb(d, i)
                    skip, i = _uleb(d, i)
                    step = ptr + skip
                for k in range(cnt):
                    a = addr + k * step
                    if not any(x.addr == a for x in img.imports):
                        lib = img.libraries[dylib - 1] if 0 < dylib <= len(img.libraries) else ""
                        img.imports.append(Import(a, lib, name))
                if op == 0x90:
                    segoff += ptr
                elif op == 0xC0:
                    segoff += cnt * step
            elif op == 0x00 and lazy:
                continue
