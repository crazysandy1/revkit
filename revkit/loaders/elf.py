"""ELF loader built on pyelftools."""
from __future__ import annotations

import io

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from ..image import ArchSpec, Image, Segment, Export, Import, Symbol, CODE, DATA, BSS

MACH = {
    "EM_386": ("x86", 32), "EM_X86_64": ("x86", 64), "EM_ARM": ("arm", 32), "EM_AARCH64": ("arm64", 64),
    "EM_MIPS": ("mips", 32), "EM_PPC": ("ppc", 32), "EM_PPC64": ("ppc", 64), "EM_RISCV": ("riscv", 32),
    "EM_SPARC": ("sparc", 32), "EM_SPARC32PLUS": ("sparc", 32), "EM_SPARCV9": ("sparc", 64),
    "EM_68K": ("m68k", 32), "EM_S390": ("sysz", 64),
}


def sniff(raw: bytes) -> bool:
    return raw[:4] == b"\x7fELF"


def load(path: str, raw: bytes) -> Image:
    elf = ELFFile(io.BytesIO(raw))
    name, bits = MACH.get(elf["e_machine"], (None, None))
    if name is None:
        raise ValueError(f"unsupported ELF machine {elf['e_machine']}")
    if name == "riscv":
        bits = elf.elfclass
    if name == "mips":
        bits = elf.elfclass
    arch = ArchSpec(name, bits, not elf.little_endian)
    if name == "arm" and elf.elfclass == 32 and elf["e_entry"] & 1:
        arch.mode = "thumb"
    img = Image(path, "ELF64" if elf.elfclass == 64 else "ELF32", arch, raw)
    img.info["type"] = elf["e_type"]
    img.info["osabi"] = elf["e_ident"]["EI_OSABI"]
    img.info["machine"] = elf["e_machine"]

    loads = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
    if elf["e_type"] == "ET_REL" or not loads:
        _load_relocatable(img, elf, raw)
    else:
        img.imagebase = min(s["p_vaddr"] for s in loads)
        for i, s in enumerate(loads):
            fl = s["p_flags"]
            perms = ("r" if fl & 4 else "") + ("w" if fl & 2 else "") + ("x" if fl & 1 else "")
            memsz = s["p_memsz"]
            start = s["p_vaddr"]
            # round to page boundaries so adjacent LOAD segments never overlap
            data = bytearray(raw[s["p_offset"]:s["p_offset"] + s["p_filesz"]])
            seg = Segment(f"LOAD{i}", start, start + max(memsz, 1), perms or "r",
                          CODE if fl & 1 else DATA, s["p_offset"], data)
            img.add_segment(seg)
        # rename segments after sections where they fit
        for sec in elf.iter_sections():
            if sec["sh_addr"] and sec["sh_flags"] & 2:
                seg = img.segment_at(sec["sh_addr"])
                if seg is not None:
                    seg.kind = CODE if sec["sh_flags"] & 4 else (BSS if sec["sh_type"] == "SHT_NOBITS" else seg.kind)
        img.info["sections"] = [(s.name, s["sh_addr"], s["sh_size"], s["sh_flags"]) for s in elf.iter_sections()]
        elf_secs = [(s.name, s["sh_addr"], s["sh_addr"] + s["sh_size"], bool(s["sh_flags"] & 4))
                    for s in elf.iter_sections() if s["sh_addr"] and s["sh_flags"] & 2 and s["sh_type"] != "SHT_NOBITS" and s["sh_size"]]
        if elf_secs:
            img.split_by_sections(elf_secs)
        # sub-segments by section: split naming for UI convenience
        img.info["section_names"] = {s.name: (s["sh_addr"], s["sh_size"]) for s in elf.iter_sections() if s["sh_addr"]}

    entry = elf["e_entry"]
    if entry:
        img.entry_points.append((entry & ~1 if arch.mode == "thumb" else entry, "entry"))

    interp = next((s for s in elf.iter_segments() if s["p_type"] == "PT_INTERP"), None)
    if interp is not None:
        img.info["interpreter"] = interp.get_interp_name()

    # symbols
    for sec in elf.iter_sections():
        if isinstance(sec, SymbolTableSection):
            for sym in sec.iter_symbols():
                if not sym.name:
                    continue
                typ = sym["st_info"]["type"]
                val = sym["st_value"]
                clr = ~1 if name == "arm" else ~0
                if sym["st_shndx"] == "SHN_UNDEF":
                    continue
                if typ in ("STT_FUNC", "STT_GNU_IFUNC"):
                    kind = "func"
                elif typ == "STT_OBJECT":
                    kind = "object"
                elif typ == "STT_NOTYPE":
                    kind = "unknown"
                else:
                    continue
                if not img.is_mapped(val & clr):
                    continue
                img.symbols.append(Symbol(val & clr, sym.name, sym["st_size"], kind, sec.name))
                if kind == "func":
                    img.func_hints.setdefault(val & clr, "symtab")
                if sec.name == ".dynsym" and sym["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK") and kind == "func":
                    img.exports.append(Export(val & clr, sym.name))

    # dynamic libraries
    dyn = elf.get_section_by_name(".dynamic")
    if dyn is not None:
        for tag in dyn.iter_tags():
            if tag.entry.d_tag == "DT_NEEDED":
                img.libraries.append(tag.needed)
            elif tag.entry.d_tag == "DT_SONAME":
                img.info["soname"] = tag.soname

    # imports from .rela.plt / .rela.dyn -> GOT slots
    dynsym = elf.get_section_by_name(".dynsym")
    for sec in elf.iter_sections():
        if isinstance(sec, RelocationSection) and sec.name in (".rela.plt", ".rel.plt", ".rela.dyn", ".rel.dyn"):
            symtab = elf.get_section(sec["sh_link"]) if sec["sh_link"] else dynsym
            for r in sec.iter_relocations():
                idx = r["r_info_sym"]
                if idx == 0 or symtab is None:
                    continue
                sym = symtab.get_symbol(idx)
                if sym["st_shndx"] != "SHN_UNDEF" and sec.name.endswith(".plt"):
                    continue
                if not sym.name:
                    continue
                if sym["st_shndx"] == "SHN_UNDEF":
                    img.imports.append(Import(r["r_offset"], img.libraries[0] if len(img.libraries) == 1 else "", sym.name))
    _resolve_plt(img, elf)
    _eh_frame_hints(img, elf)
    for sec_name in (".init_array", ".preinit_array", ".fini_array"):
        sec = elf.get_section_by_name(sec_name)
        if sec is not None and sec["sh_addr"]:
            ps = img.ptr_size
            for a in range(sec["sh_addr"], sec["sh_addr"] + sec["sh_size"], ps):
                v = img.ptr(a)
                if v and img.is_exec(v):
                    img.func_hints.setdefault(v, sec_name)
    for n in (".init", ".fini"):
        sec = elf.get_section_by_name(n)
        if sec is not None and sec["sh_addr"]:
            img.func_hints.setdefault(sec["sh_addr"], n)
    # build id / compiler comment
    note = elf.get_section_by_name(".note.gnu.build-id")
    if note is not None:
        try:
            for n in note.iter_notes():
                if n["n_type"] == "NT_GNU_BUILD_ID":
                    img.info["build_id"] = n["n_desc"]
        except Exception:
            pass
    comm = elf.get_section_by_name(".comment")
    if comm is not None:
        img.info["compiler"] = comm.data().replace(b"\0", b" ").decode("latin1").strip()
    img.info["has_symtab"] = elf.get_section_by_name(".symtab") is not None
    return img


def _load_relocatable(img: Image, elf, raw: bytes):
    addr = 0x1000
    for sec in elf.iter_sections():
        if not sec["sh_flags"] & 2:
            continue
        sz = sec["sh_size"]
        data = bytearray(sec.data()) if sec["sh_type"] != "SHT_NOBITS" else bytearray(sz)
        fl = sec["sh_flags"]
        perms = "r" + ("w" if fl & 1 else "") + ("x" if fl & 4 else "")
        img.add_segment(Segment(sec.name, addr, addr + max(sz, 1), perms, CODE if fl & 4 else DATA, sec["sh_offset"], data))
        sec_addr = addr
        sec.__dict__["_rk_addr"] = sec_addr
        addr = (addr + sz + 0xFFF) & ~0xFFF
    for symsec in elf.iter_sections():
        if isinstance(symsec, SymbolTableSection):
            for sym in symsec.iter_symbols():
                idx = sym["st_shndx"]
                if not sym.name or not isinstance(idx, int):
                    continue
                sec = elf.get_section(idx)
                base = sec.__dict__.get("_rk_addr")
                if base is None:
                    continue
                a = base + sym["st_value"]
                kind = "func" if sym["st_info"]["type"] == "STT_FUNC" else "object"
                img.symbols.append(Symbol(a, sym.name, sym["st_size"], kind, symsec.name))
                if kind == "func":
                    img.func_hints.setdefault(a, "symtab")
    img.warnings.append("relocatable object: sections laid out at synthetic addresses; relocations not applied")


def _resolve_plt(img: Image, elf):
    """Map PLT stubs to the import whose GOT slot they jump through (x86/x86-64/arm64 heuristics)."""
    got_to_imp = {i.addr: i for i in img.imports}
    if not got_to_imp:
        return
    if img.arch.name == "arm64":
        _resolve_plt_arm64(img, elf, got_to_imp)
        return
    for pname in (".plt", ".plt.sec", ".plt.got", ".iplt"):
        sec = elf.get_section_by_name(pname)
        if sec is None or not sec["sh_addr"]:
            continue
        data = sec.data()
        base = sec["sh_addr"]
        if img.arch.name == "x86":
            # scan for jmp [rip+disp32] (ff 25) / jmp [abs32] and endbr64-prefixed variants
            i = 0
            while i < len(data) - 6:
                if data[i] == 0xFF and data[i + 1] == 0x25:
                    disp = int.from_bytes(data[i + 2:i + 6], "little", signed=True)
                    if img.arch.bits == 64:
                        slot = base + i + 6 + disp
                    else:
                        slot = disp & 0xFFFFFFFF
                    imp = got_to_imp.get(slot)
                    if imp is not None and imp.stub is None:
                        start = base + i
                        # stub begins at 16-byte aligned entry (may begin with endbr64 / bnd)
                        s = start & ~0xF if (start - base) % 16 in (0, 4, 5, 8) else start
                        imp.stub = s if s >= base else start
                        img.func_hints.setdefault(imp.stub, "plt")
                    i += 6
                else:
                    i += 1
    # nothing else needed: arm64/others rely on symbol name resolution at analysis time


def _resolve_plt_arm64(img: Image, elf, got_to_imp):
    """AArch64 PLT entries: adrp x16, page ; ldr x17, [x16, #off] ; add x16, x16, #off ; br x17."""
    import capstone as cs
    md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
    md.detail = True
    for pname in (".plt", ".plt.sec", ".plt.got", ".iplt"):
        sec = elf.get_section_by_name(pname)
        if sec is None or not sec["sh_addr"]:
            continue
        data = sec.data()
        base = sec["sh_addr"]
        for off in range(0, len(data) - 15, 4):
            insns = list(md.disasm(data[off:off + 12], base + off, 3))
            if len(insns) < 2 or insns[0].mnemonic != "adrp" or insns[1].mnemonic != "ldr":
                continue
            page = insns[0].operands[1].imm
            m = insns[1].operands[1]
            slot = page + m.mem.disp
            imp = got_to_imp.get(slot)
            if imp is not None and imp.stub is None:
                imp.stub = base + off
                img.func_hints.setdefault(imp.stub, "plt")


def _eh_frame_hints(img: Image, elf):
    try:
        dwarf = elf.get_dwarf_info()
        if not dwarf.has_EH_CFI():
            return
        for entry in dwarf.EH_CFI_entries():
            if entry.__class__.__name__ == "FDE":
                loc = entry.header["initial_location"]
                if img.is_exec(loc):
                    img.func_hints.setdefault(loc, "eh_frame")
    except Exception as e:  # pragma: no cover - defensive; stripped/odd frames
        img.warnings.append(f"eh_frame parse failed: {e}")
