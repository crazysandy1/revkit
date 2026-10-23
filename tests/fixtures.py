"""Builders for small, fully-known test binaries (ELF64/ELF32/PE64) assembled with Keystone.

Because the content of every fixture is authored here, tests can assert exact expected analysis results
instead of relying on whatever binaries happen to exist on the host.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

import keystone as ks

X64_PROGRAM = r"""
_start:
    xor ebp, ebp
    call main
    mov edi, eax
    call my_exit
main:
    push rbp
    mov rbp, rsp
    sub rsp, 0x20
    lea rdi, [rip + msg_hello]
    call say
    mov edi, 5
    call fact
    mov dword ptr [rbp - 4], eax
    mov edi, 2
    call dispatch
    add eax, dword ptr [rbp - 4]
    mov dword ptr [rip + counter], eax
    mov rax, qword ptr [rip + fnptr_table]
    leave
    ret
say:
    push rbx
    mov rbx, rdi
    mov rsi, rbx
    mov edx, 5
    mov edi, 1
    mov eax, 1
    syscall
    pop rbx
    ret
fact:
    push rbp
    mov rbp, rsp
    sub rsp, 16
    mov dword ptr [rbp - 4], edi
    cmp dword ptr [rbp - 4], 1
    jg fact_rec
    mov eax, 1
    leave
    ret
fact_rec:
    mov eax, dword ptr [rbp - 4]
    sub eax, 1
    mov edi, eax
    call fact
    imul eax, dword ptr [rbp - 4]
    leave
    ret
dispatch:
    cmp edi, 3
    ja dispatch_default
    lea rdx, [rip + jt]
    movsxd rax, dword ptr [rdx + rdi*4]
    add rax, rdx
    jmp rax
case0:
    mov eax, 10
    ret
case1:
    mov eax, 20
    ret
case2:
    mov eax, 30
    ret
case3:
    mov eax, 40
    ret
dispatch_default:
    xor eax, eax
    ret
my_exit:
    mov eax, 60
    syscall
    hlt
unreachable_tail:
    ud2
.balign 8
jt:
    .long case0 - jt
    .long case1 - jt
    .long case2 - jt
    .long case3 - jt
msg_hello:
    .asciz "Hello, reverse engineer!"
.balign 8
fnptr_table:
    .quad fact
    .quad say
counter:
    .quad 0
"""

X64_FUNCS = ["_start", "main", "say", "fact", "dispatch", "my_exit"]


def build_x64(text: str = X64_PROGRAM, base: int = 0x401000):
    """Assemble `text` at `base`; return (bytes, labels) with labels verified by full assembly."""
    k = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_64)
    code, _ = k.asm(text, base, as_bytes=True)
    code = bytes(code)
    # Determine label addresses exactly: assemble a probe per label that ends with `.byte 0xAB` marker.
    labels: Dict[str, int] = {}
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.endswith(":") and not s.startswith("."):
            marker = "\n".join(lines[:i + 1]) + "\n.byte 0xFA, 0xCE, 0xFA, 0xCE, 0x11, 0x22\n" + "\n".join(lines[i + 1:])
            c2, _ = k.asm(marker, base, as_bytes=True)
            c2 = bytes(c2)
            pos = c2.find(b"\xfa\xce\xfa\xce\x11\x22")
            labels[s[:-1]] = base + pos
    return code, labels


# ---------------------------------------------------------------------------
# ELF64 writer
# ---------------------------------------------------------------------------
def build_elf64(code: bytes, base: int, entry: int, symbols: Optional[Dict[str, Tuple[int, int, str]]] = None,
                machine: int = 62) -> bytes:
    """Single RWX PT_LOAD ELF64 with .text/.symtab/.strtab/.shstrtab. symbols: name -> (addr, size, 'func'|'object')."""
    symbols = symbols or {}
    ehsize, phsize, shsize = 64, 56, 64
    text_off = 0x1000
    shstr = b"\0.text\0.symtab\0.strtab\0.shstrtab\0"
    off_text_name = 1
    off_symtab_name = 7
    off_strtab_name = 15
    off_shstr_name = 23
    strtab = b"\0"
    syms = [struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)]
    for name, (addr, size, kind) in symbols.items():
        idx = len(strtab)
        strtab += name.encode() + b"\0"
        info = (1 << 4) | (2 if kind == "func" else 1)
        syms.append(struct.pack("<IBBHQQ", idx, info, 0, 1, addr, size))
    symtab = b"".join(syms)
    body = code
    off_symtab = text_off + len(body)
    off_strtab = off_symtab + len(symtab)
    off_shstr = off_strtab + len(strtab)
    off_sh = (off_shstr + len(shstr) + 7) & ~7
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    ehdr += struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, entry, ehsize, off_sh, 0, ehsize, phsize, 1, shsize, 5, 4)
    phdr = struct.pack("<IIQQQQQQ", 1, 7, text_off, base, base, len(body), len(body), 0x1000)
    sh = [b"\0" * 64]
    sh.append(struct.pack("<IIQQQQIIQQ", off_text_name, 1, 7, base, text_off, len(body), 0, 0, 16, 0))
    sh.append(struct.pack("<IIQQQQIIQQ", off_symtab_name, 2, 0, 0, off_symtab, len(symtab), 3, 1, 8, 24))
    sh.append(struct.pack("<IIQQQQIIQQ", off_strtab_name, 3, 0, 0, off_strtab, len(strtab), 0, 0, 1, 0))
    sh.append(struct.pack("<IIQQQQIIQQ", off_shstr_name, 3, 0, 0, off_shstr, len(shstr), 0, 0, 1, 0))
    out = bytearray(ehdr + phdr)
    out += b"\0" * (text_off - len(out))
    out += body + symtab + strtab + shstr
    out += b"\0" * (off_sh - len(out))
    out += b"".join(sh)
    return bytes(out)


# ---------------------------------------------------------------------------
# PE64 writer (one code section, one data section, import table)
# ---------------------------------------------------------------------------
class PE64Builder:
    """Lay out .text (RX) + .idata (R) with an import directory; supports rip-relative IAT calls."""
    SECT_ALIGN, FILE_ALIGN = 0x1000, 0x200

    def __init__(self, imports: Dict[str, List[str]], image_base: int = 0x140000000):
        self.imports = imports
        self.image_base = image_base
        self.text_rva = 0x1000
        self.idata_rva = 0x2000
        # compute idata layout
        self.iat_rva: Dict[str, int] = {}
        off = 0
        n_desc = len(imports) + 1
        desc_size = n_desc * 20
        ilt_off, iat_off = {}, {}
        cur = desc_size
        for dll, funcs in imports.items():
            ilt_off[dll] = cur
            cur += (len(funcs) + 1) * 8
        for dll, funcs in imports.items():
            iat_off[dll] = cur
            cur += (len(funcs) + 1) * 8
        hint_off = {}
        for dll, funcs in imports.items():
            for f in funcs:
                hint_off[(dll, f)] = cur
                cur += 2 + len(f) + 1 + ((len(f) + 1) % 2)
        dll_name_off = {}
        for dll in imports:
            dll_name_off[dll] = cur
            cur += len(dll) + 1
        data = bytearray(cur)
        for i, (dll, funcs) in enumerate(imports.items()):
            struct.pack_into("<IIIII", data, i * 20, self.idata_rva + ilt_off[dll], 0, 0,
                             self.idata_rva + dll_name_off[dll], self.idata_rva + iat_off[dll])
            for k, f in enumerate(funcs):
                v = self.idata_rva + hint_off[(dll, f)]
                struct.pack_into("<Q", data, ilt_off[dll] + 8 * k, v)
                struct.pack_into("<Q", data, iat_off[dll] + 8 * k, v)
                struct.pack_into("<H", data, hint_off[(dll, f)], 0)
                data[hint_off[(dll, f)] + 2:hint_off[(dll, f)] + 2 + len(f)] = f.encode()
                self.iat_rva[f] = self.idata_rva + iat_off[dll] + 8 * k
            data[dll_name_off[dll]:dll_name_off[dll] + len(dll)] = dll.encode()
        self.idata = bytes(data)
        self.import_dir_size = desc_size

    def iat_va(self, name: str) -> int:
        return self.image_base + self.iat_rva[name]

    def build(self, code: bytes, entry_offset: int = 0, pdata: Optional[List[Tuple[int, int]]] = None,
              text_flags: int = 0x60000020) -> bytes:
        FA, SA = self.FILE_ALIGN, self.SECT_ALIGN
        align = lambda v, a: (v + a - 1) // a * a
        headers_size = 0x400
        text_raw = align(len(code), FA)
        idata_raw = align(len(self.idata), FA)
        sects = [(b".text", self.text_rva, code, text_flags, headers_size),
                 (b".idata", self.idata_rva, self.idata, 0x40000040, headers_size + text_raw)]
        extra = b""
        if pdata:
            pd = b"".join(struct.pack("<III", s, e, 0x3000) for s, e in pdata)
            sects.append((b".pdata", 0x3000, pd, 0x40000040, headers_size + text_raw + idata_raw))
        nsects = len(sects)
        dos = bytearray(0x80)
        dos[:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, 0x80)
        coff = struct.pack("<HHIIIHH", 0x8664, nsects, 0, 0, 0, 240, 0x22)
        last_rva = max(s[1] + len(s[2]) for s in sects)
        opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 14, 0, text_raw, idata_raw, 0, self.text_rva + entry_offset,
                          self.text_rva, self.image_base, SA, FA, 6, 0, 0, 0, 6, 0, 0,
                          align(last_rva, SA), headers_size, 0, 3, 0x8160, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        dd = bytearray(16 * 8)
        struct.pack_into("<II", dd, 8, self.idata_rva, self.import_dir_size)
        if pdata:
            struct.pack_into("<II", dd, 3 * 8, 0x3000, len(pdata) * 12)
        sh = b""
        for name, rva, content, flags, raw_ptr in sects:
            sh += struct.pack("<8sIIIIIIHHI", name, len(content), rva, align(len(content), FA), raw_ptr, 0, 0, 0, 0, flags)
        out = bytearray(bytes(dos) + b"PE\0\0" + coff + opt + bytes(dd) + sh)
        out += b"\0" * (headers_size - len(out))
        for name, rva, content, flags, raw_ptr in sects:
            out += content + b"\0" * (align(len(content), FA) - len(content))
        return bytes(out)


# ---------------------------------------------------------------------------
# PE64 program with an import table and .pdata
# ---------------------------------------------------------------------------
PE_PROGRAM = r"""
start:
    sub rsp, 0x28
    xor ecx, ecx
    lea rdx, [rip + msg]
    lea r8, [rip + cap]
    xor r9d, r9d
call_mb_site:
    .byte 0xff, 0x15
    .long {d1}
    xor ecx, ecx
call_ep_site:
    .byte 0xff, 0x15
    .long {d2}
    int3
start_end:
helper:
    mov eax, ecx
    add eax, edx
    ret
helper_end:
msg:
    .asciz "Hello from PE"
cap:
    .asciz "revkit"
"""


def build_pe_sample():
    """Returns (pe_bytes, info) where info has labels (virtual addresses) and import slot addresses."""
    b = PE64Builder({"user32.dll": ["MessageBoxA"], "kernel32.dll": ["ExitProcess"]})
    base = b.image_base + b.text_rva
    k = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_64)
    labels = {}
    # pass 1: dummy displacements to learn call-site offsets
    _, lab = _labels(k, PE_PROGRAM.format(d1=0, d2=0), base)
    d1 = b.iat_va("MessageBoxA") - (lab["call_mb_site"] + 6)
    d2 = b.iat_va("ExitProcess") - (lab["call_ep_site"] + 6)
    text = PE_PROGRAM.format(d1=d1 & 0xFFFFFFFF, d2=d2 & 0xFFFFFFFF)
    code, labels = _labels(k, text, base)
    pdata = [(b.text_rva + (labels["start"] - base), b.text_rva + (labels["start_end"] - base)),
             (b.text_rva + (labels["helper"] - base), b.text_rva + (labels["helper_end"] - base))]
    pe = b.build(code, entry_offset=0, pdata=pdata)
    return pe, {"labels": labels, "iat": {n: b.iat_va(n) for n in ("MessageBoxA", "ExitProcess")}, "base": b.image_base}


def _labels(k, text, base, marker_asm=".byte 0xFA, 0xCE, 0xFA, 0xCE, 0x11, 0x22", marker=b"\xfa\xce\xfa\xce\x11\x22"):
    code, _ = k.asm(text, base, as_bytes=True)
    code = bytes(code)
    labels = {}
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.endswith(":") and not s.startswith("."):
            m = "\n".join(lines[:i + 1]) + "\n" + marker_asm + "\n" + "\n".join(lines[i + 1:])
            c2, _ = k.asm(m, base, as_bytes=True)
            labels[s[:-1]] = base + bytes(c2).find(marker)
    return code, labels


# ---------------------------------------------------------------------------
# ARM64 ELF
# ---------------------------------------------------------------------------
ARM64_PROGRAM = """
f1:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    bl f2
    bl f3
    ldp x29, x30, [sp], #16
    ret
f2:
    mov w0, #7
    ret
f3:
    cmp w0, #3
    b.gt f3_big
    mov w0, #1
    ret
f3_big:
    mov w0, #2
    ret
"""


def build_arm64_elf():
    k = ks.Ks(ks.KS_ARCH_ARM64, ks.KS_MODE_LITTLE_ENDIAN)
    base = 0x400000
    code, labels = _labels(k, ARM64_PROGRAM, base, ".word 0xface1234, 0x11223344", b"\x34\x12\xce\xfa\x44\x33\x22\x11")
    syms = {n: (labels[n], 0, "func") for n in ("f1", "f2", "f3")}
    return build_elf64(code, base, labels["f1"], syms, machine=183), labels


# ---------------------------------------------------------------------------
# Mach-O 64 (x86-64)
# ---------------------------------------------------------------------------
def build_macho64(code: bytes, entry_off: int = 0, symbols=None) -> bytes:
    symbols = symbols or {}          # name -> offset inside code
    text_vm = 0x100000000
    hdr_size = 32
    seg_cmd = 72 + 80
    zero_cmd = 72
    main_cmd = 24
    symtab_cmd = 24
    sizeofcmds = zero_cmd + seg_cmd + main_cmd + symtab_cmd
    code_off = 0x1000
    strtab = b"\0" + b"".join(n.encode() + b"\0" for n in symbols)
    nl, off = b"", 1
    for n, o in symbols.items():
        nl += struct.pack("<IBBHQ", off, 0x0F, 1, 0, text_vm + code_off + o)
        off += len(n) + 1
    symoff = code_off + len(code)
    stroff = symoff + len(nl)
    out = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 4, sizeofcmds, 0x200085, 0)
    out += struct.pack("<II16sQQQQiiII", 0x19, zero_cmd, b"__PAGEZERO", 0, 0x100000000, 0, 0, 0, 0, 0, 0)
    sect = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", text_vm + code_off, len(code), code_off, 4, 0, 0, 0x80000400, 0, 0, 0)
    out += struct.pack("<II16sQQQQiiII", 0x19, seg_cmd, b"__TEXT", text_vm, 0x2000, 0, code_off + len(code), 7, 5, 1, 0) + sect
    out += struct.pack("<IIQQ", 0x80000028, main_cmd, code_off + entry_off, 0)
    out += struct.pack("<IIIIII", 2, symtab_cmd, symoff, len(symbols), stroff, len(strtab))
    out += b"\0" * (code_off - len(out)) + code + nl + strtab
    return out


def build_pe_program(text: str, imports):
    """Generic PE64 builder: labels named `site_<import>_<n>` followed by `.byte 0xff,0x15 / .long {site_<import>_<n>}`
    are patched into rip-relative IAT calls. `imports` is {dll: [names]}."""
    import re as _re
    b = PE64Builder(imports)
    base = b.image_base + b.text_rva
    k = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_64)
    sites = _re.findall(r"^(site_(\w+?)_\d+):", text, _re.M)
    zero = {s: 0 for s, _ in sites}
    _, lab = _labels(k, text.format(**zero), base)
    disp = {s: (b.iat_va(n) - (lab[s] + 6)) & 0xFFFFFFFF for s, n in sites}
    final = text.format(**disp)
    code, labels = _labels(k, final, base)
    fn_labels = [n for n in labels if n.endswith("_end")]
    pdata = []
    for n in fn_labels:
        st = n[:-4]
        if st in labels:
            pdata.append((b.text_rva + labels[st] - base, b.text_rva + labels[n] - base))
    pe = b.build(code, entry_offset=labels.get("start", base) - base, pdata=pdata)
    return pe, {"labels": labels, "iat": {n: b.iat_va(n) for ns in imports.values() for n in ns}, "base": b.image_base}


VULN_PROGRAM = r"""
start:
    sub rsp, 0x28
    xor ecx, ecx
    call vuln
    call echo
    add rsp, 0x28
    ret
start_end:
vuln:
    push rbp
    mov rbp, rsp
    sub rsp, 0x50
    lea rcx, [rbp - 0x20]
    lea rdx, [rip + big]
site_strcpy_1:
    .byte 0xff, 0x15
    .long {site_strcpy_1}
    lea rcx, [rip + cmdline]
site_system_1:
    .byte 0xff, 0x15
    .long {site_system_1}
    leave
    ret
vuln_end:
echo:
    sub rsp, 0x28
    mov rcx, rdx
site_printf_1:
    .byte 0xff, 0x15
    .long {site_printf_1}
    add rsp, 0x28
    ret
echo_end:
big:
    .asciz "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
cmdline:
    .asciz "cmd.exe /c whoami"
secret:
    .asciz "password=hunter2secret99"
"""


def build_vuln_pe():
    return build_pe_program(VULN_PROGRAM, {"msvcrt.dll": ["strcpy", "system", "printf"]})
