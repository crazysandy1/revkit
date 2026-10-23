import os
import struct

import keystone as ks
import pytest

import fixtures as F
from revkit.api import Project


def _blob(tmp_path, asm, mode=ks.KS_MODE_64, name="b.bin", arch="x86_64", base=0x1000, entry_label=None):
    k = ks.Ks(ks.KS_ARCH_X86, mode)
    code, lab = F._labels(k, asm, base)
    f = tmp_path / name
    f.write_bytes(code)
    p = Project.load(str(f), arch=arch, base=base, entry=lab[entry_label] if entry_label else base)
    return p, lab, bytes(code)


X32 = """
f_add:
    push ebp
    mov ebp, esp
    mov eax, dword ptr [ebp + 8]
    add eax, dword ptr [ebp + 0xc]
    pop ebp
    ret
f_main:
    push ebp
    mov ebp, esp
    sub esp, 8
    push 5
    push 3
    call f_add
    add esp, 8
    mov dword ptr [ebp - 4], eax
    cmp dword ptr [ebp - 4], 7
    jle small
    mov eax, 1
    leave
    ret
small:
    mov eax, dword ptr [ebp - 4]
    leave
    ret
f_stdcall:
    push ebp
    mov ebp, esp
    mov eax, dword ptr [ebp + 8]
    imul eax, dword ptr [ebp + 0xc]
    pop ebp
    ret 8
"""


def test_x86_32bit_cdecl_and_stdcall(tmp_path):
    p, lab, _ = _blob(tmp_path, X32, ks.KS_MODE_32, arch="x86", entry_label="f_main")
    t = p.decompile_text(lab["f_add"])
    assert "int __cdecl" in t and "return a1 + a2;" in t
    m = p.decompile_text(lab["f_main"])
    assert "(3, 5)" in m and "if ( var_8 <= 7 )" in m
    s = p.decompile_text(lab["f_stdcall"])
    assert "__stdcall" in s and "a1 * a2" in s


def test_struct_field_rendering(tmp_path):
    p, lab, _ = _blob(tmp_path, """
getsum:
    mov eax, dword ptr [rdi + 4]
    add eax, dword ptr [rdi]
    mov dword ptr [rdi + 8], eax
    ret
""")
    p.add_types("struct acc { int x; int y; int total; };")
    p.rename_var(0x1000, "a1", "acc", "struct acc *")
    t = p.decompile_text(0x1000)
    assert "acc->y + acc->x" in t and "acc->total = " in t


def test_set_function_end_and_undo(proj, labels):
    f = proj.function(labels["main"])
    mid = labels["main"] + 0x1E
    assert proj.set_function_end(labels["main"], mid)
    assert proj.function(labels["main"]).end <= mid
    assert proj.undo()
    assert proj.function(labels["main"]).end > mid


def test_unpack_emulation(tmp_path):
    asm = """
stub:
    lea rsi, [rip + payload]
    mov ecx, payload_end - payload
decode:
    xor byte ptr [rsi], 0x5a
    inc rsi
    dec ecx
    jnz decode
    jmp payload
.balign 16
payload:
    mov eax, 0x1337
    ret
payload_end:
"""
    k = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_64)
    code, lab = F._labels(k, asm, 0x1000)
    code = bytearray(code)
    off = lab["payload"] - 0x1000
    plain = bytes(code[off:])
    for i in range(off, len(code)):
        code[i] ^= 0x5A
    f = tmp_path / "packed.bin"
    f.write_bytes(code)
    p = Project.load(str(f), arch="x86_64", base=0x1000, entry=0x1000)
    r = p.unpack(dump_path=str(tmp_path / "out.bin"))
    assert r["ok"] and r["oep"] == lab["payload"]
    assert open(r["dump"], "rb").read()[off:off + len(plain)] == plain
    q = Project.load(r["dump"], arch="x86_64", base=r["base"], entry=r["oep"])
    assert "return 0x1337;" in q.decompile_text(r["oep"])


def test_import_names_formats(proj, labels, tmp_path):
    f = tmp_path / "names.map"
    f.write_text(f"; map\n{labels['fact']:x} factorial_map\n{labels['say']:#x},print_msg\n")
    assert proj.import_names(str(f)) == 2
    assert proj.db.display_name(labels["fact"]) == "factorial_map"
    j = tmp_path / "n.json"
    j.write_text('{"%s": "entry_json"}' % hex(labels["_start"]))
    assert proj.import_names(str(j)) == 1
    i = tmp_path / "n.rk"
    i.write_text('set_name(0x%x, "dispatcher_idc", SN_CHECK);' % labels["dispatch"])
    assert proj.import_names(str(i)) == 1 and proj.db.display_name(labels["dispatch"]) == "dispatcher_idc"


def test_custom_loader_and_arch_registration(tmp_path):
    from revkit.loaders import register_loader, unregister_loader
    from revkit.loaders.raw import load_raw
    from revkit.image import ArchSpec
    magic = b"TOYX"

    def sniff(data, path):
        return data[:4] == magic

    def load(path, data, **kw):
        img = load_raw(path, data[4:], ArchSpec("x86", 64), 0x4000, 0x4000)
        img.fmt = "TOY"
        return img
    register_loader("toy", sniff, load)
    try:
        f = tmp_path / "t.toy"
        f.write_bytes(magic + bytes.fromhex("554889e5b82a0000005dc3"))
        p = Project.load(str(f))
        assert p.image.fmt == "TOY" and p.decompile_text(0x4000).count("return 0x2a;") == 1
    finally:
        unregister_loader("toy")
    from revkit.arch import register_arch, get_arch, GenericArch
    import capstone as cs
    calls = []

    def factory(spec):
        calls.append(spec.name)
        return GenericArch(spec, cs.CS_ARCH_SPARC, cs.CS_MODE_BIG_ENDIAN, 4, 4)
    register_arch("sparc", factory)
    try:
        assert get_arch(ArchSpec("sparc", 32, True)) and calls == ["sparc"]
    finally:
        from revkit import arch as A
        A._FACTORIES.pop("sparc", None)
        A._CACHE.clear()


def test_pdb_reader_with_real_file_if_present():
    d = r"C:\Program Files\Dokan\Dokan Library-1.4.1"
    dll, pdb = os.path.join(d, "dokan1.dll"), os.path.join(d, "dokan1.pdb")
    if not (os.path.exists(dll) and os.path.exists(pdb)):
        pytest.skip("no sample PDB on this machine")
    p = Project.load(dll)
    n = p.load_pdb(pdb)
    assert n > 100
    assert any(f["name"] == "DokanOpenRequestorToken" for f in p.functions())


def test_real_world_elf_and_macho_if_present():
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".realworld")
    elf = os.path.join(root, "manylinux2014_x86_64__cffi_backend.cpython-312-x86_64-linux-gnu.so")
    if not os.path.exists(elf):
        pytest.skip("real-world samples not downloaded")
    from elftools.elf.elffile import ELFFile
    with open(elf, "rb") as fh:
        e = ELFFile(fh)
        truth = {x.header["initial_location"] for x in e.get_dwarf_info().EH_CFI_entries() if x.__class__.__name__ == "FDE"}
    p = Project.load(elf)
    ours = {f["addr"] for f in p.functions()}
    assert len(truth & ours) / len(truth) >= 0.99                 # every eh_frame function is recovered
    a64 = Project.load(os.path.join(root, "manylinux2014_aarch64__cffi_backend.cpython-312-aarch64-linux-gnu.so"))
    assert a64.info()["stats"]["functions"] > 800
    bad = 0
    for f in sorted(a64.db.functions)[:150]:
        try:
            a64.decompile_text(f)
        except Exception:
            bad += 1
    assert bad == 0


def _packed_pe(tmp_path, layers=1):
    """PE64 whose entry stub XOR-decodes the real program in place, `layers` times nested."""
    import fixtures as FX
    inner = """
start:
    sub rsp, 0x28
    lea rcx, [rip + msg]
    call work
    add rsp, 0x28
    ret
work:
    mov eax, 0x2a
    ret
msg:
    .asciz "unpacked program"
"""
    k = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_64)
    b = FX.PE64Builder({"kernel32.dll": ["ExitProcess"]})
    base = b.image_base + b.text_rva
    payload, lab = FX._labels(k, inner, base)
    for layer in range(layers):
        key = 0x21 + layer
        enc = bytes(x ^ key for x in payload)
        stub = f"""
stub:
    lea rsi, [rip + body]
    mov ecx, {len(payload)}
dec_:
    xor byte ptr [rsi], {key}
    inc rsi
    dec ecx
    jnz dec_
    jmp body
body:
"""
        s_code, _ = k.asm(stub, base, as_bytes=True)
        payload = bytes(s_code) + enc
        # next layer's stub must be assembled at the same base; the decoder jumps into its own body
    pe = b.build(payload, entry_offset=0, text_flags=0xE0000020)
    f = tmp_path / "packed.exe"
    f.write_bytes(pe)
    return str(f), lab


def test_import_option_unpacks_and_decompiles(tmp_path):
    path, lab = _packed_pe(tmp_path)
    plain = Project.load(path)
    assert "unpacked program" not in " ".join(x["text"] for x in plain.strings())
    p = Project.load(path, unpack=True)
    u = p.info()["unpack"]
    assert u["ok"] and u["layers"] == 1
    assert any(x["text"] == "unpacked program" for x in p.strings())
    oep = p.image.entry_points[0][0]
    callee = p.db.callees(oep)[0]
    assert "return 0x2a;" in p.decompile_text(callee)
    # the option survives save/open (replayed deterministically)
    q = Project.open(p.save(str(tmp_path / "u.rkdb")))
    assert any(x["text"] == "unpacked program" for x in q.strings())


def test_unpack_multiple_layers_and_cli(tmp_path):
    import subprocess, sys
    path, lab = _packed_pe(tmp_path, layers=2)
    p = Project.load(path, unpack=True)
    assert p.info()["unpack"]["layers"] == 2
    assert any(x["text"] == "unpacked program" for x in p.strings())
    r = subprocess.run([sys.executable, "-m", "revkit", "analyze", path, "--unpack", "-o", str(tmp_path / "c.rkdb")],
                       capture_output=True, text=True, encoding="utf8",
                       cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    assert r.returncode == 0 and "2 layer(s)" in r.stderr


def test_unpack_on_plain_binary_is_harmless(x64_path):
    p = Project.load(x64_path, unpack=True)
    assert not p.info()["unpack"]["ok"]
    assert len(p.functions()) == 6
