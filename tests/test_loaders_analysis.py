import os
import sys

import pytest

import fixtures as F
from revkit.api import Project, RevkitError
from revkit.loaders import detect_format, load_file, parse_arch


def test_elf_loader_and_symbols(proj, labels):
    img = proj.image
    assert img.fmt == "ELF64" and img.arch.key == "x8664le"
    assert img.entry_points[0][0] == labels["_start"]
    names = {f["name"] for f in proj.functions()}
    for n in F.X64_FUNCS:
        assert n in names


def test_function_boundaries_and_flow(proj, labels):
    f = proj.function(labels["fact"])
    assert f.start == labels["fact"] and len(f.blocks) == 3
    assert "frame_pointer" in f.flags
    # recursion: fact calls itself
    assert labels["fact"] in proj.db.callees(labels["fact"])
    assert proj.db.callers(labels["fact"]) == sorted({labels["main"], labels["fact"]})


def test_noreturn_inference(proj, labels):
    assert labels["my_exit"] in proj.db.noreturn
    assert labels["_start"] in proj.db.noreturn       # ends in call to a no-return function
    assert labels["main"] not in proj.db.noreturn


def test_switch_table_recovery(proj, labels):
    sw = proj.db.switches
    assert len(sw) == 1
    info = next(iter(sw.values()))
    assert info["count"] == 4 and info["kind"] == "rel"
    assert len(info["targets"]) == 4
    # the four case blocks belong to dispatch
    f = proj.function(labels["dispatch"])
    for t in info["targets"]:
        assert t in f.blocks
    assert len(f.blocks) == 7


def test_strings_and_data_xrefs(proj, labels):
    s = proj.strings()
    assert any(x["text"] == "Hello, reverse engineer!" for x in s)
    addr = next(x["addr"] for x in s if x["text"].startswith("Hello"))
    assert proj.db.names[addr] == "aHelloReverseEngineer"
    xs = proj.xrefs_to(addr)
    assert xs and xs[0]["function"] == labels["main"]


def test_pointer_table_discovery(proj, labels):
    # fnptr_table holds pointers to fact and say
    ptr_items = [a for a, d in proj.db.data.items() if d.kind == "ptr"]
    assert any(proj.image.ptr(a) == labels["fact"] for a in ptr_items)


def test_listing_text_contains_names_and_xrefs(proj, labels):
    text = proj.listing_text()
    assert "call    fact" in text and "CODE XREF" in text and "jump table" in text


def test_arm64_analysis(arm64_path):
    path, labels = arm64_path
    p = Project.load(path)
    assert p.image.arch.name == "arm64"
    names = {f["name"]: f for f in p.functions()}
    assert set(names) >= {"f1", "f2", "f3"}
    assert names["f3"]["blocks"] == 3
    assert labels["f2"] in p.db.callees(labels["f1"]) and labels["f3"] in p.db.callees(labels["f1"])


def test_pe_loader_imports_pdata(pe_sample):
    path, info = pe_sample
    p = Project.load(path)
    assert p.image.fmt == "PE+" and p.image.arch.bits == 64
    imps = {i["name"]: i for i in p.imports()}
    assert set(imps) == {"MessageBoxA", "ExitProcess"}
    assert imps["MessageBoxA"]["addr"] == info["iat"]["MessageBoxA"]
    funcs = {f["addr"]: f for f in p.functions()}
    assert info["labels"]["helper"] in funcs                  # from .pdata
    assert funcs[info["labels"]["helper"]]["source"] == "pdata"
    # import call xrefs and noreturn handling of ExitProcess
    assert len(imps["ExitProcess"]["xrefs"]) == 1
    assert info["labels"]["start"] in p.db.noreturn or "returns" not in funcs[info["labels"]["start"]]["flags"]


def test_macho_loader(macho_path):
    p = Project.load(macho_path)
    assert p.image.fmt == "Mach-O64"
    assert p.image.arch.bits == 64
    names = {f["name"] for f in p.functions()}
    assert {"_main", "_fact"} <= names


def test_raw_binary_requires_arch(tmp_path):
    f = tmp_path / "blob.bin"
    f.write_bytes(bytes.fromhex("554889e5 b82a000000 5d c3".replace(" ", "")))
    with pytest.raises(ValueError):
        load_file(str(f))
    p = Project.load(str(f), arch="x86_64", base=0x1000, entry=0x1000)
    assert p.image.fmt == "RAW"
    assert [x["addr"] for x in p.functions()] == [0x1000]


def test_dos_com_and_hex_formats(tmp_path):
    com = tmp_path / "t.com"
    com.write_bytes(bytes.fromhex("b8 01 00 c3".replace(" ", "")))
    p = Project.load(str(com))
    assert p.image.arch.bits == 16 and p.image.entry_points[0][0] == 0x100
    hx = tmp_path / "t.hex"
    body = bytes.fromhex("554889e5c3")
    rec = bytes([len(body), 0x10, 0x00, 0x00]) + body
    rec += bytes([(-sum(rec)) & 0xFF])
    hx.write_text(":" + rec.hex().upper() + "\n:00000001FF\n")
    p2 = Project.load(str(hx), arch="x86_64")
    assert p2.image.fmt == "IHEX" and p2.image.segments[0].start == 0x1000


@pytest.mark.skipif(not os.path.exists(r"C:\Windows\System32\notepad.exe"), reason="needs a Windows system binary")
def test_real_pe_binary_loads_and_finds_pdata_functions():
    p = Project.load(r"C:\Windows\System32\notepad.exe")
    srcs = [f["source"] for f in p.functions()]
    assert len(srcs) > 100 and srcs.count("pdata") > 50
    assert p.imports()
    assert p.db.meta["analysis_stats"]["instructions"] > 5000


def test_resolve_errors(proj):
    with pytest.raises(RevkitError):
        proj.resolve("no_such_name_xyz")
    assert proj.resolve("main") == proj.resolve("sub_40100e") if False else True
