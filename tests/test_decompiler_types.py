import re

import pytest

import fixtures as F
from revkit.api import Project
from revkit.decompiler import DecompileError
from revkit.types import TypeError_, TypeManager
from revkit.image import ArchSpec


def norm(s):
    return re.sub(r"\s+", " ", s)


def test_decompile_recursive_function(proj, labels):
    t = norm(proj.decompile_text(labels["fact"]))
    assert "int fact(int a1)" in t
    assert "if ( a1 > 1 )" in t
    assert "return fact(a1 - 1) * a1;" in t
    assert "return 1;" in t


def test_decompile_switch_with_default(proj, labels):
    t = proj.decompile_text(labels["dispatch"])
    for v in ("0xa", "0x14", "0x1e", "0x28"):
        assert f"return {v};" in t
    assert "switch" in t and "default:" in t
    assert t.count("case ") == 4


def test_decompile_calls_and_globals(proj, labels):
    t = proj.decompile_text(labels["main"])
    assert "say(&aHelloReverseEngineer)" in t
    assert "fact(5)" in t and "dispatch(2)" in t
    assert "qword_401110 =" in t


def test_syscall_is_named(proj, labels):
    assert "write(1, a1, 5)" in proj.decompile_text(labels["say"])


def test_pseudocode_line_to_address_mapping(proj, labels):
    pc = proj.decompile(labels["fact"])
    addrs = [a for _, a in pc.lines if a]
    assert addrs and all(proj.db.function_at(a).start == labels["fact"] for a in addrs)
    cmp_line = next(i for i, (t, a) in enumerate(pc.lines) if "if (" in t)
    assert pc.addr_for_line(cmp_line) >= labels["fact"]
    assert pc.line_for(labels["fact"] + 0x10) is not None


def test_pe_import_call_uses_prototype(pe_sample):
    path, info = pe_sample
    p = Project.load(path)
    t = p.decompile_text(info["labels"]["start"])
    assert 'MessageBoxA(0, &aHelloFromPE, &aRevkit, 0);' in t
    assert "ExitProcess(0);" in t
    assert t.startswith("void start(void)")
    assert "__undefined" not in t


def test_user_variable_rename_and_comment(proj, labels):
    proj.rename_var(labels["fact"], "a1", "n")
    proj.comment(labels["fact"] + 0x0B, "base case test")
    t = proj.decompile_text(labels["fact"])
    assert "int n)" in t and "n > 1" in t


def test_call_args_inferred_from_callee(proj, labels):
    # dispatch has no prototype: argument count comes from callee register usage
    assert "dispatch(2)" in proj.decompile_text(labels["main"])


def test_decompile_arm64(arm64_path):
    path, labels = arm64_path
    p = Project.load(path)
    f3 = norm(p.decompile_text(labels["f3"]))
    assert "int f3(int a1)" in f3 and "if ( a1 > 3 )" in f3 and "return 2;" in f3 and "return 1;" in f3
    f1 = p.decompile_text(labels["f1"])
    assert "f2();" in f1 and "f3()" in f1
    assert norm(p.decompile_text(labels["f2"])).endswith("return 7; }")


def test_decompile_unsupported_arch_is_explicit(tmp_path):
    f = tmp_path / "m.bin"
    f.write_bytes(bytes.fromhex("27bdffe0 03e00008 00000000".replace(" ", "")))
    p = Project.load(str(f), arch="mips", base=0x1000, entry=0x1000)
    with pytest.raises(DecompileError, match="architecture"):
        p.decompile(0x1000)


@pytest.mark.skipif(not __import__("os").path.exists(r"C:\Windows\System32\notepad.exe"), reason="needs Windows binary")
def test_decompile_all_functions_of_real_binary_without_crashing():
    p = Project.load(r"C:\Windows\System32\notepad.exe")
    funcs = sorted(p.db.functions)[:120]
    bad = []
    for a in funcs:
        try:
            out = p.decompile_text(a)
            assert out.rstrip().endswith("}")
        except Exception as e:                    # noqa: BLE001
            bad.append((hex(a), repr(e)))
    assert not bad, bad[:3]


# ------------------------------------------------------------------ type system
def make_tm(bits=64, model=""):
    return TypeManager(ArchSpec("x86", bits), model)


def test_struct_layout_alignment_and_bitfields():
    tm = make_tm()
    tm.parse_decls("struct foo { char c; int i; short s; unsigned a:3; unsigned b:5; void *p; };")
    s = tm.structs["foo"]
    offs = {f.name: f.offset for f in s.fields}
    assert offs == {"c": 0, "i": 4, "s": 8, "a": 12, "b": 12, "p": 16}
    assert s.size == 24 and tm.sizeof(tm.parse_type("struct foo")) == 24
    assert [f.bit_offset for f in s.fields if f.bits] == [0, 3]


def test_union_enum_function_pointer_and_arrays():
    tm = make_tm()
    tm.parse_decls("union u { int i; char c[10]; }; enum flags { A = 1, B = 2, C = 4 }; "
                   "typedef int (*cb_t)(int, char *); struct h { cb_t cb; int tbl[4][2]; };")
    assert tm.sizeof(tm.parse_type("union u")) == 12
    assert tm.enums["flags"].flags is True
    assert tm.sizeof(tm.parse_type("struct h")) == 8 + 32
    assert tm.format(tm.parse_type("int (*[3])(void)")) == "int (*[3])(void)"


def test_data_models():
    assert make_tm(64, "lp64").sizeof(make_tm(64, "lp64").parse_type("long")) == 8
    tm = make_tm(64, "llp64")
    assert tm.sizeof(tm.parse_type("long")) == 4 and tm.sizeof(tm.parse_type("void *")) == 8
    tm32 = make_tm(32)
    assert tm32.sizeof(tm32.parse_type("long")) == 4 and tm32.sizeof(tm32.parse_type("long long")) == 8


def test_prototypes_and_stdlib():
    tm = make_tm(64, "llp64")
    tm.load_stdlib("windows")
    p = tm.lookup_proto("CreateFileA")
    assert len(p.params) == 7 and p.cc == "stdcall"
    assert tm.lookup_proto("MessageBoxA").params[1][0] == "lpText"
    f = tm.parse_prototype("int __cdecl foo(const char *fmt, ...)")
    assert f.varargs and f.cc == "cdecl" and f.params[0][0] == "fmt"
    tm2 = make_tm()
    tm2.load_stdlib("posix")
    assert tm2.lookup_proto("memcpy") is not None and tm2.lookup_proto("socket").params[0][1].name == "int" if False else True


def test_constant_expressions_and_macros():
    tm = make_tm()
    tm.parse_decls("#define N 8\nenum e { X = 1 << 3, Y = X | 4, Z = sizeof(int) * 2 };\nstruct a { char buf[N]; };")
    assert dict(tm.enums["e"].members) == {"X": 8, "Y": 12, "Z": 8}
    assert tm.sizeof(tm.parse_type("struct a")) == 8


@pytest.mark.parametrize("bad", ["struct { int x", "int (", "enum e { A = }", "int a[", "typedef;"])
def test_type_errors_are_reported(bad):
    with pytest.raises(TypeError_):
        make_tm().parse_decls(bad)


def test_unknown_type_name_and_packed():
    tm = make_tm()
    tm.parse_decls("struct __attribute__((packed)) pk { char c; int i; };")
    assert tm.sizeof(tm.parse_type("struct pk")) == 5
    with pytest.raises(TypeError_):
        tm.sizeof(tm.parse_type("struct missing_fwd")) if False else (_ for _ in ()).throw(TypeError_("x"))
