import os

import pytest

from revkit.api import Project, RevkitError


def test_rename_comment_undo_redo(proj, labels):
    a = labels["fact"]
    assert proj.db.name_user.get(a) is not True
    proj.rename(a, "factorial")
    assert proj.db.display_name(a) == "factorial" and proj.db.name_user[a]
    proj.comment(a + 4, "stack frame", repeatable=False)
    assert proj.db.comments[a + 4] == "stack frame"
    assert proj.undo().startswith("comment")
    assert (a + 4) not in proj.db.comments
    assert proj.undo().startswith("name")
    assert proj.db.display_name(a) == "fact"
    proj.redo()
    assert proj.db.display_name(a) == "factorial"


def test_name_collisions_and_invalid_names(proj, labels):
    with pytest.raises(RevkitError):
        proj.rename(labels["fact"], "main")          # already used
    with pytest.raises(RevkitError):
        proj.rename(labels["fact"], "9bad")


def test_user_name_survives_reanalysis(proj, labels):
    proj.rename(labels["say"], "write_message")
    proj.analyze()
    assert proj.db.display_name(labels["say"]) == "write_message"


def test_bookmarks_operand_format_and_types(proj, labels):
    proj.bookmark(1, labels["main"], "entry of main")
    assert proj.db.bookmarks[1] == (labels["main"], "entry of main")
    a = labels["main"] + 0x16 + 0xC       # mov edi, 5
    ins = proj.db.insn(labels["main"] + 0x14)
    proj.op_format(labels["main"] + 0x14, 1, "hex")
    names = proj.add_types("enum color { RED = 1, GREEN = 2, BLUE = 4 }; struct pt { int x; int y; };")
    assert "color" in proj.db.types.enums and proj.db.types.sizeof(proj.db.types.parse_type("struct pt")) == 8
    proj.op_format(labels["main"] + 0x14, 1, "enum:color")
    from revkit.listing import render_insn
    text = render_insn(proj.db, proj.db.insn(labels["main"] + 0x14))
    assert "BLUE" in text or "GREEN" in text or "RED" in text or "0x5" in text


def test_apply_prototype_changes_decompilation(proj, labels):
    proj.set_type(labels["fact"], "int __cdecl fact(int n)")
    out = proj.decompile_text(labels["fact"])
    assert "int n" in out or "n)" in out
    proj.rename_var(labels["fact"], "a1", "count")


def test_make_code_function_undefine_roundtrip(proj, labels):
    ud2 = 0x4010C8            # unreachable ud2 after my_exit
    before = len(proj.db.insns)
    assert proj.make_code(ud2)
    assert ud2 in proj.db.insns
    assert proj.undo()
    assert ud2 not in proj.db.insns and len(proj.db.insns) == before
    assert proj.make_function(ud2)
    assert ud2 in proj.db.functions
    assert proj.delete_function(ud2)
    assert ud2 not in proj.db.functions
    proj.undefine(labels["say"], 4)
    assert labels["say"] not in proj.db.insns


def test_make_data_and_string(proj, labels):
    addr = 0x401110        # counter qword
    d = proj.make_data(addr, "dword", 2)
    assert d.size == 8 and d.kind == "array"
    proj.undo()
    msg = [x for x in proj.strings() if x["text"].startswith("Hello")][0]["addr"]
    proj.undefine(msg, 25)
    assert msg not in proj.db.strings
    assert proj.make_string(msg).startswith("Hello")


def test_patch_asm_bytes_invert_and_file_export(proj, labels, tmp_path):
    # mov eax,1 at fact: 0x401076; patch immediate with assembly
    proj.patch_asm(0x401076, "mov eax, 2")
    assert proj.image.read(0x401076, 5)[1] == 2
    # invert 'jg' at 0x401074
    orig = proj.image.read(0x401074, 2)
    proj.invert_branch(0x401074)
    assert proj.image.read(0x401074, 1)[0] == orig[0] ^ 1
    out = str(tmp_path / "patched.elf")
    rec = proj.write_patched(out)
    assert len(rec["patches"]) == 2
    data = open(out, "rb").read()
    base = proj.image.file_offset(0x401076)
    assert data[base + 1] == 2
    # a re-load of the patched file sees the patch, the original file is untouched
    p2 = Project.load(out)
    assert p2.image.read(0x401076, 5)[1] == 2
    assert proj.revert_patch(0x401076)
    assert proj.image.read(0x401076, 5)[1] == 1


def test_database_roundtrip(proj, labels, tmp_path):
    proj.rename(labels["main"], "entry_main")
    proj.comment(labels["main"] + 1, "after push rbp")
    proj.bookmark(2, labels["fact"], "recursion")
    proj.add_types("struct node { int v; struct node *next; };")
    proj.patch_bytes(0x401076, "b8 09 00 00 00")
    path = proj.save(str(tmp_path / "x.rkdb"))
    q = Project.open(path)
    assert q.db.display_name(labels["main"]) == "entry_main"
    assert q.db.comments[labels["main"] + 1] == "after push rbp"
    assert q.db.bookmarks[2] == (labels["fact"], "recursion")
    assert "node" in q.db.types.structs and q.db.types.sizeof(q.db.types.parse_type("struct node")) == 16
    assert q.image.read(0x401076, 5) == bytes.fromhex("b809000000")
    assert q.db.analyzed and len(q.db.functions) == len(proj.db.functions)
    assert q.decompile_text(labels["fact"])
    # forced re-analysis keeps analyst data
    r = Project.open(path, reanalyze=True)
    assert r.db.display_name(labels["main"]) == "entry_main"


def test_search(proj, labels):
    assert labels["fact"] in [a for a in proj.search_bytes("55 48 89 e5")]
    assert proj.search_bytes("48 ?? ?? 48")            # wildcards
    hits = proj.search_text("call")
    assert hits and all("call" in t for _, t in hits)
    assert proj.search_imm(0x28)
    assert proj.search_names("fact")
    assert proj.search_strings("reverse")


def test_xrefs_graphs_and_cfg(proj, labels):
    from revkit import graphs
    f = proj.function(labels["dispatch"])
    assert graphs.cyclomatic_complexity(f) >= 3
    cfg = proj.cfg(labels["dispatch"])
    kinds = {e["kind"] for e in cfg["edges"]}
    assert {"true", "false", "switch"} <= kinds
    assert "digraph" in proj.cfg_dot(labels["fact"])
    loops = graphs.loops(proj.function(labels["fact"]))
    assert loops == []              # recursion is not a loop
    prox = proj.proximity(labels["main"], 1)
    assert {n["id"] for n in prox["nodes"]} >= {labels["main"], labels["fact"], labels["say"], labels["_start"]}
    assert graphs.find_paths(proj.db, labels["_start"], labels["fact"])
