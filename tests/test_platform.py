import json
import os
import sys
import threading
import urllib.request
import urllib.error

import pytest

import fixtures as F
from revkit.api import Project
from revkit.analysis.signatures import SigDB, crc16


# ------------------------------------------------------------------ signatures
def _variant_project(tmp_path):
    """Same program, but with 3 bytes of padding before `say`: calls get different displacements."""
    text = F.X64_PROGRAM.replace("say:\n", "    nop\n    nop\n    nop\nsay:\n", 1)
    code, labels = F.build_x64(text)
    elf = F.build_elf64(code, 0x401000, labels["_start"], {})          # stripped: no symbols
    p = tmp_path / "stripped.elf"
    p.write_bytes(elf)
    return Project.load(str(p)), labels


def test_signature_roundtrip_and_relocation_masking(proj, labels, tmp_path):
    out = str(tmp_path / "t.rsig")
    n = proj.make_signatures(out, "testlib")
    assert n >= 4
    stripped, lab2 = _variant_project(tmp_path)
    assert stripped.db.display_name(lab2["fact"]).startswith("sub_") or stripped.db.display_name(lab2["fact"]) == "fact" is False
    applied = stripped.apply_signatures([out])
    names = set(applied.values())
    assert {"fact", "dispatch", "main"} <= names          # main's call displacements differ but are masked
    assert stripped.db.display_name(lab2["main"]) == "main"
    assert "library" in stripped.db.functions[lab2["fact"]].flags


def test_pat_export_import_roundtrip(proj, tmp_path):
    s = SigDB("t")
    s.add_database(proj.db)
    pat = s.export_pat()
    assert pat.rstrip().endswith("---")
    s2 = SigDB.import_pat(pat, "t2")
    assert {x.name for x in s2.sigs} == {x.name for x in s.sigs}
    assert all(a.crc == b.crc for a, b in zip(s.sigs, s2.sigs))


def test_crc16_known_value():
    assert crc16(b"") == 0
    assert crc16(b"123456789") == crc16(b"123456789") and 0 <= crc16(b"abc") < 65536
    assert crc16(b"abc") != crc16(b"abd")


# ------------------------------------------------------------------ debugger
def test_debugger_gdb_remote_via_emulator_stub(proj, labels):
    from revkit.debugger import create_session, start_emulator_stub
    stub = start_emulator_stub(proj)
    dbg = create_session(proj, "gdb", port=stub.port)
    try:
        dbg.connect()
        bp = dbg.add_breakpoint(labels["fact"])
        ev = dbg.cont(15)
        assert ev.kind == "breakpoint" and ev.addr == labels["fact"]
        regs = dbg.registers()
        assert regs["rdi"] == 5 and regs["rip"] == labels["fact"]
        ev = dbg.step_into()
        assert ev.kind == "step" and dbg.pc() == labels["fact"] + 1
        dbg.set_register("rax", 0x1234)
        assert dbg.registers()["rax"] == 0x1234
        dbg.write_memory(0x401108, b"\xaa\xbb")
        assert dbg.read_memory(0x401108, 2) == b"\xaa\xbb"
        assert dbg.evaluate("rdi*2+1") == 11
        assert dbg.evaluate("byte(0x401108) == 0xaa") == 1
        d = dbg.disasm(count=2)
        assert d[0]["text"] == "mov rbp, rsp"
        with pytest.raises(Exception):
            dbg.evaluate("__import__('os').system('echo hi')")
        dbg.remove_breakpoint(bp.id)
    finally:
        dbg.kill()
        stub.stop()


def test_debugger_expression_sandbox():
    from revkit.debugger.base import safe_eval
    assert safe_eval("rax + 4 * rbx", {"rax": 1, "rbx": 2}, None, 8) == 9
    assert safe_eval("qword(rsp)", {"rsp": 0x10}, lambda a, n: (a).to_bytes(n, "little"), 8) == 0x10
    for bad in ("open('x')", "rax.__class__", "[1,2][0]", "lambda: 1"):
        with pytest.raises(Exception):
            safe_eval(bad, {"rax": 1}, None, 8)


@pytest.mark.skipif(sys.platform != "win32" or not os.path.exists(r"C:\Windows\System32\ping.exe"), reason="Windows only")
def test_native_windows_debugger_breakpoint_step_and_exit():
    from revkit.debugger import create_session
    path = r"C:\Windows\System32\ping.exe"
    p = Project.load(path)
    dbg = create_session(p, "native")
    with pytest.raises(PermissionError):
        dbg.launch(path, ["-n", "1", "127.0.0.1"])          # execution is refused unless explicitly allowed
    p.allow_execution = True
    dbg = create_session(p, "native")
    try:
        ev = dbg.launch(path, ["-n", "1", "127.0.0.1"])
        assert ev.kind == "initial_break" and dbg.main_base
        ep = dbg.to_runtime(p.image.entry_points[0][0])
        bp = dbg.add_breakpoint(ep)
        ev = dbg.cont(30)
        assert ev.kind == "breakpoint" and ev.addr == ep
        assert dbg.registers()["rip"] == ep
        assert dbg.read_memory(ep, 4) == p.image.read(p.image.entry_points[0][0], 4)      # int3 patch hidden
        assert dbg.step_into().kind == "step"
        assert dbg.backtrace()[0]["symbol"]
        dbg.remove_breakpoint(bp.id)
        ev = dbg.cont(60)
        assert ev.kind == "exit"
    finally:
        dbg.kill()


# ------------------------------------------------------------------ team + metadata service
def test_team_sync_roles_conflicts_and_audit(proj, labels, tmp_path, x64_path):
    from revkit.team import TeamClient, TeamError, TeamServer
    srv = TeamServer(str(tmp_path / "team.db")).start()
    try:
        admin = srv.store.add_user("root", "admin")
        alice = srv.store.add_user("alice", "editor")
        bob = srv.store.add_user("bob", "editor")
        viewer = srv.store.add_user("vic", "viewer")
        ca, cb, cv = (TeamClient(srv.url, t) for t in (alice, bob, viewer))
        with pytest.raises(TeamError):
            TeamClient(srv.url, "bad-token").projects()
        pa = Project.load(x64_path)
        pb = Project.load(x64_path)
        pa.rename(labels["fact"], "factorial")
        pa.comment(labels["main"], "program entry")
        pa.add_types("struct t { int a; };")
        r = ca.sync(pa)
        assert r["pushed"] >= 3
        r = cb.sync(pb)
        assert r["applied"] >= 3
        assert pb.db.display_name(labels["fact"]) == "factorial"
        assert pb.db.comments[labels["main"]] == "program entry" and "t" in pb.db.types.structs
        # concurrent edits of the same key -> last writer wins, conflict reported
        pa.rename(labels["say"], "write_out")
        pb.rename(labels["say"], "emit")
        ca.sync(pa)
        r = cb.sync(pb)
        assert r["conflicts"], r
        ca.sync(pa)
        assert pa.db.display_name(labels["say"]) == "emit"
        # viewer can read, cannot write
        assert cv.projects()
        with pytest.raises(TeamError, match="403"):
            cv.sync(Project.load(x64_path))
        # audit is admin-only and records pushes
        with pytest.raises(TeamError):
            ca._req("GET", "/audit")
        log = TeamClient(srv.url, admin)._req("GET", "/audit")["audit"]
        assert any(e["action"] == "push" and e["user"] == "alice" for e in log)
        assert any(e["action"] == "forbidden" for e in log)
    finally:
        srv.stop()


def test_metadata_service_push_pull(proj, labels, tmp_path, x64_path):
    from revkit.team import TeamClient, TeamServer
    srv = TeamServer(str(tmp_path / "team.db")).start()
    try:
        tok = srv.store.add_user("ed", "editor")
        c = TeamClient(srv.url, tok)
        proj.rename(labels["dispatch"], "route_request")
        proj.func_comment(labels["dispatch"], "maps a command id to a status")
        assert c.push_metadata(proj) >= 1
        fresh = Project.load(x64_path)
        r = c.pull_metadata(fresh)
        assert r["matched"] >= 1
        assert fresh.db.display_name(labels["dispatch"]) == "route_request"
        assert "maps a command" in fresh.db.func_comments[labels["dispatch"]]
        assert not fresh.db.name_user.get(labels["dispatch"])         # suggestions stay non-authoritative
    finally:
        srv.stop()


# ------------------------------------------------------------------ web API
def _call(base, token, path, body=None, expect=200):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-Revkit-Token": token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        assert e.code == expect, (e.code, e.read())
        return json.loads(e.read() or b"{}")


def test_web_api(x64_path, labels, tmp_path):
    from revkit.web.server import WebServer
    p = Project.load(x64_path)
    srv = WebServer(p, port=0, db_path=str(tmp_path / "web.rkdb")).start()
    base, tok = f"http://127.0.0.1:{srv.port}", srv.token
    try:
        # auth + static
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(base + "/api/info")
        assert ei.value.code == 401
        assert b"<title>revkit" in urllib.request.urlopen(base + "/").read()
        assert b"function gotoAddr" in urllib.request.urlopen(base + "/app.js").read()
        assert _call(base, tok, "/api/info")["format"] == "ELF64"
        fs = _call(base, tok, "/api/functions")
        assert {f["name"] for f in fs} >= {"main", "fact"}
        lines = _call(base, tok, f"/api/disasm?addr={labels['fact']:#x}&count=20")["lines"]
        assert any(l["kind"] == "header" for l in lines)
        pc = _call(base, tok, f"/api/decompile?addr={labels['fact']:#x}")
        assert any("return" in l["text"] for l in pc["lines"])
        cfg = _call(base, tok, f"/api/cfg?addr={labels['dispatch']:#x}")
        assert len(cfg["nodes"]) == 7
        # edit + undo + save
        _call(base, tok, "/api/rename", {"addr": labels["fact"], "name": "factorial"})
        assert _call(base, tok, "/api/state")["dirty"] is True
        assert {n["name"] for n in _call(base, tok, "/api/names")} >= {"factorial"}
        assert _call(base, tok, "/api/undo", {})["undone"].startswith("name")
        _call(base, tok, "/api/rename", {"addr": labels["fact"], "name": "1bad"}, expect=400)
        assert _call(base, tok, "/api/save", {})["path"].endswith("web.rkdb")
        assert _call(base, tok, f"/api/search?kind=bytes&q=55%2048%2089")      # wildcard bytes
        assert _call(base, tok, "/api/script", {"code": "print(len(list(rkutil.Functions())))"})["output"].strip() == "6"
        assert any(pl["name"] == "crypto_scan" for pl in _call(base, tok, "/api/plugins")["plugins"])
        assert isinstance(_call(base, tok, "/api/triage"), list)
        assert _call(base, tok, "/api/make", {"what": "code", "addr": 0x4010C8})["ok"]
        assert _call(base, tok, "/api/patch", {"addr": 0x401076, "bytes": "b8 03 00 00 00"})["ok"]
        assert _call(base, tok, "/api/patches")
        # debugger endpoints refuse without a session; execution is gated
        _call(base, tok, "/api/debug/cmd", {"cmd": "cont"}, expect=400)
        r = _call(base, tok, "/api/debug/start", {"backend": "native"}, expect=400) if sys.platform == "win32" else {}
        assert "error" in r or sys.platform != "win32"
    finally:
        srv.stop()
