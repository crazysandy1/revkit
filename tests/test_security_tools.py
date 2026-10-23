import json
import os
import struct
import subprocess
import sys

import pytest

import fixtures as F
from revkit.api import Project


@pytest.fixture(scope="module")
def vuln(tmp_path_factory):
    pe, info = F.build_vuln_pe()
    p = tmp_path_factory.mktemp("v") / "vuln.exe"
    p.write_bytes(pe)
    return Project.load(str(p)), info


# ------------------------------------------------------------------ triage
def test_triage_findings_with_evidence(vuln):
    p, info = vuln
    fs = p.triage()
    by_cat = {}
    for f in fs:
        by_cat.setdefault(f["category"], []).append(f)
    so = by_cat["stack-overflow"][0]
    assert so["severity"] == "critical" and so["confidence"] == "high"
    assert "69 bytes into 32-byte" in so["title"]
    assert any("dest=" in e for e in so["evidence"])
    assert any(f["title"].startswith("printf: non-constant format") for f in fs)
    assert any(f["category"] == "secrets" for f in fs)
    assert any(f["category"] == "hardening" for f in fs)
    cmd = [f for f in fs if f["category"] == "command-exec"]
    assert cmd and cmd[0]["severity"] == "info"           # constant command line is informational, not injection


def test_triage_status_workflow_is_persisted(vuln, tmp_path):
    from revkit.vulns import set_status
    p, _ = vuln
    fid = p.triage()[0]["id"]
    set_status(p, fid, "false-positive", "reviewed by analyst", "tester")
    again = {f["id"]: f for f in p.triage()}
    assert again[fid]["status"] == "false-positive" and again[fid]["note"] == "reviewed by analyst"
    with pytest.raises(ValueError):
        set_status(p, fid, "bogus")
    q = Project.open(p.save(str(tmp_path / "v.rkdb")))
    assert {f["id"]: f for f in q.triage()}[fid]["status"] == "false-positive"
    assert any(e["op"].startswith("triage") for e in q.db.audit)


def test_explain_function_has_evidence(vuln):
    p, info = vuln
    ex = p.explain(info["labels"]["vuln"])
    claims = " ".join(b["claim"] for b in ex["evidence_bullets"])
    assert "command execution" in claims or "process creation" in claims.lower() or "string handling" in claims
    assert all(b["evidence"] for b in ex["evidence_bullets"])
    assert ex["verified"] is True
    llm = p.explain(info["labels"]["vuln"], use_llm=True)["llm"]
    assert llm["unverified"] is True                      # LLM text is always marked unverified (or unavailable)


# ------------------------------------------------------------------ MBA
@pytest.mark.parametrize("expr,expected", [
    ("(x ^ y) + 2*(x & y)", "x+y"),
    ("(x | y) + (x & y)", "x+y"),
    ("2*(x|y) - (x^y)", "x+y"),
    ("(x & ~y) + y", "x|y"),
    ("(x|y) - (x&y)", "x^y"),
])
def test_mba_simplification_is_verified(expr, expected):
    from revkit.deobf import simplify_mba
    r = simplify_mba(expr)
    assert r["output"].replace(" ", "") == expected and r["verified"]


def test_mba_never_returns_unverified_rewrite_and_constants():
    from revkit.deobf import simplify_mba, evaluate, _parse
    r = simplify_mba("(x*y) + (x&y)*3")           # non-linear: either simplified & verified, or untouched
    assert r["output"] == "(x*y) + (x&y)*3" or r["verified"]
    assert simplify_mba("3*5-2")["output"] == "13"
    # independent check of a returned rewrite on random 64-bit inputs
    import random
    r = simplify_mba("(a ^ b) + 2*(a & b)")
    for _ in range(200):
        env = {"a": random.getrandbits(64), "b": random.getrandbits(64)}
        assert evaluate(_parse(r["input"]), env) == evaluate(_parse(r["output"]), env)


# ------------------------------------------------------------------ crypto constants, packing
def _blob_project(tmp_path, data, name="blob.bin"):
    f = tmp_path / name
    f.write_bytes(data)
    return Project.load(str(f), arch="x86_64", base=0x10000, entry=0x10000)


def test_crypto_constant_detection(tmp_path):
    from revkit.crypto import _AES_SBOX
    data = bytes([0xC3] * 16) + _AES_SBOX + struct.pack("<4I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476) + \
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" + b"expand 32-byte k"
    p = _blob_project(tmp_path, data)
    from revkit.crypto import find_crypto_constants
    names = {h["name"] for h in find_crypto_constants(p.db)}
    assert {"AES", "MD5", "Base64", "ChaCha/Salsa20"} <= names
    plug = p.db  # plugin annotates
    from revkit.plugins import PluginManager
    pm = PluginManager(p)
    pm.discover()
    res = pm.run("crypto_scan")
    assert res["annotated"] >= 4


def test_packing_indicators(tmp_path):
    import random
    rnd = random.Random(1)
    high = bytes(rnd.getrandbits(8) for _ in range(8192))
    p = _blob_project(tmp_path, high)
    r = p.packer_report()
    assert any("entropy" in f["title"].lower() or "writable+executable" in f["title"] for f in r["findings"])
    assert r["verdict"] in ("suspicious", "likely packed/obfuscated")
    from revkit.packers import entropy
    assert entropy(b"\x00" * 100) == 0 and entropy(bytes(range(256))) == pytest.approx(8.0)


# ------------------------------------------------------------------ emulation
def test_emulate_function_and_decode_strings(tmp_path):
    from revkit.emulate import emulate, decode_strings
    # int add3(int a, int b, int c) { return a + b + c; } as raw x86-64 (SysV)
    code = bytes.fromhex("8d0437 01d0 c3".replace(" ", ""))        # lea eax,[rdi+rsi]; add eax,edx; ret
    p = _blob_project(tmp_path, code)
    r = emulate(p, 0x10000, [1, 2, 3])
    assert r.ok or r.error == ""
    assert r.regs["rax"] & 0xFFFFFFFF == 6

    # xor decoder: void dec(char *buf) { for (i = 0; buf[i]; i++) buf[i] ^= 0x5a; }
    dec = bytes.fromhex("31c9 8a0c0f 84c9 7407 80f15a 880c0f ffc0 ebf1 c3".replace(" ", "")) if False else None
    import keystone as ks
    asm = """
    xor ecx, ecx
    loop_:
    mov al, byte ptr [rdi + rcx]
    test al, al
    jz done
    xor al, 0x5a
    mov byte ptr [rdi + rcx], al
    inc rcx
    jmp loop_
    done:
    ret
    """
    code2, _ = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_64).asm(asm, 0x10000, as_bytes=True)
    enc = bytes(b ^ 0x5a for b in b"secret-config") + b"\x00"
    blob = bytes(code2) + b"\x90" * (0x40 - len(code2)) + enc
    p2 = _blob_project(tmp_path, blob, "dec.bin")
    r = emulate(p2, 0x10000, [0x10040], memory={})
    assert any(b"secret-config" in d for _, _, d in r.writes), r.error


# ------------------------------------------------------------------ vault + audit
def test_vault_and_tamper_evident_audit(tmp_path, monkeypatch):
    from revkit import secure
    sample = tmp_path / "evil.bin"
    sample.write_bytes(b"MZ" + os.urandom(100))
    rec = secure.import_sample(str(sample), source="unit test", notes="n")
    assert rec["defanged"] and os.path.basename(rec["stored"]).endswith(".defanged")
    assert not os.access(rec["stored"], os.W_OK)
    assert secure.list_samples()[0]["sha256"] == rec["sha256"]
    out = secure.export_sample(rec["sha256"], str(tmp_path / "out.bin"))
    assert open(out, "rb").read() == sample.read_bytes()
    assert secure.verify_audit()["ok"] and secure.verify_audit()["entries"] == 2
    # tamper with the log
    log = secure.audit_path()
    lines = open(log, encoding="utf8").read().splitlines()
    rec0 = json.loads(lines[0])
    rec0["detail"]["name"] = "innocent.txt"
    lines[0] = json.dumps(rec0, sort_keys=True)
    open(log, "w", encoding="utf8").write("\n".join(lines) + "\n")
    v = secure.verify_audit()
    assert v["ok"] is False and v["broken_at_line"] == 1
    # vault integrity check on export
    os.chmod(rec["stored"], 0o666)
    open(rec["stored"], "ab").write(b"x")
    with pytest.raises(ValueError):
        secure.export_sample(rec["sha256"], str(tmp_path / "out2.bin"))


def test_execution_gate(proj):
    from revkit.secure import require_execution_permission
    with pytest.raises(PermissionError):
        require_execution_permission(proj, "test")
    proj.allow_execution = True
    require_execution_permission(proj, "test")


# ------------------------------------------------------------------ plugins
def test_plugin_trust_and_provenance(proj, tmp_path):
    from revkit.plugins import PluginManager, create_plugin_template, trust_plugin, trusted_hashes, PluginError
    path = tmp_path / "myplug.py"
    create_plugin_template(str(path), "myplug")
    pm = PluginManager(proj)
    pm.discover([str(tmp_path)])
    assert pm.rejected and "untrusted" in pm.rejected[0]["reason"]
    sha = trust_plugin(str(path))
    assert sha in trusted_hashes()
    pm2 = PluginManager(proj)
    pm2.discover([str(tmp_path)])
    assert "myplug" in pm2.plugins and pm2.run("myplug")["functions"] == len(proj.db.functions)
    assert pm2.run_action("myplug", "hello").endswith("functions")
    # modifying the file invalidates trust (pinned to the SHA-256)
    path.write_text(path.read_text() + "\n# changed\n")
    pm3 = PluginManager(proj)
    pm3.discover([str(tmp_path)])
    assert "myplug" not in pm3.plugins
    # incompatible API version is rejected even when trusted
    bad = tmp_path / "old.py"
    bad.write_text("from revkit.plugins import Plugin\nclass P(Plugin):\n    name='old'\n    api_version=99\nPLUGIN=P\n")
    with pytest.raises(PluginError, match="API version"):
        PluginManager(proj, allow_untrusted=True).load(str(bad))


def test_builtin_plugins(proj):
    from revkit.plugins import PluginManager
    pm = PluginManager(proj)
    names = {x["name"] for x in pm.discover()}
    assert {"crypto_scan", "api_tagger", "rea_bridge"} <= names
    assert not pm.rejected


# ------------------------------------------------------------------ scripting
def test_scripting_native_and_scripting_compat(proj, labels):
    r = proj.run_script("""
print(len(list(rkutil.Functions())))
ea = rk.get_name_ea_simple('fact')
print(hex(ea), rk.get_func_name(ea))
rk.set_cmt(ea, 'from script', 0)
rk.set_name(ea, 'fact_script')
print(sum(1 for _ in rkutil.XrefsTo(ea)))
print(str(rkapi.decompile(ea)).splitlines()[0])
result = [hex(x) for x in rkutil.FuncItems(ea)][:2]
""")
    assert r.ok, r.error
    out = r.output.split("\n")
    assert out[0] == "6" and "fact" in out[1] and out[2] == "3" and out[3].startswith("int ")
    assert proj.db.comments[labels["fact"]] == "from script" and proj.db.display_name(labels["fact"]) == "fact_script"
    bad = proj.run_script("raise RuntimeError('boom')")
    assert not bad.ok and "boom" in bad.error


# ------------------------------------------------------------------ reports, exports, diff, batch
def test_report_and_exports(proj, labels):
    md = proj.report("markdown")
    assert "# Analysis report" in md and proj.image.sha256 in md and "Findings" in md
    html = proj.report("html")
    assert html.startswith("<!doctype html>") and "<table>" in html
    data = json.loads(proj.report("json"))
    assert data["info"]["sha256"] == proj.image.sha256
    from revkit import report as R
    assert "address,name" in R.export_functions_csv(proj)
    assert "main" in R.export_map(proj)
    proj.rename(labels["fact"], "factorial")
    assert 'set_name(0x401065, "factorial"' in R.export_names_script(proj)
    assert "rk.set_name(0x401065, 'factorial')" in R.export_python_script(proj)
    assert json.loads(R.export_json(proj))["functions"]


def test_binary_diff(proj, tmp_path):
    text = F.X64_PROGRAM.replace("mov eax, 40", "mov eax, 41").replace("say:\n", "    nop\n    nop\nsay:\n", 1)
    code, labels = F.build_x64(text)
    syms = {n: (labels[n], 0, "func") for n in F.X64_FUNCS}
    p2 = tmp_path / "v2.elf"
    p2.write_bytes(F.build_elf64(code, 0x401000, labels["_start"], syms))
    other = Project.load(str(p2))
    d = proj.diff(other)
    s = d["summary"]
    assert s["matched"] == 6 and s["added"] == 0 and s["removed"] == 0
    changed = {m["name_a"] for m in d["changed"]}
    assert "dispatch" in changed                         # the 40 -> 41 constant change
    assert any(m["name_a"] == "fact" and m["identical"] for m in d["matched"])
    from revkit.bindiff import function_diff
    text_diff = function_diff(proj, other, proj.resolve("dispatch"), other.resolve("dispatch"))
    assert "-mov eax, 0x28" in text_diff and "+mov eax, 0x29" in text_diff


def test_batch_headless(tmp_path, x64_path, pe_sample):
    from revkit.batch import run_batch
    res = run_batch([x64_path, pe_sample[0], str(tmp_path / "missing.bin")], str(tmp_path / "out"), jobs=2, decompile=True, report=True)
    ok = [r for r in res["results"] if r["ok"]]
    assert len(ok) == 2
    for r in ok:
        assert os.path.exists(r["database"]) and r["functions"] > 0 and r["decompile_failures"] == 0
    q = Project.open(ok[0]["database"])
    assert q.db.analyzed


def test_cli_end_to_end(x64_path, tmp_path):
    def run(*a):
        r = subprocess.run([sys.executable, "-m", "revkit", *a], capture_output=True, text=True, encoding="utf8",
                           cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return r
    db = str(tmp_path / "c.rkdb")
    r = run("analyze", x64_path, "-o", db)
    assert r.returncode == 0 and "6 functions" in r.stdout
    assert "fact" in run("functions", db, "--json").stdout
    assert "int fact(int a1)" in run("decompile", db, "fact").stdout
    assert run("rename", db, "fact", "factorial").returncode == 0
    assert "factorial" in run("functions", db).stdout
    assert run("rename", db, "fact", "x").returncode == 2           # unknown name -> clean error
    assert "x+y" in run("mba", "(x ^ y) + 2*(x & y)").stdout
    assert run("doctor").returncode == 0
    r = run("emulate", db, "factorial", "5")
    assert r.returncode in (0, 2)
    out = tmp_path / "patched.bin"
    r = run("patch", db, "0x401076", "--nop", "5", "-o", str(out))
    assert r.returncode == 0 and out.exists()
