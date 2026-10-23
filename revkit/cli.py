"""Command-line interface: `python -m revkit <command>` (also installed as `revkit`)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import List, Optional

from . import __version__
from .api import Project, RevkitError


def _open(path: str, args=None, analyze: bool = True) -> Project:
    if path.endswith(".rkdb"):
        return Project.open(path)
    kw = {}
    if args is not None:
        for k in ("fmt", "arch", "base", "entry"):
            v = getattr(args, k, None)
            if v is not None:
                kw[k] = v
        if getattr(args, "unpack", False):
            kw["unpack"] = True
    return Project.load(path, analyze_now=analyze, **kw)


def _addr(s: str) -> int:
    return int(s, 0)


def _out(args, data, text_fn=None):
    if getattr(args, "json", False) or text_fn is None:
        print(json.dumps(data, indent=1, default=lambda o: f"{o:#x}" if isinstance(o, int) else str(o)))
    else:
        text_fn(data)


def _table(rows: List[dict], cols: List[str], widths: Optional[List[int]] = None):
    widths = widths or [max(len(c), *(len(str(r.get(c, ""))) for r in rows)) if rows else len(c) for c in cols]
    print("  ".join(c.ljust(w) for c, w in zip(cols, widths)))
    for r in rows:
        print("  ".join(str(r.get(c, "")).ljust(w) for c, w in zip(cols, widths)))


def _hex(v):
    return f"{v:#x}" if isinstance(v, int) else v


# ------------------------------------------------------------------------------------------------ commands
def cmd_analyze(a):
    t = time.time()
    p = _open(a.file, a, analyze=False)
    from .analysis import Options
    opts = Options(min_string=a.min_string, prologue_scan=not a.no_prologue_scan, strings=not a.no_strings,
                   signatures=not a.no_signatures)
    st = p.analyze(opts, progress=(lambda m: print(f"  {m}", file=sys.stderr)) if a.verbose else None)
    if a.sigs:
        applied = p.apply_signatures(a.sigs)
        print(f"signatures applied: {len(applied)}", file=sys.stderr)
    out = a.output or (os.path.splitext(a.file)[0] + ".rkdb")
    if a.unpack:
        u = p.info()["unpack"]
        print("unpack: " + (f"{u['layers']} layer(s), OEP(s) " + ", ".join(hex(x) for x in u["oeps"]) if u and u.get("ok") else
                            "nothing unpacked (not packed, or emulation could not follow the stub)"), file=sys.stderr)
    p.save(out)
    info = p.info()
    if a.json:
        print(json.dumps({"database": out, "stats": st, "info": info}, indent=1, default=str))
    else:
        print(f"{info['path']}\n  format {info['format']}  arch {info['arch_key']}  sha256 {info['sha256']}")
        print(f"  {st['functions']} functions, {st['instructions']} instructions, {st['strings']} strings, "
              f"{st['xrefs']} xrefs in {st['seconds']}s (passes: {st['passes']})")
        print(f"database saved: {out}")


def cmd_info(a):
    p = _open(a.file, a)
    _out(a, p.info(), lambda d: [print(f"{k:14} {v}") for k, v in d.items() if k not in ("loader_info", "stats")])


def cmd_functions(a):
    p = _open(a.file, a)
    rows = [{**f, "addr": _hex(f["addr"]), "flags": ",".join(f["flags"])} for f in p.functions(a.filter)]
    if a.limit:
        rows = rows[:a.limit]
    _out(a, rows, lambda d: _table(d, ["addr", "name", "size", "blocks", "callers", "callees", "flags"]))


def cmd_strings(a):
    p = _open(a.file, a)
    rows = p.strings(a.min_len, a.filter)
    _out(a, rows, lambda d: [print(f"{_hex(r['addr'])}  {r['text']!r}") for r in d])


def cmd_imports(a):
    p = _open(a.file, a)
    _out(a, p.imports(), lambda d: [print(f"{_hex(r['addr'])}  {r['module']}!{r['name']}  xrefs={len(r['xrefs'])}") for r in d])


def cmd_exports(a):
    p = _open(a.file, a)
    _out(a, p.exports(), lambda d: [print(f"{_hex(r['addr'])}  {r['name']}") for r in d])


def cmd_segments(a):
    p = _open(a.file, a)
    _out(a, p.segments(), lambda d: _table([{**r, "start": _hex(r["start"]), "end": _hex(r["end"])} for r in d],
                                          ["name", "start", "end", "perms", "kind"]))


def cmd_disasm(a):
    p = _open(a.file, a)
    if a.function:
        print(p.disasm_function(a.target))
        return
    for ln in p.disasm(a.target, a.count):
        if ln.kind in ("code", "data", "unknown"):
            print(f"{ln.addr:08x}  {ln.bytes:<24} {ln.text}" + (f"    ; {ln.comment}" if ln.comment else ""))
        elif ln.kind != "blank":
            print(f"{ln.addr:08x}  {ln.text}")


def cmd_listing(a):
    p = _open(a.file, a)
    text = p.listing_text(with_bytes=a.bytes)
    if a.output:
        with open(a.output, "w", encoding="utf8") as f:
            f.write(text)
        print(f"wrote {a.output} ({len(text.splitlines())} lines)")
    else:
        print(text)


def cmd_decompile(a):
    p = _open(a.file, a)
    if a.all:
        res = p.decompile_all()
        text = "\n\n".join(f"// {p.db.display_name(k)} @ {k:#x}\n{v}" for k, v in res.items())
        if a.output:
            open(a.output, "w", encoding="utf8").write(text)
            print(f"wrote {a.output}: {len(res)} functions")
        else:
            print(text)
        return
    print(p.decompile_text(a.target))


def cmd_xrefs(a):
    p = _open(a.file, a)
    d = {"to": p.xrefs_to(a.target), "from": p.xrefs_from(a.target)}
    def show(d):
        print("references to:")
        for r in d["to"]:
            print(f"  {r['from']:#x} {r['kind']:6} {r['text']}")
        print("references from:")
        for r in d["from"]:
            print(f"  {r['to']:#x} {r['kind']:6} {r['name']}")
    _out(a, d, show)


def cmd_cfg(a):
    p = _open(a.file, a)
    print(p.cfg_dot(a.target) if a.dot else json.dumps(p.cfg(a.target), indent=1))


def cmd_callgraph(a):
    p = _open(a.file, a)
    print(p.callgraph_dot(a.root))


def cmd_hexdump(a):
    p = _open(a.file, a)
    for r in p.hexdump(a.target, a.length):
        print(f"{r['addr']:08x}  {r['hex']:<48}  {r['ascii']}")


def cmd_search(a):
    p = _open(a.file, a)
    if a.bytes:
        for x in p.search_bytes(a.bytes):
            print(f"{x:#x}")
    elif a.text:
        for x, t in p.search_text(a.text, regex=a.regex):
            print(f"{x:#x}  {t}")
    elif a.imm is not None:
        for x in p.search_imm(a.imm):
            print(f"{x:#x}  {p._text(x)}")
    elif a.name:
        for x, n in p.search_names(a.name, regex=a.regex):
            print(f"{x:#x}  {n}")
    elif a.string:
        for x, t in p.search_strings(a.string, regex=a.regex):
            print(f"{x:#x}  {t!r}")
    else:
        print("choose one of --bytes/--text/--imm/--name/--string", file=sys.stderr)
        return 2


def _save_if_db(p: Project, a):
    if a.file.endswith(".rkdb"):
        p.save()


def cmd_rename(a):
    p = _open(a.file, a)
    p.rename(a.target, a.name)
    _save_if_db(p, a)


def cmd_comment(a):
    p = _open(a.file, a)
    p.comment(a.target, a.text, a.repeatable)
    _save_if_db(p, a)


def cmd_types(a):
    p = _open(a.file, a)
    src = open(a.header, encoding="utf8").read()
    names = p.add_types(src)
    print("declared:", ", ".join(names))
    _save_if_db(p, a)


def cmd_patch(a):
    p = _open(a.file, a)
    if a.asm:
        print("patched bytes:", p.patch_asm(a.target, a.asm).hex())
    elif a.bytes:
        p.patch_bytes(a.target, a.bytes)
    elif a.nop:
        p.nop(a.target, a.nop)
    elif a.invert:
        print("new bytes:", p.invert_branch(a.target).hex())
    elif a.force_jump:
        print("new bytes:", p.force_jump(a.target).hex())
    if a.output:
        rec = p.write_patched(a.output)
        print(json.dumps(rec, indent=1))
    _save_if_db(p, a)


def cmd_sig(a):
    from .analysis.signatures import SigDB
    if a.sig_cmd == "make":
        s = SigDB(a.name)
        for f in a.inputs:
            if f.endswith(".a"):
                n = s.add_archive(f)
            elif f.endswith(".o"):
                n = s.add_elf_object(f)
            else:
                n = s.add_database(_open(f, a).db, only_named=not a.all_functions, lib=a.name)
            print(f"{f}: {n} signatures")
        s.save(a.output)
        if a.pat:
            open(a.pat, "w").write(s.export_pat())
        print(f"saved {a.output} ({len(s.sigs)} signatures)")
    else:
        p = _open(a.file, a)
        applied = p.apply_signatures(a.sigs or None)
        for addr, nm in sorted(applied.items()):
            print(f"{addr:#x}  {nm}")
        print(f"{len(applied)} functions recognised")
        _save_if_db(p, a)


def cmd_diff(a):
    p1, p2 = _open(a.a, a), _open(a.b, a)
    r = p1.diff(p2)
    if a.json:
        print(json.dumps(r, indent=1))
        return
    s = r["summary"]
    print(f"A: {s['functions_a']} functions   B: {s['functions_b']} functions   matched {s['matched']}  identical {s['identical']}  "
          f"changed {s['changed']}  removed {s['removed']}  added {s['added']}   similarity {s['overall_similarity']}")
    for m in r["changed"][:a.limit]:
        print(f"  changed  {m['name_a']} ({m['a']:#x}) -> {m['name_b']} ({m['b']:#x})  sim={m['similarity']} via {m['method']}")
    for x in r["removed"][:a.limit]:
        print(f"  removed  {x['name']} ({x['addr']:#x})")
    for x in r["added"][:a.limit]:
        print(f"  added    {x['name']} ({x['addr']:#x})")


def cmd_triage(a):
    p = _open(a.file, a)
    fs = p.triage()
    if a.status:
        from .vulns import set_status
        set_status(p, a.status[0], a.status[1], a.note or "", os.environ.get("USERNAME", ""))
        _save_if_db(p, a)
        print("status updated")
        return
    _out(a, fs, lambda d: [print(f"[{f['severity']:8}] {f['id']} {f['title']}  ({f['category']}, {f['confidence']}, {f['status']})"
                                 + (f" @ {f['address']:#x}" if f['address'] else "")) for f in d])


def cmd_report(a):
    p = _open(a.file, a)
    text = p.report(a.rfmt)
    if a.output:
        open(a.output, "w", encoding="utf8").write(text)
        print(f"wrote {a.output}")
    else:
        print(text)


def cmd_export(a):
    from . import report as R
    p = _open(a.file, a)
    fns = {"asm": lambda: p.listing_text(with_bytes=True), "json": lambda: R.export_json(p), "csv": lambda: R.export_functions_csv(p),
           "map": lambda: R.export_map(p), "rk": lambda: R.export_names_script(p), "py": lambda: R.export_python_script(p),
           "header": lambda: R.export_c_header(p), "dot": lambda: p.callgraph_dot()}
    text = fns[a.what]()
    if a.output:
        open(a.output, "w", encoding="utf8").write(text)
        print(f"wrote {a.output}")
    else:
        print(text)


def cmd_packer(a):
    p = _open(a.file, a)
    _out(a, p.packer_report(), lambda d: (print("verdict:", d["verdict"]), [print(f"  [{f['severity']}] {f['title']}: {f['detail']}") for f in d["findings"]],
                                          _table([{**s, "start": _hex(s["start"])} for s in d["sections"]], ["name", "start", "size", "perms", "entropy"])))


def cmd_crypto(a):
    from .crypto import find_crypto_constants
    p = _open(a.file, a)
    for h in find_crypto_constants(p.db):
        print(f"{h['addr']:#x}  {h['name']:10} {h['detail']}")


def cmd_mba(a):
    from .deobf import simplify_mba
    r = simplify_mba(a.expr, a.bits)
    print(json.dumps(r, indent=1) if a.json else f"{r['input']}\n  => {r['output']}   [{r['method']}; verified: {r['verified'] or 'no'}]")


def cmd_emulate(a):
    from .emulate import emulate
    p = _open(a.file, a)
    r = emulate(p, p.resolve(a.target), [int(x, 0) for x in a.args], a.max_insns)
    print(json.dumps(r.to_dict(), indent=1))


def cmd_unpack(a):
    p = _open(a.file, a)
    r = p.unpack(max_insns=a.max_insns, dump_path=a.output)
    print(json.dumps(r, indent=1, default=lambda o: f"{o:#x}" if isinstance(o, int) else str(o)))
    return 0 if r["ok"] else 1


def cmd_import_names(a):
    p = _open(a.file, a)
    print(f"{p.import_names(a.names)} names applied")
    _save_if_db(p, a)


def cmd_pdb(a):
    p = _open(a.file, a)
    print(f"{p.load_pdb(a.pdb)} symbols applied")
    _save_if_db(p, a)


def cmd_explain(a):
    p = _open(a.file, a)
    r = p.explain(a.target, a.llm)
    print(json.dumps(r, indent=1, default=str))


def cmd_script(a):
    p = _open(a.file, a)
    r = p.run_script(a.script, a.args)
    sys.stdout.write(r.output)
    if not r.ok:
        sys.stderr.write(r.error)
        return 1
    _save_if_db(p, a)


def cmd_plugin(a):
    from .plugins import PluginManager, trust_plugin, create_plugin_template, trusted_hashes
    if a.plugin_cmd == "new":
        create_plugin_template(a.path, os.path.splitext(os.path.basename(a.path))[0])
        print(f"template written to {a.path}")
        return
    if a.plugin_cmd == "trust":
        print("sha256:", trust_plugin(a.path))
        return
    p = _open(a.file, a)
    pm = PluginManager(p, allow_untrusted=getattr(a, "allow_untrusted", False))
    pm.discover()
    if a.plugin_cmd == "list":
        _out(a, {"plugins": pm.list(), "rejected": pm.rejected},
             lambda d: ([print(f"{x['name']:16} v{x['version']:6} {'builtin' if x['builtin'] else 'external':8} {x['description']}") for x in d["plugins"]],
                        [print(f"REJECTED {r['path']}: {r['reason']}") for r in d["rejected"]]))
    else:
        print(json.dumps(pm.run(a.name, a.arg), indent=1, default=str))
        _save_if_db(p, a)


def cmd_batch(a):
    from .batch import run_batch
    res = run_batch(a.inputs, a.outdir, jobs=a.jobs, decompile=a.decompile, report=a.report, timeout=a.timeout)
    print(json.dumps(res, indent=1) if a.json else "\n".join(
        f"{'OK ' if r['ok'] else 'ERR'} {r['input']}  {r.get('functions', '')} funcs  {r.get('seconds', '')}s  {r.get('error', '')}" for r in res["results"]))
    return 0 if all(r["ok"] for r in res["results"]) else 1


def cmd_serve(a):
    from .web.server import serve
    p = _open(a.file, a)
    p.allow_execution = a.allow_exec
    serve(p, a.host, a.port, open_browser=not a.no_browser, db_path=a.file if a.file.endswith(".rkdb") else None)


def cmd_debug(a):
    from .debugger.repl import run_repl
    p = _open(a.file, a)
    p.allow_execution = a.allow_exec
    return run_repl(p, a)


def cmd_stub(a):
    from .debugger import start_emulator_stub
    p = _open(a.file, a)
    stub = start_emulator_stub(p, a.entry, a.host, a.port)
    print(f"emulator GDB stub listening on {a.host}:{stub.port}  (gdb: target remote {a.host}:{stub.port})")
    try:
        while stub.thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        stub.stop()


def cmd_team(a):
    from .team import TeamServer, TeamClient, TeamStore
    if a.team_cmd == "serve":
        s = TeamServer(a.db, a.host, a.port, a.cert, a.key)
        print(f"team server on {s.url}")
        try:
            s.serve_forever()
        except KeyboardInterrupt:
            s.stop()
    elif a.team_cmd == "add-user":
        st = TeamStore(a.db)
        print(f"token for {a.name} ({a.role}): {st.add_user(a.name, a.role)}\n(shown once; only its hash is stored)")
    else:
        cl = TeamClient(a.url, a.token or os.environ.get("REVKIT_TEAM_TOKEN", ""), verify_tls=not a.insecure)
        p = _open(a.file, a)
        if a.team_cmd == "sync":
            print(json.dumps(cl.sync(p), indent=1))
        elif a.team_cmd == "push-meta":
            print("stored", cl.push_metadata(p))
        elif a.team_cmd == "pull-meta":
            print(json.dumps(cl.pull_metadata(p), indent=1))
        _save_if_db(p, a)


def cmd_vault(a):
    from . import secure
    if a.vault_cmd == "import":
        print(json.dumps(secure.import_sample(a.path, a.source, a.notes), indent=1))
    elif a.vault_cmd == "list":
        for s in secure.list_samples():
            print(f"{s['sha256']}  {s['size']:>10}  {s['original_name']}  {s.get('source', '')}")
    elif a.vault_cmd == "export":
        print(secure.export_sample(a.sha256, a.output))
    elif a.vault_cmd == "verify-audit":
        r = secure.verify_audit()
        print(json.dumps(r))
        return 0 if r["ok"] else 1


def cmd_doctor(a):
    import importlib
    ok = True
    for mod, why in [("capstone", "disassembly"), ("keystone", "assembler/patching"), ("pefile", "PE loader"),
                     ("elftools", "ELF loader"), ("unicorn", "emulation/stub")]:
        try:
            m = importlib.import_module(mod)
            print(f"  ok   {mod:10} {getattr(m, '__version__', '')}  ({why})")
        except Exception as e:
            ok = False
            print(f"  MISS {mod:10} ({why}): {e}")
    import shutil
    for tool, why in [("node", "REA bridge (JavaScript apps)"), ("npx", "REA bridge"), ("gdbserver", "remote debugging target"),
                      ("gdb", "optional external client")]:
        print(f"  {'ok  ' if shutil.which(tool) else 'n/a '} {tool:10} ({why})")
    print(f"revkit {__version__} on Python {sys.version.split()[0]} / {sys.platform}")
    return 0 if ok else 1


# ------------------------------------------------------------------------------------------------ parser
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="revkit", description="Programmable reverse-engineering platform")
    ap.add_argument("--version", action="version", version=f"revkit {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_, file=True):
        sp = sub.add_parser(name, help=help_)
        if file:
            sp.add_argument("file", help="binary or .rkdb database")
            sp.add_argument("--fmt", help="force loader (pe, elf, macho, raw, com, ihex, srec)")
            sp.add_argument("--arch", help="architecture for headerless input (x86, x86_64, arm, arm64, mips, ppc, riscv64, ...)")
            sp.add_argument("--base", type=_addr, help="load address for raw input")
            sp.add_argument("--entry", type=_addr, help="entry point for raw input")
            sp.add_argument("--unpack", action="store_true",
                            help="emulate the packer stub first and analyse the unpacked code (import option)")
        sp.add_argument("--json", action="store_true", help="machine-readable output")
        sp.set_defaults(fn=fn)
        return sp

    sp = add("analyze", cmd_analyze, "load + auto-analyse a binary and save a database")
    sp.add_argument("-o", "--output")
    sp.add_argument("-v", "--verbose", action="store_true")
    sp.add_argument("--min-string", type=int, default=4)
    sp.add_argument("--no-strings", action="store_true")
    sp.add_argument("--no-prologue-scan", action="store_true")
    sp.add_argument("--no-signatures", action="store_true")
    sp.add_argument("--sigs", nargs="*", help="signature files (.rsig/.pat) to apply")
    add("info", cmd_info, "summary of a binary/database")
    sp = add("functions", cmd_functions, "list functions")
    sp.add_argument("--filter")
    sp.add_argument("--limit", type=int)
    sp = add("strings", cmd_strings, "list strings")
    sp.add_argument("--min-len", type=int, default=4)
    sp.add_argument("--filter")
    add("imports", cmd_imports, "list imports")
    add("exports", cmd_exports, "list exports")
    add("segments", cmd_segments, "list segments")
    sp = add("disasm", cmd_disasm, "disassemble at an address/name")
    sp.add_argument("target")
    sp.add_argument("-n", "--count", type=int, default=40)
    sp.add_argument("-f", "--function", action="store_true", help="disassemble the whole function")
    sp = add("listing", cmd_listing, "full text listing (.asm)")
    sp.add_argument("-o", "--output")
    sp.add_argument("--bytes", action="store_true")
    sp = add("decompile", cmd_decompile, "pseudocode for a function (or --all)")
    sp.add_argument("target", nargs="?")
    sp.add_argument("--all", action="store_true")
    sp.add_argument("-o", "--output")
    sp = add("xrefs", cmd_xrefs, "cross-references to/from an address")
    sp.add_argument("target")
    sp = add("cfg", cmd_cfg, "control-flow graph (json or --dot)")
    sp.add_argument("target")
    sp.add_argument("--dot", action="store_true")
    sp = add("callgraph", cmd_callgraph, "call graph in DOT")
    sp.add_argument("--root")
    sp = add("hexdump", cmd_hexdump, "hex dump")
    sp.add_argument("target")
    sp.add_argument("-l", "--length", type=int, default=256)
    sp = add("search", cmd_search, "search bytes/text/immediates/names/strings")
    sp.add_argument("--bytes")
    sp.add_argument("--text")
    sp.add_argument("--imm", type=_addr)
    sp.add_argument("--name")
    sp.add_argument("--string")
    sp.add_argument("--regex", action="store_true")
    sp = add("rename", cmd_rename, "rename an address (database only)")
    sp.add_argument("target")
    sp.add_argument("name")
    sp = add("comment", cmd_comment, "set a comment (database only)")
    sp.add_argument("target")
    sp.add_argument("text")
    sp.add_argument("-r", "--repeatable", action="store_true")
    sp = add("types", cmd_types, "load C declarations from a header file")
    sp.add_argument("header")
    sp = add("patch", cmd_patch, "patch bytes/asm/nops and optionally write a patched copy")
    sp.add_argument("target")
    sp.add_argument("--bytes")
    sp.add_argument("--asm")
    sp.add_argument("--nop", type=int, help="NOP this many bytes")
    sp.add_argument("--invert", action="store_true", help="invert the conditional branch at target")
    sp.add_argument("--force-jump", action="store_true")
    sp.add_argument("-o", "--output", help="write the patched file here")
    sp = sub.add_parser("sig", help="function signatures")
    ssub = sp.add_subparsers(dest="sig_cmd", required=True)
    m = ssub.add_parser("make")
    m.add_argument("inputs", nargs="+", help="databases/binaries with symbols, ELF .o, or ar .a archives")
    m.add_argument("-o", "--output", required=True)
    m.add_argument("--name", default="user")
    m.add_argument("--pat", help="also write a text .pat file")
    m.add_argument("--all-functions", action="store_true")
    m.add_argument("--fmt"), m.add_argument("--arch"), m.add_argument("--base", type=_addr), m.add_argument("--entry", type=_addr)
    ap_ = ssub.add_parser("apply")
    ap_.add_argument("file")
    ap_.add_argument("--sigs", nargs="*")
    ap_.add_argument("--fmt"), ap_.add_argument("--arch"), ap_.add_argument("--base", type=_addr), ap_.add_argument("--entry", type=_addr)
    sp.set_defaults(fn=cmd_sig, json=False)
    sp = sub.add_parser("diff", help="compare two binaries/databases")
    sp.add_argument("a"), sp.add_argument("b")
    sp.add_argument("--limit", type=int, default=50)
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--fmt"), sp.add_argument("--arch"), sp.add_argument("--base", type=_addr), sp.add_argument("--entry", type=_addr)
    sp.set_defaults(fn=cmd_diff)
    sp = add("triage", cmd_triage, "heuristic vulnerability findings + review workflow")
    sp.add_argument("--status", nargs=2, metavar=("ID", "STATUS"))
    sp.add_argument("--note")
    sp = add("report", cmd_report, "analysis report")
    sp.add_argument("--format", dest="rfmt", default="markdown", choices=["markdown", "html", "json"])
    sp.add_argument("-o", "--output")
    sp = add("export", cmd_export, "export data")
    sp.add_argument("what", choices=["asm", "json", "csv", "map", "rk", "py", "header", "dot"])
    sp.add_argument("-o", "--output")
    add("packer", cmd_packer, "packing/obfuscation indicators")
    add("crypto", cmd_crypto, "find cryptographic constants")
    sp = sub.add_parser("mba", help="simplify a mixed boolean-arithmetic expression")
    sp.add_argument("expr")
    sp.add_argument("--bits", type=int, default=64)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=cmd_mba)
    sp = add("emulate", cmd_emulate, "emulate a function with Unicorn")
    sp.add_argument("target")
    sp.add_argument("args", nargs="*")
    sp.add_argument("--max-insns", type=int, default=200000)
    sp = add("unpack", cmd_unpack, "emulate an unpacking stub and dump the unpacked image")
    sp.add_argument("-o", "--output", help="write the unpacked flat image here")
    sp.add_argument("--max-insns", type=int, default=20_000_000)
    sp = add("import-names", cmd_import_names, "import names from MAP/CSV/JSON/script")
    sp.add_argument("names")
    sp = add("pdb", cmd_pdb, "apply public symbols from a Microsoft PDB")
    sp.add_argument("pdb")
    sp = add("explain", cmd_explain, "evidence-linked function explanation")
    sp.add_argument("target")
    sp.add_argument("--llm", action="store_true", help="also ask an LLM (needs ANTHROPIC_API_KEY or REVKIT_LLM_COMMAND)")
    sp = add("script", cmd_script, "run a Python script against a database")
    sp.add_argument("script")
    sp.add_argument("args", nargs="*")
    sp = sub.add_parser("plugin", help="plugins")
    psub = sp.add_subparsers(dest="plugin_cmd", required=True)
    for n in ("list", "run"):
        q = psub.add_parser(n)
        q.add_argument("file")
        q.add_argument("--allow-untrusted", action="store_true")
        q.add_argument("--json", action="store_true")
        q.add_argument("--fmt"), q.add_argument("--arch"), q.add_argument("--base", type=_addr), q.add_argument("--entry", type=_addr)
        if n == "run":
            q.add_argument("name")
            q.add_argument("arg", nargs="?")
    q = psub.add_parser("trust")
    q.add_argument("path")
    q = psub.add_parser("new")
    q.add_argument("path")
    sp.set_defaults(fn=cmd_plugin)
    sp = sub.add_parser("batch", help="headless batch analysis of many files")
    sp.add_argument("inputs", nargs="+")
    sp.add_argument("--outdir", required=True)
    sp.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 2)
    sp.add_argument("--decompile", action="store_true")
    sp.add_argument("--report", action="store_true")
    sp.add_argument("--timeout", type=int, default=3600)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=cmd_batch)
    sp = add("serve", cmd_serve, "start the web UI")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8765)
    sp.add_argument("--no-browser", action="store_true")
    sp.add_argument("--allow-exec", action="store_true", help="permit debugger launch/attach (runs the sample!)")
    sp = add("debug", cmd_debug, "interactive debugger (native on Windows, or --gdb host:port)")
    sp.add_argument("--args", nargs="*", default=[])
    sp.add_argument("--gdb", help="host:port of a remote GDB stub")
    sp.add_argument("--allow-exec", action="store_true", help="permit launching the sample natively (runs it!)")
    sp = add("stub", cmd_stub, "serve an emulated copy of the image over the GDB protocol")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=0)
    sp = sub.add_parser("team", help="collaboration + metadata server")
    tsub = sp.add_subparsers(dest="team_cmd", required=True)
    q = tsub.add_parser("serve")
    q.add_argument("--db", default="revkit-team.db"), q.add_argument("--host", default="127.0.0.1"), q.add_argument("--port", type=int, default=8800)
    q.add_argument("--cert"), q.add_argument("--key")
    q = tsub.add_parser("add-user")
    q.add_argument("--db", default="revkit-team.db"), q.add_argument("name"), q.add_argument("role", choices=["viewer", "editor", "admin"])
    for n in ("sync", "push-meta", "pull-meta"):
        q = tsub.add_parser(n)
        q.add_argument("file"), q.add_argument("--url", required=True), q.add_argument("--token")
        q.add_argument("--insecure", action="store_true")
        q.add_argument("--fmt"), q.add_argument("--arch"), q.add_argument("--base", type=_addr), q.add_argument("--entry", type=_addr)
    sp.set_defaults(fn=cmd_team)
    sp = sub.add_parser("vault", help="secure sample vault + audit log")
    vsub = sp.add_subparsers(dest="vault_cmd", required=True)
    q = vsub.add_parser("import")
    q.add_argument("path"), q.add_argument("--source", default=""), q.add_argument("--notes", default="")
    vsub.add_parser("list")
    q = vsub.add_parser("export")
    q.add_argument("sha256"), q.add_argument("output")
    vsub.add_parser("verify-audit")
    sp.set_defaults(fn=cmd_vault)
    sp = sub.add_parser("doctor", help="check dependencies")
    sp.set_defaults(fn=cmd_doctor)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = build_parser()
    a = ap.parse_args(argv)
    if a.cmd in ("decompile",) and not a.all and not a.target:
        ap.error("decompile needs a target or --all")
    try:
        return a.fn(a) or 0
    except (RevkitError, ValueError, FileNotFoundError, PermissionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
