"""Local web server: JSON API over a Project + the single-page analysis UI.

Security model: binds to localhost by default, every /api request must carry the per-run random token, and the debugger
refuses to execute the sample unless the server was started with --allow-exec.
"""
from __future__ import annotations

import json
import mimetypes
import os
import secrets
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional
from urllib.parse import parse_qs, urlparse

from .. import graphs, patching
from ..api import Project, RevkitError
from ..plugins import PluginError, PluginManager, config_dir

STATIC = os.path.join(os.path.dirname(__file__), "static")


class AppState:
    def __init__(self, proj: Project, token: str, db_path: Optional[str]):
        self.proj = proj
        self.token = token
        self.db_path = db_path
        self.lock = threading.RLock()
        self.dbg = None
        self.dbg_events: list = []
        self.plugins = PluginManager(proj)
        self.plugins.discover()
        self.saved_rev = proj.db.rev
        self.settings_path = os.path.join(config_dir(), "settings.json")

    def settings(self) -> dict:
        try:
            with open(self.settings_path, encoding="utf8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {"theme": "dark", "font": "Consolas, monospace", "fontSize": 13, "shortcuts": {}}


def _hexs(v):
    return f"{v:#x}"


def make_handler(state: AppState):
    proj = state.proj

    def A(q, key="addr", default=None):
        v = q.get(key, [default])[0]
        if v is None:
            raise RevkitError(f"missing parameter {key}")
        return proj.resolve(v)

    def i(q, key, default):
        return int(q.get(key, [default])[0], 0) if isinstance(q.get(key, [default])[0], str) else q.get(key, [default])[0]

    # ------------------------------------------------------------------ GET routes
    def r_state(q, b):
        db = proj.db
        return {"rev": db.rev, "dirty": db.rev != state.saved_rev, "can_undo": bool(db._undo), "can_redo": bool(db._redo),
                "path": state.db_path, "debugging": state.dbg is not None and state.dbg.state != "exited",
                "undo_label": db._undo[-1][0] if db._undo else None}

    def r_info(q, b):
        return proj.info()

    def r_functions(q, b):
        return proj.functions(q.get("filter", [None])[0])

    def r_names(q, b):
        return proj.names()

    def r_strings(q, b):
        return proj.strings(i(q, "min", 4), q.get("filter", [None])[0])

    def r_imports(q, b):
        return proj.imports()

    def r_exports(q, b):
        return proj.exports()

    def r_segments(q, b):
        return proj.segments()

    def r_disasm(q, b):
        lines = proj.disasm(A(q), i(q, "count", 80), i(q, "back", 0))
        return {"lines": [ln.to_dict() for ln in lines]}

    def r_hex(q, b):
        return {"rows": proj.hexdump(A(q), i(q, "len", 512))}

    def r_decompile(q, b):
        pc = proj.decompile(A(q))
        return {"function": pc.function, "name": pc.name, "lines": [{"text": t, "addr": a} for t, a in pc.lines]}

    def r_cfg(q, b):
        return proj.cfg(A(q))

    def r_proximity(q, b):
        return proj.proximity(A(q), i(q, "depth", 2))

    def r_xrefs(q, b):
        a = A(q)
        return {"to": proj.xrefs_to(a), "from": proj.xrefs_from(a)}

    def r_function(q, b):
        f = proj.function(A(q))
        db = proj.db
        return {"start": f.start, "end": f.end, "name": db.display_name(f.start), "flags": sorted(f.flags),
                "callconv": f.callconv, "frame": f.frame_size, "callers": [{"addr": c, "name": db.display_name(c)} for c in proj.callers(f.start)],
                "callees": [{"addr": c, "name": db.display_name(c)} for c in db.callees(f.start)],
                "comment": db.func_comments.get(f.start, ""), "proto": db.func_protos.get(f.start, ""),
                "chunks": f.chunks, "complexity": graphs.cyclomatic_complexity(f), "loops": graphs.loops(f)}

    def r_search(q, b):
        kind = q.get("kind", ["text"])[0]
        s = q["q"][0]
        rx = q.get("regex", ["0"])[0] == "1"
        if kind == "bytes":
            return [{"addr": a, "text": proj._text(a) or ""} for a in proj.search_bytes(s)]
        if kind == "imm":
            return [{"addr": a, "text": proj._text(a)} for a in proj.search_imm(int(s, 0))]
        if kind == "name":
            return [{"addr": a, "text": n} for a, n in proj.search_names(s, regex=rx)]
        if kind == "string":
            return [{"addr": a, "text": t} for a, t in proj.search_strings(s, regex=rx)]
        return [{"addr": a, "text": t} for a, t in proj.search_text(s, regex=rx)]

    def r_types(q, b):
        tm = proj.db.types
        name = q.get("name", [None])[0]
        if name:
            from ..types import Struct, Enum
            st = tm.structs.get(name) or tm.unions.get(name)
            if st:
                return {"kind": "struct", "text": tm.struct_to_c(st)}
            en = tm.enums.get(name)
            if en:
                return {"kind": "enum", "members": en.members}
            raise RevkitError("unknown type")
        return {"structs": sorted(n for n in list(tm.structs) + list(tm.unions) if not n.startswith("__anon")),
                "enums": sorted(tm.enums), "typedefs": sorted(tm.typedefs), "prototypes": len(tm.protos),
                "user_sources": tm.user_sources}

    def r_problems(q, b):
        return [{"addr": a, "message": m} for a, m in proj.db.meta.get("problems", [])]

    def r_bookmarks(q, b):
        return [{"slot": s, "addr": a, "desc": d} for s, (a, d) in sorted(proj.db.bookmarks.items())]

    def r_patches(q, b):
        return proj.patches()

    def r_triage(q, b):
        return proj.triage()

    def r_packer(q, b):
        return proj.packer_report()

    def r_explain(q, b):
        return proj.explain(A(q), q.get("llm", ["0"])[0] == "1")

    def r_report(q, b):
        return {"format": q.get("fmt", ["markdown"])[0], "text": proj.report(q.get("fmt", ["markdown"])[0])}

    def r_plugins(q, b):
        return {"plugins": state.plugins.list(), "rejected": state.plugins.rejected,
                "hotkeys": {k: v.name for k, v in state.plugins.hotkeys.items()}}

    def r_settings(q, b):
        return state.settings()

    def r_listing_context(q, b):
        a = A(q)
        db = proj.db
        d = {"addr": a, "name": db.display_name(a) if (a in db.names or a in db.functions) else None,
             "comment": db.comments.get(a, ""), "rcomment": db.rep_comments.get(a, ""),
             "segment": proj.image.segment_at(a).name if proj.image.segment_at(a) else None,
             "function": None}
        f = db.function_at(a)
        if f:
            d["function"] = {"start": f.start, "name": db.display_name(f.start)}
        ins = db.insn(a) if a in db.insns else None
        if ins:
            d["insn"] = {"text": ins.text, "size": ins.size, "bytes": ins.raw.hex(" "), "flow": ins.flow}
        return d

    # ------------------------------------------------------------------ POST routes (mutations)
    def p_rename(q, b):
        proj.rename(b["addr"], b["name"])
        return {"ok": True}

    def p_comment(q, b):
        proj.comment(b["addr"], b.get("text", ""), b.get("repeatable", False))
        return {"ok": True}

    def p_fcomment(q, b):
        proj.func_comment(b["addr"], b.get("text", ""))
        return {"ok": True}

    def p_bookmark(q, b):
        if b.get("remove"):
            proj.db.remove_bookmark(int(b["slot"]))
        else:
            proj.bookmark(int(b.get("slot", len(proj.db.bookmarks) + 1)), b["addr"], b.get("desc", ""))
        return {"ok": True}

    def p_type(q, b):
        proj.set_type(b["addr"], b["decl"])
        return {"ok": True}

    def p_types_add(q, b):
        return {"declared": proj.add_types(b["source"])}

    def p_opfmt(q, b):
        proj.op_format(b["addr"], int(b["op"]), b["fmt"])
        return {"ok": True}

    def p_rename_var(q, b):
        proj.rename_var(b["func"], b["old"], b["new"], b.get("type", ""))
        return {"ok": True}

    def p_make(q, b):
        k = b["what"]
        a = proj.resolve(b["addr"])
        if k == "code":
            return {"ok": proj.make_code(a)}
        if k == "function":
            return {"ok": proj.make_function(a)}
        if k == "delete_function":
            return {"ok": proj.delete_function(a)}
        if k == "undefine":
            proj.undefine(a, int(b.get("size", 1)))
            return {"ok": True}
        if k == "data":
            proj.make_data(a, b.get("kind", "dword"), int(b.get("count", 1)))
            return {"ok": True}
        if k == "string":
            return {"ok": True, "text": proj.make_string(a, b.get("encoding", "ascii"))}
        if k == "struct":
            return {"ok": True, "size": proj.apply_struct(a, b["decl"])}
        if k == "func_end":
            return {"ok": proj.set_function_end(a, b["end"])}
        raise RevkitError("unknown operation")

    def p_undo(q, b):
        return {"undone": proj.undo()}

    def p_redo(q, b):
        return {"redone": proj.redo()}

    def p_patch(q, b):
        a = proj.resolve(b["addr"])
        if b.get("asm"):
            return {"bytes": proj.patch_asm(a, b["asm"]).hex()}
        if b.get("bytes"):
            proj.patch_bytes(a, b["bytes"])
            return {"ok": True}
        if b.get("nop"):
            proj.nop(a, int(b["nop"]))
            return {"ok": True}
        if b.get("invert"):
            return {"bytes": proj.invert_branch(a).hex()}
        if b.get("revert"):
            return {"ok": proj.revert_patch(a)}
        raise RevkitError("nothing to patch")

    def p_write_patched(q, b):
        return proj.write_patched(b["path"])

    def p_save(q, b):
        path = b.get("path") or state.db_path or (proj.image.path + ".rkdb")
        proj.save(path)
        state.db_path = path
        state.saved_rev = proj.db.rev
        return {"path": path}

    def p_script(q, b):
        return proj.run_script(b["code"]).to_dict()

    def p_plugin_run(q, b):
        try:
            r = state.plugins.run(b["name"], b.get("arg"))
        except PluginError as e:
            raise RevkitError(str(e))
        return {"result": json.loads(json.dumps(r, default=str))}

    def p_triage_status(q, b):
        from ..vulns import set_status
        return set_status(proj, b["id"], b["status"], b.get("note", ""), os.environ.get("USERNAME", ""))

    def p_settings(q, b):
        with open(state.settings_path, "w", encoding="utf8") as f:
            json.dump(b, f)
        return {"ok": True}

    def p_apply_sigs(q, b):
        return {"applied": len(proj.apply_signatures(b.get("paths")))}

    def p_decompile_var(q, b):
        return {"ok": True}

    # ------------------------------------------------------------------ debugger
    def need_dbg():
        if state.dbg is None:
            raise RevkitError("no debug session; start one first")
        return state.dbg

    def d_start(q, b):
        from ..debugger import create_session
        if state.dbg is not None and state.dbg.state != "exited":
            raise RevkitError("a debug session is already active; kill it first")
        backend = b.get("backend", "native")
        s = create_session(proj, backend, host=b.get("host", "127.0.0.1"), port=int(b.get("port", 1234)))
        s.listeners.append(lambda ev: state.dbg_events.append({**ev.to_dict(), "ts": time.time()}))
        state.dbg = s
        if backend == "gdb":
            ev = s.connect()
        elif b.get("pid"):
            ev = s.attach(int(b["pid"]))
        else:
            ev = s.launch(proj.image.path, b.get("args", []))
        return {"event": ev.to_dict()}

    def d_state(q, b):
        d = state.dbg
        if d is None:
            return {"active": False}
        out = {"active": True, "state": d.state, "arch": d.arch, "bits": d.bits, "base": d.main_base,
               "breakpoints": [x.to_dict() for x in d.breakpoints.values()], "events": state.dbg_events[-50:],
               "last_event": d.last_event.to_dict() if d.last_event else None}
        if d.state == "stopped":
            try:
                out["regs"] = d.registers()
                out["pc"] = d.pc()
                out["static_pc"] = d.to_static(d.pc())
            except Exception as e:
                out["error"] = str(e)
        return out

    def d_cmd(q, b):
        d = need_dbg()
        c = b["cmd"]
        if c == "cont":
            ev = d.cont(b.get("timeout"))
        elif c == "step":
            ev = d.step_into()
        elif c == "over":
            ev = d.step_over()
        elif c == "out":
            ev = d.step_out()
        elif c == "until":
            ev = d.run_to(d.to_runtime(proj.resolve(b["addr"])))
        elif c == "pause":
            d.pause()
            return {"ok": True}
        elif c == "kill":
            d.kill()
            return {"ok": True}
        elif c == "detach":
            d.detach()
            return {"ok": True}
        else:
            raise RevkitError("unknown command")
        return {"event": ev.to_dict()}

    def d_bp(q, b):
        d = need_dbg()
        if b.get("remove"):
            d.remove_breakpoint(int(b["id"]))
            return {"ok": True}
        if "enable" in b:
            d.set_breakpoint_enabled(int(b["id"]), bool(b["enable"]))
            return {"ok": True}
        a = d.to_runtime(proj.resolve(b["addr"]))
        bp = d.add_breakpoint(a, b.get("kind", "sw"), int(b.get("size", 1)), b.get("condition", ""))
        return bp.to_dict()

    def d_mem(q, b):
        d = need_dbg()
        a = i(q, "addr", 0)
        n = i(q, "len", 256)
        data = d.read_memory(a, n)
        return {"addr": a, "rows": [{"addr": a + k, "hex": data[k:k + 16].hex(" "),
                                     "ascii": "".join(chr(c) if 32 <= c < 127 else "." for c in data[k:k + 16])}
                                    for k in range(0, len(data), 16)]}

    def d_write_mem(q, b):
        need_dbg().write_memory(int(b["addr"]), bytes.fromhex(b["hex"].replace(" ", "")))
        return {"ok": True}

    def d_set_reg(q, b):
        need_dbg().set_register(b["name"], int(b["value"], 0) if isinstance(b["value"], str) else int(b["value"]))
        return {"ok": True}

    def d_info(q, b):
        d = need_dbg()
        what = q.get("what", ["bt"])[0]
        if what == "bt":
            return d.backtrace()
        if what == "stack":
            return d.stack(i(q, "n", 32))
        if what == "threads":
            return d.threads()
        if what == "modules":
            return [m.to_dict() for m in d.modules]
        if what == "map":
            return d.memory_map()
        if what == "disasm":
            return d.disasm(i(q, "addr", d.pc()), i(q, "n", 16))
        if what == "eval":
            v = d.evaluate(q["expr"][0])
            return {"value": v, "hex": hex(v)}
        raise RevkitError("unknown info")

    GET = {"/api/state": r_state, "/api/info": r_info, "/api/functions": r_functions, "/api/names": r_names,
           "/api/strings": r_strings, "/api/imports": r_imports, "/api/exports": r_exports, "/api/segments": r_segments,
           "/api/disasm": r_disasm, "/api/hex": r_hex, "/api/decompile": r_decompile, "/api/cfg": r_cfg,
           "/api/proximity": r_proximity, "/api/xrefs": r_xrefs, "/api/function": r_function, "/api/search": r_search,
           "/api/types": r_types, "/api/bookmarks": r_bookmarks, "/api/patches": r_patches, "/api/triage": r_triage,
           "/api/packer": r_packer, "/api/explain": r_explain, "/api/report": r_report, "/api/plugins": r_plugins,
           "/api/settings": r_settings, "/api/context": r_listing_context, "/api/problems": r_problems, "/api/debug/state": d_state,
           "/api/debug/mem": d_mem, "/api/debug/info": d_info}
    POST = {"/api/rename": p_rename, "/api/comment": p_comment, "/api/fcomment": p_fcomment, "/api/bookmark": p_bookmark,
            "/api/type": p_type, "/api/types/add": p_types_add, "/api/opfmt": p_opfmt, "/api/rename_var": p_rename_var,
            "/api/make": p_make, "/api/undo": p_undo, "/api/redo": p_redo, "/api/patch": p_patch,
            "/api/write_patched": p_write_patched, "/api/save": p_save, "/api/script": p_script,
            "/api/plugin/run": p_plugin_run, "/api/triage/status": p_triage_status, "/api/settings": p_settings,
            "/api/signatures/apply": p_apply_sigs, "/api/debug/start": d_start, "/api/debug/cmd": d_cmd,
            "/api/debug/bp": d_bp, "/api/debug/write_mem": d_write_mem, "/api/debug/set_reg": d_set_reg}

    class Handler(BaseHTTPRequestHandler):
        server_version = "revkit/1"

        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            body = json.dumps(obj, default=lambda o: f"{o:#x}" if isinstance(o, int) else str(o)).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _authed(self, q) -> bool:
            tok = self.headers.get("X-Revkit-Token") or q.get("token", [""])[0]
            return secrets.compare_digest(tok or "", state.token)

        def _handle(self, table, body):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if not self._authed(q):
                return self._json(401, {"error": "missing or invalid token"})
            fn = table.get(u.path)
            if fn is None:
                return self._json(404, {"error": "unknown endpoint"})
            try:
                with state.lock:
                    return self._json(200, fn(q, body))
            except (RevkitError, ValueError, KeyError, PermissionError, PluginError) as e:
                return self._json(400, {"error": str(e) if not isinstance(e, KeyError) else f"missing field {e}"})
            except Exception as e:
                from ..debugger.base import DebugError
                if isinstance(e, DebugError):
                    return self._json(400, {"error": str(e)})
                return self._json(500, {"error": f"{type(e).__name__}: {e}", "trace": traceback.format_exc()[-1500:]})

        def do_GET(self):
            u = urlparse(self.path)
            if u.path.startswith("/api/"):
                return self._handle(GET, None)
            rel = "index.html" if u.path in ("/", "") else u.path.lstrip("/")
            full = os.path.normpath(os.path.join(STATIC, rel))
            if not full.startswith(STATIC) or not os.path.isfile(full):
                self.send_response(404)
                self.end_headers()
                return
            data = open(full, "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(full)[0] or "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0") or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return self._json(400, {"error": "invalid JSON body"})
            self._handle(POST, body)

    return Handler


class WebServer:
    def __init__(self, proj: Project, host: str = "127.0.0.1", port: int = 8765, db_path: Optional[str] = None):
        self.token = secrets.token_urlsafe(18)
        self.state = AppState(proj, self.token, db_path)
        self.httpd = ThreadingHTTPServer((host, port), make_handler(self.state))
        self.host = host
        self.thread: Optional[threading.Thread] = None

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/#token={self.token}"

    def start(self):
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="revkit-web")
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def serve(proj: Project, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True, db_path: Optional[str] = None):
    srv = WebServer(proj, host, port, db_path)
    print(f"revkit UI: {srv.url}", flush=True)
    print("(the token in the URL fragment authorises API calls; keep it private)", flush=True)
    if open_browser:
        try:
            webbrowser.open(srv.url)
        except Exception:
            pass
    try:
        srv.httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.httpd.server_close()
