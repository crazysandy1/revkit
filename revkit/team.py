"""Team collaboration + private function-metadata service.

Server: stdlib HTTP(S) JSON API backed by SQLite.
  * users with roles (admin / editor / viewer) and bearer tokens (stored only as SHA-256 hashes)
  * projects keyed by sample SHA-256; each project owns an append-only, server-ordered operation log of analyst edits
  * every authenticated request is written to an audit table
  * metadata service: function fingerprint -> {name, comment, prototype}; only fingerprints and analyst-chosen text are
    exchanged, never bytes of the sample
Client: `TeamClient` pushes the local edit journal and pulls remote edits (last-writer-wins per key, with conflicts reported).
Transport security is the operator's responsibility: run behind TLS (pass cert/key to `serve`) for anything but localhost.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

ROLES = {"viewer": 1, "editor": 2, "admin": 3}


def _hash_token(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def op_key(op: dict) -> str:
    """Identity of the thing an edit touches; two edits with the same key conflict."""
    k = op["kind"]
    if k in ("name", "fcomment", "anterior", "posterior", "type", "make_function", "delete_function", "make_code", "undefine"):
        return f"{k}:{op.get('addr')}"
    if k == "comment":
        return f"comment:{op.get('addr')}:{op.get('repeatable', False)}"
    if k == "bookmark":
        return f"bookmark:{op.get('slot')}"
    if k == "opfmt":
        return f"opfmt:{op.get('addr')}:{op.get('op')}"
    if k == "var":
        return f"var:{op.get('func')}:{op.get('loc')}"
    if k == "triage":
        return f"triage:{op.get('finding')}"
    if k == "types_src":
        return f"types:{hashlib.sha1(op.get('src', '').encode()).hexdigest()[:10]}"
    return f"{k}:{op.get('id')}"


class TeamStore:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()
        self.con = sqlite3.connect(path, check_same_thread=False)
        self.con.executescript("""
        CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, role TEXT NOT NULL, token_hash TEXT NOT NULL, created REAL);
        CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY, name TEXT, sha256 TEXT, created REAL, owner TEXT);
        CREATE TABLE IF NOT EXISTS ops(seq INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT, user TEXT, ts REAL,
                                       opid TEXT, key TEXT, body TEXT);
        CREATE INDEX IF NOT EXISTS ops_project ON ops(project, seq);
        CREATE UNIQUE INDEX IF NOT EXISTS ops_unique ON ops(project, opid);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, user TEXT, action TEXT, detail TEXT, ip TEXT);
        CREATE TABLE IF NOT EXISTS meta(arch TEXT, fp TEXT, name TEXT, comment TEXT, proto TEXT, size INTEGER, user TEXT, ts REAL,
                                        PRIMARY KEY(arch, fp, user));
        """)
        self.con.commit()

    # ---- users
    def add_user(self, name: str, role: str) -> str:
        if role not in ROLES:
            raise ValueError("role must be admin, editor or viewer")
        token = secrets.token_hex(24)
        with self.lock:
            self.con.execute("INSERT OR REPLACE INTO users VALUES(?,?,?,?)", (name, role, _hash_token(token), time.time()))
            self.con.commit()
        return token

    def authenticate(self, token: str) -> Optional[Tuple[str, str]]:
        h = _hash_token(token or "")
        with self.lock:
            row = self.con.execute("SELECT name, role FROM users WHERE token_hash=?", (h,)).fetchone()
        return (row[0], row[1]) if row else None

    def list_users(self):
        with self.lock:
            return [{"name": n, "role": r, "created": c} for n, r, c in self.con.execute("SELECT name, role, created FROM users")]

    def remove_user(self, name: str):
        with self.lock:
            self.con.execute("DELETE FROM users WHERE name=?", (name,))
            self.con.commit()

    def audit(self, user: str, action: str, detail: str = "", ip: str = ""):
        with self.lock:
            self.con.execute("INSERT INTO audit(ts,user,action,detail,ip) VALUES(?,?,?,?,?)", (time.time(), user, action, detail[:2000], ip))
            self.con.commit()

    # ---- projects / ops
    def ensure_project(self, pid: str, name: str, sha: str, owner: str):
        with self.lock:
            self.con.execute("INSERT OR IGNORE INTO projects VALUES(?,?,?,?,?)", (pid, name, sha, time.time(), owner))
            self.con.commit()

    def projects(self):
        with self.lock:
            return [{"id": i, "name": n, "sha256": s, "created": c, "owner": o, "ops": self.con.execute(
                "SELECT COUNT(*) FROM ops WHERE project=?", (i,)).fetchone()[0]}
                for i, n, s, c, o in self.con.execute("SELECT id,name,sha256,created,owner FROM projects")]

    def push(self, pid: str, user: str, ops: List[dict], base_seq: int) -> dict:
        accepted, dups, conflicts = [], 0, []
        with self.lock:
            for op in ops:
                key = op_key(op)
                other = self.con.execute("SELECT seq, user FROM ops WHERE project=? AND key=? AND seq>? AND user!=? ORDER BY seq DESC LIMIT 1",
                                         (pid, key, base_seq, user)).fetchone()
                try:
                    cur = self.con.execute("INSERT INTO ops(project,user,ts,opid,key,body) VALUES(?,?,?,?,?,?)",
                                           (pid, user, op.get("ts", time.time()), op["id"], key, json.dumps(op)))
                except sqlite3.IntegrityError:
                    dups += 1
                    continue
                accepted.append(cur.lastrowid)
                if other:
                    conflicts.append({"key": key, "overwrote_seq": other[0], "overwrote_user": other[1], "seq": cur.lastrowid})
            self.con.commit()
            head = self.con.execute("SELECT COALESCE(MAX(seq),0) FROM ops WHERE project=?", (pid,)).fetchone()[0]
        return {"accepted": len(accepted), "duplicates": dups, "conflicts": conflicts, "head": head}

    def pull(self, pid: str, since: int, exclude_user: Optional[str] = None, limit: int = 5000) -> dict:
        with self.lock:
            rows = self.con.execute("SELECT seq,user,body FROM ops WHERE project=? AND seq>? ORDER BY seq LIMIT ?", (pid, since, limit)).fetchall()
            head = self.con.execute("SELECT COALESCE(MAX(seq),0) FROM ops WHERE project=?", (pid,)).fetchone()[0]
        ops = [{"seq": s, "user": u, "op": json.loads(b)} for s, u, b in rows if u != exclude_user]
        last = rows[-1][0] if rows else since
        return {"ops": ops, "head": head, "next": last}

    # ---- metadata service
    def meta_push(self, user: str, arch: str, items: List[dict]) -> int:
        with self.lock:
            for it in items:
                self.con.execute("INSERT OR REPLACE INTO meta VALUES(?,?,?,?,?,?,?,?)",
                                 (arch, it["fp"], it["name"][:256], it.get("comment", "")[:2000], it.get("proto", "")[:1000],
                                  int(it.get("size", 0)), user, time.time()))
            self.con.commit()
        return len(items)

    def meta_query(self, arch: str, fps: List[str]) -> Dict[str, dict]:
        out: Dict[str, dict] = {}
        with self.lock:
            for i in range(0, len(fps), 500):
                chunk = fps[i:i + 500]
                q = ",".join("?" * len(chunk))
                for fp, name, comment, proto, size, user, ts in self.con.execute(
                        f"SELECT fp,name,comment,proto,size,user,ts FROM meta WHERE arch=? AND fp IN ({q}) ORDER BY ts", [arch] + chunk):
                    out[fp] = {"name": name, "comment": comment, "proto": proto, "size": size, "user": user, "ts": ts}
        return out

    def read_audit(self, limit: int = 500):
        with self.lock:
            return [{"ts": t, "user": u, "action": a, "detail": d, "ip": ip} for t, u, a, d, ip in
                    self.con.execute("SELECT ts,user,action,detail,ip FROM audit ORDER BY id DESC LIMIT ?", (limit,))]


class _Handler(BaseHTTPRequestHandler):
    store: TeamStore = None  # type: ignore[assignment]
    server_version = "revkit-team/1"

    def log_message(self, *a):
        pass

    def _send(self, code: int, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self, need: str) -> Optional[Tuple[str, str]]:
        tok = self.headers.get("Authorization", "")
        tok = tok[7:] if tok.startswith("Bearer ") else tok
        who = self.store.authenticate(tok)
        if not who:
            self.store.audit("?", "auth-failed", self.path, self.client_address[0])
            self._send(401, {"error": "invalid or missing token"})
            return None
        if ROLES[who[1]] < ROLES[need]:
            self.store.audit(who[0], "forbidden", f"{self.path} needs {need}", self.client_address[0])
            self._send(403, {"error": f"requires role {need}"})
            return None
        return who

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", "0") or 0)
        if n > 64 * 1024 * 1024:
            raise ValueError("request too large")
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path == "/health":
                return self._send(200, {"ok": True})
            if u.path == "/projects":
                who = self._auth("viewer")
                if who:
                    self._send(200, {"projects": self.store.projects()})
            elif u.path.startswith("/projects/") and u.path.endswith("/ops"):
                who = self._auth("viewer")
                if who:
                    pid = u.path.split("/")[2]
                    since = int(q.get("since", ["0"])[0])
                    self.store.audit(who[0], "pull", f"{pid} since {since}", self.client_address[0])
                    self._send(200, self.store.pull(pid, since, exclude_user=who[0] if q.get("exclude_self") else None))
            elif u.path == "/audit":
                who = self._auth("admin")
                if who:
                    self._send(200, {"audit": self.store.read_audit()})
            elif u.path == "/users":
                who = self._auth("admin")
                if who:
                    self._send(200, {"users": self.store.list_users()})
            else:
                self._send(404, {"error": "not found"})
        except Exception as e:
            self._send(500, {"error": str(e)})

    def do_POST(self):
        u = urlparse(self.path)
        try:
            body = self._body()
            if u.path == "/projects":
                who = self._auth("editor")
                if who:
                    self.store.ensure_project(body["id"], body.get("name", body["id"]), body.get("sha256", ""), who[0])
                    self.store.audit(who[0], "create-project", body["id"], self.client_address[0])
                    self._send(200, {"ok": True})
            elif u.path.startswith("/projects/") and u.path.endswith("/ops"):
                who = self._auth("editor")
                if who:
                    pid = u.path.split("/")[2]
                    r = self.store.push(pid, who[0], body.get("ops", []), int(body.get("base_seq", 0)))
                    self.store.audit(who[0], "push", f"{pid} +{r['accepted']} conflicts={len(r['conflicts'])}", self.client_address[0])
                    self._send(200, r)
            elif u.path == "/users":
                who = self._auth("admin")
                if who:
                    tok = self.store.add_user(body["name"], body["role"])
                    self.store.audit(who[0], "add-user", f"{body['name']} ({body['role']})", self.client_address[0])
                    self._send(200, {"token": tok})
            elif u.path == "/meta/push":
                who = self._auth("editor")
                if who:
                    n = self.store.meta_push(who[0], body["arch"], body["items"])
                    self.store.audit(who[0], "meta-push", f"{n} functions", self.client_address[0])
                    self._send(200, {"stored": n})
            elif u.path == "/meta/query":
                who = self._auth("viewer")
                if who:
                    self.store.audit(who[0], "meta-query", f"{len(body['fps'])} fingerprints", self.client_address[0])
                    self._send(200, {"results": self.store.meta_query(body["arch"], body["fps"])})
            else:
                self._send(404, {"error": "not found"})
        except KeyError as e:
            self._send(400, {"error": f"missing field {e}"})
        except Exception as e:
            self._send(500, {"error": str(e)})

    def do_DELETE(self):
        u = urlparse(self.path)
        if u.path.startswith("/users/"):
            who = self._auth("admin")
            if who:
                self.store.remove_user(u.path.split("/")[2])
                self.store.audit(who[0], "remove-user", u.path.split("/")[2], self.client_address[0])
                self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not found"})


class TeamServer:
    def __init__(self, db_path: str, host: str = "127.0.0.1", port: int = 0, certfile: Optional[str] = None,
                 keyfile: Optional[str] = None):
        self.store = TeamStore(db_path)
        handler = type("H", (_Handler,), {"store": self.store})
        self.httpd = ThreadingHTTPServer((host, port), handler)
        if certfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.scheme = "https" if certfile else "http"
        self.thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        h, p = self.httpd.server_address[:2]
        return f"{self.scheme}://{h}:{p}"

    def start(self):
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="revkit-team")
        self.thread.start()
        return self

    def serve_forever(self):
        self.httpd.serve_forever()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class TeamError(Exception):
    pass


class TeamClient:
    def __init__(self, url: str, token: str, verify_tls: bool = True, cafile: Optional[str] = None):
        self.url, self.token = url.rstrip("/"), token
        self.ctx = None
        if url.startswith("https"):
            self.ctx = ssl.create_default_context(cafile=cafile)
            if not verify_tls:
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE

    def _req(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30, context=self.ctx) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error", str(e))
            except Exception:
                msg = str(e)
            raise TeamError(f"{e.code}: {msg}") from None
        except urllib.error.URLError as e:
            raise TeamError(f"cannot reach {self.url}: {e.reason}") from None

    def projects(self):
        return self._req("GET", "/projects")["projects"]

    def sync(self, proj, project_id: Optional[str] = None) -> dict:
        """Push unsynced local edits, then pull and apply everyone else's edits. State lives in db.meta['team']."""
        db = proj.db
        pid = project_id or proj.image.sha256
        st = db.meta.setdefault("team", {})
        since = st.get(pid, {}).get("since", 0)
        pushed_upto = st.get(pid, {}).get("pushed", 0)
        self._req("POST", "/projects", {"id": pid, "name": proj.image.path.replace("\\", "/").split("/")[-1], "sha256": proj.image.sha256})
        pending = db.oplog[pushed_upto:]
        res = {"pushed": 0, "conflicts": [], "applied": 0}
        if pending:
            r = self._req("POST", f"/projects/{pid}/ops", {"ops": pending, "base_seq": since})
            res["pushed"], res["conflicts"] = r["accepted"], r["conflicts"]
            pushed_upto = len(db.oplog)
        pulled = self._req("GET", f"/projects/{pid}/ops?since={since}&exclude_self=1")
        for item in pulled["ops"]:
            try:
                db.apply_op(item["op"])
                res["applied"] += 1
            except Exception as e:
                res.setdefault("errors", []).append({"seq": item["seq"], "error": str(e)})
        st[pid] = {"since": pulled["head"] if pulled["head"] >= pulled["next"] else pulled["next"], "pushed": pushed_upto}
        # our own pushed ops are already local: advance 'since' past them
        st[pid]["since"] = pulled["head"]
        db.emit("team-sync", **{k: v for k, v in res.items() if k != "errors"})
        return res

    # ---- metadata service
    def push_metadata(self, proj, only_user_named: bool = True) -> int:
        from .fingerprint import function_hash
        db = proj.db
        items = []
        for a, f in db.functions.items():
            n = db.names.get(a)
            if not n or (only_user_named and not db.name_user.get(a)):
                continue
            if "thunk" in f.flags and "import" in f.flags:
                continue
            if f.size < 12:
                continue
            items.append({"fp": function_hash(db, f), "name": n, "comment": db.func_comments.get(a, ""),
                          "proto": db.func_protos.get(a, ""), "size": f.size})
        if not items:
            return 0
        return self._req("POST", "/meta/push", {"arch": proj.image.arch.key, "items": items})["stored"]

    def pull_metadata(self, proj, apply: bool = True) -> dict:
        from .fingerprint import function_hash
        db = proj.db
        fp_to_addr: Dict[str, int] = {}
        for a, f in db.functions.items():
            if db.name_user.get(a) or "import" in f.flags or f.size < 12:
                continue
            fp_to_addr[function_hash(db, f)] = a
        if not fp_to_addr:
            return {"matched": 0}
        r = self._req("POST", "/meta/query", {"arch": proj.image.arch.key, "fps": list(fp_to_addr)})["results"]
        applied = []
        for fp, m in r.items():
            a = fp_to_addr[fp]
            if apply:
                if db.set_name(a, m["name"], user=False, force=True):
                    db.signatures_applied[a] = f"metadata:{m['user']}"
                    if m.get("comment") and a not in db.func_comments:
                        db.func_comments[a] = f"[metadata from {m['user']}] {m['comment']}"
                    if m.get("proto") and a not in db.func_protos:
                        try:
                            db.apply_type(a, m["proto"])
                        except Exception:
                            pass
            applied.append({"addr": a, "name": m["name"], "user": m["user"]})
        return {"matched": len(r), "results": applied}
