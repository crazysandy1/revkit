"""Static vulnerability triage with evidence and an analyst-review workflow.

These are *heuristic findings for review*, not proof of exploitability. Every finding carries its evidence (addresses,
decompiled arguments, strings) and a confidence level; analysts set a status (new / confirmed / false-positive / fixed)
that is persisted in the database together with an audit trail.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Dict, List, Optional

from .decompiler.ir import CallE, Const, Var, Un, Bin, Mem, Cast, fmt, walk
from .db import Database

SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# name -> (category, base severity, index of destination arg, index of size arg or None, advice)
COPY_SINKS = {
    "strcpy": ("unbounded-copy", "high", 0, None), "wcscpy": ("unbounded-copy", "high", 0, None),
    "strcat": ("unbounded-copy", "high", 0, None), "wcscat": ("unbounded-copy", "high", 0, None),
    "lstrcpyA": ("unbounded-copy", "high", 0, None), "lstrcpyW": ("unbounded-copy", "high", 0, None),
    "lstrcatA": ("unbounded-copy", "high", 0, None), "StrCpyA": ("unbounded-copy", "high", 0, None),
    "sprintf": ("unbounded-format", "high", 0, None), "vsprintf": ("unbounded-format", "high", 0, None),
    "wsprintfA": ("unbounded-format", "high", 0, None), "wsprintfW": ("unbounded-format", "high", 0, None),
    "gets": ("unbounded-input", "critical", 0, None),
    "memcpy": ("bounded-copy", "medium", 0, 2), "memmove": ("bounded-copy", "medium", 0, 2),
    "strncpy": ("bounded-copy", "medium", 0, 2), "strncat": ("bounded-copy", "medium", 0, 2),
    "RtlCopyMemory": ("bounded-copy", "medium", 0, 2), "RtlMoveMemory": ("bounded-copy", "medium", 0, 2),
    "read": ("bounded-input", "medium", 1, 2), "recv": ("bounded-input", "medium", 1, 2),
    "fread": ("bounded-input", "medium", 0, None), "fgets": ("bounded-input", "medium", 0, 1),
    "ReadFile": ("bounded-input", "medium", 1, 2),
}
EXEC_SINKS = {"system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve", "WinExec", "ShellExecuteA",
              "ShellExecuteW", "CreateProcessA", "CreateProcessW", "_wsystem", "ShellExecuteExA"}
FORMAT_SINKS = {"printf": 0, "fprintf": 1, "sprintf": 1, "snprintf": 2, "syslog": 1, "vprintf": 0, "vsprintf": 1,
                "wsprintfA": 1, "dprintf": 1, "printf_s": 0}
ALLOC_SINKS = {"malloc": 0, "calloc": None, "realloc": 1, "HeapAlloc": 2, "VirtualAlloc": 1, "LocalAlloc": 1,
               "GlobalAlloc": 1, "alloca": 0}
SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "private key material", "high"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id", "high"),
    (re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*\S{4,}"), "hard-coded credential pattern", "medium"),
    (re.compile(r"(?i)\bhttps?://[^\s/]*:[^\s/@]+@"), "URL with embedded credentials", "high"),
    (re.compile(r"(?i)\bhttp://(?!localhost|127\.)[\w.-]+"), "cleartext HTTP URL", "low"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b"), "hard-coded IP:port endpoint", "low"),
]


def _fid(*parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:12]


def _name_of(c: dict) -> str:
    n = c.get("name") or ""
    return n.replace("__imp_", "").lstrip("_") if n else ""


def _norm(n: str) -> str:
    return re.sub(r"(?:_chk|_s)$", "", n.lstrip("_")) if n else n


def _const_str(db: Database, e) -> Optional[str]:
    if isinstance(e, Const):
        s = db.strings.get(e.v)
        if s is not None:
            return s.text
    if isinstance(e, Un) and e.op == "&" and isinstance(e.a, Var):
        return None
    return None


def _stack_target(e):
    """Return the stack object name when `e` is &var / &var + offset."""
    if isinstance(e, Un) and e.op == "&" and isinstance(e.a, Var):
        return e.a.name
    if isinstance(e, Bin) and e.op == "+" and isinstance(e.a, Un) and e.a.op == "&" and isinstance(e.a.a, Var):
        return e.a.a.name
    return None


def scan(proj, max_functions: int = 5000) -> List[dict]:
    from .decompiler import decompile
    db = proj.db
    findings: List[dict] = []

    def add(sev, cat, title, addr, func, evidence, conf="medium", fix=""):
        fid = _fid(cat, title, addr)
        f = {"id": fid, "severity": sev, "category": cat, "title": title, "address": addr,
             "function": func, "evidence": evidence, "confidence": conf, "remediation": fix,
             "status": "new", "note": ""}
        t = db.triage.get(fid)
        if t:
            f["status"], f["note"] = t.get("status", "new"), t.get("note", "")
        findings.append(f)

    # ---- mitigations
    findings.extend(_mitigations(proj))
    # ---- hard-coded secrets
    for a, s in db.strings.items():
        for rx, label, sev in SECRET_PATTERNS:
            if rx.search(s.text):
                fn = _first_user(db, a)
                add(sev, "secrets", f"{label}", a, fn, [f"string at {a:#x}: {s.text[:80]!r}"], "medium",
                    "Remove embedded secrets; load them from a protected store at runtime.")
    # ---- call-site analysis
    sinks = set(COPY_SINKS) | EXEC_SINKS | set(FORMAT_SINKS) | set(ALLOC_SINKS)
    interesting = _functions_calling(db, sinks)
    for fa in sorted(interesting)[:max_functions]:
        try:
            pc = decompile(db, fa)
        except Exception:
            continue
        fname = db.display_name(fa)
        for c in pc.calls:
            name = _norm(_name_of(c))
            args = c["args"]
            if name in COPY_SINKS:
                cat, sev, di, si = COPY_SINKS[name]
                dst = args[di] if di < len(args) else None
                st = _stack_target(dst) if dst is not None else None
                bufsz = pc.stack_buffers.get(st) if st else None
                if si is not None and si < len(args):
                    n = args[si]
                    if isinstance(n, Const) and bufsz is not None and n.v > bufsz:
                        add("critical", "stack-overflow", f"{name}: constant length {n.v} exceeds stack buffer ({bufsz} bytes)",
                            c["addr"], fname, [f"dest={fmt(dst)}", f"len={fmt(n)}", f"estimated buffer size={bufsz}"], "high",
                            "Bound the copy length by the destination size.")
                        continue
                    if not isinstance(n, Const) and st:
                        add("medium", "bounded-copy", f"{name}: variable length into stack buffer {st}", c["addr"], fname,
                            [f"dest={fmt(dst)}", f"len={fmt(n)}", f"estimated buffer size={bufsz}"], "low",
                            "Verify the length is validated against the buffer size before the copy.")
                        continue
                if si is None:
                    src = args[1] if len(args) > 1 else None
                    lit = _const_str(db, src) if src is not None else None
                    if lit is not None and bufsz is not None and len(lit) + 1 > bufsz:
                        add("critical", "stack-overflow", f"{name}: literal of {len(lit) + 1} bytes into {bufsz}-byte stack buffer",
                            c["addr"], fname, [f"dest={fmt(dst)}", f"src={lit[:60]!r}"], "high", "Use a bounded copy.")
                    elif lit is None:
                        add(sev, cat, f"{name}: unbounded copy of non-constant data" + (f" into stack buffer {st}" if st else ""),
                            c["addr"], fname, [f"call: {name}({', '.join(fmt(a) for a in args)})"],
                            "medium" if st else "low", f"Replace {name} with a length-checked alternative.")
                elif name in ("gets",):
                    add("critical", cat, "gets() can never be used safely", c["addr"], fname, ["gets call"], "high", "Use fgets.")
            if name in EXEC_SINKS:
                cmd = args[0] if args else None
                if name in ("CreateProcessA", "CreateProcessW"):
                    cmd = args[1] if len(args) > 1 and not (isinstance(args[1], Const) and args[1].v == 0) else args[0] if args else None
                if cmd is not None and _const_str(db, cmd) is None and not (isinstance(cmd, Const) and cmd.v == 0):
                    add("high", "command-injection", f"{name}: non-constant command", c["addr"], fname,
                        [f"call: {name}({', '.join(fmt(a) for a in args)})"], "medium",
                        "Avoid shell execution; pass argv arrays and validate inputs.")
                else:
                    add("info", "command-exec", f"{name}: executes external command", c["addr"], fname,
                        [f"command={_const_str(db, cmd)!r}" if cmd is not None else "command=?"], "high", "")
            if name in FORMAT_SINKS:
                i = FORMAT_SINKS[name]
                if i < len(args) and _const_str(db, args[i]) is None and not isinstance(args[i], Const):
                    add("high", "format-string", f"{name}: non-constant format string", c["addr"], fname,
                        [f"format argument={fmt(args[i])}"], "medium", "Use a constant format and pass data as arguments.")
            if name in ALLOC_SINKS:
                i = ALLOC_SINKS[name]
                sz = args[i] if i is not None and i < len(args) else None
                if sz is not None and any(isinstance(x, Bin) and x.op in ("*", "<<") for x in walk(sz)) and \
                        any(isinstance(x, Var) for x in walk(sz)):
                    add("medium", "integer-overflow", f"{name}: size computed by multiplication of variables", c["addr"], fname,
                        [f"size={fmt(sz)}"], "low", "Check for overflow before allocation (use calloc or checked multiply).")
    # ---- crypto
    from .crypto import find_crypto_constants
    for hit in find_crypto_constants(db):
        sev = "medium" if hit["name"] in ("MD5", "SHA1", "DES", "RC4", "CRC32") and hit["weak"] else "info"
        add(sev, "crypto", f"{hit['name']} constants present", hit["addr"], _first_user(db, hit["addr"], True),
            [f"{hit['detail']}"], "medium",
            "Prefer modern algorithms (SHA-256+, AES-GCM, ChaCha20-Poly1305)." if hit["weak"] else "")
    findings.sort(key=lambda f: (-SEV[f["severity"]], f["address"] or 0))
    return findings


def _functions_calling(db: Database, names) -> List[int]:
    wanted = set()
    for n in names:
        wanted.update({n, "_" + n, "__imp_" + n, n + "_chk", "__" + n + "_chk", n + "_s"})
    out = set()
    for addr, nm in db.names.items():
        base = nm
        if base in wanted or base.lstrip("_") in names:
            targets = {addr}
            f = db.functions.get(addr)
            for fr, k in db.xrefs_to.get(addr, ()):
                ff = db.function_at(fr)
                if ff:
                    out.add(ff.start)
            if f is not None:
                for fr, k in db.xrefs_to.get(addr, ()):
                    pass
    # thunks: callers of thunk functions named after the import
    for a, f in db.functions.items():
        if f.thunk_target is not None or "thunk" in f.flags:
            nm = db.names.get(a, "")
            if nm.lstrip("_") in names:
                for fr, k in db.xrefs_to.get(a, ()):
                    ff = db.function_at(fr)
                    if ff:
                        out.add(ff.start)
    return list(out)


def _first_user(db: Database, addr: int, code_ref: bool = False) -> Optional[str]:
    for fr, k in db.xrefs_to.get(addr, ()):
        f = db.function_at(fr)
        if f:
            return db.display_name(f.start)
    f = db.function_at(addr)
    return db.display_name(f.start) if f else None


def _mitigations(proj) -> List[dict]:
    img, db = proj.image, proj.db
    out = []
    info = img.info
    def add(sev, title, ev):
        fid = _fid("mitigation", title)
        f = {"id": fid, "severity": sev, "category": "hardening", "title": title, "address": None, "function": None,
             "evidence": ev, "confidence": "high", "remediation": "Enable the corresponding compiler/linker hardening option.",
             "status": "new", "note": ""}
        t = db.triage.get(fid)
        if t:
            f["status"], f["note"] = t.get("status", "new"), t.get("note", "")
        out.append(f)
    if img.fmt.startswith("PE"):
        dc = info.get("dll_characteristics", 0)
        if not dc & 0x40:
            add("medium", "ASLR (DYNAMIC_BASE) disabled", [f"DllCharacteristics={dc:#x}"])
        if not dc & 0x100:
            add("medium", "DEP (NX_COMPAT) disabled", [f"DllCharacteristics={dc:#x}"])
        if not dc & 0x4000:
            add("low", "Control Flow Guard not enabled", [f"DllCharacteristics={dc:#x}"])
        if dc & 0x400 == 0 and False:
            pass
        names = {i.name for i in img.imports}
        if "__security_check_cookie" not in names and not any(n and "security_cookie" in n for n in db.names.values()):
            add("low", "No stack cookie (/GS) markers found", ["no __security_cookie symbol"])
    elif img.fmt.startswith("ELF"):
        names = {i.name for i in img.imports} | {s.name for s in img.symbols}
        if "__stack_chk_fail" not in names:
            add("medium", "No stack protector (__stack_chk_fail not referenced)", [])
        if img.info.get("type") == "ET_EXEC":
            add("low", "Not position independent (ET_EXEC)", [])
        if not any(s.executable is False and "w" in s.perms and False for s in img.segments):
            pass
        for s in img.segments:
            if s.executable and "w" in s.perms:
                add("high", f"Segment {s.name} is writable and executable", [f"{s.start:#x}-{s.end:#x} perms={s.perms}"])
    return out


def set_status(proj, finding_id: str, status: str, note: str = "", user: str = "") -> dict:
    if status not in ("new", "confirmed", "false-positive", "fixed", "accepted-risk", "needs-info"):
        raise ValueError("invalid status")
    rec = {"status": status, "note": note, "user": user, "ts": time.time()}
    proj.db.triage[finding_id] = rec
    proj.db.journal("triage", finding=finding_id, data=rec)
    proj.db.audit.append({"ts": rec["ts"], "user": user, "op": f"triage {finding_id} -> {status}"})
    return rec
