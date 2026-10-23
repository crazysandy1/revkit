"""Secure sample handling: a hash-addressed vault with provenance and a tamper-evident (hash-chained) audit log."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import time
from typing import Dict, List, Optional

from .plugins import config_dir

GENESIS = "0" * 64


def vault_dir() -> str:
    d = os.environ.get("REVKIT_VAULT") or os.path.join(config_dir(), "vault")
    os.makedirs(d, exist_ok=True)
    return d


def audit_path() -> str:
    return os.path.join(config_dir(), "audit.log")


def _last_hash(path: str) -> str:
    if not os.path.exists(path):
        return GENESIS
    last = GENESIS
    with open(path, "rb") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    last = json.loads(line)["hash"]
                except (ValueError, KeyError):
                    pass
    return last


def audit(action: str, **detail) -> dict:
    """Append a hash-chained audit record: each entry commits to the previous one, so edits or deletions are detectable."""
    path = audit_path()
    prev = _last_hash(path)
    rec = {"ts": time.time(), "user": os.environ.get("USERNAME") or os.environ.get("USER") or "?", "action": action,
           "detail": detail, "prev": prev}
    body = json.dumps(rec, sort_keys=True)
    rec["hash"] = hashlib.sha256((prev + body).encode()).hexdigest()
    with open(path, "a", encoding="utf8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def verify_audit(path: Optional[str] = None) -> dict:
    path = path or audit_path()
    prev, n = GENESIS, 0
    if not os.path.exists(path):
        return {"ok": True, "entries": 0}
    with open(path, encoding="utf8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            h = rec.pop("hash")
            if rec["prev"] != prev:
                return {"ok": False, "entries": n, "broken_at_line": i, "reason": "chain link mismatch"}
            if hashlib.sha256((prev + json.dumps(rec, sort_keys=True)).encode()).hexdigest() != h:
                return {"ok": False, "entries": n, "broken_at_line": i, "reason": "record content altered"}
            prev = h
            n += 1
    return {"ok": True, "entries": n, "head": prev}


def import_sample(path: str, source: str = "", notes: str = "", defang: bool = True) -> dict:
    """Copy `path` into the vault under its SHA-256, mark it read-only and record provenance. The original is untouched."""
    with open(path, "rb") as f:
        data = f.read()
    sha = hashlib.sha256(data).hexdigest()
    d = os.path.join(vault_dir(), sha)
    os.makedirs(d, exist_ok=True)
    dest = os.path.join(d, "sample.bin.defanged" if defang else "sample.bin")
    if not os.path.exists(dest):
        with open(dest, "wb") as f:
            f.write(data)
        os.chmod(dest, stat.S_IREAD)
    prov = {"sha256": sha, "md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(), "size": len(data),
            "original_name": os.path.basename(path), "source": source, "notes": notes, "imported": time.time(),
            "defanged": defang, "stored": dest}
    pf = os.path.join(d, "provenance.json")
    history = []
    if os.path.exists(pf):
        try:
            history = json.load(open(pf, encoding="utf8")).get("history", [])
        except ValueError:
            pass
    history.append({"ts": prov["imported"], "source": source, "notes": notes})
    prov["history"] = history
    with open(pf, "w", encoding="utf8") as f:
        json.dump(prov, f, indent=1)
    audit("sample-import", sha256=sha, name=prov["original_name"], source=source)
    return prov


def list_samples() -> List[dict]:
    out = []
    root = vault_dir()
    for sha in sorted(os.listdir(root)):
        pf = os.path.join(root, sha, "provenance.json")
        if os.path.exists(pf):
            try:
                out.append(json.load(open(pf, encoding="utf8")))
            except ValueError:
                pass
    return out


def export_sample(sha256: str, out_path: str) -> str:
    """Copy a vaulted sample out (e.g. into an analysis VM). Verifies the hash first; logged."""
    d = os.path.join(vault_dir(), sha256)
    src = next((os.path.join(d, n) for n in ("sample.bin", "sample.bin.defanged") if os.path.exists(os.path.join(d, n))), None)
    if src is None:
        raise FileNotFoundError(sha256)
    data = open(src, "rb").read()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError("vault integrity check failed: stored bytes no longer match the SHA-256")
    with open(out_path, "wb") as f:
        f.write(data)
    audit("sample-export", sha256=sha256, to=os.path.abspath(out_path))
    return out_path


def require_execution_permission(proj, action: str):
    """Running the sample on the host is refused unless the operator opted in (and it is logged)."""
    if not getattr(proj, "allow_execution", False):
        raise PermissionError(
            f"{action} would execute the sample on this machine. Re-run with --allow-exec (or set proj.allow_execution=True) "
            "only inside an isolated analysis VM/sandbox.")
    audit("execution-approved", sha256=proj.image.sha256, what=action)
