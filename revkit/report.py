"""Report generation (markdown / html / json) and data exporters (asm, csv, map, rk/python scripts, C headers)."""
from __future__ import annotations

import csv
import html
import io
import json
import time
from collections import Counter
from typing import Dict, List

from . import graphs
from .explain import CAPABILITIES
import re


def _collect(proj, with_vulns: bool = True) -> dict:
    db, img = proj.db, proj.image
    info = proj.info()
    funcs = proj.functions()
    top = sorted(funcs, key=lambda f: -f["complexity"])[:15]
    imports_by_mod: Dict[str, List[str]] = {}
    for i in img.imports:
        imports_by_mod.setdefault(i.module or "(unknown)", []).append(i.display)
    caps: Dict[str, List[str]] = {}
    for i in img.imports:
        bare = i.display.lstrip("_")
        for label, rx, _ in CAPABILITIES:
            if re.match(rx, bare):
                caps.setdefault(label, []).append(i.display)
    data = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "info": info, "segments": proj.segments(),
        "function_count": len(funcs), "top_complex": top, "imports": imports_by_mod, "capabilities": caps,
        "exports": proj.exports()[:200], "strings": proj.strings(min_len=6)[:200],
        "user_names": [n for n in proj.names() if n["user"]],
        "comments": [{"addr": a, "text": t} for a, t in sorted(db.comments.items())],
        "bookmarks": [{"slot": s, "addr": a, "desc": d} for s, (a, d) in sorted(db.bookmarks.items())],
        "patches": proj.patches(), "packing": proj.packer_report(),
    }
    if with_vulns:
        data["findings"] = proj.triage()
    from .crypto import find_crypto_constants
    data["crypto"] = find_crypto_constants(db)[:50]
    return data


def build_report(proj, fmt: str = "markdown") -> str:
    d = _collect(proj)
    if fmt == "json":
        return json.dumps(d, indent=2, default=str)
    md = _markdown(d)
    if fmt == "markdown":
        return md
    if fmt == "html":
        return _html(d, md)
    raise ValueError("fmt must be markdown, html or json")


def _markdown(d: dict) -> str:
    i = d["info"]
    L: List[str] = []
    L.append(f"# Analysis report: {i['path'].replace(chr(92), '/').split('/')[-1]}\n")
    L.append(f"_Generated {d['generated']} by revkit._\n")
    L.append("## Sample\n")
    L.append(f"| Field | Value |\n|---|---|\n| SHA-256 | `{i['sha256']}` |\n| MD5 | `{i['md5']}` |\n| Size | {i['size']} bytes |\n"
             f"| Format | {i['format']} |\n| Architecture | {i['arch_key']} |\n| Image base | `{i['imagebase']:#x}` |\n"
             f"| Functions | {i['functions']} |\n| Instructions | {i['instructions']} |\n| Strings | {i['strings']} |")
    if i.get("compiler"):
        L.append(f"\nCompiler comment: `{i['compiler']}`")
    L.append("\n## Segments\n")
    L.append("| Name | Start | Size | Perms | Entropy |\n|---|---|---|---|---|")
    ent = {s["name"]: s["entropy"] for s in d["packing"]["sections"]}
    for s in d["segments"]:
        L.append(f"| {s['name']} | `{s['start']:#x}` | {s['size']:#x} | {s['perms']} | {ent.get(s['name'], '')} |")
    L.append(f"\n**Packing verdict:** {d['packing']['verdict']}")
    for f in d["packing"]["findings"]:
        L.append(f"- ({f['severity']}) {f['title']} — {f['detail']}")
    L.append("\n## Capabilities inferred from imports\n")
    if d["capabilities"]:
        for k, v in sorted(d["capabilities"].items()):
            L.append(f"- **{k}**: {', '.join(sorted(set(v))[:12])}")
    else:
        L.append("_No known capability APIs imported._")
    L.append("\n## Imports\n")
    for mod, fns in sorted(d["imports"].items()):
        L.append(f"- `{mod}` ({len(fns)}): {', '.join(sorted(fns)[:15])}{' …' if len(fns) > 15 else ''}")
    if d.get("crypto"):
        L.append("\n## Cryptographic constants\n")
        for c in d["crypto"][:20]:
            L.append(f"- {c['name']} — {c['detail']} at `{c['addr']:#x}`")
    L.append("\n## Most complex functions\n")
    L.append("| Function | Address | Blocks | Complexity | Callers | Callees |\n|---|---|---|---|---|---|")
    for f in d["top_complex"]:
        L.append(f"| {f['name']} | `{f['addr']:#x}` | {f['blocks']} | {f['complexity']} | {f['callers']} | {f['callees']} |")
    if "findings" in d:
        L.append("\n## Findings (heuristic, for analyst review)\n")
        if not d["findings"]:
            L.append("_No findings._")
        for f in d["findings"][:100]:
            loc = f"`{f['address']:#x}`" if f.get("address") is not None else "—"
            L.append(f"- **[{f['severity'].upper()}]** {f['title']} ({f['category']}, confidence {f['confidence']}, "
                     f"status {f['status']}) at {loc} in {f.get('function') or '—'}")
            for ev in f["evidence"][:3]:
                L.append(f"    - evidence: {ev}")
    if d["user_names"] or d["comments"] or d["bookmarks"]:
        L.append("\n## Analyst annotations\n")
        for n in d["user_names"][:100]:
            L.append(f"- `{n['addr']:#x}` renamed **{n['name']}**")
        for c in d["comments"][:100]:
            L.append(f"- `{c['addr']:#x}`: {c['text']}")
        for b in d["bookmarks"]:
            L.append(f"- bookmark {b['slot']}: `{b['addr']:#x}` {b['desc']}")
    if d["patches"]:
        L.append("\n## Patches applied to the working copy\n")
        for p in d["patches"]:
            L.append(f"- `{p['addr']:#x}`: `{p['original']}` → `{p['patched']}`")
    L.append("\n---\n_Static analysis report. Findings are heuristics and require verification._")
    return "\n".join(L)


def _html(d: dict, md: str) -> str:
    body = []
    in_table = False
    for line in md.splitlines():
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            if not in_table:
                body.append("<table>")
                in_table = True
                body.append("<tr>" + "".join(f"<th>{html.escape(c)}</th>" for c in cells) + "</tr>")
            else:
                body.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
            continue
        if in_table:
            body.append("</table>")
            in_table = False
        if line.startswith("# "):
            body.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.strip().startswith("- "):
            ind = (len(line) - len(line.lstrip())) // 4
            body.append(f"<div style='margin-left:{ind * 20}px'>• {_inline(line.strip()[2:])}</div>")
        elif line.strip():
            body.append(f"<p>{_inline(line)}</p>")
    if in_table:
        body.append("</table>")
    css = "body{font-family:Segoe UI,Arial,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#1b1f23}" \
          "table{border-collapse:collapse;width:100%;margin:.5rem 0}td,th{border:1px solid #d0d7de;padding:4px 8px;text-align:left}" \
          "code{background:#f3f4f6;padding:1px 4px;border-radius:3px}h1,h2{border-bottom:1px solid #d0d7de;padding-bottom:.3rem}"
    return f"<!doctype html><html><head><meta charset='utf-8'><title>Analysis report</title><style>{css}</style></head><body>{''.join(body)}</body></html>"


def _inline(s: str) -> str:
    s = html.escape(s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"_([^_]+)_", r"<i>\1</i>", s)
    return s


# ------------------------------------------------------------------ exporters
def export_functions_csv(proj) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["address", "name", "size", "blocks", "complexity", "callers", "callees", "flags"])
    for f in proj.functions():
        w.writerow([f"{f['addr']:#x}", f["name"], f["size"], f["blocks"], f["complexity"], f["callers"], f["callees"], " ".join(f["flags"])])
    return out.getvalue()


def export_map(proj) -> str:
    db = proj.db
    lines = [f"; MAP file generated by revkit for {proj.image.path}"]
    for s in proj.image.segments:
        lines.append(f"; segment {s.name} {s.start:#x}-{s.end:#x} {s.perms}")
    for a in sorted(set(db.names) | set(db.functions)):
        lines.append(f"{a:016X}  {db.display_name(a)}")
    return "\n".join(lines)


def export_names_script(proj) -> str:
    """Names script restoring names, comments, and function boundaries."""
    db = proj.db
    L = ["// names script generated by revkit", "static main() {"]
    for a, n in sorted(db.names.items()):
        if db.name_user.get(a):
            L.append(f'  set_name({a:#x}, "{n}", SN_CHECK);')
    for a, c in sorted(db.comments.items()):
        L.append(f'  set_cmt({a:#x}, "{c.replace(chr(34), chr(39))}", 0);')
    for a, c in sorted(db.rep_comments.items()):
        L.append(f'  set_cmt({a:#x}, "{c.replace(chr(34), chr(39))}", 1);')
    for a, f in sorted(db.functions.items()):
        L.append(f"  add_func({a:#x}, {f.end:#x});")
    L.append("}")
    return "\n".join(L)


def export_python_script(proj) -> str:
    """A revkit/revkit script reproducing the analyst's edits on a fresh database."""
    db = proj.db
    L = ["# generated by revkit: replays analyst annotations", "import rk"]
    for a, n in sorted(db.names.items()):
        if db.name_user.get(a):
            L.append(f"rk.set_name({a:#x}, {n!r})")
    for a, c in sorted(db.comments.items()):
        L.append(f"rk.set_cmt({a:#x}, {c!r}, 0)")
    for a, c in sorted(db.rep_comments.items()):
        L.append(f"rk.set_cmt({a:#x}, {c!r}, 1)")
    return "\n".join(L)


def export_c_header(proj) -> str:
    tm = proj.db.types
    L = ["/* types exported by revkit */"]
    for s in tm.user_sources:
        L.append(s)
    for name, st in tm.structs.items():
        if name.startswith("__anon") or not st.fields:
            continue
        if any(name in src for src in tm.user_sources):
            continue
    return "\n".join(L)


def export_json(proj) -> str:
    db = proj.db
    d = {"info": proj.info(), "segments": proj.segments(), "functions": proj.functions(), "names": proj.names(),
         "strings": proj.strings(), "imports": proj.imports(), "exports": proj.exports(),
         "comments": {hex(a): t for a, t in db.comments.items()},
         "xrefs": [{"from": f, "to": t, "kind": k} for f, lst in db.xrefs_from.items() for t, k in lst]}
    return json.dumps(d, indent=1, default=str)
