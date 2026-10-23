"""Evidence-linked function explanations.

`explain_function` builds a structured, deterministic summary from facts in the database (APIs called, strings referenced,
constants, control-flow shape, callers). Every statement lists the addresses that support it, so the analyst can verify it.
With `use_llm=True` and an ANTHROPIC_API_KEY (or `REVKIT_LLM_COMMAND`) the facts + decompiled code are sent to a model
to draft a prose explanation; the model's text is returned *separately* from the verified facts and clearly marked as
unverified. Nothing is sent anywhere unless `use_llm` is requested explicitly.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Dict, List, Optional

from . import graphs

CAPABILITIES = [
    ("file I/O", r"^(CreateFile|ReadFile|WriteFile|DeleteFile|CopyFile|MoveFile|FindFirstFile|fopen|fread|fwrite|open|read|write|unlink|rename|fclose|NtCreateFile)", "file"),
    ("networking", r"^(socket|connect|bind|listen|accept|send|recv|sendto|recvfrom|WSA|Internet|HttpSendRequest|URLDownload|getaddrinfo|gethostby|WinHttp|curl_)", "net"),
    ("process creation / execution", r"^(CreateProcess|ShellExecute|WinExec|system|popen|exec|fork|posix_spawn|NtCreateUserProcess|CreateRemoteThread)", "exec"),
    ("memory management", r"^(VirtualAlloc|VirtualProtect|HeapAlloc|malloc|calloc|realloc|free|mmap|mprotect|NtAllocateVirtualMemory|WriteProcessMemory|ReadProcessMemory)", "mem"),
    ("registry access", r"^(Reg(Open|Create|Query|Set|Delete|Close)|NtOpenKey|NtSetValueKey)", "reg"),
    ("cryptography", r"^(Crypt|BCrypt|NCrypt|EVP_|AES_|SHA\d*_|MD5|RSA_|SSL_|CC_)", "crypto"),
    ("string handling", r"^(str|wcs|mem|lstr|sprintf|snprintf|sscanf|MultiByteToWideChar|WideCharToMultiByte)", "string"),
    ("threading / synchronisation", r"^(CreateThread|pthread_|WaitFor|Enter|Leave|InitializeCriticalSection|CreateMutex|CreateEvent|Sleep)", "thread"),
    ("anti-debugging / environment checks", r"^(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|ptrace|OutputDebugString|GetTickCount|QueryPerformanceCounter|rdtsc)", "antidbg"),
    ("dynamic code loading", r"^(LoadLibrary|GetProcAddress|dlopen|dlsym|LdrLoadDll|LdrGetProcedureAddress)", "dyn"),
    ("UI", r"^(MessageBox|CreateWindow|DialogBox|GetMessage|DispatchMessage|SendMessage|DefWindowProc|ShowWindow)", "ui"),
]


def _callee_names(db, fa: int) -> List[tuple]:
    out = []
    f = db.functions[fa]
    for b in f.blocks.values():
        for ia in b.insns:
            for to, k in db.xrefs_from.get(ia, ()):
                if k == "call":
                    imp = db.import_at(to)
                    nm = imp.display if imp is not None else db.display_name(to)
                    out.append((ia, nm, to))
    return out


def explain_function(proj, fa: int, use_llm: bool = False) -> dict:
    db = proj.db
    f = db.functions[fa]
    calls = _callee_names(db, fa)
    caps: Dict[str, List[dict]] = {}
    for ia, nm, to in calls:
        bare = nm.replace("__imp_", "").lstrip("_")
        for label, rx, key in CAPABILITIES:
            if re.match(rx, bare):
                caps.setdefault(label, []).append({"addr": ia, "call": nm})
    strings = []
    consts = []
    for b in f.blocks.values():
        for ia in b.insns:
            for kind, a in (db.insn(ia).refs if db.insn(ia) else ()):
                s = db.strings.get(a)
                if s is not None:
                    strings.append({"addr": ia, "string_addr": a, "text": s.text[:120]})
            ins = db.insn(ia)
            if ins:
                for v in ins.imms:
                    if v > 0xFFFF and not db.image.is_mapped(v):
                        consts.append({"addr": ia, "value": hex(v)})
    loops = graphs.loops(f)
    sw = [a for a in db.switches if f.contains(a)]
    facts = {
        "function": db.display_name(fa), "address": fa, "size": f.size, "blocks": len(f.blocks),
        "cyclomatic_complexity": graphs.cyclomatic_complexity(f), "loops": len(loops), "switches": len(sw),
        "callers": [db.display_name(c) for c in db.callers(fa)][:12], "callees": sorted({nm for _, nm, _ in calls})[:30],
        "thunk": "thunk" in f.flags, "noreturn": fa in db.noreturn, "library": "library" in f.flags,
    }
    bullets: List[dict] = []
    if "thunk" in f.flags:
        bullets.append({"claim": f"Thunk: forwards directly to {db.display_name(f.thunk_target) if f.thunk_target else 'another function'}.",
                        "evidence": [fa]})
    for label, items in caps.items():
        bullets.append({"claim": f"Performs {label} via " + ", ".join(sorted({i['call'] for i in items})[:6]) + ".",
                        "evidence": [i["addr"] for i in items][:8]})
    if strings:
        bullets.append({"claim": "References strings: " + "; ".join(repr(s["text"][:50]) for s in strings[:5]) + ".",
                        "evidence": [s["addr"] for s in strings][:8]})
    if loops:
        bullets.append({"claim": f"Contains {len(loops)} loop(s) (natural loops detected from back edges).",
                        "evidence": [l["header"] for l in loops][:6]})
    if sw:
        bullets.append({"claim": f"Contains {len(sw)} jump-table switch(es) with " +
                        ", ".join(str(db.switches[a]['count']) for a in sw) + " case(s).", "evidence": sw})
    if consts:
        bullets.append({"claim": "Uses large immediate constants (possible keys, magic numbers or hashes): " +
                        ", ".join(c["value"] for c in consts[:5]) + ".", "evidence": [c["addr"] for c in consts][:8]})
    if fa in db.noreturn:
        bullets.append({"claim": "Never returns (terminates the process/thread or loops forever).", "evidence": [fa]})
    if not bullets:
        bullets.append({"claim": f"Plain computation: {len(f.blocks)} basic block(s), no recognisable API usage.", "evidence": [fa]})
    # one-line role inference
    role = _role(caps, f, db)
    result = {"summary": role, "facts": facts, "evidence_bullets": bullets, "verified": True,
              "note": "Statements are derived from static facts; addresses listed under 'evidence' support each claim."}
    if use_llm:
        result["llm"] = _llm_explain(proj, fa, facts, bullets)
    return result


def _role(caps, f, db) -> str:
    if not caps:
        return "Internal helper with no direct system-API usage."
    keys = sorted(caps, key=lambda k: -len(caps[k]))
    return "Likely role: " + " / ".join(keys[:3]) + " (inferred from API usage; confirm in the code)."


def _llm_explain(proj, fa: int, facts: dict, bullets: List[dict]) -> dict:
    try:
        code = proj.decompile_text(fa)[:12000]
    except Exception:
        code = "(decompilation unavailable)"
    prompt = ("You are assisting a reverse engineer. Explain what this function does in a short paragraph and list uncertainties. "
              "Only use the supplied facts and code; do not invent behaviour.\n\nFACTS:\n" + json.dumps(facts, indent=1) +
              "\n\nPSEUDOCODE:\n" + code)
    cmd = os.environ.get("REVKIT_LLM_COMMAND")
    if cmd:
        import subprocess
        p = subprocess.run(cmd, input=prompt, capture_output=True, text=True, shell=True, timeout=120)
        return {"provider": "command", "text": p.stdout.strip(), "unverified": True}
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return {"provider": None, "error": "set ANTHROPIC_API_KEY or REVKIT_LLM_COMMAND to enable LLM explanations",
                "unverified": True}
    body = json.dumps({"model": os.environ.get("REVKIT_LLM_MODEL", "claude-sonnet-5-5"), "max_tokens": 700,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers={
        "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            d = json.loads(r.read())
        return {"provider": "anthropic", "text": "".join(b.get("text", "") for b in d.get("content", [])), "unverified": True}
    except Exception as e:
        return {"provider": "anthropic", "error": str(e), "unverified": True}
