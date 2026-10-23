"""Headless batch analysis: many binaries, process pool, per-file databases, optional decompile dumps and reports."""
from __future__ import annotations

import concurrent.futures as cf
import glob
import os
import time
import traceback
from typing import Dict, List


def _expand(inputs: List[str]) -> List[str]:
    files: List[str] = []
    for i in inputs:
        if os.path.isdir(i):
            for root, _, names in os.walk(i):
                files += [os.path.join(root, n) for n in names]
        elif any(c in i for c in "*?["):
            files += glob.glob(i)
        else:
            files.append(i)
    return sorted(dict.fromkeys(f for f in files if os.path.isfile(f)))


def _job(path: str, outdir: str, decompile: bool, report: bool) -> Dict:
    from .api import Project
    t = time.time()
    res: Dict = {"input": path, "ok": False}
    try:
        p = Project.load(path)
        base = os.path.join(outdir, os.path.basename(path))
        res["database"] = p.save(base + ".rkdb")
        res["sha256"] = p.image.sha256
        res["functions"] = len(p.db.functions)
        res["instructions"] = len(p.db.insns)
        res["strings"] = len(p.db.strings)
        if decompile:
            ok = fail = 0
            with open(base + ".c", "w", encoding="utf8") as f:
                for a in sorted(p.db.functions):
                    try:
                        f.write(f"// {p.db.display_name(a)} @ {a:#x}\n{p.decompile_text(a)}\n\n")
                        ok += 1
                    except Exception as e:
                        f.write(f"// {p.db.display_name(a)} @ {a:#x}: decompilation failed ({e})\n\n")
                        fail += 1
            res["decompiled"] = ok
            res["decompile_failures"] = fail
        if report:
            open(base + ".report.md", "w", encoding="utf8").write(p.report("markdown"))
        res["ok"] = True
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
        res["trace"] = traceback.format_exc()[-1500:]
    res["seconds"] = round(time.time() - t, 2)
    return res


def run_batch(inputs: List[str], outdir: str, jobs: int = 2, decompile: bool = False, report: bool = False,
              timeout: int = 3600) -> Dict:
    os.makedirs(outdir, exist_ok=True)
    files = _expand(inputs)
    results: List[Dict] = []
    if jobs <= 1 or len(files) <= 1:
        results = [_job(f, outdir, decompile, report) for f in files]
    else:
        with cf.ProcessPoolExecutor(max_workers=jobs) as ex:
            futs = {ex.submit(_job, f, outdir, decompile, report): f for f in files}
            for fut, f in futs.items():
                try:
                    results.append(fut.result(timeout=timeout))
                except Exception as e:
                    results.append({"input": f, "ok": False, "error": f"{type(e).__name__}: {e}"})
    results.sort(key=lambda r: r["input"])
    return {"count": len(results), "ok": sum(r["ok"] for r in results), "results": results}
