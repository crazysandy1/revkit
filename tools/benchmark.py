"""Benchmark analysis and decompilation throughput.  Usage: python tools/benchmark.py FILE [FILE...]"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from revkit.api import Project  # noqa: E402


def main(paths):
    print(f"{'file':44} {'size':>9} {'load+analyze s':>14} {'funcs':>6} {'insns':>8} {'insn/s':>8} {'decomp/100fn s':>14}")
    for f in paths:
        t = time.time()
        p = Project.load(f)
        ta = time.time() - t
        st = p.info()["stats"]
        funcs = sorted(p.db.functions)[:100]
        t = time.time()
        ok = 0
        for a in funcs:
            try:
                p.decompile_text(a)
                ok += 1
            except Exception:
                pass
        td = time.time() - t
        print(f"{os.path.basename(f)[:44]:44} {os.path.getsize(f):>9} {ta:>14.1f} {st['functions']:>6} {st['instructions']:>8} "
              f"{st['instructions'] / ta:>8.0f} {td:>10.1f} ({ok}/{len(funcs)})")


if __name__ == "__main__":
    main(sys.argv[1:])
