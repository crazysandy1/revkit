"""Mixed Boolean-Arithmetic (MBA) simplification.

Linear MBA expressions (sums of constant multiples of bitwise functions of the variables) are reduced exactly using
the truth-table method: the value on 0/1 inputs determines the coefficients over the conjunction basis, because a linear
MBA is bit-parallel. Candidate simplifications are enumerated by size and every result is *verified* against the input on
exhaustive small-width inputs and random 64-bit inputs before being returned. Non-linear expressions fall back to the
same candidate search (which is only accepted when verification passes); otherwise the input is returned unchanged.
"""
from __future__ import annotations

import ast
import itertools
import random
from typing import Dict, List, Optional, Tuple

MASK64 = (1 << 64) - 1


# ------------------------------------------------------------------ parsing / evaluation
def _parse(expr: str) -> ast.AST:
    return ast.parse(expr.replace("^^", "**"), mode="eval").body


def variables(expr: str) -> List[str]:
    return sorted({n.id for n in ast.walk(_parse(expr)) if isinstance(n, ast.Name)})


def evaluate(node: ast.AST, env: Dict[str, int], bits: int = 64) -> int:
    m = (1 << bits) - 1

    def ev(n):
        if isinstance(n, ast.Constant):
            return int(n.value) & m
        if isinstance(n, ast.Name):
            return env[n.id] & m
        if isinstance(n, ast.UnaryOp):
            v = ev(n.operand)
            if isinstance(n.op, ast.Invert):
                return ~v & m
            if isinstance(n.op, ast.USub):
                return -v & m
            if isinstance(n.op, ast.UAdd):
                return v
        if isinstance(n, ast.BinOp):
            a, b = ev(n.left), ev(n.right)
            op = n.op
            if isinstance(op, ast.Add):
                return (a + b) & m
            if isinstance(op, ast.Sub):
                return (a - b) & m
            if isinstance(op, ast.Mult):
                return (a * b) & m
            if isinstance(op, ast.BitAnd):
                return a & b
            if isinstance(op, ast.BitOr):
                return a | b
            if isinstance(op, ast.BitXor):
                return a ^ b
            if isinstance(op, ast.LShift):
                return (a << (b % bits)) & m
            if isinstance(op, ast.RShift):
                return a >> (b % bits)
        raise ValueError(f"unsupported syntax: {ast.dump(n)[:60]}")
    return ev(node)


# ------------------------------------------------------------------ truth-table linear MBA solver
def _signature(node, names: List[str], bits: int) -> List[int]:
    """Value of the expression with each variable fixed to 0 or to all-ones (bit-parallel truth table)."""
    m = (1 << bits) - 1
    sig = []
    for combo in itertools.product((0, 1), repeat=len(names)):
        env = {n: (m if v else 0) for n, v in zip(names, combo)}
        sig.append(evaluate(node, env, bits))
    return sig


def linear_coefficients(expr: str, bits: int = 64) -> Optional[Dict[Tuple[str, ...], int]]:
    """f = sum_S c_S * AND(S)  with AND(()) == -1.  Returns {S: signed c_S} (nonzero entries only)."""
    node = _parse(expr)
    names = variables(expr)
    k = len(names)
    if k == 0 or k > 6:
        return None
    m = (1 << bits) - 1
    sig = {}
    for i, combo in enumerate(itertools.product((0, 1), repeat=k)):
        sig[tuple(n for n, b in zip(names, combo) if b)] = _signature(node, names, bits)[i]
    coef: Dict[Tuple[str, ...], int] = {}
    for r in range(k + 1):
        for S in itertools.combinations(names, r):
            total = 0
            for q in range(r + 1):
                for T in itertools.combinations(S, q):
                    total += (-1) ** (r - q) * (-sig[T])
            coef[S] = total & m
    return {S: (c if c >> (bits - 1) == 0 else c - (1 << bits)) for S, c in coef.items() if c}


def _render_linear(coefs: Dict[Tuple[str, ...], int]) -> str:
    if not coefs:
        return "0"
    parts = []
    for S, c in sorted(coefs.items(), key=lambda kv: (len(kv[0]), kv[0])):
        if S == ():
            v = -c                              # constant term is c * (-1)
            parts.append(f"{'+' if v > 0 else '-'}{abs(v)}")
            continue
        term = "(" + "&".join(S) + ")" if len(S) > 1 else S[0]
        if c == 1:
            parts.append(f"+{term}")
        elif c == -1:
            parts.append(f"-{term}")
        else:
            parts.append(f"{'+' if c > 0 else '-'}{abs(c)}*{term}")
    out = "".join(parts)
    return out[1:] if out.startswith("+") else out


# ------------------------------------------------------------------ candidate search
def _candidates(names: List[str], max_ops: int):
    """Yield expression strings with increasing operator count."""
    leaves = list(names) + ["1", "-1", "2"]
    level = {0: list(dict.fromkeys(leaves))}
    ops = ["+", "-", "&", "|", "^", "*", "<<", ">>"]
    for n in range(1, max_ops + 1):
        out = []
        # unary
        for e in level.get(n - 1, []):
            out.append(f"~({e})" if not e.isidentifier() else f"~{e}")
            out.append(f"-({e})" if not e.isidentifier() else f"-{e}")
        # binary: sizes (i, n-1-i)
        for i in range(0, n):
            j = n - 1 - i
            for a in level.get(i, []):
                for b in level.get(j, []):
                    for op in ops:
                        if op in ("<<", ">>") and not b.lstrip("-").isdigit():
                            continue
                        out.append(f"({a}{op}{b})")
        level[n] = list(dict.fromkeys(out))
        for e in level[n]:
            yield e
        if len(level[n]) > 400000:
            break


def _equiv(a: ast.AST, b: ast.AST, names: List[str], bits: int = 64, samples: int = 3000) -> str:
    rng = random.Random(0xC0FFEE)
    if len(names) <= 2:
        for combo in itertools.product(range(256), repeat=len(names)):
            env = dict(zip(names, combo))
            if evaluate(a, env, 8) != evaluate(b, env, 8):
                return ""
    for _ in range(samples):
        env = {n: rng.getrandbits(bits) for n in names}
        for special in (0, MASK64):
            pass
        if evaluate(a, env, bits) != evaluate(b, env, bits):
            return ""
    edge = [0, 1, MASK64, 1 << 63, (1 << 63) - 1, 0xFF, 0xFFFF]
    for combo in itertools.product(edge, repeat=len(names)):
        env = dict(zip(names, combo))
        if evaluate(a, env, bits) != evaluate(b, env, bits):
            return ""
    return "exhaustive-8bit+random-64bit" if len(names) <= 2 else "random-64bit"


def simplify_mba(expr: str, bits: int = 64, max_ops: int = 4) -> dict:
    """Return {'input', 'output', 'verified', 'method', 'steps'}; `output` equals `input` when nothing simpler was found."""
    node = _parse(expr)
    names = variables(expr)
    res = {"input": expr, "output": expr, "verified": "", "method": "none", "names": names}
    if not names:
        v = evaluate(node, {}, bits)
        res.update(output=str(v), verified="constant-fold", method="constant")
        return res
    size = lambda e: sum(1 for n in ast.walk(_parse(e)) if isinstance(n, (ast.BinOp, ast.UnaryOp)))
    best = expr
    sig = _signature(node, names, bits) if len(names) <= 6 else None
    lin = linear_coefficients(expr, bits) if len(names) <= 6 else None
    if lin is not None:
        lin_expr = _render_linear(lin)
        try:
            ver = _equiv(node, _parse(lin_expr), names, bits)
        except Exception:
            ver = ""
        if ver and size(lin_expr) < size(best):
            best, res["method"], res["verified"] = lin_expr, "linear-MBA basis", ver
            res["steps"] = [f"linear coefficients: {lin}"]
    # smallest equivalent candidate by signature match then full verification
    if sig is not None and size(best) > 1:
        tried = 0
        for cand in _candidates(names, min(max_ops, max(1, size(best) - 1))):
            tried += 1
            if tried > 600000:
                break
            try:
                cn = _parse(cand)
                if _signature(cn, names, bits) != sig:
                    continue
                ver = _equiv(node, cn, names, bits)
            except Exception:
                continue
            if ver and size(cand) < size(best):
                best, res["method"], res["verified"] = cand, "candidate search", ver
                break
    # remove redundant outer parentheses
    while best.startswith("(") and best.endswith(")") and _balanced_inner(best):
        best = best[1:-1]
    res["output"] = best
    return res


def _balanced_inner(s: str) -> bool:
    depth = 0
    for i, ch in enumerate(s):
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0 and i < len(s) - 1:
            return False
    return True
