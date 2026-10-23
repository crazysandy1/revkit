"""Assembler front-end (Keystone) used for patching and for building test fixtures."""
from __future__ import annotations

import keystone as ks

from .image import ArchSpec


def _ks(spec: ArchSpec) -> ks.Ks:
    be = ks.KS_MODE_BIG_ENDIAN if spec.big_endian else ks.KS_MODE_LITTLE_ENDIAN
    n = spec.name
    if n == "x86":
        return ks.Ks(ks.KS_ARCH_X86, {16: ks.KS_MODE_16, 32: ks.KS_MODE_32, 64: ks.KS_MODE_64}[spec.bits])
    if n == "arm":
        return ks.Ks(ks.KS_ARCH_ARM, ks.KS_MODE_ARM | be)
    if n == "thumb":
        return ks.Ks(ks.KS_ARCH_ARM, ks.KS_MODE_THUMB | be)
    if n == "arm64":
        return ks.Ks(ks.KS_ARCH_ARM64, ks.KS_MODE_LITTLE_ENDIAN)
    if n == "mips":
        return ks.Ks(ks.KS_ARCH_MIPS, (ks.KS_MODE_MIPS64 if spec.bits == 64 else ks.KS_MODE_MIPS32) | be)
    if n == "ppc":
        return ks.Ks(ks.KS_ARCH_PPC, (ks.KS_MODE_PPC64 if spec.bits == 64 else ks.KS_MODE_PPC32) | be)
    if n == "sparc":
        return ks.Ks(ks.KS_ARCH_SPARC, ks.KS_MODE_SPARC32 | ks.KS_MODE_BIG_ENDIAN)
    raise ValueError(f"no assembler available for architecture {spec.name}")


def assemble(spec: ArchSpec, text: str, addr: int = 0) -> bytes:
    """Assemble one or more instructions (';' or newline separated) located at `addr`."""
    k = _ks(spec)
    try:
        enc, _ = k.asm(text, addr, as_bytes=True)
    except ks.KsError as e:
        raise ValueError(f"assembler error: {e}") from e
    if not enc:
        raise ValueError("assembler produced no output")
    return bytes(enc)
