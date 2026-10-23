"""Fallback for architectures without a lifter."""
from .decompile import DecompileError


def decompile_generic(db, f, ctx):
    raise DecompileError(f"decompiler does not support architecture {db.image.arch.name!r}")
