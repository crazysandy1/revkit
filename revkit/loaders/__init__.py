"""Loader registry with automatic format detection and manual override."""
from __future__ import annotations

import os
from typing import Optional

from ..image import ArchSpec, Image
from . import pe, elf, macho, raw as rawmod
from .raw import parse_arch

__all__ = ["load_file", "detect_format", "parse_arch", "LOADERS", "register_loader", "unregister_loader"]

# Custom loaders registered by plugins/SDK users: name -> (sniff(data, path) -> bool, load(path, data, **kw) -> Image)
_CUSTOM = {}


def register_loader(name: str, sniff, load) -> None:
    """Add a loader. `sniff(data: bytes, path: str) -> bool` decides whether it handles a file; `load(path, data, **kw)`
    returns an `Image` (see revkit.image). Custom loaders are tried before the built-in ones."""
    _CUSTOM[name] = (sniff, load)


def unregister_loader(name: str) -> None:
    _CUSTOM.pop(name, None)

LOADERS = {
    "pe": pe, "elf": elf, "macho": macho,
}


def detect_format(data: bytes, path: str = "") -> str:
    for name, (sniff, _) in _CUSTOM.items():
        try:
            if sniff(data, path):
                return name
        except Exception:
            continue
    if pe.sniff(data):
        return "pe"
    if elf.sniff(data):
        return "elf"
    if macho.sniff(data):
        return "macho"
    low = path.lower()
    if low.endswith((".hex", ".ihex")) and data[:1] == b":":
        return "ihex"
    if data[:1] == b"S" and low.endswith((".srec", ".s19", ".s28", ".s37", ".mot")):
        return "srec"
    if low.endswith(".com"):
        return "com"
    return "raw"


def load_file(path: str, fmt: Optional[str] = None, arch: Optional[str] = None, base: int = 0,
              entry: Optional[int] = None, slice_cpu: Optional[int] = None, unpack: bool = False) -> Image:
    img = _load_file(path, fmt, arch, base, entry, slice_cpu)
    if unpack:
        from ..emulate import unpack_image
        img.unpack_result = unpack_image(img)
    return img


def _load_file(path: str, fmt: Optional[str] = None, arch: Optional[str] = None, base: int = 0,
               entry: Optional[int] = None, slice_cpu: Optional[int] = None) -> Image:
    """Load `path`. `fmt` forces a loader ("pe","elf","macho","raw","com","ihex","srec").

    For headerless inputs the caller must supply `arch` (and usually `base`/`entry`)."""
    with open(path, "rb") as f:
        data = f.read()
    fmt = fmt or detect_format(data, path)
    if fmt in _CUSTOM:
        return _CUSTOM[fmt][1](path, data, arch=arch, base=base, entry=entry)
    if fmt == "pe":
        return pe.load(path, data)
    if fmt == "elf":
        return elf.load(path, data)
    if fmt == "macho":
        return macho.load(path, data, slice_cpu)
    if fmt == "com":
        return rawmod.load_com(path, data)
    if fmt in ("ihex", "srec"):
        if not arch:
            raise ValueError(f"{fmt} requires --arch")
        a = parse_arch(arch)
        return (rawmod.load_ihex if fmt == "ihex" else rawmod.load_srec)(path, data, a)
    if fmt == "raw":
        if not arch:
            raise ValueError(
                "unrecognised file format; supply --arch (and --base/--entry) to load it as a raw binary")
        return rawmod.load_raw(path, data, parse_arch(arch), base, entry)
    raise ValueError(f"unknown format {fmt!r}")
