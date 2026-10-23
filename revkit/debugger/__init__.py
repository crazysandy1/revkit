"""Debugger facade: native debugging on Windows, remote debugging over GDB RSP, and an emulator-backed stub."""
from __future__ import annotations

import sys
from typing import Optional

from .base import Breakpoint, DebugError, DebugEvent, DebugSession, Module, safe_eval


def create_session(proj=None, backend: str = "auto", host: str = "127.0.0.1", port: int = 1234, arch: Optional[str] = None) -> DebugSession:
    """backend: 'native' (this OS), 'gdb' (remote stub at host:port), or 'auto' (native if supported)."""
    if backend == "gdb":
        from .gdbremote import GdbRemoteDebugger
        return GdbRemoteDebugger(proj, host, port, arch)
    if backend in ("auto", "native"):
        if sys.platform == "win32":
            from .win import WindowsDebugger
            return WindowsDebugger(proj)
        if backend == "native":
            raise DebugError("native debugging is implemented for Windows; on this OS use backend='gdb' with gdbserver")
    raise DebugError("no native debugger for this platform: start gdbserver and use backend='gdb'")


def start_emulator_stub(proj, entry: Optional[int] = None, host: str = "127.0.0.1", port: int = 0):
    from .stub import EmuGdbStub
    s = EmuGdbStub(proj, entry, host, port)
    s.start()
    return s
