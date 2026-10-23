"""Emulator-backed GDB stub: serves a Unicorn-emulated copy of the loaded image over the GDB Remote Serial Protocol.

Lets you debug code for architectures/OSes that cannot be run natively (firmware, shellcode, foreign ABIs) with any
RSP-capable client (including revkit's own GdbRemoteDebugger and gdb itself)."""
from __future__ import annotations

import socket
import threading
from typing import Dict, List, Optional, Set

from unicorn import (Uc, UC_ARCH_ARM64, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_32, UC_MODE_64, UC_MODE_ARM, UcError)
from unicorn import arm64_const as a64, x86_const as x

from .gdbremote import LAYOUTS, checksum
from ..emulate import HEAP_BASE, HEAP_SIZE, STACK_BASE, STACK_SIZE, UC_LOCK

X64_REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"] + [f"r{i}" for i in range(8, 16)] + ["rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"]


class EmuGdbStub:
    def __init__(self, proj, entry: Optional[int] = None, host: str = "127.0.0.1", port: int = 0):
        with UC_LOCK:
            a = proj.image.arch
            if a.name == "x86" and a.bits == 64:
                self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
                self.regs = X64_REGS
                self.layout = LAYOUTS["x86_64"]
                self.rid = lambda n: getattr(x, f"UC_X86_REG_{n.upper()}")
                self.pcreg = "rip"
            elif a.name == "arm64":
                self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
                self.regs = [n for n, _ in LAYOUTS["aarch64"]]
                self.layout = LAYOUTS["aarch64"]
                self.rid = lambda n: {"sp": a64.UC_ARM64_REG_SP, "pc": a64.UC_ARM64_REG_PC, "cpsr": a64.UC_ARM64_REG_NZCV}.get(
                    n, None) or getattr(a64, f"UC_ARM64_REG_{n.upper()}")
                self.pcreg = "pc"
            else:
                raise ValueError("emulator stub supports x86-64 and arm64")
            pg = 0x1000
            for s in proj.image.segments:
                lo, hi = s.start & ~(pg - 1), (s.end + pg - 1) & ~(pg - 1)
                try:
                    self.uc.mem_map(lo, hi - lo)
                except Exception:
                    pass
                self.uc.mem_write(s.start, bytes(s.data))
            self.uc.mem_map(STACK_BASE, STACK_SIZE)
            self.uc.mem_write(STACK_BASE, b"\0")
            sp = STACK_BASE + STACK_SIZE - 0x1000
            if a.name == "arm64":
                self.uc.reg_write(a64.UC_ARM64_REG_SP, sp)
            else:
                self.uc.reg_write(x.UC_X86_REG_RSP, sp)
            self.uc.reg_write(self.rid(self.pcreg), entry if entry is not None else proj.image.entry_points[0][0])
        self.bps: Set[int] = set()
        self.sock = socket.socket()
        self.sock.bind((host, port))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread: Optional[threading.Thread] = None
        self.running = True
        self.exited = False

    def start(self) -> int:
        self.thread = threading.Thread(target=self._serve, daemon=True, name="revkit-emu-stub")
        self.thread.start()
        return self.port

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        conn.settimeout(None)
        buf = b""
        noack = False
        while self.running:
            try:
                d = conn.recv(65536)
            except OSError:
                break
            if not d:
                break
            buf += d
            while True:
                if buf[:1] == b"\x03":
                    buf = buf[1:]
                    continue
                s = buf.find(b"$")
                e = buf.find(b"#", s + 1)
                if s < 0 or e < 0 or len(buf) < e + 3:
                    break
                payload = buf[s + 1:e].decode("latin1")
                buf = buf[e + 3:]
                if not noack:
                    conn.sendall(b"+")
                reply = self.handle(payload)
                if payload == "QStartNoAckMode":
                    noack = True
                if reply is None:
                    return
                data = reply.encode("latin1")
                conn.sendall(b"$" + data + b"#" + checksum(data))
                if payload == "k":
                    return
        conn.close()

    # ------------------------------------------------------------------ packet handling
    def handle(self, p: str) -> Optional[str]:
        uc = self.uc
        if p.startswith("qSupported"):
            return "PacketSize=4000;QStartNoAckMode+;swbreak+;vContSupported+"
        if p == "QStartNoAckMode":
            return "OK"
        if p == "vCont?":
            return "vCont;c;s"
        if p == "?":
            return "T05thread:01;"
        if p in ("Hg0", "Hc0", "Hg1", "Hc1", "Hc-1") or p.startswith(("Hg", "Hc")):
            return "OK"
        if p == "qfThreadInfo":
            return "m1"
        if p == "qsThreadInfo":
            return "l"
        if p == "qC":
            return "QC1"
        if p == "g":
            out = ""
            for n, sz in self.layout:
                try:
                    out += uc.reg_read(self.rid(n)).to_bytes(sz, "little", signed=False).hex() if True else ""
                except Exception:
                    out += "00" * sz
            return out
        if p.startswith("G"):
            raw, pos = p[1:], 0
            for n, sz in self.layout:
                chunk = raw[pos:pos + sz * 2]
                pos += sz * 2
                if len(chunk) == sz * 2:
                    try:
                        uc.reg_write(self.rid(n), int.from_bytes(bytes.fromhex(chunk), "little"))
                    except Exception:
                        pass
            return "OK"
        if p.startswith("P"):
            idx, val = p[1:].split("=")
            n, sz = self.layout[int(idx, 16)]
            uc.reg_write(self.rid(n), int.from_bytes(bytes.fromhex(val), "little"))
            return "OK"
        if p.startswith("m"):
            a, l = p[1:].split(",")
            try:
                return bytes(uc.mem_read(int(a, 16), int(l, 16))).hex()
            except UcError:
                return "E01"
        if p.startswith("M"):
            head, data = p[1:].split(":")
            a, l = head.split(",")
            try:
                uc.mem_write(int(a, 16), bytes.fromhex(data))
                return "OK"
            except UcError:
                return "E01"
        if p.startswith(("Z0", "Z1")):
            self.bps.add(int(p.split(",")[1], 16))
            return "OK"
        if p.startswith(("z0", "z1")):
            self.bps.discard(int(p.split(",")[1], 16))
            return "OK"
        if p.startswith(("Z", "z")):
            return ""
        if p in ("c", "vCont;c") or p.startswith("c"):
            return self._run(False)
        if p in ("s", "vCont;s") or p.startswith("s"):
            return self._run(True)
        if p == "D":
            return "OK"
        if p == "k":
            return None
        return ""

    def _pc(self) -> int:
        return self.uc.reg_read(self.rid(self.pcreg))

    def _run(self, single: bool) -> str:
        uc = self.uc
        if self.exited:
            return "W00"
        pc = self._pc()
        try:
            if single:
                uc.emu_start(pc, 0xFFFFFFFFFFFFFFF0, count=1)
                return "T05thread:01;"
            # run until a breakpoint address is reached (skipping a breakpoint at the start pc)
            stop = {"hit": False}

            def hook(uc_, addr, size, ud):
                if addr in self.bps and addr != pc:
                    stop["hit"] = True
                    uc_.emu_stop()
            h = uc.hook_add(UC_HOOK_CODE, hook)
            try:
                uc.emu_start(pc, 0xFFFFFFFFFFFFFFF0, count=50_000_000)
            finally:
                uc.hook_del(h)
            if stop["hit"]:
                return "T05thread:01;swbreak:;"
            self.exited = True
            return "W00"
        except UcError:
            self.exited = True
            return "T0bthread:01;"          # SIGSEGV-ish: emulation fault
