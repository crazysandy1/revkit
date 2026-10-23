"""GDB Remote Serial Protocol client: debug any target that exposes a gdbserver-compatible stub
(gdbserver, QEMU -gdb, OpenOCD, lldb-server in gdb-remote mode, or revkit's own emulator stub)."""
from __future__ import annotations

import re
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

from .base import Breakpoint, DebugError, DebugEvent, DebugSession, Module

LAYOUTS = {
    "x86_64": [("rax", 8), ("rbx", 8), ("rcx", 8), ("rdx", 8), ("rsi", 8), ("rdi", 8), ("rbp", 8), ("rsp", 8)] +
              [(f"r{i}", 8) for i in range(8, 16)] + [("rip", 8), ("eflags", 4), ("cs", 4), ("ss", 4), ("ds", 4), ("es", 4),
                                                      ("fs", 4), ("gs", 4)],
    "i386": [(n, 4) for n in ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs")],
    "aarch64": [(f"x{i}", 8) for i in range(31)] + [("sp", 8), ("pc", 8), ("cpsr", 4)],
    "arm": [(f"r{i}", 4) for i in range(13)] + [("sp", 4), ("lr", 4), ("pc", 4)],
}


def checksum(data: bytes) -> bytes:
    return b"%02x" % (sum(data) & 0xFF)


class RspConnection:
    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        self.no_ack = False

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, payload: str):
        data = payload.encode("latin1")
        self.sock.sendall(b"$" + data + b"#" + checksum(data))
        if not self.no_ack:
            while True:
                c = self._read1()
                if c == b"+":
                    return
                if c == b"-":
                    self.sock.sendall(b"$" + data + b"#" + checksum(data))
                elif c == b"$":
                    self.buf = c + self.buf  # reply began before ack; keep it
                    return

    def _read1(self) -> bytes:
        if self.buf:
            c, self.buf = self.buf[:1], self.buf[1:]
            return c
        d = self.sock.recv(65536)
        if not d:
            raise DebugError("connection closed by the remote stub")
        self.buf = d[1:]
        return d[:1]

    def recv(self, timeout: Optional[float] = None) -> str:
        old = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            while True:
                c = self._read1()
                if c == b"$":
                    break
            data = b""
            while True:
                c = self._read1()
                if c == b"#":
                    break
                data += c
            cs = self._read1() + self._read1()
            if not self.no_ack:
                self.sock.sendall(b"+")
            return _unescape(data).decode("latin1")
        finally:
            self.sock.settimeout(old)

    def interrupt(self):
        self.sock.sendall(b"\x03")


def _unescape(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        c = data[i]
        if c == 0x7D and i + 1 < len(data):
            out.append(data[i + 1] ^ 0x20)
            i += 2
        elif c == 0x2A and out:              # run-length encoding
            n = data[i + 1] - 29
            out.extend(bytes([out[-1]]) * n)
            i += 2
        else:
            out.append(c)
            i += 1
    return bytes(out)


class GdbRemoteDebugger(DebugSession):
    def __init__(self, proj=None, host: str = "127.0.0.1", port: int = 1234, arch: Optional[str] = None, timeout: float = 10.0):
        super().__init__(proj)
        self.host, self.port, self.timeout = host, port, timeout
        self.conn: Optional[RspConnection] = None
        self.layout: List[Tuple[str, int]] = []
        self.arch_hint = arch
        self.cur_tid = 1
        self.features: Dict[str, str] = {}
        self._lock = threading.Lock()
        self.vcont = False

    # ------------------------------------------------------------------ session
    def connect(self) -> DebugEvent:
        self.conn = RspConnection(self.host, self.port, self.timeout)
        q = self._xfer("qSupported:multiprocess+;swbreak+;hwbreak+;vContSupported+;xmlRegisters=i386")
        for item in q.split(";"):
            if "=" in item:
                k, v = item.split("=", 1)
                self.features[k] = v
            else:
                self.features[item.rstrip("+-")] = item[-1] if item and item[-1] in "+-" else ""
        if "QStartNoAckMode" in q:
            if self._xfer("QStartNoAckMode") == "OK":
                self.conn.no_ack = True
        self.layout = self._discover_layout()
        self.bits = 8 * max(sz for _, sz in self.layout) if self.layout else 64
        self.arch = self.arch_hint or (self.proj.image.arch.name if self.proj else "")
        r = self._xfer("vCont?")
        self.vcont = r.startswith("vCont")
        stop = self._xfer("?")
        self.state = "stopped"
        ev = self._parse_stop(stop)
        self._after_connect()
        return ev

    launch = None   # remote targets are started by the stub; use connect()

    def attach(self, pid: int):
        raise DebugError("use connect() for remote debugging")

    def _after_connect(self):
        if self.proj is not None and self.main_base is None:
            self.main_base = self.proj.image.imagebase
            self.modules.append(Module(self.proj.image.path.replace("\\", "/").split("/")[-1], self.main_base,
                                       max(s.end for s in self.proj.image.segments) - self.main_base))

    def detach(self):
        try:
            self._xfer("D")
        finally:
            self.state = "exited"
            if self.conn:
                self.conn.close()

    def kill(self):
        try:
            self.conn.send("k")
        except Exception:
            pass
        self.state = "exited"
        if self.conn:
            self.conn.close()

    # ------------------------------------------------------------------ protocol helpers
    def _xfer(self, pkt: str) -> str:
        with self._lock:
            self.conn.send(pkt)
            return self.conn.recv()

    def _discover_layout(self) -> List[Tuple[str, int]]:
        if self.features.get("qXfer:features:read"):
            try:
                xml = self._read_xml("target.xml")
                regs = self._parse_tdesc(xml)
                if regs:
                    return regs
            except Exception:
                pass
        hint = self.arch_hint or (self.proj.image.arch.name if self.proj else "")
        bits = self.proj.image.arch.bits if self.proj else 64
        key = {"x86": "x86_64" if bits == 64 else "i386", "arm64": "aarch64", "aarch64": "aarch64", "arm": "arm"}.get(hint, "x86_64")
        return LAYOUTS.get(key, LAYOUTS["x86_64"])

    def _read_xml(self, annex: str) -> str:
        out, off = "", 0
        while True:
            r = self._xfer(f"qXfer:features:read:{annex}:{off:x},fff")
            if not r or r[0] not in "ml":
                raise DebugError("bad qXfer reply")
            out += r[1:]
            off += len(r) - 1
            if r[0] == "l":
                return out

    def _parse_tdesc(self, xml: str, depth: int = 0) -> List[Tuple[str, int]]:
        regs: List[Tuple[int, str, int]] = []
        nxt = 0
        for m in re.finditer(r"<(reg|xi:include)\b([^>]*)/?>", xml):
            attrs = dict(re.findall(r'(\w+)="([^"]*)"', m.group(2)))
            if m.group(1) == "xi:include" and depth < 4:
                sub = self._read_xml(attrs["href"])
                for n, sz in self._parse_tdesc(sub, depth + 1):
                    regs.append((nxt, n, sz))
                    nxt += 1
                continue
            num = int(attrs["regnum"]) if "regnum" in attrs else nxt
            regs.append((num, attrs["name"], int(attrs["bitsize"]) // 8))
            nxt = num + 1
        regs.sort()
        return [(n, sz) for _, n, sz in regs]

    def _parse_stop(self, r: str) -> DebugEvent:
        if not r:
            return DebugEvent("stopped", self.cur_tid)
        c = r[0]
        if c in "TS":
            sig = int(r[1:3], 16)
            info = {"signal": sig}
            tid = self.cur_tid
            for part in r[3:].split(";"):
                if part.startswith("thread:"):
                    t = part[7:].split(".")[-1]
                    tid = int(t, 16) if t not in ("-1", "") else tid
                    self.cur_tid = tid
                elif part in ("swbreak:", "hwbreak:") or part.startswith(("swbreak", "hwbreak")):
                    info["breakpoint"] = True
            pc = self._pc_quiet()
            kind = "step" if getattr(self, "_stepping", False) and sig == 5 else ("breakpoint" if sig == 5 else "signal")
            bp = next((b for b in self.breakpoints.values() if b.enabled and b.addr == pc), None)
            if bp is not None and kind != "step":
                kind = "breakpoint"
                info["id"] = bp.id
                bp.hits += 1
            return DebugEvent(kind, tid, pc, info)
        if c == "W":
            self.state = "exited"
            return DebugEvent("exit", 0, 0, {"code": int(r[1:3], 16)})
        if c == "X":
            self.state = "exited"
            return DebugEvent("exit", 0, 0, {"signal": int(r[1:3], 16)})
        if c == "O":
            return DebugEvent("output", 0, 0, {"text": bytes.fromhex(r[1:]).decode("latin1")})
        return DebugEvent("stopped", self.cur_tid, 0, {"raw": r})

    def _pc_quiet(self) -> int:
        try:
            return self.pc()
        except Exception:
            return 0

    # ------------------------------------------------------------------ execution
    def cont(self, timeout: Optional[float] = None) -> DebugEvent:
        self._stepping = False
        return self._resume("vCont;c" if self.vcont else "c", timeout)

    def step_into(self) -> DebugEvent:
        self._stepping = True
        return self._resume("vCont;s" if self.vcont else "s", 15)

    def _resume(self, pkt: str, timeout):
        with self._lock:
            self.state = "running"
            self.conn.send(pkt)
            deadline = None if timeout is None else time.time() + timeout
            while True:
                try:
                    r = self.conn.recv(0.5)
                except socket.timeout:
                    if deadline is not None and time.time() > deadline:
                        self.conn.interrupt()
                        deadline = None
                    continue
                if r.startswith("O"):
                    self._fire(self._parse_stop(r))
                    continue
                break
        ev = self._parse_stop(r)
        if ev.kind != "exit":
            self.state = "stopped"
        self._fire(ev)
        return ev

    def pause(self):
        self.conn.interrupt()

    # ------------------------------------------------------------------ breakpoints
    def add_breakpoint(self, addr: int, kind: str = "sw", size: int = 1, condition: str = "", temporary: bool = False) -> Breakpoint:
        z = {"sw": 0, "hw-exec": 1, "hw-write": 2, "hw-rw": 4}[kind]
        kindsz = size if kind != "sw" else (4 if self.layout and self.layout[0][0].startswith("x") and self.bits == 64 and self.arch == "arm64" else 1)
        r = self._xfer(f"Z{z},{addr:x},{kindsz:x}")
        if r != "OK":
            raise DebugError(f"stub refused breakpoint at {addr:#x}: {r or 'unsupported'}")
        bp = Breakpoint(self._next_bp, addr, kind, size, condition, True, 0, temporary, self.to_static(addr))
        self._next_bp += 1
        self.breakpoints[bp.id] = bp
        return bp

    def remove_breakpoint(self, bid: int):
        bp = self.breakpoints.pop(bid, None)
        if bp:
            z = {"sw": 0, "hw-exec": 1, "hw-write": 2, "hw-rw": 4}[bp.kind]
            self._xfer(f"z{z},{bp.addr:x},{bp.size if bp.kind != 'sw' else 1:x}")

    def set_breakpoint_enabled(self, bid: int, enabled: bool):
        bp = self.breakpoints[bid]
        if bp.enabled == enabled:
            return
        z = {"sw": 0, "hw-exec": 1, "hw-write": 2, "hw-rw": 4}[bp.kind]
        self._xfer(f"{'Z' if enabled else 'z'}{z},{bp.addr:x},{bp.size if bp.kind != 'sw' else 1:x}")
        bp.enabled = enabled

    # ------------------------------------------------------------------ state
    def registers(self, tid: Optional[int] = None) -> Dict[str, int]:
        r = self._xfer("g")
        if r.startswith("E"):
            raise DebugError(f"register read failed: {r}")
        out, pos = {}, 0
        for name, sz in self.layout:
            chunk = r[pos:pos + sz * 2]
            pos += sz * 2
            if len(chunk) < sz * 2:
                break
            if "x" in chunk:
                continue
            out[name] = int.from_bytes(bytes.fromhex(chunk), "little")
        return out

    def set_register(self, name: str, value: int, tid: Optional[int] = None):
        for i, (n, sz) in enumerate(self.layout):
            if n == name:
                r = self._xfer(f"P{i:x}={(value & ((1 << sz * 8) - 1)).to_bytes(sz, 'little').hex()}")
                if r != "OK":
                    raise DebugError(f"register write failed: {r}")
                return
        raise DebugError(f"unknown register {name}")

    def read_memory(self, addr: int, size: int) -> bytes:
        out = b""
        while size > 0:
            n = min(size, 0x800)
            r = self._xfer(f"m{addr:x},{n:x}")
            if r.startswith("E") or not r:
                raise DebugError(f"cannot read memory at {addr:#x}")
            out += bytes.fromhex(r)
            addr += n
            size -= n
        return out

    def write_memory(self, addr: int, data: bytes):
        r = self._xfer(f"M{addr:x},{len(data):x}:{data.hex()}")
        if r != "OK":
            raise DebugError(f"cannot write memory at {addr:#x}: {r}")

    def threads(self) -> List[dict]:
        out = []
        r = self._xfer("qfThreadInfo")
        while r.startswith("m"):
            for t in r[1:].split(","):
                out.append({"tid": int(t.split(".")[-1], 16), "current": int(t.split(".")[-1], 16) == self.cur_tid})
            r = self._xfer("qsThreadInfo")
        return out or [{"tid": self.cur_tid, "current": True}]

    def select_thread(self, tid: int):
        if self._xfer(f"Hg{tid:x}") != "OK":
            raise DebugError("thread selection failed")
        self.cur_tid = tid
