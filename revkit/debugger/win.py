"""Native Windows debugger back-end built on the Win32 debugging API (ctypes). x64 targets (and WoW64 x86 targets)."""
from __future__ import annotations

import ctypes
import os
import queue
import sys
import threading
from ctypes import wintypes as wt
from typing import Dict, List, Optional

from .base import Breakpoint, DebugError, DebugEvent, DebugSession, Module

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("Windows only")

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

# ---- constants
DEBUG_PROCESS, DEBUG_ONLY_THIS_PROCESS, CREATE_NO_WINDOW, CREATE_NEW_CONSOLE = 0x1, 0x2, 0x08000000, 0x10
EXCEPTION_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, CREATE_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT, \
    EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, UNLOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT = range(1, 10)
DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED = 0x00010002, 0x80010001
EXC_BREAKPOINT, EXC_SINGLE_STEP, EXC_WOW64_BREAKPOINT, EXC_WOW64_SINGLE_STEP = 0x80000003, 0x80000004, 0x80000003, 0x4000001E
EXC_ACCESS_VIOLATION = 0xC0000005
CONTEXT_AMD64 = 0x100000
CONTEXT_CONTROL, CONTEXT_INTEGER, CONTEXT_SEGMENTS, CONTEXT_FLOATING, CONTEXT_DEBUG = 0x1, 0x2, 0x4, 0x8, 0x10
CONTEXT_ALL64 = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING | CONTEXT_DEBUG
CONTEXT_I386 = 0x10000
CONTEXT_ALL32 = CONTEXT_I386 | 0x1 | 0x2 | 0x4 | 0x10
PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x1F03FF
PAGE_EXECUTE_READWRITE = 0x40
TF = 0x100
MEM_COMMIT = 0x1000


class CONTEXT64(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64), ("P3Home", ctypes.c_uint64), ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
        ("ContextFlags", wt.DWORD), ("MxCsr", wt.DWORD),
        ("SegCs", wt.WORD), ("SegDs", wt.WORD), ("SegEs", wt.WORD), ("SegFs", wt.WORD), ("SegGs", wt.WORD), ("SegSs", wt.WORD),
        ("EFlags", wt.DWORD),
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64), ("Dr2", ctypes.c_uint64), ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64), ("Rdx", ctypes.c_uint64), ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64), ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64), ("R9", ctypes.c_uint64), ("R10", ctypes.c_uint64), ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64), ("R14", ctypes.c_uint64), ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("FltSave", ctypes.c_ubyte * 512),
        ("VectorRegister", ctypes.c_ubyte * (16 * 26)),
        ("VectorControl", ctypes.c_uint64), ("DebugControl", ctypes.c_uint64), ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64), ("LastExceptionToRip", ctypes.c_uint64), ("LastExceptionFromRip", ctypes.c_uint64),
    ]


class CONTEXT32(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", wt.DWORD),
        ("Dr0", wt.DWORD), ("Dr1", wt.DWORD), ("Dr2", wt.DWORD), ("Dr3", wt.DWORD), ("Dr6", wt.DWORD), ("Dr7", wt.DWORD),
        ("ControlWord", wt.DWORD), ("StatusWord", wt.DWORD), ("TagWord", wt.DWORD), ("ErrorOffset", wt.DWORD),
        ("ErrorSelector", wt.DWORD), ("DataOffset", wt.DWORD), ("DataSelector", wt.DWORD), ("RegisterArea", ctypes.c_ubyte * 80),
        ("Cr0NpxState", wt.DWORD),
        ("SegGs", wt.DWORD), ("SegFs", wt.DWORD), ("SegEs", wt.DWORD), ("SegDs", wt.DWORD),
        ("Edi", wt.DWORD), ("Esi", wt.DWORD), ("Ebx", wt.DWORD), ("Edx", wt.DWORD), ("Ecx", wt.DWORD), ("Eax", wt.DWORD),
        ("Ebp", wt.DWORD), ("Eip", wt.DWORD), ("SegCs", wt.DWORD), ("EFlags", wt.DWORD), ("Esp", wt.DWORD), ("SegSs", wt.DWORD),
        ("ExtendedRegisters", ctypes.c_ubyte * 512),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR), ("lpTitle", wt.LPWSTR),
                ("dwX", wt.DWORD), ("dwY", wt.DWORD), ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD),
                ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD), ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE), ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD)]


class EXCEPTION_RECORD(ctypes.Structure):
    pass


EXCEPTION_RECORD._fields_ = [("ExceptionCode", wt.DWORD), ("ExceptionFlags", wt.DWORD),
                             ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)), ("ExceptionAddress", ctypes.c_void_p),
                             ("NumberParameters", wt.DWORD), ("ExceptionInformation", ctypes.c_uint64 * 15)]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", wt.DWORD)]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hThread", wt.HANDLE), ("lpThreadLocalBase", ctypes.c_void_p), ("lpStartAddress", ctypes.c_void_p)]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", wt.HANDLE), ("hProcess", wt.HANDLE), ("hThread", wt.HANDLE), ("lpBaseOfImage", ctypes.c_void_p),
                ("dwDebugInfoFileOffset", wt.DWORD), ("nDebugInfoSize", wt.DWORD), ("lpThreadLocalBase", ctypes.c_void_p),
                ("lpStartAddress", ctypes.c_void_p), ("lpImageName", ctypes.c_void_p), ("fUnicode", wt.WORD)]


class EXIT_CODE_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wt.DWORD)]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", wt.HANDLE), ("lpBaseOfDll", ctypes.c_void_p), ("dwDebugInfoFileOffset", wt.DWORD),
                ("nDebugInfoSize", wt.DWORD), ("lpImageName", ctypes.c_void_p), ("fUnicode", wt.WORD)]


class UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p)]


class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
    _fields_ = [("lpDebugStringData", ctypes.c_void_p), ("fUnicode", wt.WORD), ("nDebugStringLength", wt.WORD)]


class _U(ctypes.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("CreateThread", CREATE_THREAD_DEBUG_INFO),
                ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO), ("ExitThread", EXIT_CODE_INFO),
                ("ExitProcess", EXIT_CODE_INFO), ("LoadDll", LOAD_DLL_DEBUG_INFO), ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
                ("DebugString", OUTPUT_DEBUG_STRING_INFO)]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", wt.DWORD), ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD), ("u", _U)]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p), ("AllocationProtect", wt.DWORD),
                ("PartitionId", wt.WORD), ("RegionSize", ctypes.c_size_t), ("State", wt.DWORD), ("Protect", wt.DWORD),
                ("Type", wt.DWORD)]


def _setup_api():
    H, V, S, B, D = wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.BOOL, wt.DWORD
    k32.CreateProcessW.argtypes = [wt.LPCWSTR, wt.LPWSTR, V, V, B, D, V, wt.LPCWSTR, ctypes.POINTER(STARTUPINFOW),
                                   ctypes.POINTER(PROCESS_INFORMATION)]
    k32.CreateProcessW.restype = B
    k32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), D]
    k32.WaitForDebugEvent.restype = B
    k32.ContinueDebugEvent.argtypes = [D, D, D]
    k32.ContinueDebugEvent.restype = B
    k32.ReadProcessMemory.argtypes = [H, V, V, S, ctypes.POINTER(S)]
    k32.ReadProcessMemory.restype = B
    k32.WriteProcessMemory.argtypes = [H, V, V, S, ctypes.POINTER(S)]
    k32.WriteProcessMemory.restype = B
    k32.VirtualProtectEx.argtypes = [H, V, S, D, ctypes.POINTER(D)]
    k32.VirtualProtectEx.restype = B
    k32.FlushInstructionCache.argtypes = [H, V, S]
    k32.OpenThread.argtypes = [D, B, D]
    k32.OpenThread.restype = H
    k32.GetThreadContext.argtypes = [H, V]
    k32.GetThreadContext.restype = B
    k32.SetThreadContext.argtypes = [H, V]
    k32.SetThreadContext.restype = B
    k32.CloseHandle.argtypes = [H]
    k32.TerminateProcess.argtypes = [H, wt.UINT]
    k32.DebugActiveProcess.argtypes = [D]
    k32.DebugActiveProcessStop.argtypes = [D]
    k32.DebugBreakProcess.argtypes = [H]
    k32.OpenProcess.argtypes = [D, B, D]
    k32.OpenProcess.restype = H
    k32.VirtualQueryEx.argtypes = [H, V, ctypes.POINTER(MEMORY_BASIC_INFORMATION), S]
    k32.VirtualQueryEx.restype = S
    k32.IsWow64Process.argtypes = [H, ctypes.POINTER(B)]
    k32.GetFinalPathNameByHandleW.argtypes = [H, wt.LPWSTR, D, D]
    k32.GetFinalPathNameByHandleW.restype = D
    k32.Wow64GetThreadContext.argtypes = [H, V]
    k32.Wow64SetThreadContext.argtypes = [H, V]
    k32.SuspendThread.argtypes = [H]
    k32.ResumeThread.argtypes = [H]


_setup_api()

REG64 = ["Rax", "Rbx", "Rcx", "Rdx", "Rsi", "Rdi", "Rbp", "Rsp", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "Rip"]
REG32 = ["Eax", "Ebx", "Ecx", "Edx", "Esi", "Edi", "Ebp", "Esp", "Eip"]


def _aligned(ctype_):
    size = ctypes.sizeof(ctype_)
    raw = ctypes.create_string_buffer(size + 16)
    addr = ctypes.addressof(raw)
    off = (-addr) % 16
    obj = ctype_.from_buffer(raw, off)
    return obj, raw


class WindowsDebugger(DebugSession):
    """All Win32 debug calls must come from the thread that created/attached the process: a worker thread owns them."""

    def __init__(self, proj=None):
        super().__init__(proj)
        self._q: "queue.Queue" = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self.pid = 0
        self.hproc = None
        self.main_tid = 0
        self.cur_tid = 0
        self.hthreads: Dict[int, int] = {}
        self.wow64 = False
        self._pending: Optional[tuple] = None          # (pid, tid, continue_status) awaiting ContinueDebugEvent
        self._reinsert: Optional[int] = None            # bp address to re-arm after the next single-step
        self._step_mode = False
        self.output: List[str] = []
        self.exit_code: Optional[int] = None
        self._owner_started = threading.Event()
        self.skip_first_chance_exceptions = False

    # ---------------------------------------------------------------- actor plumbing
    def _call(self, fn, *a, **kw):
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, daemon=True, name="revkit-dbg")
            self._thread.start()
        if threading.current_thread() is self._thread:
            return fn(*a, **kw)
        done = threading.Event()
        box = {}
        self._q.put((fn, a, kw, box, done))
        done.wait()
        if "exc" in box:
            raise box["exc"]
        return box.get("val")

    def _loop(self):
        while True:
            fn, a, kw, box, done = self._q.get()
            try:
                box["val"] = fn(*a, **kw)
            except BaseException as e:   # noqa: BLE001 - propagated to caller
                box["exc"] = e
            done.set()

    def _gate(self, action):
        if self.proj is not None:
            from ..secure import require_execution_permission
            require_execution_permission(self.proj, f"debugger {action}")

    # ---------------------------------------------------------------- lifecycle
    def launch(self, path: str, args: Optional[List[str]] = None, cwd: Optional[str] = None) -> DebugEvent:
        return self._call(self._launch, path, args or [], cwd)

    def _launch(self, path, args, cwd):
        self._gate("launch")
        cmd = ctypes.create_unicode_buffer(subprocess_list2cmd([path] + list(args)), 32768)
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        pi = PROCESS_INFORMATION()
        ok = k32.CreateProcessW(None, cmd, None, None, False, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, None, cwd,
                                ctypes.byref(si), ctypes.byref(pi))
        if not ok:
            raise DebugError(f"CreateProcess failed: {ctypes.WinError(ctypes.get_last_error())}")
        self.pid = pi.dwProcessId
        self.hproc = pi.hProcess
        self.main_tid = self.cur_tid = pi.dwThreadId
        k32.CloseHandle(pi.hThread)
        return self._start_common()

    def attach(self, pid: int) -> DebugEvent:
        return self._call(self._attach, pid)

    def _attach(self, pid):
        self._gate("attach")
        if not k32.DebugActiveProcess(pid):
            raise DebugError(f"DebugActiveProcess failed: {ctypes.WinError(ctypes.get_last_error())}")
        self.pid = pid
        self.hproc = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        return self._start_common()

    def _start_common(self) -> DebugEvent:
        w = wt.BOOL()
        k32.IsWow64Process(self.hproc, ctypes.byref(w))
        self.wow64 = bool(w.value)
        self.bits = 32 if self.wow64 else 64
        self.arch = "x86"
        self.state = "stopped"
        # run until the loader's initial breakpoint
        while True:
            ev = self._wait_event(10000)
            if ev is None:
                raise DebugError("timeout waiting for the initial debug events")
            if ev.kind == "initial_break":
                self.state = "stopped"
                self.last_event = ev
                return ev
            if ev.kind == "exit":
                raise DebugError(f"process exited during startup (code {ev.info.get('code')})")
            self._resume_pending()

    def detach(self):
        self._call(self._detach)

    def _detach(self):
        self._remove_all_breakpoints()
        self._resume_pending()
        k32.DebugActiveProcessStop(self.pid)
        self.state = "exited"

    def kill(self):
        self._call(self._kill)

    def _kill(self):
        if self.hproc and self.state != "exited":
            self._remove_all_breakpoints(ignore_errors=True)
            k32.TerminateProcess(self.hproc, 1)
            try:
                self._resume_pending()
                for _ in range(20):
                    ev = self._wait_event(500)
                    if ev is None or ev.kind == "exit":
                        break
                    self._resume_pending()
            except Exception:
                pass
            self.state = "exited"

    # ---------------------------------------------------------------- low level memory
    def read_memory(self, addr: int, size: int) -> bytes:
        return self._call(self._read, addr, size)

    def _read(self, addr, size) -> bytes:
        buf = ctypes.create_string_buffer(size)
        n = ctypes.c_size_t()
        if not k32.ReadProcessMemory(self.hproc, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)) and n.value == 0:
            raise DebugError(f"cannot read {size} bytes at {addr:#x}")
        data = buf.raw[:n.value]
        # hide our own int3 patches
        for bp in self.breakpoints.values():
            if bp.kind == "sw" and bp.enabled and bp.orig and addr <= bp.addr < addr + len(data):
                data = data[:bp.addr - addr] + bp.orig + data[bp.addr - addr + 1:]
        return data

    def write_memory(self, addr: int, data: bytes):
        self._call(self._write, addr, data)

    def _write(self, addr, data):
        old = wt.DWORD()
        k32.VirtualProtectEx(self.hproc, ctypes.c_void_p(addr), len(data), PAGE_EXECUTE_READWRITE, ctypes.byref(old))
        n = ctypes.c_size_t()
        ok = k32.WriteProcessMemory(self.hproc, ctypes.c_void_p(addr), data, len(data), ctypes.byref(n))
        k32.VirtualProtectEx(self.hproc, ctypes.c_void_p(addr), len(data), old.value, ctypes.byref(old))
        k32.FlushInstructionCache(self.hproc, ctypes.c_void_p(addr), len(data))
        if not ok:
            raise DebugError(f"cannot write memory at {addr:#x}")

    # ---------------------------------------------------------------- registers
    def _hthread(self, tid):
        h = self.hthreads.get(tid)
        if not h:
            h = k32.OpenThread(THREAD_ALL_ACCESS, False, tid)
            self.hthreads[tid] = h
        return h

    def _get_ctx(self, tid):
        h = self._hthread(tid)
        if self.wow64:
            ctx, keep = _aligned(CONTEXT32)
            ctx.ContextFlags = CONTEXT_ALL32
            if not k32.Wow64GetThreadContext(h, ctypes.addressof(ctx)):
                raise DebugError("Wow64GetThreadContext failed")
        else:
            ctx, keep = _aligned(CONTEXT64)
            ctx.ContextFlags = CONTEXT_ALL64
            if not k32.GetThreadContext(h, ctypes.addressof(ctx)):
                raise DebugError(f"GetThreadContext failed: {ctypes.WinError(ctypes.get_last_error())}")
        return ctx, keep

    def _set_ctx(self, tid, ctx):
        h = self._hthread(tid)
        fn = k32.Wow64SetThreadContext if self.wow64 else k32.SetThreadContext
        if not fn(h, ctypes.addressof(ctx)):
            raise DebugError("SetThreadContext failed")

    def registers(self, tid: Optional[int] = None) -> Dict[str, int]:
        return self._call(self._registers, tid or self.cur_tid)

    def _registers(self, tid):
        ctx, _keep = self._get_ctx(tid)
        names = REG32 if self.wow64 else REG64
        out = {n.lower(): int(getattr(ctx, n)) for n in names}
        out["eflags"] = int(ctx.EFlags)
        for s in ("SegCs", "SegDs", "SegEs", "SegFs", "SegGs", "SegSs"):
            out[s[3:].lower()] = int(getattr(ctx, s))
        return out

    def set_register(self, name: str, value: int, tid: Optional[int] = None):
        self._call(self._set_register, name, value, tid or self.cur_tid)

    def _set_register(self, name, value, tid):
        ctx, _keep = self._get_ctx(tid)
        attr = name.capitalize() if name.lower() != "eflags" else "EFlags"
        if not hasattr(ctx, attr):
            raise DebugError(f"unknown register {name}")
        setattr(ctx, attr, value & (0xFFFFFFFF if self.wow64 else 0xFFFFFFFFFFFFFFFF))
        self._set_ctx(tid, ctx)

    # ---------------------------------------------------------------- breakpoints
    def add_breakpoint(self, addr: int, kind: str = "sw", size: int = 1, condition: str = "", temporary: bool = False) -> Breakpoint:
        return self._call(self._add_bp, addr, kind, size, condition, temporary)

    def _add_bp(self, addr, kind, size, condition, temporary):
        bp = Breakpoint(self._next_bp, addr, kind, size, condition, True, 0, temporary, self.to_static(addr))
        self._next_bp += 1
        if kind == "sw":
            bp.orig = self._read_raw(addr, 1)
            self._write(addr, b"\xCC")
        else:
            used = {b.slot for b in self.breakpoints.values() if b.slot is not None}
            free = [s for s in range(4) if s not in used]
            if not free:
                raise DebugError("all four hardware breakpoint slots are in use")
            bp.slot = free[0]
            self.breakpoints[bp.id] = bp
            self._apply_hw()
            return bp
        self.breakpoints[bp.id] = bp
        return bp

    def _read_raw(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        n = ctypes.c_size_t()
        if not k32.ReadProcessMemory(self.hproc, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)) or n.value != size:
            raise DebugError(f"cannot read memory at {addr:#x}")
        return buf.raw

    def remove_breakpoint(self, bid: int):
        self._call(self._rm_bp, bid)

    def _rm_bp(self, bid):
        bp = self.breakpoints.pop(bid, None)
        if bp is None:
            return
        if bp.kind == "sw":
            if bp.enabled and self.state != "exited":
                self._write(bp.addr, bp.orig)
        else:
            self._apply_hw()

    def set_breakpoint_enabled(self, bid: int, enabled: bool):
        self._call(self._enable_bp, bid, enabled)

    def _enable_bp(self, bid, enabled):
        bp = self.breakpoints[bid]
        if bp.enabled == enabled:
            return
        bp.enabled = enabled
        if bp.kind == "sw":
            self._write(bp.addr, b"\xCC" if enabled else bp.orig)
        else:
            self._apply_hw()

    def _remove_all_breakpoints(self, ignore_errors=False):
        for bid in list(self.breakpoints):
            try:
                self._rm_bp(bid)
            except DebugError:
                if not ignore_errors:
                    raise

    def _apply_hw(self):
        for tid in list(self.hthreads) or [self.cur_tid]:
            try:
                ctx, _k = self._get_ctx(tid)
            except DebugError:
                continue
            dr7 = 0
            for slot in range(4):
                setattr(ctx, f"Dr{slot}", 0)
            for bp in self.breakpoints.values():
                if bp.kind != "sw" and bp.enabled and bp.slot is not None:
                    setattr(ctx, f"Dr{bp.slot}", bp.addr)
                    rw = {"hw-exec": 0, "hw-write": 1, "hw-rw": 3}[bp.kind]
                    ln = {1: 0, 2: 1, 4: 3, 8: 2}.get(bp.size, 0) if bp.kind != "hw-exec" else 0
                    dr7 |= (1 << (bp.slot * 2)) | (rw << (16 + bp.slot * 4)) | (ln << (18 + bp.slot * 4))
            ctx.Dr7 = dr7
            self._set_ctx(tid, ctx)

    # ---------------------------------------------------------------- execution control
    def cont(self, timeout: Optional[float] = None) -> DebugEvent:
        return self._call(self._cont, timeout)

    def _cont(self, timeout):
        if self.state == "exited":
            raise DebugError("process has exited")
        # step off a breakpoint we are sitting on
        pc = self._registers(self.cur_tid)["eip" if self.wow64 else "rip"]
        at_bp = next((b for b in self.breakpoints.values() if b.kind == "sw" and b.enabled and b.addr == pc), None)
        if at_bp is not None:
            ev = self._step_over_breakpoint(at_bp)
            if ev is not None:
                return ev
        self._resume_pending()
        self.state = "running"
        return self._run_until_stop(timeout)

    def _step_over_breakpoint(self, bp: Breakpoint) -> Optional[DebugEvent]:
        """Single-step the original instruction with the int3 removed, then re-arm. Returns an event if something else happened."""
        self._write(bp.addr, bp.orig)
        self._set_tf(self.cur_tid, True)
        self._resume_pending()
        ev = self._run_until_stop(10000, stepping=True)
        if bp.id in self.breakpoints and bp.enabled:
            try:
                self._write(bp.addr, b"\xCC")
            except DebugError:
                pass
        if ev.kind != "step":
            return ev
        return None

    def step_into(self) -> DebugEvent:
        return self._call(self._step)

    def _step(self):
        if self.state == "exited":
            raise DebugError("process has exited")
        pc = self._registers(self.cur_tid)["eip" if self.wow64 else "rip"]
        at_bp = next((b for b in self.breakpoints.values() if b.kind == "sw" and b.enabled and b.addr == pc), None)
        if at_bp is not None:
            self._write(at_bp.addr, at_bp.orig)
        self._set_tf(self.cur_tid, True)
        self._resume_pending()
        self.state = "running"
        ev = self._run_until_stop(10000, stepping=True)
        if at_bp is not None and at_bp.id in self.breakpoints and at_bp.enabled:
            self._write(at_bp.addr, b"\xCC")
        return ev

    def _set_tf(self, tid, on):
        ctx, _k = self._get_ctx(tid)
        ctx.EFlags = (ctx.EFlags | TF) if on else (ctx.EFlags & ~TF)
        self._set_ctx(tid, ctx)

    def pause(self):
        if self.hproc:
            k32.DebugBreakProcess(self.hproc)

    def _resume_pending(self):
        if self._pending is not None:
            pid, tid, status = self._pending
            k32.ContinueDebugEvent(pid, tid, status)
            self._pending = None

    def _run_until_stop(self, timeout, stepping=False) -> DebugEvent:
        total = 0
        limit = (timeout if timeout is not None else 1e9)
        while True:
            ev = self._wait_event(250)
            if ev is None:
                total += 0.25
                if total >= limit:
                    self.pause()
                    total = -1e9
                continue
            if ev.kind in ("module_load", "module_unload", "thread_create", "thread_exit", "output"):
                self._resume_pending()
                continue
            self.state = "exited" if ev.kind == "exit" else "stopped"
            return ev

    # ---------------------------------------------------------------- event pump
    def _wait_event(self, ms: int) -> Optional[DebugEvent]:
        de = DEBUG_EVENT()
        if not k32.WaitForDebugEvent(ctypes.byref(de), ms):
            err = ctypes.get_last_error()
            if err == 121:           # ERROR_SEM_TIMEOUT
                return None
            raise DebugError(f"WaitForDebugEvent failed: {ctypes.WinError(err)}")
        code, pid, tid = de.dwDebugEventCode, de.dwProcessId, de.dwThreadId
        self._pending = (pid, tid, DBG_CONTINUE)
        self.cur_tid = tid if code == EXCEPTION_DEBUG_EVENT else self.cur_tid
        u = de.u
        if code == CREATE_PROCESS_DEBUG_EVENT:
            info = u.CreateProcessInfo
            self.main_base = info.lpBaseOfImage
            self.hthreads[tid] = info.hThread
            self.main_tid = self.cur_tid = tid
            path = self._path_of_handle(info.hFile)
            self.modules.append(Module(os.path.basename(path) or "main", self.main_base or 0, self._image_size(self.main_base), path))
            if info.hFile:
                k32.CloseHandle(info.hFile)
            ev = DebugEvent("module_load", tid, self.main_base or 0, {"name": os.path.basename(path), "main": True})
        elif code == CREATE_THREAD_DEBUG_EVENT:
            self.hthreads[tid] = u.CreateThread.hThread
            ev = DebugEvent("thread_create", tid, u.CreateThread.lpStartAddress or 0)
        elif code == EXIT_THREAD_DEBUG_EVENT:
            self.hthreads.pop(tid, None)
            ev = DebugEvent("thread_exit", tid, 0, {"code": u.ExitThread.dwExitCode})
        elif code == EXIT_PROCESS_DEBUG_EVENT:
            self.exit_code = u.ExitProcess.dwExitCode
            self.state = "exited"
            ev = DebugEvent("exit", tid, 0, {"code": self.exit_code})
        elif code == LOAD_DLL_DEBUG_EVENT:
            info = u.LoadDll
            path = self._path_of_handle(info.hFile)
            if info.hFile:
                k32.CloseHandle(info.hFile)
            m = Module(os.path.basename(path), info.lpBaseOfDll or 0, self._image_size(info.lpBaseOfDll), path)
            self.modules.append(m)
            ev = DebugEvent("module_load", tid, m.base, {"name": m.name, "path": path})
        elif code == UNLOAD_DLL_DEBUG_EVENT:
            base = u.UnloadDll.lpBaseOfDll
            self.modules = [m for m in self.modules if m.base != base]
            ev = DebugEvent("module_unload", tid, base or 0)
        elif code == OUTPUT_DEBUG_STRING_EVENT:
            info = u.DebugString
            try:
                raw = self._read_raw(info.lpDebugStringData, info.nDebugStringLength)
                txt = raw.decode("utf-16-le" if info.fUnicode else "latin1", "replace").rstrip("\0")
            except DebugError:
                txt = ""
            self.output.append(txt)
            ev = DebugEvent("output", tid, 0, {"text": txt})
        elif code == EXCEPTION_DEBUG_EVENT:
            ev = self._on_exception(u.Exception, tid)
        else:
            ev = DebugEvent("other", tid)
        self._fire(ev)
        return ev

    _initial_break_seen = False

    def _on_exception(self, ex, tid) -> DebugEvent:
        rec = ex.ExceptionRecord
        code = rec.ExceptionCode
        addr = rec.ExceptionAddress or 0
        first = bool(ex.dwFirstChance)
        pcname = "eip" if self.wow64 else "rip"
        if code in (EXC_BREAKPOINT, EXC_WOW64_BREAKPOINT):
            if not self._initial_break_seen:
                self._initial_break_seen = True
                return DebugEvent("initial_break", tid, addr)
            bp = next((b for b in self.breakpoints.values() if b.kind == "sw" and b.enabled and b.addr == addr), None)
            if bp is not None:
                # move back onto the breakpoint instruction
                self._set_register(pcname, addr, tid)
                bp.hits += 1
                if bp.condition:
                    try:
                        if not self._eval_cond(bp.condition):
                            self._write(bp.addr, bp.orig)
                            self._set_tf(tid, True)
                            self._resume_pending()
                            return self._cond_step_continue(bp, tid)
                    except Exception as e:
                        return DebugEvent("breakpoint", tid, addr, {"id": bp.id, "condition_error": str(e)})
                return DebugEvent("breakpoint", tid, addr, {"id": bp.id, "static": self.to_static(addr)})
            # user-level int3 in the target
            self._pending = (self._pending[0], self._pending[1], DBG_CONTINUE)
            return DebugEvent("exception", tid, addr, {"code": code, "name": "breakpoint", "first_chance": first})
        if code in (EXC_SINGLE_STEP, EXC_WOW64_SINGLE_STEP):
            ctx, _k = self._get_ctx(tid)
            dr6 = int(ctx.Dr6)
            if dr6 & 0xF:
                slot = next(i for i in range(4) if dr6 & (1 << i))
                bp = next((b for b in self.breakpoints.values() if b.slot == slot), None)
                ctx.Dr6 = 0
                self._set_ctx(tid, ctx)
                if bp:
                    bp.hits += 1
                    return DebugEvent("breakpoint", tid, int(getattr(ctx, 'Eip' if self.wow64 else 'Rip')),
                                      {"id": bp.id, "hardware": True, "kind": bp.kind})
            return DebugEvent("step", tid, int(getattr(ctx, 'Eip' if self.wow64 else 'Rip')))
        self._pending = (self._pending[0], self._pending[1], DBG_EXCEPTION_NOT_HANDLED)
        return DebugEvent("exception", tid, addr, {"code": code, "first_chance": first,
                                                   "name": "access violation" if code == EXC_ACCESS_VIOLATION else hex(code)})

    def _cond_step_continue(self, bp, tid):
        ev = self._run_until_stop(10000, stepping=True)
        if bp.id in self.breakpoints and bp.enabled:
            self._write(bp.addr, b"\xCC")
        if ev.kind == "step":
            self._resume_pending()
            return self._run_until_stop(None)
        return ev

    def _eval_cond(self, cond: str) -> bool:
        regs = {k: v for k, v in self._registers(self.cur_tid).items()}
        from .base import safe_eval
        return bool(safe_eval(cond, regs, self._read, self.bits // 8,
                              {m.name.lower().split(".")[0]: m.base for m in self.modules}))

    # ---------------------------------------------------------------- misc
    def _path_of_handle(self, h) -> str:
        if not h:
            return ""
        buf = ctypes.create_unicode_buffer(1024)
        n = k32.GetFinalPathNameByHandleW(h, buf, 1024, 0)
        p = buf.value if n else ""
        return p[4:] if p.startswith("\\\\?\\") else p

    def _image_size(self, base) -> int:
        if not base:
            return 0
        try:
            hdr = self._read_raw(base, 0x400)
            pe = int.from_bytes(hdr[0x3C:0x40], "little")
            return int.from_bytes(hdr[pe + 24 + 56:pe + 24 + 60], "little")
        except Exception:
            return 0

    def threads(self) -> List[dict]:
        return [{"tid": t, "current": t == self.cur_tid} for t in self.hthreads]

    def select_thread(self, tid: int):
        if tid not in self.hthreads:
            raise DebugError(f"unknown thread {tid}")
        self.cur_tid = tid

    def memory_map(self) -> List[dict]:
        return self._call(self._memmap)

    def _memmap(self):
        out = []
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        while addr < 0x7FFFFFFF0000 and k32.VirtualQueryEx(self.hproc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.State == MEM_COMMIT:
                out.append({"base": mbi.BaseAddress or 0, "size": mbi.RegionSize, "protect": hex(mbi.Protect), "type": hex(mbi.Type)})
            nxt = (mbi.BaseAddress or 0) + mbi.RegionSize
            if nxt <= addr:
                break
            addr = nxt
            if len(out) > 5000:
                break
        return out


def subprocess_list2cmd(args: List[str]) -> str:
    import subprocess
    return subprocess.list2cmdline(args)
