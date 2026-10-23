"""Interactive command-line debugger (gdb-flavoured)."""
from __future__ import annotations

import shlex
import sys

from . import create_session
from .base import DebugError

HELP = """commands:
  run                      start the program (native)            c / cont          continue
  break|b <addr|name> [if <expr>]   software breakpoint           hbreak <addr>     hardware execute breakpoint
  watch <addr> [w|rw] [size]        hardware data breakpoint      delete <id>       remove breakpoint
  bl                       list breakpoints                       s / step          step into
  n / next                 step over                              finish            run until return
  until <addr>             run to address                         regs              show registers
  set <reg> <value>        write a register                       x <addr> [len]    hex dump memory
  dis [addr] [count]       disassemble                            bt                backtrace
  stack [n]                stack words                            threads / thread <tid>
  mods                     modules                                map               memory map
  p <expr>                 evaluate (regs, numbers, qword(addr))  kill / q          quit
"""


def run_repl(proj, a) -> int:
    if a.gdb:
        host, _, port = a.gdb.partition(":")
        dbg = create_session(proj, "gdb", host=host or "127.0.0.1", port=int(port))
        ev = dbg.connect()
        print("connected;", ev.to_dict())
    else:
        dbg = create_session(proj, "native")
        ev = None

    def res(tok: str) -> int:
        try:
            return dbg.to_runtime(proj.resolve(tok))
        except Exception:
            return int(tok, 0)

    def show(ev):
        print(f"[{ev.kind}] tid={ev.tid} addr={ev.addr:#x}" + (f" {dbg._function_for_runtime(ev.addr)}" if ev.addr else "") +
              (" " + str({k: v for k, v in ev.info.items() if k not in ('static',)}) if ev.info else ""))
        if ev.kind != "exit" and dbg.state != "exited":
            try:
                for d in dbg.disasm(count=3):
                    print(f"   {d['addr']:#x}  {d['text']}")
            except Exception:
                pass

    if not a.gdb:
        try:
            ev = dbg.launch(proj.image.path, a.args)
        except PermissionError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        print(f"started pid {dbg.pid}; image base {dbg.main_base:#x}")
        # convenience: stop at the program entry
        if proj.image.entry_points:
            dbg.add_breakpoint(dbg.to_runtime(proj.image.entry_points[0][0]))
    print("type 'help' for commands")
    while True:
        try:
            line = input("(revkit) ").strip()
        except (EOFError, KeyboardInterrupt):
            line = "q"
        if not line:
            continue
        try:
            parts = shlex.split(line)
            cmd, args = parts[0], parts[1:]
            if cmd in ("q", "quit", "kill", "exit"):
                dbg.kill()
                return 0
            elif cmd == "help":
                print(HELP)
            elif cmd in ("c", "cont", "continue", "run"):
                show(dbg.cont())
            elif cmd in ("s", "step", "si"):
                show(dbg.step_into())
            elif cmd in ("n", "next", "ni"):
                show(dbg.step_over())
            elif cmd in ("finish", "out"):
                show(dbg.step_out())
            elif cmd == "until":
                show(dbg.run_to(res(args[0])))
            elif cmd in ("b", "break", "bp"):
                cond = ""
                if "if" in args:
                    i = args.index("if")
                    cond, args = " ".join(args[i + 1:]), args[:i]
                bp = dbg.add_breakpoint(res(args[0]), condition=cond)
                print(f"breakpoint {bp.id} at {bp.addr:#x}")
            elif cmd == "hbreak":
                bp = dbg.add_breakpoint(res(args[0]), "hw-exec")
                print(f"hardware breakpoint {bp.id} at {bp.addr:#x}")
            elif cmd == "watch":
                kind = "hw-rw" if len(args) > 1 and args[1] == "rw" else "hw-write"
                bp = dbg.add_breakpoint(res(args[0]), kind, int(args[2]) if len(args) > 2 else 4)
                print(f"watchpoint {bp.id} at {bp.addr:#x}")
            elif cmd in ("d", "delete"):
                dbg.remove_breakpoint(int(args[0]))
            elif cmd == "bl":
                for b in dbg.breakpoints.values():
                    print(f"{b.id}: {b.kind} {b.addr:#x} hits={b.hits} {'if ' + b.condition if b.condition else ''}")
            elif cmd == "regs":
                for k, v in dbg.registers().items():
                    print(f"{k:8} {v:#018x}")
            elif cmd == "set":
                dbg.set_register(args[0], int(args[1], 0))
            elif cmd == "x":
                addr = res(args[0])
                n = int(args[1], 0) if len(args) > 1 else 64
                data = dbg.read_memory(addr, n)
                for i in range(0, len(data), 16):
                    chunk = data[i:i + 16]
                    print(f"{addr + i:#014x}  {chunk.hex(' '):<47}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)}")
            elif cmd == "dis":
                for d in dbg.disasm(res(args[0]) if args else None, int(args[1]) if len(args) > 1 else 8):
                    print(f"{d['addr']:#x}  {d['bytes']:<24} {d['text']}")
            elif cmd in ("bt", "backtrace", "where"):
                for i, f in enumerate(dbg.backtrace()):
                    print(f"#{i}  {f['pc']:#x}  {f.get('symbol') or ''}")
            elif cmd == "stack":
                for e in dbg.stack(int(args[0]) if args else 16):
                    print(f"{e['addr']:#x}  {e['value']:#018x}  {e.get('symbol') or ''}")
            elif cmd == "threads":
                for t in dbg.threads():
                    print(("* " if t["current"] else "  ") + str(t["tid"]))
            elif cmd == "thread":
                dbg.select_thread(int(args[0]))
            elif cmd == "mods":
                for m in dbg.modules:
                    print(f"{m.base:#016x}  {m.size:#10x}  {m.name}")
            elif cmd == "map":
                for r in dbg.memory_map():
                    print(f"{r['base']:#016x}  {r['size']:#10x}  {r['protect']}")
            elif cmd in ("p", "print"):
                v = dbg.evaluate(" ".join(args))
                print(f"{v} = {v:#x}")
            else:
                print("unknown command; type 'help'")
        except (DebugError, ValueError, IndexError, KeyError, PermissionError) as e:
            print(f"error: {e}")
