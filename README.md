# revkit

[![CI](https://github.com/crazysandy1/revkit/actions/workflows/ci.yml/badge.svg)](https://github.com/crazysandy1/revkit/actions)
![python](https://img.shields.io/badge/python-3.10%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green)

**revkit is an open reverse-engineering platform.** Give it a compiled program (Windows, Linux, macOS, firmware, raw machine code)
and it shows what the program does without the source: disassembly, graphs, cross-references, C-like pseudocode, debugging, patching,
comparison, scripting and team sharing. It runs as a CLI, a Python library, a local web app, and a Windows `revkit.exe`.

Guide: [`docs/GUIDE.md`](docs/GUIDE.md) | Feature status: [`docs/FEATURES.md`](docs/FEATURES.md) | Dependencies: [`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md) |
Licence: MIT, see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Why

Source code is often missing (legacy code, third-party libraries, malware, firmware). Commercial tools are costly and closed.
revkit is scriptable, runs headless in CI, and answers common questions with evidence: what APIs does it call, where is this string
used, what changed between two versions, is it packed, does it call an unsafe `strcpy`.

## Feature list

- **Loaders:** PE, ELF, Mach-O (thin/fat), raw binary, DOS COM, Intel HEX, S-record, plugin loaders.
- **Architectures (disassembly):** x86/x64, ARM, Thumb, AArch64, MIPS, PowerPC, RISC-V, SPARC, M68K, 6502, SysZ.
- **Auto-analysis:** function discovery (symbols, exception tables, call targets, prologues, pointer tables), no-return inference,
  jump-table recovery, thunks and import stubs, strings (ASCII/UTF-16/UTF-8), cross-references.
- **Views:** linear listing, flow graph, call graph, pseudocode, hex, lists (functions, names, strings, imports, exports, segments,
  problems, bookmarks), search (bytes with wildcards, text, immediates, names, strings).
- **Decompiler:** x86, x64, AArch64; loops, if/else, switch, API prototypes, struct fields, variable rename/retype.
- **Editing:** rename, comments, types, make code/data/string/function, undefine, operand formats, undo/redo, saved databases.
- **Types:** C declaration parser (structs, unions, enums, bitfields, function pointers), bundled Win32/libc/POSIX prototypes.
- **Recognition:** signature matching (`.rsig`, text pattern import/export), private metadata server, PDB symbols.
- **Patching:** bytes, assembly, NOP, branch invert/force, write patched copy.
- **Debugging:** native Windows debugger, remote GDB protocol client, emulator-backed GDB stub.
- **Hard binaries:** `--unpack` (emulates packer stubs), packer indicators, string-decoder execution, verified MBA simplifier, crypto constants.
- **Security:** vulnerability triage with review workflow, hardening checks, secret detection, evidence-linked explanations, reports.
- **Automation:** Python API, scripting shims (`rk`, `rkutil`, `rkapi`), plugin SDK, batch mode, exports (asm, JSON, CSV, MAP, DOT, header).
- **Collaboration:** team server (roles, audit log, edit sync), sample vault with tamper-evident audit log.

## Status and honesty

Implemented features are tested (88 tests) and were also run on real PE, ELF and Mach-O files. Known gaps (no decompiler for
ARM32/MIPS/PPC/RISC-V, no native Linux/macOS debugger, no C++ demangling, pure-Python speed) are listed in `docs/FEATURES.md`.
Findings and decompiled code are heuristics: verify important conclusions.

## Install and run

```bash
python -m pip install -e .[test]
python -m revkit doctor
python -m revkit analyze sample.exe -o sample.rkdb
python -m revkit decompile sample.rkdb main
python -m revkit serve sample.rkdb          # web UI, prints a URL with an access token
```

## Standalone app (Windows)

`dist
evkit.exe` is a single-file build (no Python needed). Double-click it: pick a file, answer whether it is packed, and the
analysis UI opens in your browser. With arguments it is the full CLI (`revkit.exe analyze x.exe --unpack`). Rebuild with `build_app.bat`
(runs the tests first, then PyInstaller).

## Common commands

| Task | Command |
|---|---|
| Functions / strings / imports | `revkit functions DB`, `strings`, `imports`, `exports`, `segments` |
| Disassemble | `revkit disasm DB fact -f`, `revkit listing DB -o out.asm` |
| Decompile | `revkit decompile DB NAME` or `--all -o out.c` |
| Xrefs, CFG, call graph | `revkit xrefs DB ADDR`, `cfg DB FUNC --dot`, `callgraph DB` |
| Edit | `rename`, `comment`, `types header.h`, `patch DB ADDR --asm "mov eax, 1" -o patched.exe` |
| Signatures | `revkit sig make lib.a -o lib.rsig`, `revkit sig apply DB --sigs lib.rsig` |
| Compare | `revkit diff old.exe new.exe` |
| Security | `revkit triage DB`, `packer`, `crypto`, `report --format html`, `explain DB FUNC` |
| Packed input | `revkit analyze packed.exe --unpack` (also on `decompile`, `serve`, any command taking a binary) |
| Deobfuscation | `revkit mba "(x ^ y) + 2*(x & y)"`, `emulate`, `unpack -o dump.bin` |
| Debug | `revkit debug sample.exe --allow-exec`, `revkit debug sample --gdb host:port`, `revkit stub sample` |
| Script / plugins | `revkit script DB script.py`, `revkit plugin list DB`, `plugin trust FILE` |
| Batch | `revkit batch dir/ --outdir out -j 8 --decompile --report` |
| Team / metadata | `revkit team serve`, `team add-user`, `team sync DB --url ...` |
| Sample vault | `revkit vault import FILE`, `vault verify-audit` |

Python API:

```python
from revkit.api import Project
p = Project.load("sample.exe")
print(p.decompile_text("main"))
p.rename("sub_401000", "parse_config"); p.save("sample.rkdb")
```

## Web UI shortcuts (rebindable in Settings)

`N` rename, `;` comment, `:` repeatable comment, `G` goto, `X` xrefs, `Space` text/graph, `Tab` disassembly/pseudocode, `F5` decompile,
`C` code, `D` data, `U` undefine, `P` function, `A` string, `Y` type, `H` operand format, `B` bookmark, `Esc` back, `/` search,
`Ctrl+Z/Y` undo/redo, `Ctrl+S` save, `Ctrl+P` patch, `F2/F7/F8/F9` breakpoint/step/over/continue.

## Safety

- The sample is never executed unless `--allow-exec` is passed (debugger launch/attach). Do that inside an isolated VM.
- `revkit vault` stores samples read-only by SHA-256 with a hash-chained audit log.
- Plugins run in-process; third-party plugins must be trusted explicitly (SHA-256 pinned).
- The web server binds to localhost and requires a random per-run token.

## Measured performance (Windows 11, Python 3.12, `tools/benchmark.py`)

| File | Size | Analyze | Instructions | Decompile 100 functions |
|---|---|---|---|---|
| notepad.exe (x64 PE) | 360 KB | 2.4 s | 37,764 | 0.2 s |
| kernel32.dll (x64 PE) | 844 KB | 22 s | 128,949 | 59 s |
| cffi backend (x86-64 ELF) | 349 KB | 7.8 s | 46,796 | < 1 s (mostly stubs) |
| cffi backend (AArch64 ELF) | 453 KB | 6.9 s | 53,197 | 0.1 s |

## Tests

`python -m pytest tests` (85 tests, about 2 minutes). Fixtures are assembled at test time with Keystone. Some tests use binaries
found on the machine (Windows system files, `.realworld/` samples from PyPI wheels) and skip when absent.

## Layout

`revkit/loaders` formats; `arch.py` ISA semantics; `analysis/` auto-analysis, switch tables, signatures; `db.py` database + undo +
journal; `decompiler/` IR, x86/AArch64 lifters, structuring; `debugger/` Windows native, GDB RSP client, emulator stub;
`web/` server + UI; `team.py` collaboration/metadata; `plugins/`, `scripting.py`, `vulns.py`, `deobf.py`, `emulate.py`, `bindiff.py`.

## Contributing

Contributions are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

1. Fork, create a branch, `python -m pip install -e .[test]`.
2. Make the change with a test (`tests/`), run `python -m pytest tests`.
3. Open a pull request describing the behaviour change and how you verified it.

Good first areas: decompiler for ARM32/MIPS/PPC/RISC-V; C++ demangling and vtable recovery; native Linux/macOS debugger;
signature data; more loaders (COFF `.obj`, Java classes); UI polish; performance (the engine is pure Python).
Report security issues privately: [`SECURITY.md`](SECURITY.md). Do not commit malware samples or copyrighted binaries.

## Roadmap

Short term: more architectures in the decompiler, demangling, faster analysis. Long term: native debuggers on all OSes, richer type
recovery, plugin marketplace with signed plugins.

## Legal

For authorised security research, defensive analysis and interoperability only. revkit is an independent project and is not
affiliated with or endorsed by any commercial reverse-engineering product or vendor. All product names mentioned in third-party
data belong to their owners. Provided "as is" under the MIT licence, without warranty.
