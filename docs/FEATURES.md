# Feature tracker

Status: **Done** = implemented and covered by tests or verified on real binaries. **Partial** = works with stated limits.
**Missing** = not implemented. Nothing here is mocked: every row is backed by code in `revkit/`.

Verification used: 85 automated tests (`pytest tests`), plus manual runs on real binaries (Windows `notepad.exe`, `kernel32.dll`,
`ping.exe`; ELF/Mach-O `cffi` extension modules for x86-64 and AArch64 downloaded from PyPI wheels; Dokan DLL + real PDB).
On the x86-64 ELF sample, 100 % of the 515 `.eh_frame` function starts are recovered.

| Catalog § | Capability | Status | Where / notes |
|---|---|---|---|
| 2.1 | Load PE, ELF, Mach-O (thin+fat), raw, DOS COM, Intel HEX, S-record; manual arch/base/entry; custom loaders | Done | `revkit/loaders/`, `register_loader()`. ELF `.o` relocatable: Partial (sections laid out, relocations not applied). COFF `.obj`, `.a` members as inputs: Missing (ar archives are readable for signature creation only) |
| 2.2 | Sections, entry points, imports/exports, relocations, symbols, strings, arch info | Done | Relocations are recorded and used as code-pointer hints. PDB public symbols: Done (`load_pdb`). DWARF types/lines: Missing |
| 2.4 | Raw/embedded images, load address | Done | `--arch --base --entry`; sparse HEX/SREC |
| 3.1 | Disassembly x86/x64, ARM, Thumb, AArch64, MIPS, PPC, RISC-V, SPARC, M68K, 6502, SysZ | Done | Capstone. Flow/xref semantics are strongest on x86/x64/AArch64; other ISAs: direct branches and simple constant-pair references only |
| 3.2 | Interactive editing: rename, comments (regular, repeatable, anterior, posterior, function), types, make code/data/string/function, undefine, operand formats, function end | Done | `Project`, web UI shortcuts, undo/redo |
| 3.3 | Auto-analysis | Done | recursive descent, no-return inference (iterative), switch tables (x86/x64, AArch64, MIPS abs), prologue/gap scan, pointer tables, thunks, PLT/stub import mapping. Heuristic (can be wrong on packed code) |
| 3.4 | Operand details, formats (hex/dec/oct/bin/char/neg/offset/enum) | Done | |
| 4.1-4.3 | Linear view, graph view, proximity (call graph), functions/names/strings/imports/exports/segments/structs/enums/problems/bookmarks/patches, hex view, search, goto, back/forward, themes, fonts, shortcuts, bookmarks | Done | Web UI (`revkit serve`). Per-user keybindings stored in `~/.revkit/settings.json` |
| 4.2 | Type libraries view | Partial | bundled prototype/struct libs (Win32 subset, libc, POSIX); no GUI for browsing prototypes |
| 5 | Function discovery, chunks, callers/callees, xrefs, annotations | Done | Indirect calls: resolved through imports, thunks, constant pointers; virtual dispatch/vtables are NOT resolved |
| 6 | CFG, loops, dominators, complexity, DOT/JSON export | Done | |
| 7.1-7.2 | Decompiler: x86, x86-64, AArch64 | Done | Own IR pipeline (lift, stack-variable recovery, liveness, web splitting, inlining, structuring, switch, loops, gotos). Quality is below commercial decompilers on optimised code (no type recovery beyond sizes/prototypes, no `for` recovery, floats/SIMD become intrinsics) |
| 7.2 | Rename variables/functions, pseudocode<->assembly sync | Done | line-to-address map |
| 7.3 | Other architectures | Missing | ARM32, MIPS, PPC, RISC-V decompilation raise a clear `DecompileError` |
| 7.4, 8 | Types: structs, unions, enums, bitfields, arrays, function pointers, packed, prototypes, struct-typed pointers render as `p->field` | Done | C declaration parser with layout engine |
| 8 | Field-access cross references per struct member | Missing | |
| 9 | Strings (ASCII/UTF-16/UTF-8), constants, imports/exports, API capability tagging | Done | |
| 10.1 | signature-based library recognition | Partial | own `.rsig` format; build from binaries with symbols, ELF `.o`, `ar` archives; `.pat` import/export. Vendor binary signature files are NOT read. No signature data is bundled |
| 10.2 | metadata service (private) | Done | `revkit team serve`; exchanges fingerprints + analyst names only. No public service |
| 11 | Debugger: launch/attach, SW/HW breakpoints, conditions, step/over/out/run-to, registers, memory, stack, threads, modules, expressions, backtrace | Done (Windows x64 + WoW64 x86 native); remote any-arch via GDB RSP; emulator-backed stub | Native Linux/macOS debugger: Missing (use gdbserver/lldb-server with `--gdb`). WoW64 path is implemented but only x64 was exercised |
| 12 | Patching: bytes, assemble, NOP, invert branch, force jump, revert, export patched file with provenance, PE checksum | Done | original file never modified |
| 13 | Packer indicators, entropy, MBA simplification (verified), emulation, emulation-based unpacking, string decoder emulation, crypto constant detection | Done | MBA solver is exact for linear MBA; non-linear only when a verified smaller form is found. Unpacking works for in-place decoders (execute-written-memory detection); anti-emulation tricks defeat it |
| 13 | Import option `--unpack` / `Project.load(unpack=True)`: emulate the packer stub, analyse and decompile the unpacked image, multi-layer | Done | verified on synthetic 1- and 2-layer XOR-packed PE; real packers (UPX, etc.) not tested here. Imports rebuilt by the stub are not reconstructed (stubbed calls return 0); anti-emulation defeats it |
| 14 | Scripting: native API + scripting-style `rk`/`rkutil`/`rkapi` subset | Partial | Common functions only; not a drop-in for all of scripting |
| 15 | SDK: Python plugins, custom loaders, processor modules (`register_arch`), actions/hotkeys/hooks | Done | No C++ SDK. In-process plugins are not sandboxed; trust is SHA-256 pinned |
| 16, 17 | CLI, batch/headless (process pool), `open_database()` | Done | |
| 18 | Plugin discovery/management/provenance | Done | bundled: `crypto_scan`, `api_tagger`, `rea_bridge` |
| 19 | Team server: roles, audit log, op-log sync with conflict reporting | Done | last-writer-wins per key. TLS supported via cert/key; operator must provide certs. No offline merge UI |
| 20 | Persistence: SQLite database, embedded sample, versioned analysis cache, edit journal, audit | Done | |
| 21 | Security workflows: triage with evidence and review workflow, explanations with evidence links, optional LLM text (marked unverified) | Done | findings are heuristics |
| 22 | Export: asm, JSON, CSV, MAP, names script, Python, C header, DOT, reports (md/html/json); import names (MAP/CSV/JSON/script) | Done | |
| 23 | Configuration | Done | themes, fonts, shortcuts, analysis options |
| 24, 25 | Licensing/editions, deployment | n/a | open implementation; see `DEPENDENCIES.md` |
| 29 | Secure sample handling: hash-addressed vault, read-only copies, tamper-evident audit chain, execution gate | Done | |
| 29 | Performance benchmarks | Done | `tools/benchmark.py`, results in README |
| 29 | Tests with known binaries | Done | fixtures are assembled with Keystone at test time (`tests/fixtures.py`) |
| 29 | Large-file handling | Partial | pure-Python engine, roughly 5-15 k instructions/s; a 10 MB binary takes minutes |
| 27 | Source recovery, backend recovery, full deobfuscation | n/a | out of scope exactly as the catalog states |

## Known gaps (not implemented)

- Decompilation of ARM32/MIPS/PPC/RISC-V; type recovery; `for` loops; C++ constructs; vtable/RTTI recovery.
- Native debugging on Linux/macOS; kernel debugging; trace/record-replay.
- commercial tools binary signature/`.sig` and `.til` formats; real metadata service interoperability.
- .NET/Java/WASM/Android managed-code analysis (use REA: `revkit/plugins/builtin/rea_bridge.py` for JavaScript apps).
- Demangling of C++ names.
- advanced microcode API and C++ SDK.
