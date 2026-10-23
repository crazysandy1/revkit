# revkit user guide

## 1. What it is

revkit is a reverse-engineering platform. You give it a compiled program (a Windows `.exe`/`.dll`, a Linux or macOS binary, firmware,
or raw machine code) and it shows what the program does without the source code: assembly, control-flow graphs, cross-references,
strings, imports, and C-like pseudocode. It also lets you rename, comment, patch, debug, compare, script and share your findings.

It runs as a command-line tool, a Python library, and a local web app (also packaged as a Windows `revkit.exe`).

## 2. Why it is needed

- Source code is often missing: legacy software, third-party libraries, malware, firmware, closed-source drivers.
- Commercial tools cost a lot and are closed. revkit is scriptable, open, and runs headless in CI or batch pipelines.
- Common questions have common answers: "what APIs does it call?", "where is this string used?", "did the patch change this
  function?", "is this binary packed?", "does it have an unsafe `strcpy`?" revkit answers each with evidence (addresses, code).

Typical users: malware analysts, vulnerability researchers, compatibility engineers, students learning machine code.
Use it only on software you are authorised to analyse.

## 3. Features

**Loading**: PE, ELF, Mach-O (thin and fat), raw binary, DOS COM, Intel HEX, S-record, custom loaders by plugin.

**Analysis**: instruction decoding for x86/x64, ARM, Thumb, AArch64, MIPS, PowerPC, RISC-V, SPARC, M68K, 6502, SysZ; function discovery
(symbols, exception tables, call targets, prologues, pointer tables); no-return inference; jump-table recovery; thunks and import
stubs; strings (ASCII, UTF-16, UTF-8); cross-references.

**Views**: linear disassembly, flow graph, call graph, pseudocode, hex, function/name/string/import/export/segment lists, problems list,
bookmarks, search (bytes with wildcards, text, immediates, names, strings).

**Decompiler** (x86, x64, AArch64): C-like pseudocode with loops, if/else, switch, prototypes for known APIs, struct fields (`p->x`),
variable rename and retype, line-to-address sync.

**Editing**: rename, repeatable/anterior/posterior comments, types and prototypes, make code/data/string/function, undefine, set
function end, operand formats, unlimited undo/redo, saved databases (`.rkdb`).

**Types**: C declaration parser (structs, unions, enums, bitfields, arrays, function pointers, packed), bundled Win32/libc/POSIX prototypes.

**Recognition**: signature matching for library functions (own `.rsig` format, `.pat` import/export), private metadata server for sharing
function names, PDB symbol import.

**Patching**: patch bytes or assembly, NOP, invert or force branches, revert, write a patched copy (original untouched, PE checksum fixed).

**Debugging**: native Windows debugger (breakpoints, hardware watchpoints, conditions, step/over/out, registers, memory, threads,
backtrace, expressions); remote debugging over the GDB protocol for any architecture; emulator-backed stub for firmware and shellcode.

**Hard binaries**: entropy and packer indicators, emulator, **`--unpack`** (emulates the packer stub, analyses the unpacked code),
string-decoder execution, verified mixed-boolean-arithmetic simplifier, crypto constant detection.

**Security workflow**: vulnerability triage with evidence and review status, hardening checks (ASLR, DEP, stack protector), secret
detection, evidence-linked function explanations (optional LLM text, marked unverified), reports in Markdown/HTML/JSON.

**Automation**: Python scripting with scripting shims `rk`/`rkutil`/`rkapi`, plugin SDK (trusted, versioned), batch mode,
headless API, exports (asm, JSON, CSV, MAP, names script, Python, C header, DOT).

**Collaboration**: team server with roles, audit log and edit sync; secure sample vault with hash-chained audit log.

Exact status and limits of every capability: `docs/FEATURES.md`.

## 4. Install

```bash
python -m pip install -e .[test]
python -m revkit doctor          # checks dependencies
```

Windows without Python: use `dist\revkit.exe` (build it with `build_app.bat`).

## 5. How to use

### Web app (easiest)

```bash
python -m revkit serve program.exe            # opens the UI; add --unpack for packed files
```

Or double-click `revkit.exe`, choose a file, answer "packed?". Keep the printed URL private (it contains an access token).
Click names to jump, press `N` to rename, `F5` for pseudocode, `Space` for the graph, `X` for cross-references, `/` to search,
`Ctrl+S` to save. All shortcuts can be changed in Settings.

### Command line

```bash
revkit analyze sample.exe -o sample.rkdb          # analyse once, save
revkit functions sample.rkdb                      # list functions
revkit decompile sample.rkdb main                 # pseudocode
revkit xrefs sample.rkdb 0x401000                 # who uses this address
revkit rename sample.rkdb sub_401000 parse_config
revkit triage sample.rkdb                         # findings to review
revkit report sample.rkdb --format html -o report.html
revkit diff old.exe new.exe                       # what changed between versions
revkit analyze packed.exe --unpack -o u.rkdb      # packed input
revkit patch sample.rkdb 0x401076 --asm "mov eax, 1" -o patched.exe
revkit batch samples/ --outdir out -j 8 --decompile --report
```

### Python

```python
from revkit.api import Project
p = Project.load("sample.exe")                  # unpack=True for packed files
for f in p.functions()[:5]:
    print(f["name"], hex(f["addr"]))
print(p.decompile_text("main"))
p.rename("sub_401000", "parse_config")
p.save("sample.rkdb")
```

### Scripts and plugins

`revkit script sample.rkdb script.py` runs Python with `proj`, `db`, `image` and `rk`/`rkutil`/`rkapi` available.
Plugins: `revkit plugin new myplugin.py`, review the file, `revkit plugin trust myplugin.py`, `revkit plugin list sample.rkdb`.

### Debugging

```bash
revkit debug sample.exe --allow-exec            # runs the sample! use a VM
revkit stub firmware.bin --arch arm64 --base 0x0 --entry 0x0   # emulated GDB target
revkit debug firmware.bin --gdb 127.0.0.1:PORT  # attach to any GDB stub
```

### Typical investigation

1. `analyze` the file; open it in `serve`. 2. Read imports and strings; note suspicious APIs. 3. Follow a string to its function with `X`.
4. Press `F5`, rename functions and variables as you learn. 5. Run `triage` and `packer`. 6. Save, then export a report.

## 6. Safety

The sample is not executed unless you pass `--allow-exec`. The emulator and debugger are not sandboxes: analyse malware in a VM.
Findings and decompiled code are heuristics; verify important conclusions in the disassembly.

## 7. Limits

No decompiler for ARM32/MIPS/PPC/RISC-V; no native Linux/macOS debugger; no C++ demangling or vtable recovery; no vendor signature/type-library
formats; pure-Python speed (roughly 5–15 thousand instructions per second). See `docs/FEATURES.md` for the full list.
