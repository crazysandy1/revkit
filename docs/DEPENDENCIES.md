# External dependencies

## Required (pip)

| Package | Used for |
|---|---|
| `capstone` >= 5 | instruction decoding for all architectures |
| `keystone-engine` | assembler for patching and for building test fixtures |
| `pefile` | PE parsing (the `.pdata` exception table is parsed by revkit itself) |
| `pyelftools` | ELF parsing, `.eh_frame` function starts |
| `unicorn` >= 2 | emulation, unpacking, string-decoder execution, emulator GDB stub |
| Python >= 3.10 | the whole platform (tested on 3.12, Windows 11) |

Install: `python -m pip install -e .[test]` or `python -m pip install capstone keystone-engine pefile pyelftools unicorn pytest`.

## Optional

| Tool | Needed for |
|---|---|
| Node.js / `npx` + network | `rea_bridge` plugin (REA `rea-agents@6.7.0` JavaScript/Electron analysis) |
| `ANTHROPIC_API_KEY` or `REVKIT_LLM_COMMAND` | `revkit explain --llm` (text is marked unverified; nothing is sent unless requested) |
| `gdbserver` / `lldb-server` / QEMU `-gdb` | native-OS debugging on Linux/macOS via `revkit debug --gdb host:port` |
| TLS certificate + key | `revkit team serve --cert --key` for non-localhost use |

## Platform notes

- Native debugger uses the Win32 debugging API (ctypes); no extra packages. It executes the sample: it is blocked unless
  `--allow-exec` is given. Use an isolated VM.
- REA providers (Ghidra, Hopper, Kuna) were not configured on the development host, so REA native providers were not used.
  revkit does not depend on them.
- No data leaves the machine except where explicitly requested (LLM explanations, team/metadata server you run yourself, `npx`
  package download for `rea_bridge`).
