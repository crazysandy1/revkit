# Contributing

1. `python -m pip install -e .[test]`
2. `python -m pytest tests` must pass (about 2 minutes). Tests build their binaries with Keystone; some use files found on the
   machine and skip when absent.
3. Add a test with every behaviour change. Prefer fixtures with known expected results (`tests/fixtures.py`).
4. Do not add mock or placeholder analysis results. If a feature is partial, say so in `docs/FEATURES.md`.
5. Keep third-party licences in mind (`THIRD_PARTY_NOTICES.md`). Do not commit samples of real malware or copyrighted binaries.

Good first areas: decompiler for ARM32/MIPS/PPC/RISC-V, C++ demangling and vtable recovery, native Linux/macOS debugger, more
signature data, UI polish. Be respectful; see `CODE_OF_CONDUCT.md`.
