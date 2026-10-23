# Third-party notices

revkit's own source is MIT licensed (`LICENSE`). It depends on these libraries, installed separately from PyPI:

| Package | License (as published on PyPI) | Note |
|---|---|---|
| capstone | BSD | disassembly |
| keystone-engine | GPL-2.0 (Keystone) | assembler; revkit imports it at run time |
| unicorn | GPL-2.0 / BSD per upstream metadata | emulation |
| pefile | MIT | PE parsing |
| pyelftools | Public domain | ELF parsing |

**Binary distribution warning.** `dist/revkit.exe` bundles keystone-engine and unicorn. Distributing that binary means you must
satisfy their GPL-2.0 terms (for example by offering corresponding source and licensing the combined binary under GPL-2.0).
Source-only distribution of revkit with these as pip dependencies does not bundle them. Have legal review confirm the licence
choice before publishing binaries. If you want a permissive binary, replace keystone/unicorn first.

Typelibs in `revkit/typelibs/` are hand-written declarations of public API signatures, not copies of vendor headers.
