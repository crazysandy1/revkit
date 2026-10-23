# Security policy

revkit analyses untrusted binaries. Report vulnerabilities privately (GitHub "Report a vulnerability" or the maintainer's email)
instead of opening a public issue. Include version, OS, a minimal sample or steps, and impact.

Design rules: samples are never executed unless `--allow-exec` is given; the web UI binds to localhost with a per-run token;
plugins are in-process and must be SHA-256 trusted; the debugger and emulator are not a sandbox, so analyse malware in an isolated VM.
