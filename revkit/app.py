"""Desktop launcher: pick a file (or pass one), optionally unpack it, then open the analysis UI in the browser.

Used as the entry point of the packaged `revkit.exe`. With arguments it behaves exactly like the CLI (`revkit.exe analyze ...`);
with no arguments it opens a file picker and starts the web UI.
"""
from __future__ import annotations

import os
import sys


def _pick():
    import tkinter as tk
    from tkinter import filedialog, messagebox
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askopenfilename(title="revkit: choose a binary or .rkdb database")
    if not path:
        return None, False
    unpack = False
    if not path.endswith(".rkdb"):
        unpack = messagebox.askyesno("revkit", "Is this file packed?\n\nYes = emulate the packer stub first and analyse the unpacked code.")
    root.destroy()
    return path, unpack


def main() -> int:
    if len(sys.argv) > 1:
        from revkit.cli import main as cli_main
        return cli_main(sys.argv[1:])
    path, unpack = _pick()
    if not path:
        return 0
    from revkit.cli import main as cli_main
    args = ["serve", path]
    if unpack:
        args.append("--unpack")
    print(f"Loading {path} ... (analysis can take a while for large files)", flush=True)
    return cli_main(args)


if __name__ == "__main__":
    sys.exit(main())
