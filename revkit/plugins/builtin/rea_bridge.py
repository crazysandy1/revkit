"""Bridge to the REA toolchain (rea-agents) for targets revkit's native engine does not cover.

REA's JavaScript/ASAR application analysis needs no native engine, only Node.js. This plugin shells out to the
`rea-agents` CLI (via an installed `rea` command or `npx -y rea-agents@<pinned>`) and returns its Evidence JSON.
Requires: Node.js/npm and, for the first `npx` run, network access to the npm registry.
"""
import json
import shutil
import subprocess

from revkit.plugins import Plugin

REA_PACKAGE = "rea-agents@6.7.0"


class ReaBridge(Plugin):
    name = "rea_bridge"
    version = "1.0"
    description = "Analyze a JavaScript tree / Electron ASAR with the REA CLI (external dependency)"
    permissions = ["exec", "network"]

    def run(self, proj, arg=None):
        if not arg:
            raise ValueError("pass the absolute path of an extracted JavaScript tree or .asar file")
        exe = shutil.which("rea")
        cmd = [exe] if exe else (["npx", "-y", REA_PACKAGE] if shutil.which("npx") else None)
        if cmd is None:
            raise RuntimeError("neither `rea` nor `npx` is on PATH; install Node.js to use this bridge")
        p = subprocess.run(cmd + ["analyze-javascript-application", str(arg), "--json"], capture_output=True, text=True, timeout=600)
        if p.returncode != 0:
            raise RuntimeError(p.stderr.strip()[:500] or "rea command failed")
        try:
            return json.loads(p.stdout)
        except ValueError:
            return {"raw": p.stdout[:20000]}


PLUGIN = ReaBridge
