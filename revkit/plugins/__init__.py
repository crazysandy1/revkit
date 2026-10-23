"""Plugin SDK: discovery, provenance/trust checks, lifecycle, actions with hotkeys, and event hooks.

A plugin is a Python file defining either `PLUGIN_ENTRY()` returning a `Plugin` instance, or a `Plugin` subclass named
`PLUGIN`. Plugins run in-process with the privileges of revkit (Python cannot sandbox them), so third-party plugins must be
explicitly trusted: trust is pinned to the SHA-256 of the file, shown with the plugin's declared permissions, and recorded
in ~/.revkit/trusted_plugins.json. Bundled plugins ship with the package and are trusted by default.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

PLUGIN_API_VERSION = 1


class PluginError(Exception):
    pass


@dataclass
class Action:
    name: str
    label: str
    callback: Callable[..., Any]
    hotkey: str = ""
    menu: str = "Edit/Plugins"
    tooltip: str = ""


class Plugin:
    """Base class. Override `init`/`run`/`term`; register extra `actions` and event `hooks`."""
    name = "unnamed"
    version = "0.0"
    description = ""
    hotkey = ""
    api_version = PLUGIN_API_VERSION
    permissions: List[str] = []     # informational: "filesystem-write", "network", "exec"
    author = ""

    def __init__(self):
        self.actions: List[Action] = []
        self.hooks: Dict[str, Callable] = {}
        self.proj = None

    def init(self, proj) -> bool:
        """Return False to decline loading for this database."""
        return True

    def run(self, proj, arg: Any = None) -> Any:
        raise NotImplementedError

    def term(self):
        pass


@dataclass
class LoadedPlugin:
    plugin: Plugin
    path: str
    sha256: str
    builtin: bool
    enabled: bool = True
    error: str = ""

    def info(self) -> dict:
        p = self.plugin
        return {"name": p.name, "version": p.version, "description": p.description, "hotkey": p.hotkey,
                "path": self.path, "sha256": self.sha256, "builtin": self.builtin, "enabled": self.enabled,
                "permissions": list(p.permissions), "author": p.author,
                "actions": [{"name": a.name, "label": a.label, "hotkey": a.hotkey, "menu": a.menu} for a in p.actions]}


def config_dir() -> str:
    d = os.environ.get("REVKIT_HOME") or os.path.join(os.path.expanduser("~"), ".revkit")
    os.makedirs(d, exist_ok=True)
    return d


def _trust_file() -> str:
    return os.path.join(config_dir(), "trusted_plugins.json")


def trusted_hashes() -> Dict[str, str]:
    try:
        with open(_trust_file(), encoding="utf8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def trust_plugin(path: str) -> str:
    h = file_sha256(path)
    t = trusted_hashes()
    t[h] = os.path.abspath(path)
    with open(_trust_file(), "w", encoding="utf8") as f:
        json.dump(t, f, indent=1)
    return h


def untrust_plugin(sha: str):
    t = trusted_hashes()
    t.pop(sha, None)
    with open(_trust_file(), "w", encoding="utf8") as f:
        json.dump(t, f, indent=1)


def file_sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def plugin_dirs() -> List[str]:
    dirs = [os.path.join(os.path.dirname(__file__), "builtin"), os.path.join(config_dir(), "plugins")]
    env = os.environ.get("REVKIT_PLUGINS")
    if env:
        dirs += env.split(os.pathsep)
    return [d for d in dirs if os.path.isdir(d)]


class PluginManager:
    def __init__(self, proj, allow_untrusted: bool = False):
        self.proj = proj
        self.allow_untrusted = allow_untrusted
        self.plugins: Dict[str, LoadedPlugin] = {}
        self.rejected: List[dict] = []
        self.hotkeys: Dict[str, Action] = {}

    def discover(self, dirs: Optional[List[str]] = None) -> List[dict]:
        builtin_dir = os.path.join(os.path.dirname(__file__), "builtin")
        for d in dirs or plugin_dirs():
            for fn in sorted(os.listdir(d)):
                if fn.endswith(".py") and not fn.startswith("_"):
                    p = os.path.join(d, fn)
                    try:
                        self.load(p, builtin=os.path.abspath(d) == os.path.abspath(builtin_dir))
                    except PluginError as e:
                        self.rejected.append({"path": p, "reason": str(e)})
        return [lp.info() for lp in self.plugins.values()]

    def load(self, path: str, builtin: bool = False) -> LoadedPlugin:
        sha = file_sha256(path)
        if not builtin and not self.allow_untrusted and sha not in trusted_hashes():
            raise PluginError(f"untrusted plugin (sha256 {sha[:16]}...). Review the source and trust it with "
                              f"`revkit plugin trust {path}`.")
        modname = f"revkit_plugin_{hashlib.md5(path.encode()).hexdigest()[:8]}"
        spec = importlib.util.spec_from_file_location(modname, path)
        if spec is None or spec.loader is None:
            raise PluginError("cannot import plugin")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[modname] = mod
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            raise PluginError(f"error while importing: {e}") from e
        if hasattr(mod, "PLUGIN_ENTRY"):
            plugin = mod.PLUGIN_ENTRY()
        elif hasattr(mod, "PLUGIN"):
            plugin = mod.PLUGIN() if isinstance(mod.PLUGIN, type) else mod.PLUGIN
        else:
            raise PluginError("module defines neither PLUGIN_ENTRY() nor PLUGIN")
        if not isinstance(plugin, Plugin):
            raise PluginError("plugin entry did not return a Plugin")
        if plugin.api_version != PLUGIN_API_VERSION:
            raise PluginError(f"plugin API version {plugin.api_version} is not supported (host is {PLUGIN_API_VERSION})")
        try:
            ok = plugin.init(self.proj)
        except Exception as e:
            raise PluginError(f"init failed: {e}") from e
        if ok is False:
            raise PluginError("plugin declined to load for this database")
        plugin.proj = self.proj
        lp = LoadedPlugin(plugin, path, sha, builtin)
        self.plugins[plugin.name] = lp
        if plugin.hotkey:
            self.hotkeys[plugin.hotkey] = Action(plugin.name, plugin.name, lambda p=plugin: p.run(self.proj), plugin.hotkey)
        for a in plugin.actions:
            if a.hotkey:
                self.hotkeys[a.hotkey] = a
        for ev, cb in plugin.hooks.items():
            self.proj.on(ev, cb)
        return lp

    def run(self, name: str, arg: Any = None) -> Any:
        lp = self.plugins.get(name)
        if lp is None:
            raise PluginError(f"no such plugin {name!r}")
        if not lp.enabled:
            raise PluginError(f"plugin {name!r} is disabled")
        return lp.plugin.run(self.proj, arg)

    def run_action(self, plugin: str, action: str, arg: Any = None) -> Any:
        lp = self.plugins.get(plugin)
        if lp is None:
            raise PluginError(f"no such plugin {plugin!r}")
        for a in lp.plugin.actions:
            if a.name == action:
                return a.callback(self.proj, arg)
        raise PluginError(f"no action {action!r} in {plugin!r}")

    def set_enabled(self, name: str, enabled: bool):
        self.plugins[name].enabled = enabled

    def unload_all(self):
        for lp in self.plugins.values():
            try:
                lp.plugin.term()
            except Exception:
                traceback.print_exc()
        self.plugins.clear()

    def list(self) -> List[dict]:
        return [lp.info() for lp in self.plugins.values()]


def create_plugin_template(path: str, name: str):
    """Write a documented starter plugin."""
    src = f'''"""{name}: describe what the plugin does."""
from revkit.plugins import Plugin, Action


class {name.title().replace("_", "")}(Plugin):
    name = "{name}"
    version = "0.1"
    description = "Example plugin"
    hotkey = ""
    permissions = []          # declare "filesystem-write", "network" or "exec" if needed

    def init(self, proj):
        self.actions.append(Action("hello", "Say hello", lambda p, arg=None: f"{{len(p.db.functions)}} functions"))
        return True

    def run(self, proj, arg=None):
        return {{"functions": len(proj.db.functions)}}


PLUGIN = {name.title().replace("_", "")}
'''
    with open(path, "w", encoding="utf8") as f:
        f.write(src)
