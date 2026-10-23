import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fixtures as F  # noqa: E402
from revkit.api import Project  # noqa: E402


@pytest.fixture(scope="session")
def tmp_session(tmp_path_factory):
    return tmp_path_factory.mktemp("revkit")


@pytest.fixture(scope="session")
def x64():
    code, labels = F.build_x64()
    syms = {n: (labels[n], 0, "func") for n in F.X64_FUNCS}
    elf = F.build_elf64(code, 0x401000, labels["_start"], syms)
    return elf, labels, code


@pytest.fixture(scope="session")
def x64_path(tmp_session, x64):
    p = tmp_session / "t64.elf"
    p.write_bytes(x64[0])
    return str(p)


@pytest.fixture()
def proj(x64_path):
    """Fresh analysed project per test (analysis is fast)."""
    return Project.load(x64_path)


@pytest.fixture(scope="session")
def labels(x64):
    return x64[1]


@pytest.fixture(scope="session")
def pe_sample(tmp_session):
    pe, info = F.build_pe_sample()
    p = tmp_session / "t.exe"
    p.write_bytes(pe)
    return str(p), info


@pytest.fixture(scope="session")
def arm64_path(tmp_session):
    pe, labels = F.build_arm64_elf()
    p = tmp_session / "a64.elf"
    p.write_bytes(pe)
    return str(p), labels


@pytest.fixture(scope="session")
def macho_path(tmp_session, x64):
    code, labels = x64[2], x64[1]
    mo = F.build_macho64(code, labels["main"] - 0x401000, {"_main": labels["main"] - 0x401000, "_fact": labels["fact"] - 0x401000})
    p = tmp_session / "t.macho"
    p.write_bytes(mo)
    return str(p)


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Never touch the real ~/.revkit from tests."""
    monkeypatch.setenv("REVKIT_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("REVKIT_VAULT", str(tmp_path / "vault"))
    yield
