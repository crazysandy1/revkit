# PyInstaller spec: python -m PyInstaller revkit.spec --noconfirm
from PyInstaller.utils.hooks import collect_all
datas, binaries, hidden = [], [], ["revkit.cli", "revkit.web.server", "tkinter"]
for pkg in ("capstone", "keystone", "unicorn", "pefile", "elftools"):
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hidden += h
datas += [("revkit/typelibs", "revkit/typelibs"), ("revkit/web/static", "revkit/web/static"),
          ("revkit/plugins/builtin", "revkit/plugins/builtin")]
a = Analysis(["revkit/app.py"], pathex=["."], binaries=binaries, datas=datas, hiddenimports=hidden)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="revkit", console=True, upx=False)
