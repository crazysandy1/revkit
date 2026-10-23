"""Annotate cryptographic constants (S-boxes, IVs, CRC tables, alphabets) found in the database."""
from revkit.plugins import Action, Plugin
from revkit.crypto import find_crypto_constants


class CryptoScan(Plugin):
    name = "crypto_scan"
    version = "1.0"
    description = "Find crypto constants and label them in the database"
    hotkey = "Ctrl-Alt-C"

    def run(self, proj, arg=None):
        hits = find_crypto_constants(proj.db)
        n = 0
        for h in hits:
            a = h["addr"]
            label = f"{h['name']}_{h['detail'].split()[0].replace('-', '_')}"
            if a in proj.db.insns:
                proj.db.set_comment(a, f"crypto: {h['name']} ({h['detail']})")
            else:
                proj.db.set_name(a, f"{label}_{a:X}", user=False, force=True)
                proj.db.set_comment(a, f"crypto: {h['name']} ({h['detail']})")
            n += 1
        return {"annotated": n, "hits": hits}


PLUGIN = CryptoScan
