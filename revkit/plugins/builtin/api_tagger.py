"""Tag functions with capability comments derived from the APIs they call."""
from revkit.explain import explain_function
from revkit.plugins import Plugin


class ApiTagger(Plugin):
    name = "api_tagger"
    version = "1.0"
    description = "Add '[capability]' function comments from imported API usage"

    def run(self, proj, arg=None):
        tagged = {}
        for a in list(proj.db.functions):
            if "thunk" in proj.db.functions[a].flags:
                continue
            ex = explain_function(proj, a)
            caps = [b["claim"].split(" via ")[0].replace("Performs ", "") for b in ex["evidence_bullets"] if b["claim"].startswith("Performs ")]
            if caps:
                existing = proj.db.func_comments.get(a, "")
                tag = "[" + ", ".join(caps) + "]"
                if tag not in existing:
                    proj.db.set_func_comment(a, (existing + "\n" if existing else "") + tag)
                tagged[a] = caps
        return {"tagged_functions": len(tagged), "detail": {hex(k): v for k, v in list(tagged.items())[:50]}}


PLUGIN = ApiTagger
