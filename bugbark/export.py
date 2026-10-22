"""Static export of the dashboard (for GitHub Pages): the same page, with the API saved as JSON files."""
import json
import os
import shutil

from .web import STATIC, App


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))


def export_site(cfg, db, engine, notifier, out):
    app = App(cfg, db, engine, notifier)
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as f:
        page = f.read().replace("<!--STATIC-->", "<script>window.CVE_STATIC = true;</script>")
    with open(os.path.join(out, "index.html"), "w", encoding="utf-8") as f:
        f.write(page)
    for name in ("manifest.webmanifest", "icon.svg"):
        shutil.copy(os.path.join(STATIC, name), out)
    open(os.path.join(out, ".nojekyll"), "w").close()

    ids = set()
    for view, limit in (("important", 500), ("kev", 300), ("all", 300)):
        d = app.cves({"view": [view]}, limit=limit)
        _write(os.path.join(out, "api", f"cves-{view}.json"), d)
        ids.update(i["id"] for i in d["items"])
    for cid in ids:
        _write(os.path.join(out, "api", "cve", f"{cid}.json"), app.cve(cid, mark_seen=False))
    _write(os.path.join(out, "api", "monitors.json"), app.monitors())
    _write(os.path.join(out, "api", "health.json"), app.health())
    return len(ids)
