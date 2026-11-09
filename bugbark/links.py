"""Lists of malicious and phishing sites, exported for the dashboard's link checker (the check runs on the phone)."""
import urllib.request

from . import util
from .util import log


def parse_list(text):
    """Domains (one per line, hosts-file and adblock styles too) or full URLs; comments skipped."""
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        if line.startswith(("0.0.0.0 ", "127.0.0.1 ")):
            line = line.split()[1]
        line = line.removeprefix("||").removesuffix("^")
        if line.startswith(("http://", "https://")):
            out.add(line.rstrip("/").lower())
        elif "." in line and " " not in line and "/" not in line:
            out.add(line.lower())
    return out


class Links:
    def __init__(self, cfg, db):
        self.cfg, self.db = cfg, db
        self.l = cfg["links"]

    def run(self):
        if not self.l["enabled"]:
            return
        ok, total = 0, 0
        for source, url in self.l["lists"].items():
            try:
                req = urllib.request.Request(url, headers={"User-Agent": util.UA})
                with urllib.request.urlopen(req, timeout=120) as r:
                    entries = parse_list(r.read().decode("utf-8", "ignore"))
            except Exception as e:
                log.warning("Link list %s: download failed, keeping the old one: %s", source, e)
                continue
            if entries:
                self.db.set_blocklist(source, entries)
                ok += 1
                total += len(entries)
        if self.l["lists"] and not ok:
            raise RuntimeError("all link lists failed to download")
        self.db.set_meta("links_updated", util.iso(util.now()))
        log.info("Link lists: %s entries from %s lists", total, ok)

    def export(self):
        """{source: [domains...]} plus full URLs, and the most visited sites for look-alike checks."""
        lists = {}
        for r in self.db.q("SELECT entry, source FROM blocklist"):
            lists.setdefault(r["source"], []).append(r["entry"])
        top = [r["domain"] for r in self.db.q("SELECT domain FROM toplist WHERE rank <= 3000 ORDER BY rank")]
        return {"updated": self.db.get_meta("links_updated"), "lists": lists, "top": top}
