"""Malicious packages (OSV / OpenSSF): alerts when a widely used npm or PyPI package gets a malicious release."""
import time
import urllib.parse
import urllib.request
from datetime import timedelta

from . import util
from .breaches import count_text
from .util import log

OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
ECOSYSTEMS = ("npm", "PyPI")
INDEX_BYTES = 128 * 1024  # the index is newest first: the first ~2000 rows cover weeks


def recent_ids(ecosystem, since):
    """Malicious-package advisories (MAL-*) modified after `since`, newest first."""
    req = urllib.request.Request(f"{OSV_BUCKET}/{ecosystem}/modified_id.csv",
                                 headers={"User-Agent": util.UA, "Range": f"bytes=0-{INDEX_BYTES - 1}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        lines = r.read().decode("utf-8", "ignore").splitlines()
    out, newest = [], since
    for line in lines[:-1]:  # the last line may be cut off
        ts, _, vid = line.partition(",")
        if ts <= since:
            break
        newest = max(newest, ts)
        if vid.startswith("MAL-"):
            out.append(vid)
    return out, newest


def weekly_downloads(ecosystem, name):
    if ecosystem == "npm":
        d = util.http_json("https://api.npmjs.org/downloads/point/last-week/" + urllib.parse.quote(name, safe="@"),
                           timeout=20, retries=2)
        return (d or {}).get("downloads", 0)
    d = util.http_json(f"https://pypistats.org/api/packages/{urllib.parse.quote(name.lower())}/recent",
                       timeout=20, retries=2)
    return ((d or {}).get("data") or {}).get("last_week", 0)


class Packages:
    def __init__(self, cfg, db, notifier):
        self.cfg, self.db, self.notifier = cfg, db, notifier
        self.p = cfg["packages"]

    def run(self):
        if not self.p["enabled"]:
            return
        fresh = util.iso(util.now() - timedelta(days=3))
        checked = alerts = 0
        for eco in ECOSYSTEMS:
            key = "osv_last:" + eco
            last = self.db.get_meta(key)
            if last is None:  # first run: start from now, don't replay the history
                self.db.set_meta(key, util.iso(util.now()))
                continue
            ids, newest = recent_ids(eco, last)
            for vid in ids[:self.p["max_per_run"]]:
                try:
                    adv = util.http_json(f"{OSV_BUCKET}/{eco}/{vid}.json", timeout=20, retries=2)
                except Exception as e:
                    log.warning("OSV: could not fetch %s: %s", vid, e)
                    continue
                if adv.get("withdrawn") or (adv.get("published") or "") < fresh:
                    continue
                for a in adv.get("affected", []):
                    name = a.get("package", {}).get("name")
                    if not name or self.db.get_package(eco, name, vid):
                        continue
                    checked += 1
                    try:
                        downloads = weekly_downloads(eco, name)
                    except Exception as e:
                        log.warning("Downloads for %s/%s: %s", eco, name, e)
                        downloads = None
                    if eco == "PyPI":
                        time.sleep(1)  # pypistats allows a few requests per second
                    row = {"id": vid, "ecosystem": eco, "name": name, "versions": a.get("versions", [])[:10],
                           "downloads": downloads, "published": util.norm_ts(adv.get("published")),
                           "summary": adv.get("summary") or "", "details": util.shorten(adv.get("details"), 600),
                           "refs": [r["url"] for r in adv.get("references", []) if r.get("url", "").startswith("https://")][:5]}
                    self.db.add_package(row)
                    if downloads and downloads >= self.p["min_weekly_downloads"]:
                        self.send(row)
                        alerts += 1
            self.db.set_meta(key, newest)
        self.db.prune_packages(util.iso(util.now() - timedelta(days=35)))
        log.info("Malicious packages: %s checked, %s popular", checked, alerts)

    def send(self, p):
        versions = ", ".join(p["versions"][:5]) or "all versions"
        lines = [f"{p['ecosystem']} · {count_text(p['downloads'])} downloads a week",
                 f"Malicious versions: {versions}",
                 "If you installed it: remove those versions, rotate secrets and tokens on that machine.",
                 "", util.shorten(p["details"] or p["summary"], 240)]
        url = f"https://osv.dev/vulnerability/{p['id']}"
        self.notifier.send(f"☣ Malicious package: {p['name']}", "\n".join(lines), priority=5 if p["downloads"] >= 1e6 else 4,
                           click=url, actions=[("Details", url)])
