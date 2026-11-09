"""Data breaches (Have I Been Pwned) and ransomware victims (ransomware.live)."""
import csv
import hashlib
import html
import io
import re
import urllib.request
from datetime import timedelta

from . import util
from .util import log

HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"
VICTIMS_URL = "https://api.ransomware.live/v2/recentvictims"
TRANCO_LATEST = "https://tranco-list.eu/api/lists/date/latest"
TOPLIST_SIZE = 100000


def count_text(n):
    if n >= 1e9:
        return f"{n / 1e9:.1f}B".replace(".0B", "B")
    if n >= 1e6:
        return f"{n / 1e6:.1f}M".replace(".0M", "M")
    if n >= 1e3:
        return f"{n / 1e3:.0f}K"
    return str(n)


def strip_html(s):
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", s or "")).split())


def site_of(domain):
    """'https://www.example.co.uk/en' -> 'example.co.uk'"""
    d = (domain or "").strip().lower().split("://")[-1].split("/")[0].split(":")[0]
    d = d.removeprefix("www.")
    return d if "." in d and " " not in d else ""


class Breaches:
    def __init__(self, cfg, db, notifier):
        self.cfg, self.db, self.notifier = cfg, db, notifier
        self.b = cfg["breaches"]
        self.r = cfg["ransomware"]

    # --- Have I Been Pwned ---
    def run_hibp(self):
        if not self.b["enabled"]:
            return
        data = util.http_json(HIBP_URL, timeout=60)
        last = self.db.get_meta("hibp_last")
        keep = util.iso(util.now() - timedelta(days=90))
        new = []
        for b in data:
            added = util.norm_ts(b.get("AddedDate"))
            if not added or added < keep or b.get("IsFabricated") or b.get("IsSpamList") or not b.get("IsVerified"):
                continue
            row = {
                "name": b["Name"], "title": b.get("Title") or b["Name"], "domain": b.get("Domain") or "",
                "added": added, "breach_date": b.get("BreachDate") or "", "count": b.get("PwnCount") or 0,
                "data_classes": b.get("DataClasses") or [], "description": strip_html(b.get("Description")),
                "stealer": bool(b.get("IsStealerLog") or b.get("IsMalware")),
            }
            self.db.add_breach(row)
            if last and added > last:
                new.append(row)
        self.db.prune_breaches(keep)
        newest = max((util.norm_ts(b.get("AddedDate")) or "" for b in data), default="")
        if newest:
            self.db.set_meta("hibp_last", newest)
        big = [b for b in new if b["count"] >= self.b["min_accounts"] and not b["stealer"]]
        log.info("HIBP: %s new breaches, %s big", len(new), len(big))
        for b in sorted(big, key=lambda b: b["count"], reverse=True)[:3]:
            self.send_breach(b)

    def send_breach(self, b):
        leaked = b["data_classes"][:6]
        lines = [f"{count_text(b['count'])} accounts" + (f" · breached {b['breach_date']}" if b["breach_date"] else ""),
                 "Leaked: " + ", ".join(leaked) + (f" +{len(b['data_classes']) - 6} more" if len(b["data_classes"]) > 6 else "")]
        if any(c in b["data_classes"] for c in ("Passwords", "Password hints")):
            lines.append("⚠ Passwords included: change yours if you used this service")
        lines += ["", util.shorten(b["description"], 260)]
        url = f"https://haveibeenpwned.com/PwnedWebsites#{b['name']}"
        self.notifier.send(f"💧 Data breach: {b['title']} · {count_text(b['count'])}", "\n".join(lines),
                           priority=4 if b["count"] >= 10 * self.b["min_accounts"] else 3, click=url,
                           actions=[("Check your e-mail", "https://haveibeenpwned.com/"), ("Details", url)])

    # --- ransomware.live ---
    def run_ransomware(self):
        if not self.r["enabled"]:
            return
        self._refresh_toplist()
        data = util.http_json(VICTIMS_URL, timeout=60) or []
        first_run = self.db.get_meta("ransomware_init") is None
        new = []
        for v in data:
            url = v.get("url") or ""
            row = {
                "id": hashlib.sha1((url or f"{v.get('group')}|{v.get('victim')}").encode()).hexdigest()[:16],
                "victim": (v.get("victim") or "").strip(), "site": site_of(v.get("domain")),
                "grp": v.get("group") or "", "country": v.get("country") or "",
                "sector": "" if v.get("activity") in (None, "", "Not Found") else v["activity"],
                "discovered": util.norm_ts(v.get("discovered")) or util.iso(util.now()),
                "url": url if url.startswith("https://") else "",
            }
            row["rank"] = self.db.site_rank(row["site"]) if row["site"] else None
            if self.db.add_victim(row):
                new.append(row)
        self.db.prune_victims(util.iso(util.now() - timedelta(days=35)))
        big = [v for v in new if v["rank"] and v["rank"] <= self.r["max_rank"]]
        log.info("Ransomware: %s new victims, %s notable", len(new), len(big))
        if not first_run:
            for v in sorted(big, key=lambda v: v["rank"])[:3]:
                self.send_victim(v)
        self.db.set_meta("ransomware_init", "1")

    def send_victim(self, v):
        where = " · ".join(x for x in (v["country"], v["sector"]) if x)
        lines = [f"Claimed by the {v['grp']} gang on its leak site" + (f" · {where}" if where else ""),
                 f"Its website is among the world's top {self._round_rank(v['rank'])} sites.",
                 "A claim, not a confirmed breach: wait for the company's statement."]
        actions = [("Details", v["url"])] if v["url"] else []
        panel = util.panel_url(self.cfg, "report")
        if panel:
            actions.append(("Weekly report", panel))
        name = v["victim"] if v["site"] in v["victim"].lower() else f"{v['victim']} ({v['site']})"
        self.notifier.send(f"💀 Ransomware: {name}", "\n".join(lines), priority=3,
                           click=v["url"] or panel, actions=actions)

    @staticmethod
    def _round_rank(rank):
        for step in (100, 1000, 5000, 10000, 25000, 50000, 100000):
            if rank <= step:
                return f"{step:,}"
        return f"{rank:,}"

    def _refresh_toplist(self):
        """Tranco's list of the most visited sites, refreshed weekly: a ranked site means a sizeable company."""
        last = util.parse_ts(self.db.get_meta("toplist_updated"))
        if last and util.now() - last < timedelta(days=7):
            return
        try:
            info = util.http_json(TRANCO_LATEST, timeout=30)
            url = f"https://tranco-list.eu/download/{info['list_id']}/{TOPLIST_SIZE}"
            req = urllib.request.Request(url, headers={"User-Agent": util.UA})
            with urllib.request.urlopen(req, timeout=120) as r:
                text = r.read().decode("utf-8", "ignore")
            rows = [(d.strip().lower(), int(n)) for n, d in csv.reader(io.StringIO(text)) if n.isdigit()]
        except Exception as e:
            log.warning("Top sites list: download failed, keeping the old one: %s", e)
            return
        if len(rows) > 1000:
            self.db.set_toplist(rows)
            self.db.set_meta("toplist_updated", util.iso(util.now()))
            log.info("Top sites list: %s domains", len(rows))
