"""Collects fresh CVEs (NVD), exploited-in-the-wild ones (CISA KEV) and EPSS scores, and picks the major ones."""
import re
import time
import urllib.error
import urllib.parse
from datetime import timedelta

from . import cveorg, util
from .explain import explain
from .news import News
from .exploits import exploit_refs, github_pocs
from .util import log

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

LEVEL_RANK = {"kev": 3, "critical": 2, "high": 1, None: 0}
# Reasons that re-send an already notified CVE, because it became more dangerous
RENOTIFY_KEYS = {"kev", "poc", "epss"}
UPDATE_PREFIX = {"kev": "Now exploited: ", "poc": "Exploit published: ", "epss": "Risk increased: "}
NA = {"", "n/a", "na", "-", "*", "unspecified", "unknown"}


def severity_for(score):
    if score is None:
        return None
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def best_metric(metrics):
    """Highest CVSS score across all sources (NVD and the vendor)."""
    best = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key, []):
            d = m.get("cvssData", {})
            if d.get("baseScore") is not None and (best is None or d["baseScore"] > best[0]):
                best = (d["baseScore"], d.get("vectorString", ""))
    if best is None:
        for m in metrics.get("cvssMetricV2", []):
            d = m.get("cvssData", {})
            if d.get("baseScore") is not None:
                best = (d["baseScore"], d.get("vectorString", ""))
    return best or (None, "")


def fmt_range(version, lt=None, le=None):
    base = version if version and version.lower() not in NA and version != "0" else None
    if lt and lt not in NA:
        return f"{base} to before {lt}" if base else f"before {lt}"
    if le and le not in NA:
        return f"{base} to {le} inclusive" if base else f"up to {le} inclusive"
    return base or "all versions"


def pretty(s):
    s = (s or "").replace("_", " ").strip()
    return s.title() if s.islower() and len(s) > 3 else s


def parse_affected(c):
    """Affected products: [{vendor, product, versions[], fixed[]}]."""
    out = {}
    for a in c.get("affected", []):
        for ad in a.get("affectedData", []):
            vendor, product = ad.get("vendor") or "", ad.get("product") or ""
            # The same product often comes from several sources (CNA, CISA-ADP) with different casing
            item = out.setdefault((vendor.lower(), product.lower()), {"vendor": vendor, "product": product,
                                                                      "versions": [], "fixed": []})
            duplicate = bool(item["versions"])
            for v in ad.get("versions", []):
                if v.get("status") != "affected":
                    continue
                if not duplicate:
                    item["versions"].append(fmt_range(v.get("version"), v.get("lessThan"), v.get("lessThanOrEqual")))
                if v.get("lessThan") and v["lessThan"] not in NA and v["lessThan"] not in item["fixed"]:
                    item["fixed"].append(v["lessThan"])
            if not item["versions"] and ad.get("defaultStatus") == "affected":
                item["versions"].append("all versions")
    if not out:
        for conf in c.get("configurations", []):
            for node in conf.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if not m.get("vulnerable"):
                        continue
                    p = m.get("criteria", "").split(":")
                    if len(p) < 6:
                        continue
                    vendor, product, ver = pretty(p[3]), pretty(p[4]), p[5]
                    item = out.setdefault((vendor, product), {"vendor": vendor, "product": product,
                                                              "versions": [], "fixed": []})
                    start = m.get("versionStartIncluding") or m.get("versionStartExcluding")
                    lt, le = m.get("versionEndExcluding"), m.get("versionEndIncluding")
                    item["versions"].append(fmt_range(start or (ver if not (lt or le) else None), lt, le))
                    if lt:
                        item["fixed"].append(lt)
    return list(out.values())


def display_name(affected):
    for a in affected:
        vendor = "" if a["vendor"].lower() in NA else a["vendor"]
        product = "" if a["product"].lower() in NA else a["product"]
        if not product:
            continue
        if vendor and vendor.split()[0].lower() not in product.lower():
            return f"{vendor} {product}", vendor
        return product, vendor or product
    return None, None


def term_regex(term):
    return re.compile(r"(?<![\w./-])" + re.escape(term) + r"(?![\w-]|[./]\w)", re.I)


class Matcher:
    """Decides whether a CVE belongs to a major vendor or to a product on the watch list."""

    def __init__(self, terms):
        self.terms = [(t, term_regex(t), re.sub(r"[^a-z0-9]", "", t.lower())) for t in terms]

    def find(self, text):
        for t, rx, _ in self.terms:
            if rx.search(text):
                return t
        return None

    def match(self, data, always_desc=False):
        structured = " ; ".join(f"{a['vendor']} {a['product']}" for a in data.get("affected", [])
                                if (a["vendor"] + a["product"]).lower() not in NA)
        if structured:
            hit = self.find(structured)
            if hit:
                return hit
        # NVD gives an e-mail (secure@microsoft.com), CVE.org a short name (microsoft)
        domain = data.get("source", "").split("@")[-1].lower()
        labels = domain.split(".")[:-1] if "." in domain else [domain]
        for t, _, n in self.terms:
            if len(n) >= 3 and any(l == n or (len(n) >= 5 and l.startswith(n)) for l in labels):
                return t
        if always_desc or not structured:
            return self.find(data.get("description", "")[:500])
        return None


def parse_nvd(item):
    c = item["cve"]
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    score, vector = best_metric(c.get("metrics", {}))
    cwe = None
    for w in c.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwe = d["value"]
                break
        if cwe:
            break
    affected = parse_affected(c)
    product, vendor = display_name(affected)
    fixed = []
    for a in affected:
        for f in a["fixed"]:
            if f not in fixed:
                fixed.append(f)
    refs = [{"url": r["url"], "tags": r.get("tags", [])} for r in c.get("references", [])]
    return {
        "id": c["id"],
        "published": util.norm_ts(c.get("published")),
        "modified": util.norm_ts(c.get("lastModified")),
        "score": score,
        "severity": severity_for(score),
        "vendor": vendor,
        "product": product,
        "rejected": c.get("vulnStatus") == "Rejected",
        "data": {
            "description": desc,
            "vector": vector,
            "cwe": cwe,
            "source": c.get("sourceIdentifier", ""),
            "nvd_status": c.get("vulnStatus"),
            "affected": affected,
            "fixed": fixed,
            "refs": refs,
        },
    }


CVEORG_LIMIT = 150  # records fetched per run; NVD catches up on the rest
GROUP_MIN = 3  # this many CVEs from one vendor in one check are sent as a single message


def vendor_key(row):
    name = row["vendor"] or row["product"] or row["id"]
    return name.split()[0].lower()


def iso_date(d):
    return f"{d}T00:00:00Z" if d and len(d) == 10 else util.norm_ts(d)


class Engine:
    def __init__(self, cfg, db, notifier):
        self.cfg, self.db, self.notifier = cfg, db, notifier
        self.c = cfg["cve"]
        self.vendors = Matcher(self.c["vendors"])
        self.watch = Matcher(self.c["watch"]) if self.c["watch"] else None
        self.news = News(cfg, db, notifier)

    # --- NVD ---
    def _nvd(self, params):
        url = NVD_URL + "?" + urllib.parse.urlencode(params)
        if not self.c["nvd_api_key"]:
            return util.http_json(url, timeout=90, retries=4)
        try:
            return util.http_json(url, headers={"apiKey": self.c["nvd_api_key"]}, timeout=90, retries=4)
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            # NVD answers 404 to a wrong or not yet activated key: carry on without it
            key = self.c["nvd_api_key"]
            shape = "looks right" if re.fullmatch(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", key) else "not the usual xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx form"
            log.warning("NVD rejected the API key (HTTP 404), continuing without it. Check the NVD_API_KEY secret: "
                        "%s characters, %s.", len(key), shape)
            self.c["nvd_api_key"] = ""
            return util.http_json(url, timeout=90, retries=4)

    def _nvd_pause(self):
        # NVD rate limit: 5 requests per 30 s without a key, 50 with one
        time.sleep(0.8 if self.c["nvd_api_key"] else 6.5)

    def fetch_one(self, cid):
        d = self._nvd({"cveId": cid})
        items = d.get("vulnerabilities", []) if d else []
        if not items:
            return None
        c = parse_nvd(items[0])
        self._store(c)
        return c

    def _store(self, c):
        self.db.upsert_cve(c, util.iso(util.now()))
        k = self.db.get_kev(c["id"])
        if k:
            self.db.set_kev_flag(c["id"], k["date_added"])

    def run_nvd(self):
        end = util.now()
        last = util.parse_ts(self.db.get_meta("nvd_last"))
        first_run = last is None
        start = end - timedelta(days=self.c["initial_days"]) if first_run else last - timedelta(minutes=10)
        start = max(start, end - timedelta(days=7))
        min_pub = util.iso(end - timedelta(days=self.c["keep_days"]))
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        params = {"lastModStartDate": start.strftime(fmt), "lastModEndDate": end.strftime(fmt),
                  "resultsPerPage": 200, "startIndex": 0}
        ids = []
        total = None
        while True:
            d = self._nvd(params)
            total = d.get("totalResults", 0)
            for item in d.get("vulnerabilities", []):
                c = parse_nvd(item)
                if c["rejected"] or not c["published"]:
                    continue
                if c["published"] < min_pub and not self.db.get_kev(c["id"]):
                    continue
                self._store(c)
                ids.append(c["id"])
            params["startIndex"] += d.get("resultsPerPage", 0) or 200
            if params["startIndex"] >= total:
                break
            self._nvd_pause()
        log.info("NVD: %s changes, %s recent CVEs stored", total, len(ids))
        found = self.process(ids, suppress=first_run)
        self.db.set_meta("nvd_last", util.iso(end))
        self.db.prune_cves(min_pub, util.iso(end - timedelta(days=3)), util.iso(end - timedelta(days=30)))
        if first_run:
            kev = sum(1 for i in ids if (self.db.get_cve(i) or {}).get("kev"))
            self.notifier.send(
                "✅ BugBark is running",
                f"Major vulnerabilities in the last {self.c['initial_days']} day{'s' if self.c['initial_days'] != 1 else ''}: {found}"
                + (f", {kev} already exploited in the wild" if kev else "")
                + ". New ones will show up here.",
                priority=3, click=util.panel_url(self.cfg),
            )

    # --- CVE.org ---
    def run_cveorg(self):
        """Picks up CVEs minutes after publication; NVD's fuller record replaces them once it has them."""
        last = self.db.get_meta("cveorg_last")
        if last is None:  # the first NVD load already covers the past
            self.db.set_meta("cveorg_last", util.iso(util.now()))
            return
        changes, newest = cveorg.changes_since(last)
        fresh = util.iso(util.now() - timedelta(days=3))
        todo = []
        for cid, (url, kind) in changes.items():
            row = self.db.get_cve(cid)
            # Only brand-new CVEs, and updates to the ones NVD doesn't have yet; older CVEs are NVD's job
            if url and (row["data"].get("origin") == "cve.org" if row else kind == "new"):
                todo.append(cid)
        ids = []
        for cid in todo[:CVEORG_LIMIT]:
            try:
                c = cveorg.fetch_record(changes[cid][0])
            except Exception as e:
                log.warning("CVE.org: could not fetch %s: %s", cid, e)
                continue
            if c["rejected"] or not c["published"] or c["published"] < fresh:
                continue
            self._store(c)
            ids.append(cid)
        log.info("CVE.org: %s changes, %s fresh CVEs stored", len(changes), len(ids))
        self.process(ids)
        self.db.set_meta("cveorg_last", newest)

    # --- CISA KEV ---
    def run_kev(self):
        d = util.http_json(KEV_URL, timeout=60)
        known = self.db.kev_ids()
        first_run = not known
        new = []
        for v in d.get("vulnerabilities", []):
            if v["cveID"] in known:
                continue
            new.append({
                "id": v["cveID"],
                "date_added": iso_date(v.get("dateAdded")),
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "description": v.get("shortDescription", ""),
                "action": v.get("requiredAction", ""),
                "due": v.get("dueDate", ""),
                "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
                "notes": v.get("notes", ""),
            })
        if not new:
            return
        self.db.add_kev(new)
        log.info("KEV: %s new entries%s", len(new), " (initial load)" if first_run else "")
        if first_run:
            for e in new:
                self.db.set_kev_flag(e["id"], e["date_added"])
            return
        ids = []
        for e in new:
            if not self.db.get_cve(e["id"]):
                try:
                    self._nvd_pause()
                    if not self.fetch_one(e["id"]):
                        self._kev_stub(e)
                except Exception as ex:
                    log.warning("NVD: could not fetch %s: %s", e["id"], ex)
                    self._kev_stub(e)
            self.db.set_kev_flag(e["id"], e["date_added"])
            ids.append(e["id"])
        self.process(ids)

    def _kev_stub(self, e):
        """CVE record built from KEV data while NVD is unavailable."""
        self.db.upsert_cve({
            "id": e["id"], "published": e["date_added"], "modified": e["date_added"],
            "score": None, "severity": None, "vendor": e["vendor"],
            "product": f"{e['vendor']} {e['product']}".strip(),
            "data": {"description": e["description"], "vector": "", "cwe": None, "source": "",
                     "affected": [], "fixed": [], "refs": []},
        }, util.iso(util.now()))

    # --- EPSS ---
    def run_epss(self):
        since = util.iso(util.now() - timedelta(days=30))
        rows = self.db.q("""SELECT id FROM cves WHERE published >= ? AND status != 'dismissed'
                            AND (score IS NULL OR score >= 7)""", (since,))
        ids = [r["id"] for r in rows]
        first_run = self.db.get_meta("epss_init") is None
        updates = []
        for i in range(0, len(ids), 80):
            d = util.http_json(EPSS_URL + "?cve=" + ",".join(ids[i:i + 80]), timeout=60)
            for e in d.get("data", []):
                updates.append((float(e["epss"]), float(e["percentile"]), e["cve"]))
            time.sleep(1)
        self.db.set_epss(updates)
        log.info("EPSS: %s scores updated", len(updates))
        self.process([u[2] for u in updates], suppress=first_run)
        if updates:
            self.db.set_meta("epss_init", "1")

    # --- public exploits ---
    def run_exploits(self):
        """Looks for PoC repositories on GitHub for recent major CVEs; rechecks each one every 12 hours."""
        if not self.c["poc_search"]:
            return
        now = util.now()
        since, recheck = util.iso(now - timedelta(days=14)), util.iso(now - timedelta(hours=12))
        candidates = """FROM cves WHERE (important=1 OR kev=1) AND published >= ? AND status != 'dismissed'
                        AND poc = '[]' AND (poc_checked IS NULL OR poc_checked < ?)"""
        rows = self.db.q(f"SELECT id {candidates} ORDER BY poc_checked IS NOT NULL, published DESC LIMIT 25",
                         (since, recheck))
        # On the first sweep (and after upgrading) don't re-alert on CVEs that already had exploits
        first_sweep = self.db.get_meta("poc_init") is None
        token = self.c["github_token"]
        found = []
        for i, r in enumerate(rows):
            if i:
                time.sleep(2.2 if token else 6.5)  # GitHub search limit: 30/min with a token, 10/min without
            try:
                pocs = github_pocs(r["id"], token)
            except Exception as e:
                log.warning("GitHub search failed for %s: %s", r["id"], e)
                break
            self.db.set_poc(r["id"], pocs, util.iso(util.now()))
            if pocs:
                found.append(r["id"])
        log.info("Exploits: checked %s CVEs, public PoC for %s", len(rows), len(found))
        self.process(found, suppress=first_sweep)
        if first_sweep and not self.db.q(f"SELECT 1 {candidates} AND poc_checked IS NULL LIMIT 1", (since, recheck)):
            self.db.set_meta("poc_init", "1")

    # --- daily digest ---
    def run_digest(self):
        d = self.cfg["digest"]
        now = util.now()
        today = now.strftime("%Y-%m-%d")
        if not d["enabled"] or now.hour < d["hour_utc"] or self.db.get_meta("digest_last") == today:
            return
        if self.db.get_meta("nvd_last") is None:
            return
        since = util.iso(now - timedelta(hours=24))
        rows = self.db.q("""SELECT * FROM cves WHERE important=1 AND status != 'dismissed'
                            AND (published >= ? OR kev_added >= ?)""", (since, since))
        rows.sort(key=lambda r: (LEVEL_RANK[r["level"]], bool(r["poc"]), r["score"] or 0), reverse=True)
        kev = sum(1 for r in rows if r["kev"])
        poc = sum(1 for r in rows if r["poc"])
        lines = [f"Last 24h: {len(rows)} major · {kev} exploited · {poc} with public exploit"]
        if rows:
            lines += ["", "Top threats:"]
            for r in rows[:5]:
                tag = " · EXPLOITED" if r["kev"] else " · PoC" if r["poc"] else ""
                score = f" · {r['score']:.1f}" if r["score"] is not None else ""
                lines.append(f"• {r['id']} · {r['product'] or r['vendor'] or '?'}{score}{tag}")
        else:
            lines.append("Quiet day: no new major vulnerabilities.")
        stories = [st for st in self.news.stories(days=1) if len(st["sources"]) >= self.cfg["news"]["min_sources"]]
        if self.cfg["news"]["enabled"] and stories:
            lines += ["", "In the news:"] + [f"• {util.shorten(st['title'], 90)}" for st in stories[:3]]
        down = [m["name"] for m in self.db.q("SELECT name FROM monitors WHERE up=0 ORDER BY name")]
        if down:
            lines += ["", "Down now: " + ", ".join(down)]
        self.notifier.send(f"📋 BugBark daily · {now.strftime('%b')} {now.day}", "\n".join(lines),
                           priority=3, click=util.panel_url(self.cfg))
        self.db.set_meta("digest_last", today)

    # --- assessment and notifications ---
    def assess(self, row):
        """Returns (level, human-readable reasons, reason keys)."""
        reasons, keys, level = [], [], None
        score, data = row["score"], row["data"]

        def bump(lv):
            nonlocal level
            if LEVEL_RANK[lv] > LEVEL_RANK[level]:
                level = lv

        if row["kev"]:
            k = self.db.get_kev(row["id"])
            text = "Actively exploited in the wild (CISA KEV)"
            if k and k["data"].get("ransomware"):
                text += ", including by ransomware"
            reasons.append(text)
            keys.append("kev")
            bump("kev")
        if row["epss"] is not None and row["epss"] >= self.c["epss_threshold"]:
            reasons.append(f"High exploitation risk: EPSS {row['epss'] * 100:.0f}% chance of attacks in the next 30 days")
            keys.append("epss")
            bump("critical" if row["epss"] >= 0.8 else "high")
        vendor = self.vendors.match(data)
        if vendor and score is not None and score >= self.c["min_cvss"]:
            reasons.append(f"Critical ({score:.1f}/10) in a major vendor product: {vendor}")
            keys.append("vendor")
            bump("critical" if score >= 9 else "high")
        if self.watch and score is not None and score >= self.c["watch_min_cvss"]:
            w = self.watch.match(data, always_desc=True)
            if w:
                reasons.append(f"Affects software on your watch list: {w}")
                keys.append("watch")
                bump("critical" if score >= 9 else "high")
        anymin = self.c["any_vendor_min_cvss"]
        if anymin and score is not None and score >= anymin and "vendor" not in keys:
            reasons.append(f"Maximum severity: {score:.1f}/10")
            keys.append("max")
            bump("critical")
        # A public exploit only upgrades CVEs that are already major, otherwise every exploit-db entry would alert
        pocs = len(row.get("poc") or []) + len(exploit_refs(data))
        if keys and pocs:
            reasons.append(f"Public exploit code available ({pocs} source{'s' if pocs > 1 else ''}, unverified)")
            keys.append("poc")
            bump("critical")
        return level, reasons, keys

    def process(self, ids, suppress=False):
        pending = []
        for cid in dict.fromkeys(ids):
            row = self.db.get_cve(cid)
            if not row:
                continue
            level, reasons, keys = self.assess(row)
            self.db.set_assessment(cid, bool(keys), level, reasons)
            if not keys or row["status"] == "dismissed":
                continue
            notified = set(row["notified"])
            new = set(keys) - notified
            update = None
            if notified:
                new &= RENOTIFY_KEYS
                if "kev" in notified:
                    new -= {"poc", "epss"}
                update = next((k for k in ("kev", "poc", "epss") if k in new), None)
            if new:
                pending.append((dict(row, level=level, reasons=reasons), set(keys) | notified, update))
        if not pending:
            return 0
        if not suppress:
            self._send_pending(pending)
        for row, keys, _ in pending:
            self.db.set_notified(row["id"], keys)
        return len(pending)

    def _send_pending(self, pending):
        """Exploited CVEs and risk updates go out one by one; a batch from one vendor becomes one message."""
        instant = self.c["instant"]
        if instant == "off":
            return
        if instant == "exploited":
            pending = [p for p in pending if p[0]["kev"] or p[2] in ("kev", "poc")]
        messages, groups = [], {}
        for p in pending:
            row, _, update = p
            if row["kev"] or update:
                messages.append([p])
            else:
                groups.setdefault(vendor_key(row), []).append(p)
        for g in groups.values():
            messages += [g] if len(g) >= GROUP_MIN else [[p] for p in g]
        rank = lambda p: (LEVEL_RANK[p[0]["level"]], p[0]["score"] or 0)
        for m in messages:
            m.sort(key=rank, reverse=True)
        messages.sort(key=lambda m: rank(m[0]), reverse=True)
        limit = self.c["max_per_run"]
        for m in messages[:limit]:
            if len(m) == 1:
                self.send_cve(m[0][0], m[0][2])
            else:
                self.send_group([p[0] for p in m])
        rest = sum(len(m) for m in messages[limit:])
        if rest:
            self.notifier.send(f"…and {rest} more major vulnerabilities",
                               "See the full list in the dashboard.", priority=3, click=util.panel_url(self.cfg))

    def send_group(self, rows):
        vendor = next((r["vendor"] for r in rows if r["vendor"]), None) or rows[0]["product"] or "Vendor"
        critical = sum(1 for r in rows if r["level"] == "critical")
        kind = "critical" if critical == len(rows) else "major"
        title = f"{'🔴' if critical else '🟠'} {vendor}: {len(rows)} {kind} vulnerabilities"
        products = list(dict.fromkeys(r["product"] for r in rows if r["product"]))
        lines = []
        if products:
            lines.append("Products: " + ", ".join(products[:5]) + (f" +{len(products) - 5} more" if len(products) > 5 else ""))
        for r in rows[:8]:
            score = f" · {r['score']:.1f}" if r["score"] is not None else ""
            short = explain(r["data"].get("vector"), r["data"].get("cwe"))["short"]
            lines.append(f"• {r['id']}{score}" + (f" · {short}" if short else ""))
        if len(rows) > 8:
            lines.append(f"…and {len(rows) - 8} more")
        panel = util.panel_url(self.cfg, "q/" + urllib.parse.quote(vendor.split()[0]))
        self.notifier.send(title, "\n".join(lines), priority=4 if critical else 3, click=panel,
                           actions=[("Details", panel)] if panel else None)

    def send_cve(self, row, update=None):
        data = row["data"]
        ex = explain(data.get("vector"), data.get("cwe"))
        emoji = "🚨" if row["kev"] else "🧨" if update == "poc" else ("🔴" if row["level"] == "critical" else "🟠")
        name = row["product"] or row["vendor"] or "vulnerability"
        score = f" · {row['score']:.1f}" if row["score"] is not None else ""
        prefix = UPDATE_PREFIX.get(update, "")
        title = f"{emoji} {prefix}{row['id']} · {name}{score}"
        lines = []
        if ex["kind"]:
            lines.append(ex["kind"][0].upper() + ex["kind"][1:])
        if ex["short"]:
            lines.append(ex["short"])
        lines += ["• " + r for r in row["reasons"]]
        pocs = row.get("poc") or []
        if pocs:
            lines.append(f"🧨 Public exploit: github.com/{pocs[0]['name']}" + (f" +{len(pocs) - 1} more" if len(pocs) > 1 else "")
                         + " (unverified, don't run it outside a lab)")
        if data.get("fixed"):
            lines.append("✅ Fixed in: " + ", ".join(data["fixed"][:4]))
        lines += ["", util.shorten(data.get("description"), 280)]
        if data.get("origin") == "cve.org":
            ext = ("CVE.org", f"https://www.cve.org/CVERecord?id={row['id']}")
        else:
            ext = ("NVD", f"https://nvd.nist.gov/vuln/detail/{row['id']}")
        panel = util.panel_url(self.cfg, "cve/" + row["id"])
        actions = ([("Details", panel)] if panel else []) + [ext]
        priority = 5 if row["kev"] else 4 if row["level"] == "critical" else 3
        self.notifier.send(title, "\n".join(lines), priority=priority, click=panel or ext[1], actions=actions)
