"""Checks your own sites and ports, plus status pages of popular services."""
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from . import util
from .util import log

BROWSER_UA = "Mozilla/5.0 (compatible; bugbark/1.0; uptime check)"
INDICATOR_TEXT = {
    "none": "All systems operational",
    "minor": "Partial issues",
    "major": "Major outage",
    "critical": "Critical outage",
    "maintenance": "Scheduled maintenance",
}



def statuspage(base):
    """Atlassian Statuspage, used by most services (GitHub, Cloudflare, Zoom, ...)."""
    d = util.http_json(base.rstrip("/") + "/api/v2/summary.json", timeout=20, retries=2)
    indicator = d.get("status", {}).get("indicator", "none")
    incidents = [{"name": i.get("name", ""), "status": i.get("status", ""),
                  "impact": i.get("impact", ""), "url": i.get("shortlink") or ""}
                 for i in d.get("incidents", []) if i.get("status") not in ("resolved", "postmortem")]
    components = [c["name"] for c in d.get("components", [])
                  if not c.get("group") and c.get("status") in ("degraded_performance", "partial_outage",
                                                                "major_outage")]
    return {"indicator": indicator, "incidents": incidents, "components": components}


def slack_status(base):
    d = util.http_json("https://slack-status.com/api/v2.0.0/current", timeout=20, retries=2)
    # "notice" entries are announcements, not problems
    active = [i for i in d.get("active_incidents", []) if i.get("type") != "notice"]
    incidents = [{"name": i.get("title", ""), "status": i.get("status", ""), "impact": i.get("type", ""),
                  "url": i.get("url") or ""} for i in active]
    indicator = "major" if any(i.get("type") == "outage" for i in active) else "minor" if active else "none"
    return {"indicator": indicator, "incidents": incidents,
            "components": list(dict.fromkeys(s for i in active for s in i.get("services", [])))}


def google_cloud_status(base):
    d = util.http_json("https://status.cloud.google.com/incidents.json", timeout=30, retries=2)
    active = [i for i in d if not i.get("end")]
    incidents = [{"name": util.shorten(i.get("external_desc", ""), 140), "status": "ongoing",
                  "impact": i.get("severity", ""), "url": "https://status.cloud.google.com/" + i.get("uri", "")}
                 for i in active]
    indicator = "major" if any(i.get("severity") == "high" for i in active) else "minor" if active else "none"
    return {"indicator": indicator, "incidents": incidents,
            "components": list(dict.fromkeys(p["title"] for i in active for p in i.get("affected_products", [])))}


def aws_status(base):
    # The feed is UTF-16 JSON; json.loads detects that from the bytes
    d = util.http_json("https://health.aws.amazon.com/public/currentevents", timeout=30, retries=2) or []
    # Some regional events stay open for months (a destroyed data center): only recent ones count as an outage
    recent = (util.now() - timedelta(days=14)).timestamp()
    active = [e for e in d if e.get("status") in ("2", "3") and float(e.get("date") or 0) >= recent]
    incidents = [{"name": f"{e.get('service_name', '')} ({e.get('region_name', '')}): {e.get('summary', '')}",
                  "status": "ongoing", "impact": e.get("status"), "url": base} for e in active]
    indicator = "major" if any(e["status"] == "3" for e in active) else "minor" if active else "none"
    return {"indicator": indicator, "incidents": incidents,
            "components": list(dict.fromkeys(e.get("region_name", "") for e in active))}


def azure_status(base):
    req = urllib.request.Request("https://azure.status.microsoft/en-us/status/feed/", headers={"User-Agent": util.UA})
    with urllib.request.urlopen(req, timeout=20) as r:
        root = ET.fromstring(r.read())
    # The feed only lists active incidents
    incidents = [{"name": i.findtext("title") or "", "status": "ongoing", "impact": "",
                  "url": i.findtext("link") or ""} for i in root.iter("item")]
    return {"indicator": "major" if incidents else "none", "incidents": incidents, "components": []}


# Services with their own status format, by status page host
CUSTOM_PAGES = {
    "slack-status.com": slack_status,
    "status.cloud.google.com": google_cloud_status,
    "health.aws.amazon.com": aws_status,
    "azure.status.microsoft": azure_status,
}

def error_text(e, timeout):
    if isinstance(e, urllib.error.URLError) and not isinstance(e, urllib.error.HTTPError):
        e = e.reason if isinstance(e.reason, BaseException) else e
    if isinstance(e, (TimeoutError, socket.timeout)):
        return f"no response within {timeout}s"
    if isinstance(e, ConnectionRefusedError):
        return "connection refused (service not running or port closed)"
    if isinstance(e, socket.gaierror):
        return "domain not found (DNS error)"
    if isinstance(e, ssl.SSLCertVerificationError):
        return "SSL certificate error: " + (e.verify_message or str(e))
    if isinstance(e, ssl.SSLError):
        return "SSL error: " + str(e)
    if isinstance(e, ConnectionResetError):
        return "connection reset"
    if isinstance(e, OSError) and e.errno == 113:
        return "host unreachable"
    return str(e)


def check_http(site, timeout):
    url = site["url"]
    expect = site.get("expect_status")
    req = urllib.request.Request(url, headers={"User-Agent": BROWSER_UA}, method=site.get("method", "GET"))
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code = r.status
            body = r.read(512 * 1024) if site.get("contains") else b""
    except urllib.error.HTTPError as e:
        code, body = e.code, b""
    except Exception as e:
        return False, error_text(e, timeout), None
    latency = round((time.monotonic() - t0) * 1000)
    ok = code in (expect if isinstance(expect, list) else [expect]) if expect else code < 400
    if not ok:
        return False, f"HTTP {code}", latency
    if site.get("contains") and site["contains"].encode() not in body:
        return False, f"page does not contain \"{site['contains']}\"", latency
    return True, f"HTTP {code}", latency


def check_tcp(port, timeout):
    t0 = time.monotonic()
    try:
        with socket.create_connection((port["host"], int(port["port"])), timeout=timeout):
            pass
    except Exception as e:
        return False, error_text(e, timeout), None
    return True, "port open", round((time.monotonic() - t0) * 1000)


class Monitor:
    def __init__(self, cfg, db, notifier):
        self.cfg, self.db, self.notifier = cfg, db, notifier
        self.m = cfg["monitor"]

    def _targets(self):
        out = []
        for s in self.m.get("sites", []):
            out.append(("http", s.get("name") or s["url"], s["url"], s))
        for p in self.m.get("ports", []):
            out.append(("tcp", p.get("name") or f"{p['host']}:{p['port']}", f"{p['host']}:{p['port']}", p))
        return out

    def run_checks(self):
        targets = self._targets()
        self.db.prune_monitors(("http", "tcp"), {f"{k}:{n}" for k, n, _, _ in targets})
        if not targets:
            return
        timeout = self.m["timeout_seconds"]

        def run(t):
            kind, _, _, item = t
            return check_http(item, timeout) if kind == "http" else check_tcp(item, timeout)

        with ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(run, targets))
        for t, res in zip(targets, results):
            self._update(t, *res)

    def _update(self, target, ok, detail, latency):
        kind, name, addr, item = target
        key = f"{kind}:{name}"
        prev = self.db.get_monitor(key)
        now = util.now()
        was_up = prev["up"] if prev else None
        since = prev["since"] if prev else None
        threshold = item.get("fail_threshold", self.m["fail_threshold"])
        click = item.get("url") or util.panel_url(self.cfg, "status")
        if ok:
            fails = 0
            if was_up == 0:
                down_for = (now - util.parse_ts(since)).total_seconds() if since else 0
                self.notifier.send(f"🟢 Back up: {name}",
                                   f"{addr}\nWas down for {util.duration(down_for)}.",
                                   priority=3, click=click)
            if was_up != 1:
                since = util.iso(now)
            up = 1
        else:
            fails = (prev["fails"] if prev else 0) + 1
            up = was_up
            if fails >= threshold and was_up != 0:
                up, since = 0, util.iso(now)
                log.warning("Down: %s: %s", name, detail)
                self.notifier.send(f"🔴 Down: {name}", f"{addr}\nReason: {detail}",
                                   priority=4, click=click)
        self.db.save_monitor({"key": key, "kind": kind, "name": name, "target": addr, "up": up,
                              "since": since, "latency": latency, "detail": detail, "fails": fails,
                              "last_check": util.iso(now), "extra": {}})

    def run_status_pages(self):
        pages = self.cfg["status_pages"]["pages"]
        self.db.prune_monitors(("status",), {f"status:{n}" for n in pages})
        if not pages:
            return
        with ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(lambda kv: (kv, self._fetch_page(kv[1])), pages.items()))
        for (name, base), res in results:
            self._update_page(name, base, res)

    def _fetch_page(self, base):
        fetch = CUSTOM_PAGES.get(urllib.parse.urlsplit(base).hostname or "", statuspage)
        try:
            return fetch(base)
        except Exception as e:
            return {"error": error_text(e, 20)}

    def _update_page(self, name, base, res):
        key = f"status:{name}"
        prev = self.db.get_monitor(key)
        now = util.iso(util.now())
        if "error" in res:
            # The status page itself is unreachable; don't treat that as a service outage
            if prev:
                prev.update(detail=f"could not fetch status: {res['error']}", last_check=now)
                self.db.save_monitor(prev)
            else:
                self.db.save_monitor({"key": key, "kind": "status", "name": name, "target": base, "up": None,
                                      "since": None, "latency": None, "detail": f"could not fetch status: {res['error']}",
                                      "fails": 0, "last_check": now, "extra": {}})
            return
        ind = res["indicator"]
        up = 1 if ind in ("none", "maintenance") else 0
        detail = INDICATOR_TEXT.get(ind, ind)
        was_up = prev["up"] if prev else None
        since = prev["since"] if prev and was_up == up else now
        old_inc = {i["name"] for i in (prev["extra"].get("incidents", []) if prev else [])}
        new_inc = [i for i in res["incidents"] if i["name"] not in old_inc]

        if prev is not None and was_up is not None:
            if up == 0 and (was_up == 1 or new_inc):
                lines = [detail]
                lines += ["• " + i["name"] for i in (new_inc or res["incidents"])[:4]]
                if res["components"]:
                    lines.append("Affected: " + ", ".join(res["components"][:6]))
                url = (new_inc or res["incidents"] or [{}])[0].get("url") or ""
                url = url if url.startswith(("https://", "http://")) else base
                self.notifier.send(f"🟠 {name}: {detail.lower()}", "\n".join(lines),
                                   priority=4 if ind in ("major", "critical") else 3, click=url)
            elif up == 1 and was_up == 0:
                down_for = (util.parse_ts(now) - util.parse_ts(prev["since"])).total_seconds() if prev["since"] else 0
                self.notifier.send(f"🟢 {name}: resolved",
                                   f"Issues lasted {util.duration(down_for)}.", priority=3, click=base)
        self.db.save_monitor({"key": key, "kind": "status", "name": name, "target": base, "up": up,
                              "since": since, "latency": None, "detail": detail, "fails": 0,
                              "last_check": now, "extra": {"incidents": res["incidents"],
                                                           "components": res["components"]}})
