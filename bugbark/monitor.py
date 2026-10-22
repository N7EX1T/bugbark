"""Checks your own sites and ports, plus status pages of popular services."""
import socket
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

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
        try:
            d = util.http_json(base.rstrip("/") + "/api/v2/summary.json", timeout=20, retries=2)
        except Exception as e:
            return {"error": error_text(e, 20)}
        indicator = d.get("status", {}).get("indicator", "none")
        incidents = [{"name": i.get("name", ""), "status": i.get("status", ""),
                      "impact": i.get("impact", ""), "url": i.get("shortlink") or ""}
                     for i in d.get("incidents", []) if i.get("status") not in ("resolved", "postmortem")]
        components = [c["name"] for c in d.get("components", [])
                      if not c.get("group") and c.get("status") in ("degraded_performance", "partial_outage",
                                                                    "major_outage")]
        return {"indicator": indicator, "incidents": incidents, "components": components}

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
                url = (new_inc or res["incidents"] or [{}])[0].get("url") or base
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
