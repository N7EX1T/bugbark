"""Dashboard: vulnerability list, details and service status."""
import hmac
import json
import os
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import util
from .explain import explain
from .util import log

STATIC = os.path.join(os.path.dirname(__file__), "static")
TYPES = {".html": "text/html; charset=utf-8", ".svg": "image/svg+xml",
         ".webmanifest": "application/manifest+json"}
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


def list_item(r):
    data = r["data"]
    return {
        "id": r["id"], "published": r["published"], "score": r["score"], "severity": r["severity"],
        "product": r["product"] or r["vendor"], "vendor": r["vendor"], "kev": bool(r["kev"]), "kev_added": r["kev_added"],
        "epss": r["epss"], "level": r["level"], "important": bool(r["important"]),
        "status": r["status"], "reasons": r["reasons"],
        "short": explain(data.get("vector"), data.get("cwe"))["short"],
        "summary": (data.get("description") or "")[:220],
    }


class App:
    def __init__(self, cfg, db, engine, notifier):
        self.cfg, self.db, self.engine, self.notifier = cfg, db, engine, notifier

    def cves(self, qs, limit=300):
        view = qs.get("view", ["important"])[0]
        text = qs.get("q", [""])[0].strip()
        where, args = [], []
        if view == "important":
            where.append("important=1")
        elif view == "kev":
            where.append("kev=1")
        if text:
            where.append("(id LIKE ? OR product LIKE ? OR vendor LIKE ? OR data LIKE ?)")
            args += [f"%{text}%"] * 4
        sql = "SELECT * FROM cves" + (" WHERE " + " AND ".join(where) if where else "")
        sql += f" ORDER BY MAX(published, COALESCE(kev_added, '')) DESC LIMIT {int(limit)}"
        items = [list_item(r) for r in self.db.q(sql, args)]
        new = self.db.q("SELECT COUNT(*) n FROM cves WHERE important=1 AND status='new'")[0]["n"]
        return {"items": items, "new": new}

    def cve(self, cid, mark_seen=True):
        row = self.db.get_cve(cid)
        if not row:
            try:
                if self.engine.fetch_one(cid):
                    self.engine.process([cid], suppress=True)
                    row = self.db.get_cve(cid)
            except Exception as e:
                log.warning("NVD: could not fetch %s: %s", cid, e)
        if not row:
            return None
        if mark_seen and row["status"] == "new":
            self.db.set_status(cid, "seen")
        kev = self.db.get_kev(cid)
        data = row["data"]
        out = list_item(row)
        out.update(
            status=row["status"],
            description=data.get("description"),
            vector=data.get("vector"), cwe=data.get("cwe"), source=data.get("source"),
            nvd_status=data.get("nvd_status"), affected=data.get("affected", []),
            fixed=data.get("fixed", []), refs=data.get("refs", []),
            epss_pct=row["epss_pct"], explain=explain(data.get("vector"), data.get("cwe")),
            kev_info=kev["data"] if kev else None,
        )
        return out

    def monitors(self):
        rows = self.db.q("SELECT * FROM monitors ORDER BY kind, name")
        items = [{k: r[k] for k in ("kind", "name", "target", "up", "since", "latency", "detail", "last_check")}
                 | {"incidents": r["extra"].get("incidents", []), "components": r["extra"].get("components", [])}
                 for r in rows]
        return {"items": items, "down": sum(1 for i in items if i["up"] == 0)}

    def health(self):
        jobs = {}
        for name in ("nvd", "kev", "epss", "sites", "status"):
            v = self.db.get_meta("job:" + name)
            if v:
                jobs[name] = json.loads(v)
        return {"jobs": jobs, "notify": self.notifier.enabled, "generated": util.iso(util.now())}


def make_handler(app):
    token = app.cfg["web"].get("token") or ""

    class Handler(BaseHTTPRequestHandler):
        server_version = "bugbark"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
            if not isinstance(body, bytes):
                body = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _auth(self, qs):
            """Returns (allowed, headers). A token from the link is remembered in a cookie."""
            if not token:
                return True, {}
            given = qs.get("token", [""])[0]
            if given and hmac.compare_digest(given, token):
                return True, {"Set-Cookie": f"t={token}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax"}
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "t" and hmac.compare_digest(v, token):
                    return True, {}
            return False, {}

        def _static(self, name, headers):
            path = os.path.join(STATIC, name)
            with open(path, "rb") as f:
                self._send(200, f.read(), TYPES[os.path.splitext(name)[1]], headers)

        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            qs = urllib.parse.parse_qs(u.query)
            ok, headers = self._auth(qs)
            if not ok:
                return self._send(401, b"Open the dashboard using the link with ?token=...", "text/plain; charset=utf-8")
            p = u.path
            try:
                if p == "/":
                    return self._static("index.html", headers)
                if p in ("/manifest.webmanifest", "/icon.svg"):
                    return self._static(p[1:], headers)
                if p == "/api/cves":
                    return self._send(200, app.cves(qs))
                if p.startswith("/api/cve/"):
                    cid = p.rsplit("/", 1)[1].upper()
                    if not CVE_ID.match(cid):
                        return self._send(400, {"error": "invalid CVE ID"})
                    r = app.cve(cid)
                    return self._send(200, r) if r else self._send(404, {"error": "not found"})
                if p == "/api/monitors":
                    return self._send(200, app.monitors())
                if p == "/api/health":
                    return self._send(200, app.health())
                self._send(404, {"error": "not found"})
            except Exception as e:
                log.exception("Web request failed: %s", p)
                self._send(500, {"error": str(e)})

        def do_POST(self):
            u = urllib.parse.urlsplit(self.path)
            ok, _ = self._auth({})
            if not ok:
                return self._send(401, {"error": "unauthorized"})
            m = re.match(r"^/api/cve/(CVE-\d{4}-\d{4,})/status$", u.path)
            if not m:
                return self._send(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            status = body.get("status")
            if status not in ("new", "seen", "done", "dismissed"):
                return self._send(400, {"error": "invalid status"})
            app.db.set_status(m.group(1), status)
            self._send(200, {"ok": True})

    return Handler


def serve(cfg, db, engine, notifier):
    app = App(cfg, db, engine, notifier)
    w = cfg["web"]
    httpd = ThreadingHTTPServer((w["host"], int(w["port"])), make_handler(app))
    log.info("Dashboard: %s", w["public_url"] or f"http://{w['host']}:{w['port']}")
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
