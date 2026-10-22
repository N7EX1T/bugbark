import http.client
import json
import logging
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

UA = "bugbark/1.0"
log = logging.getLogger("bugbark")


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(s):
    """Parse an ISO timestamp (assumes UTC when no offset is given)."""
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def norm_ts(s):
    dt = parse_ts(s)
    return iso(dt) if dt else None


def duration(seconds):
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds}s"
    m = seconds // 60
    if m < 60:
        return f"{m} min"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h}h {m}m" if m else f"{h}h"
    d, h = divmod(h, 24)
    return f"{d}d {h}h" if h else f"{d}d"


def shorten(text, limit):
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def http_json(url, headers=None, data=None, timeout=30, retries=3):
    """GET (or POST when data is given), retrying on transient errors."""
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    hdrs.update(headers or {})
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        hdrs["Content-Type"] = "application/json"
    for attempt in range(retries):
        req = urllib.request.Request(url, data=body, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 500, 502, 503, 504) and attempt < retries - 1:
                time.sleep(10 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, http.client.HTTPException, ConnectionError, TimeoutError):
            if attempt < retries - 1:
                time.sleep(5 * (attempt + 1))
                continue
            raise


def lan_ip():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def panel_url(cfg, fragment=""):
    """Dashboard link used for notification buttons."""
    w = cfg["web"]
    base = w["public_url"].rstrip("/")
    if not base:
        return None
    url = base + "/"
    if w.get("token"):
        url += "?token=" + w["token"]
    return url + (f"#/{fragment}" if fragment else "")
