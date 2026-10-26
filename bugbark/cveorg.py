"""Reads the official CVE list (CVE.org): new CVEs show up there before NVD processes them."""
import json
import urllib.request

from . import util
from .util import log

DELTA_LOG = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
CHUNK = 256 * 1024
MAX_BYTES = 8 * 1024 * 1024


def _fetch_range(url, size):
    """First `size` bytes of a file; the delta log is ~30 MB, newest entries first."""
    req = urllib.request.Request(url, headers={"User-Agent": util.UA, "Range": f"bytes=0-{size - 1}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        body = r.read()
        return body.decode("utf-8", "ignore"), r.status != 206 or len(body) < size


def changes_since(since):
    """CVE ids added or updated after `since` (ISO time): ({id: (record url, "new"/"updated")}, newest time)."""
    size = CHUNK
    while True:
        text, complete = _fetch_range(DELTA_LOG, size)
        entries, reached = _parse_prefix(text), False
        out, newest = {}, since
        for e in entries:
            if (e.get("fetchTime") or "") <= since:
                reached = True
                break
            newest = max(newest, e["fetchTime"])
            for kind in ("new", "updated"):
                for c in e.get(kind, []):
                    out.setdefault(c["cveId"], (c.get("githubLink"), kind))
        if reached or complete or size >= MAX_BYTES:
            if not reached and not complete:
                log.warning("CVE.org: gap larger than %s MB in the delta log, NVD fills it", MAX_BYTES // 2 ** 20)
            return out, newest
        size *= 4


def _parse_prefix(text):
    """Complete objects from the start of a truncated JSON array."""
    dec, i, out = json.JSONDecoder(), text.find("[") + 1, []
    while True:
        while i < len(text) and text[i] in " \t\r\n,":
            i += 1
        try:
            obj, i = dec.raw_decode(text, i)
        except ValueError:
            return out
        out.append(obj)


def _best(metrics):
    best = None
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
        for m in metrics:
            d = m.get(key) or {}
            if d.get("baseScore") is not None and (best is None or d["baseScore"] > best[0]):
                best = (d["baseScore"], d.get("vectorString", ""))
    if best is None:
        for m in metrics:
            d = m.get("cvssV2_0") or {}
            if d.get("baseScore") is not None:
                best = (d["baseScore"], d.get("vectorString", ""))
    return best or (None, "")


def parse_record(rec):
    """A CVE JSON 5 record in the same shape as parse_nvd() returns."""
    from .cves import display_name, parse_affected, severity_for
    meta = rec.get("cveMetadata", {})
    containers = rec.get("containers", {})
    cna = containers.get("cna", {})
    adp = containers.get("adp", [])
    parts = [cna] + adp
    desc = next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "")
    score, vector = _best([m for p in parts for m in p.get("metrics", [])])
    cwe = next((d["cweId"] for p in parts for t in p.get("problemTypes", []) for d in t.get("descriptions", [])
                if (d.get("cweId") or "").startswith("CWE-")), None)
    affected = parse_affected({"affected": [{"affectedData": p.get("affected", [])} for p in parts]})
    product, vendor = display_name(affected)
    fixed = list(dict.fromkeys(f for a in affected for f in a["fixed"]))
    refs = [{"url": r["url"], "tags": [t.title() for t in r.get("tags", [])]}
            for r in cna.get("references", []) if r.get("url")]
    return {
        "id": meta.get("cveId"),
        "published": util.norm_ts(meta.get("datePublished")),
        "modified": util.norm_ts(meta.get("dateUpdated")),
        "score": score,
        "severity": severity_for(score),
        "vendor": vendor,
        "product": product,
        "rejected": meta.get("state") != "PUBLISHED",
        "data": {
            "description": desc,
            "vector": vector,
            "cwe": cwe,
            # Labels like "microsoft" or "fortinet" help to match the vendor, the same way NVD's source e-mail does
            "source": meta.get("assignerShortName", ""),
            "origin": "cve.org",
            "affected": affected,
            "fixed": fixed,
            "refs": refs,
        },
    }


def fetch_record(url):
    return parse_record(util.http_json(url, timeout=30, retries=2))
