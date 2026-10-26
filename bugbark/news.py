"""Security news: groups headlines from several outlets into stories; a story many outlets cover is a big one."""
import email.utils
import hashlib
import html
import math
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import timedelta

from . import util
from .util import log

ATOM = "{http://www.w3.org/2005/Atom}"
WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*[A-Za-z0-9]|[A-Za-z0-9]")
STOP = set("""
a an the and or of to in on for with from by at as is are was were be been it its this that these those after before
over under into via new how why what who when amid about more than up out not no can could may might will would says
say said warns warn report reports hackers hacker attack attacks flaw flaws vulnerability vulnerabilities security cyber
data users million billion first now just exploited exploit exploits exploitation using used use target targets
targeted against week weekly review roundup webinar podcast sponsored
""".split())
# Names in so many headlines that sharing one says nothing: two Microsoft stories are rarely the same story
GENERIC = set("""
microsoft windows google chrome android apple ios macos linux amazon aws meta facebook openai github cisco
cisa fbi nsa ncsc europol us usa uk eu china chinese russia russian iran iranian korea korean north israel ukraine
ai llm mcp cve cvss rce sql xss csrf ssrf dll api apt mfa vpn ssh ssl tls dns ddos saas ceo ciso
""".split())
LINK_WINDOW = timedelta(hours=48)  # headlines further apart than this are different stories


def tokens(title):
    out = set()
    for w in WORD.findall(title):
        w = norm(w)
        if len(w) >= 3 and w not in STOP:
            out.add(w)
    return out


def norm(w):
    w = w.lower()
    if w.endswith("'s"):
        w = w[:-2]
    return w[:-1] if w.endswith("s") and len(w) > 4 else w


def names(titles):
    """Words that look like names: odd shapes (PHP2Shell, eMudhra, CISA), or capitalized in a sentence-case
    headline and never written in lowercase. Title Case headlines capitalize everything, so there only odd shapes count."""
    lower, found = set(), set()
    for t in titles:
        words = WORD.findall(t)
        rest = [w for w in words[1:] if len(w) > 3 and w.isalpha()]
        sentence_case = bool(rest) and sum(w[0].isupper() for w in rest) / len(rest) < 0.5
        for k, w in enumerate(words):
            if w.islower():
                lower.add(norm(w))
            if w.isdigit():
                continue
            odd = any(c.isdigit() for c in w) or (len(w) > 1 and w[1:] != w[1:].lower())
            if odd or (sentence_case and w[0].isupper()):
                found.add(norm(w))
    return found - lower - STOP - GENERIC


def fetch_feed(source, url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": util.UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        root = ET.fromstring(r.read())
    items = []
    for it in root.iter():
        if it.tag == "item":
            link = (it.findtext("link") or "").strip()
            when = it.findtext("pubDate")
            dt = email.utils.parsedate_to_datetime(when) if when else None
            summary = it.findtext("description") or ""
        elif it.tag == ATOM + "entry":
            el = it.find(ATOM + "link")
            link = (el.get("href") if el is not None else "") or ""
            dt = util.parse_ts(it.findtext(ATOM + "published") or it.findtext(ATOM + "updated"))
            summary = it.findtext(ATOM + "summary") or ""
        else:
            continue
        title = " ".join(html.unescape(it.findtext("title") or it.findtext(ATOM + "title") or "").split())
        if not title or not link.startswith(("http://", "https://")):
            continue
        items.append({
            "id": hashlib.sha1(link.encode()).hexdigest()[:16],
            "source": source,
            "title": title,
            "link": link,
            "published": util.iso(dt) if dt else util.iso(util.now()),
            "summary": util.shorten(re.sub(r"\s*The post .* appeared first on .*$", "",
                                           html.unescape(re.sub(r"<[^>]+>", " ", summary)), flags=re.S), 400),
        })
    return items


def cluster(items):
    """Groups headlines about the same event. Returns stories, biggest first."""
    toks = [tokens(i["title"]) for i in items]
    named = names(i["title"] for i in items)
    # Two shared names link two headlines, or one name (company, malware, bug nickname) plus another word
    when = [util.parse_ts(i["published"]) for i in items]
    parent = list(range(len(items)))

    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            if abs(when[i] - when[j]) > LINK_WINDOW:
                continue
            common = toks[i] & toks[j]
            shared = common & named
            if len(shared) >= 2 or (shared and len(common) >= 2):
                parent[root(i)] = root(j)
    groups = {}
    for i in range(len(items)):
        groups.setdefault(root(i), []).append(items[i])
    stories = []
    for g in groups.values():
        g.sort(key=lambda i: i["published"])
        stories.append({
            "id": g[0]["id"],
            "title": g[0]["title"],
            "summary": g[0]["summary"],
            "first": g[0]["published"],
            "last": g[-1]["published"],
            "sources": list(dict.fromkeys(i["source"] for i in g)),
            "items": [{k: i[k] for k in ("id", "source", "title", "link", "published")} for i in g],
        })
    stories.sort(key=lambda s: (len(s["sources"]), s["last"]), reverse=True)
    return stories


class News:
    def __init__(self, cfg, db, notifier):
        self.cfg, self.db, self.notifier = cfg, db, notifier
        self.n = cfg["news"]

    def stories(self, days=7):
        since = util.iso(util.now() - timedelta(days=days))
        return cluster(self.db.q("SELECT * FROM news WHERE published >= ? ORDER BY published", (since,)))

    def run(self):
        if not self.n["enabled"]:
            return
        now = util.now()
        keep = util.iso(now - timedelta(days=8))
        fetched, failed = 0, []
        for source, url in self.n["feeds"].items():
            try:
                items = fetch_feed(source, url)
            except Exception as e:
                log.warning("News: %s failed: %s", source, e)
                failed.append(source)
                continue
            # Some feeds list weeks of articles: skip what pruning would delete anyway
            fetched += self.db.add_news([i for i in items if i["published"] >= keep], util.iso(now))
        if failed and len(failed) == len(self.n["feeds"]):
            raise RuntimeError("all news feeds failed")
        self.db.prune_news(keep)
        first_run = self.db.get_meta("news_init") is None
        fresh = util.iso(now - LINK_WINDOW)
        big = [s for s in self.stories() if len(s["sources"]) >= self.n["min_sources"] and s["last"] >= fresh]
        sent = 0
        for s in big:
            ids = [i["id"] for i in s["items"]]
            if self.db.news_alerted(ids):
                continue
            if not first_run and sent < self.n["max_per_run"]:
                self.send(s)
                sent += 1
            self.db.set_news_alerted(ids)
        log.info("News: %s new headlines, %s big stories, %s alerts", fetched, len(big), sent)
        self.db.set_meta("news_init", "1")

    def send(self, s):
        outlets = ", ".join(s["sources"][:3]) + (f" +{len(s['sources']) - 3}" if len(s["sources"]) > 3 else "")
        lines = [f"Covered by {len(s['sources'])} outlets: {outlets}"]
        if s["summary"]:
            lines += ["", util.shorten(s["summary"], 280)]
        panel = util.panel_url(self.cfg, "news")
        article = s["items"][0]["link"]
        self.notifier.send(f"📰 {s['title']}", "\n".join(lines), priority=3, click=article,
                           actions=([("Read", article)] + ([("All news", panel)] if panel else [])))
