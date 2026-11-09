import json
import os
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS cves(
    id TEXT PRIMARY KEY,
    published TEXT,
    modified TEXT,
    score REAL,
    severity TEXT,
    vendor TEXT,
    product TEXT,
    data TEXT,
    kev INTEGER DEFAULT 0,
    kev_added TEXT,
    epss REAL,
    epss_pct REAL,
    important INTEGER DEFAULT 0,
    level TEXT,
    reasons TEXT DEFAULT '[]',
    notified TEXT DEFAULT '[]',
    status TEXT DEFAULT 'new',
    first_seen TEXT
);
CREATE INDEX IF NOT EXISTS cves_published ON cves(published);
CREATE TABLE IF NOT EXISTS kev(id TEXT PRIMARY KEY, date_added TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS monitors(
    key TEXT PRIMARY KEY,
    kind TEXT,
    name TEXT,
    target TEXT,
    up INTEGER,
    since TEXT,
    latency REAL,
    detail TEXT,
    fails INTEGER DEFAULT 0,
    last_check TEXT,
    extra TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS outbox(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created TEXT,
    title TEXT,
    message TEXT,
    priority INTEGER,
    click TEXT,
    actions TEXT
);
CREATE TABLE IF NOT EXISTS breaches(
    name TEXT PRIMARY KEY,
    added TEXT,
    count INTEGER,
    data TEXT
);
CREATE TABLE IF NOT EXISTS victims(
    id TEXT PRIMARY KEY,
    discovered TEXT,
    grp TEXT,
    rank INTEGER,
    data TEXT
);
CREATE TABLE IF NOT EXISTS packages(
    id TEXT,
    ecosystem TEXT,
    name TEXT,
    published TEXT,
    downloads INTEGER,
    data TEXT,
    PRIMARY KEY (id, ecosystem, name)
);
CREATE TABLE IF NOT EXISTS blocklist(entry TEXT PRIMARY KEY, source TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS toplist(domain TEXT PRIMARY KEY, rank INTEGER) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS news(
    id TEXT PRIMARY KEY,
    source TEXT,
    title TEXT,
    link TEXT,
    published TEXT,
    summary TEXT,
    alerted INTEGER DEFAULT 0,
    first_seen TEXT
);
"""

JSON_COLS = {"data": {}, "reasons": [], "notified": [], "extra": {}, "poc": []}

# Columns added after the first release: (table, column, definition)
MIGRATIONS = [
    ("cves", "poc", "TEXT DEFAULT '[]'"),
    ("cves", "poc_checked", "TEXT"),
    ("cves", "vc_added", "TEXT"),  # date added to VulnCheck's exploited list
]


def _row(r):
    if r is None:
        return None
    d = dict(r)
    for k, default in JSON_COLS.items():
        if k in d:
            d[k] = json.loads(d[k]) if d[k] else default
    return d


class DB:
    def __init__(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(SCHEMA)
            for table, col, decl in MIGRATIONS:
                if col not in {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
            self.conn.commit()

    def q(self, sql, args=()):
        with self.lock:
            return [_row(r) for r in self.conn.execute(sql, args).fetchall()]

    def x(self, sql, args=()):
        with self.lock, self.conn:
            self.conn.execute(sql, args)

    def xmany(self, sql, rows):
        with self.lock, self.conn:
            self.conn.executemany(sql, rows)

    # --- meta ---
    def get_meta(self, key, default=None):
        r = self.q("SELECT value FROM meta WHERE key=?", (key,))
        return r[0]["value"] if r else default

    def set_meta(self, key, value):
        self.x("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (key, value))

    # --- cves ---
    def upsert_cve(self, c, seen_at):
        self.x(
            """INSERT INTO cves(id,published,modified,score,severity,vendor,product,data,first_seen)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET published=excluded.published, modified=excluded.modified,
                 score=excluded.score, severity=excluded.severity, vendor=excluded.vendor,
                 product=excluded.product, data=excluded.data""",
            (c["id"], c["published"], c["modified"], c["score"], c["severity"], c["vendor"],
             c["product"], json.dumps(c["data"], ensure_ascii=False), seen_at),
        )

    def get_cve(self, cid):
        r = self.q("SELECT * FROM cves WHERE id=?", (cid,))
        return r[0] if r else None

    def set_assessment(self, cid, important, level, reasons):
        self.x("UPDATE cves SET important=?, level=?, reasons=? WHERE id=?",
               (int(important), level, json.dumps(reasons, ensure_ascii=False), cid))

    def set_notified(self, cid, keys):
        self.x("UPDATE cves SET notified=? WHERE id=?", (json.dumps(sorted(keys)), cid))

    def set_status(self, cid, status):
        self.x("UPDATE cves SET status=? WHERE id=?", (status, cid))

    def set_kev_flag(self, cid, date_added):
        self.x("UPDATE cves SET kev=1, kev_added=? WHERE id=?", (date_added, cid))

    def set_vc_flag(self, cid, date_added):
        self.x("UPDATE cves SET vc_added=? WHERE id=?", (date_added, cid))

    def set_poc(self, cid, pocs, checked):
        self.x("UPDATE cves SET poc=?, poc_checked=? WHERE id=?", (json.dumps(pocs), checked, cid))

    def set_epss(self, rows):
        self.xmany("UPDATE cves SET epss=?, epss_pct=? WHERE id=?", rows)

    def prune_cves(self, before, low_before, unimportant_before):
        """Keeps the database small. Pruned CVEs come back from NVD if they are modified later."""
        self.x("DELETE FROM cves WHERE published < ? AND kev=0", (before,))
        self.x("""DELETE FROM cves WHERE published < ? AND kev=0 AND important=0 AND notified='[]'
                  AND status IN ('new', 'seen')""", (unimportant_before,))
        self.x("""DELETE FROM cves WHERE published < ? AND kev=0 AND important=0 AND notified='[]'
                  AND status IN ('new', 'seen') AND (score IS NULL OR score < 7)""", (low_before,))

    def close(self, compact=False):
        with self.lock:
            if compact:
                self.conn.execute("VACUUM")
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.conn.execute("PRAGMA journal_mode=DELETE")
            self.conn.close()

    # --- kev ---
    def kev_ids(self):
        return {r["id"] for r in self.q("SELECT id FROM kev")}

    def add_kev(self, entries):
        self.xmany("INSERT OR REPLACE INTO kev(id,date_added,data) VALUES(?,?,?)",
                   [(e["id"], e["date_added"], json.dumps(e, ensure_ascii=False)) for e in entries])

    def get_kev(self, cid):
        r = self.q("SELECT * FROM kev WHERE id=?", (cid,))
        return r[0] if r else None

    # --- news ---
    def add_news(self, items, seen_at):
        """Stores headlines not seen before; returns how many were new."""
        with self.lock, self.conn:
            before = self.conn.total_changes
            self.conn.executemany(
                """INSERT OR IGNORE INTO news(id,source,title,link,published,summary,first_seen)
                   VALUES(:id,:source,:title,:link,:published,:summary,:seen)""",
                [dict(i, seen=seen_at) for i in items])
            return self.conn.total_changes - before

    def prune_news(self, before):
        self.x("DELETE FROM news WHERE published < ?", (before,))

    def news_alerted(self, ids):
        marks = ",".join("?" * len(ids))
        return bool(self.q(f"SELECT 1 FROM news WHERE alerted=1 AND id IN ({marks}) LIMIT 1", ids))

    def set_news_alerted(self, ids):
        self.xmany("UPDATE news SET alerted=1 WHERE id=?", [(i,) for i in ids])

    # --- breaches and ransomware ---
    def add_breach(self, b):
        self.x("INSERT OR REPLACE INTO breaches(name,added,count,data) VALUES(?,?,?,?)",
               (b["name"], b["added"], b["count"], json.dumps(b, ensure_ascii=False)))

    def prune_breaches(self, before):
        self.x("DELETE FROM breaches WHERE added < ?", (before,))

    def add_victim(self, v):
        """Stores a ransomware victim; returns False if it was already known."""
        with self.lock, self.conn:
            cur = self.conn.execute("INSERT OR IGNORE INTO victims(id,discovered,grp,rank,data) VALUES(?,?,?,?,?)",
                                    (v["id"], v["discovered"], v["grp"], v["rank"], json.dumps(v, ensure_ascii=False)))
            return cur.rowcount > 0

    def prune_victims(self, before):
        self.x("DELETE FROM victims WHERE discovered < ?", (before,))

    def add_package(self, p):
        self.x("INSERT OR REPLACE INTO packages(id,ecosystem,name,published,downloads,data) VALUES(?,?,?,?,?,?)",
               (p["id"], p["ecosystem"], p["name"], p["published"], p["downloads"], json.dumps(p, ensure_ascii=False)))

    def get_package(self, ecosystem, name, vid):
        r = self.q("SELECT data FROM packages WHERE id=? AND ecosystem=? AND name=?", (vid, ecosystem, name))
        return r[0]["data"] if r else None

    def prune_packages(self, before):
        self.x("DELETE FROM packages WHERE published < ?", (before,))

    def set_blocklist(self, source, entries):
        with self.lock, self.conn:
            self.conn.execute("DELETE FROM blocklist WHERE source=?", (source,))
            self.conn.executemany("INSERT OR IGNORE INTO blocklist(entry,source) VALUES(?,?)",
                                  [(e, source) for e in entries])

    def set_toplist(self, rows):
        with self.lock, self.conn:
            self.conn.execute("DELETE FROM toplist")
            self.conn.executemany("INSERT OR IGNORE INTO toplist(domain,rank) VALUES(?,?)", rows)

    def site_rank(self, site):
        """Rank of a site or of its registered domain (shop.example.com -> example.com)."""
        parts = site.split(".")
        names = [".".join(parts[i:]) for i in range(len(parts) - 1)]
        r = self.q(f"SELECT MIN(rank) r FROM toplist WHERE domain IN ({','.join('?' * len(names))})", names)
        return r[0]["r"] if r else None

    # --- notifications held during quiet hours ---
    def hold(self, title, message, priority, click, actions, created):
        self.x("INSERT INTO outbox(created,title,message,priority,click,actions) VALUES(?,?,?,?,?,?)",
               (created, title, message, priority, click, json.dumps(actions or [])))

    def held(self):
        rows = self.q("SELECT * FROM outbox ORDER BY id")
        for r in rows:
            r["actions"] = [tuple(a) for a in json.loads(r["actions"] or "[]")]
        return rows

    def clear_held(self, last_id):
        self.x("DELETE FROM outbox WHERE id <= ?", (last_id,))

    # --- monitors ---
    def get_monitor(self, key):
        r = self.q("SELECT * FROM monitors WHERE key=?", (key,))
        return r[0] if r else None

    def save_monitor(self, m):
        self.x(
            """INSERT OR REPLACE INTO monitors(key,kind,name,target,up,since,latency,detail,fails,last_check,extra)
               VALUES(:key,:kind,:name,:target,:up,:since,:latency,:detail,:fails,:last_check,:extra)""",
            dict(m, extra=json.dumps(m.get("extra") or {}, ensure_ascii=False)),
        )

    def prune_monitors(self, kinds, keep):
        for r in self.q(f"SELECT key FROM monitors WHERE kind IN ({','.join('?' * len(kinds))})", kinds):
            if r["key"] not in keep:
                self.x("DELETE FROM monitors WHERE key=?", (r["key"],))
