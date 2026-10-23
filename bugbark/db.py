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
"""

JSON_COLS = {"data": {}, "reasons": [], "notified": [], "extra": {}, "poc": []}

# Columns added after the first release: (table, column, definition)
MIGRATIONS = [
    ("cves", "poc", "TEXT DEFAULT '[]'"),
    ("cves", "poc_checked", "TEXT"),
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
