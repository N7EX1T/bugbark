"""Country-wide internet outages, from IODA (Georgia Tech): a cut cable, a blackout or a government shutdown."""
import json
from datetime import datetime, timedelta, timezone

from . import util
from .util import log

IODA_EVENTS = "https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events"
# Routing (BGP) and active probing see real outages; other signals (traffic telescopes, search traffic) are noisy
SOURCES = {"bgp": "routing data (BGP)", "ping-slash24": "active probing"}


def ts(epoch):
    return util.iso(datetime.fromtimestamp(epoch, timezone.utc))


class Outages:
    def __init__(self, cfg, db, notifier):
        self.cfg, self.db, self.notifier = cfg, db, notifier
        self.o = cfg["internet"]

    def events(self, days=3):
        """Significant outages from the last `days` days, biggest first."""
        now = int(util.now().timestamp())
        d = util.http_json(f"{IODA_EVENTS}?entityType=country&from={now - days * 86400}&until={now}",
                           timeout=60, retries=2)
        out = []
        for e in d.get("data") or []:
            if e.get("datasource") not in SOURCES or (e.get("score") or 0) < self.o["min_score"]:
                continue
            if (e.get("duration") or 0) < self.o["min_minutes"] * 60:
                continue
            code = (e.get("location") or "").rpartition("/")[2]
            out.append({
                "key": f"{code}:{e['start']}", "country": e.get("location_name") or code, "code": code,
                "start": ts(e["start"]), "minutes": round(e["duration"] / 60), "end": ts(e["start"] + e["duration"]),
                "ongoing": e["start"] + e["duration"] >= now - 1800,
                "source": SOURCES[e["datasource"]], "score": round(e["score"]),
                "url": f"https://ioda.inetintel.cc.gatech.edu/country/{code}",
            })
        out.sort(key=lambda e: e["score"], reverse=True)
        return out

    def run(self):
        if not self.o["enabled"]:
            return
        events = self.events()
        # Dashboard: the same list, refreshed every run
        self.db.set_meta("internet_events", json.dumps(events))
        first_run = self.db.get_meta("internet_init") is None
        seen = set(json.loads(self.db.get_meta("internet_alerted", "[]")))
        fresh = util.iso(util.now() - timedelta(hours=24))
        sent = 0
        for e in events:
            if e["key"] in seen:
                continue
            seen.add(e["key"])
            if not first_run and e["start"] >= fresh and sent < 3:
                self.send(e)
                sent += 1
        # Events older than the 3-day window can't come back, so only current keys need remembering
        current = {e["key"] for e in events}
        self.db.set_meta("internet_alerted", json.dumps(sorted(seen & current)))
        self.db.set_meta("internet_init", "1")
        log.info("Internet outages: %s significant, %s alerts", len(events), sent)

    def send(self, e):
        start = util.parse_ts(e["start"])
        lines = [f"Seen in {e['source']} since {start.strftime('%b')} {start.day}, {start.strftime('%H:%M')} UTC, "
                 f"{'ongoing for' if e['ongoing'] else 'lasted'} {util.duration(e['minutes'] * 60)}.",
                 "Could be a power cut, a damaged cable or a government shutdown."]
        self.notifier.send(f"🌐 Internet outage: {e['country']}", "\n".join(lines), priority=3, click=e["url"],
                           actions=[("Details", e["url"])])
