import argparse
import json
import logging
import os
import signal
import sys
import threading
import time

from . import util
from .config import load_config
from .cves import Engine
from .db import DB
from .export import export_site
from .monitor import Monitor
from .notify import Notifier
from .util import log
from .web import serve


JOB_NAMES = {
    "nvd": "NVD (new CVEs)", "cveorg": "CVE.org (new CVEs)", "kev": "CISA KEV", "epss": "EPSS", "exploits": "exploit search",
    "news": "security news", "digest": "daily digest", "sites": "site checks", "status": "status pages",
}
ALERT_AFTER = 3600  # a check must keep failing this long before BugBark warns about itself


class Job:
    def __init__(self, name, interval, fn):
        self.name, self.interval, self.fn = name, interval, fn
        self.next = 0

    def due(self, db):
        """For scheduled runs (GitHub Actions): has the interval passed since the last run?"""
        last = util.parse_ts(json.loads(db.get_meta("job:" + self.name, "{}")).get("last_run"))
        # Scheduled runs drift by a few minutes, so allow some slack
        return last is None or (util.now() - last).total_seconds() >= self.interval * 0.8

    def run(self, db, health):
        key = "job:" + self.name
        state = json.loads(db.get_meta(key, "{}"))
        state["last_run"] = util.iso(util.now())
        try:
            self.fn()
            state["last_ok"], state["error"] = state["last_run"], None
        except Exception as e:
            log.exception("Job %s failed", self.name)
            state["error"] = str(e) or e.__class__.__name__
        health.check(self.name, state)
        db.set_meta(key, json.dumps(state, ensure_ascii=False))
        self.next = time.time() + self.interval


class Health:
    """Warns once when a check keeps failing, and once more when it recovers."""

    def __init__(self, cfg, notifier):
        self.cfg, self.notifier = cfg, notifier

    def check(self, name, state):
        label = JOB_NAMES.get(name, name)
        if state["error"] is None:
            if state.pop("alerted", False):
                self.notifier.send(f"✅ BugBark: {label} works again", "Alerts are back to normal.",
                                   priority=3, click=util.panel_url(self.cfg))
            state.pop("failing_since", None)
            state.pop("failures", None)
            return
        state.setdefault("failing_since", state["last_run"])
        state["failures"] = state.get("failures", 0) + 1
        failing_for = (util.now() - util.parse_ts(state["failing_since"])).total_seconds()
        if failing_for >= ALERT_AFTER and not state.get("alerted"):
            self.notifier.send(
                f"⚠ BugBark: {label} failing",
                f"Failing for {util.duration(failing_for)} ({state['failures']} runs in a row).\n"
                f"Last error: {util.shorten(state['error'], 200)}\n"
                "Alerts from this check are delayed until it recovers.",
                priority=4, click=util.panel_url(self.cfg))
            state["alerted"] = True


def run_jobs(jobs, db, health, stop):
    while not stop.is_set():
        for j in jobs:
            if time.time() >= j.next and not stop.is_set():
                j.run(db, health)
        stop.wait(1)


def main():
    ap = argparse.ArgumentParser(prog="bugbark",
                                 description="BugBark: notifications about major vulnerabilities and outages")
    ap.add_argument("-c", "--config", default=os.environ.get("BUGBARK_CONFIG", "config.toml"))
    ap.add_argument("--data", default=os.environ.get("BUGBARK_DATA", "data"), help="database directory")
    ap.add_argument("--test-notify", action="store_true", help="send a test notification and exit")
    ap.add_argument("--once", action="store_true", help="run every check once and exit")
    ap.add_argument("--due", action="store_true",
                    help="run only the checks whose interval has passed, then exit (for cron / GitHub Actions)")
    ap.add_argument("--export", metavar="DIR", help="write the dashboard as a static site to DIR, then exit")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    if not cfg["web"]["public_url"]:
        cfg["web"]["public_url"] = f"http://{util.lan_ip()}:{cfg['web']['port']}"

    db = DB(os.path.join(args.data, "bugbark.db"))
    notifier = Notifier(cfg)
    engine = Engine(cfg, db, notifier)
    monitor = Monitor(cfg, db, notifier)
    health = Health(cfg, notifier)

    if args.test_notify:
        if not notifier.enabled:
            sys.exit("No notification channel configured: set ntfy_topic or Telegram in config.toml")
        panel = util.panel_url(cfg)
        ok = notifier.send("🔔 BugBark test", "Notifications work. Tap to open the dashboard.",
                           priority=4, click=panel, actions=[("Open dashboard", panel)])
        sys.exit(0 if ok else 1)

    if not notifier.enabled:
        log.warning("No notification channel configured: set ntfy_topic or Telegram in %s", args.config)

    security = [
        Job("kev", 3600, engine.run_kev),  # KEV first: the "exploited" flags depend on it
        Job("nvd", cfg["cve"]["check_minutes"] * 60, engine.run_nvd),
        Job("cveorg", cfg["cve"]["check_minutes"] * 60, engine.run_cveorg),
        Job("epss", 6 * 3600, engine.run_epss),
        Job("exploits", 1800, engine.run_exploits),
        Job("news", cfg["news"]["interval_seconds"], engine.news.run),
        Job("digest", 600, engine.run_digest),  # sends once a day, at [digest] hour_utc
    ]
    monitors = [
        Job("sites", cfg["monitor"]["interval_seconds"], monitor.run_checks),
        Job("status", cfg["status_pages"]["interval_seconds"], monitor.run_status_pages),
    ]

    if args.once or args.due or args.export:
        if args.once or args.due:
            for j in security + monitors:
                if args.once or j.due(db):
                    j.run(db, health)
        if args.export:
            n = export_site(cfg, db, engine, notifier, args.export)
            log.info("Exported dashboard with %s CVEs to %s", n, args.export)
        db.close(compact=True)
        return

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    for jobs in (security, monitors):
        threading.Thread(target=run_jobs, args=(jobs, db, health, stop), daemon=True).start()
    try:
        serve(cfg, db, engine, notifier)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()


if __name__ == "__main__":
    main()
