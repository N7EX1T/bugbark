"""Weekly report: what happened over the last 7 or 30 days, for the dashboard and a Monday notification."""
from datetime import timedelta

from . import util
from .breaches import count_text


def _days(end, n):
    return [(end - timedelta(days=n - 1 - i)).strftime("%Y-%m-%d") for i in range(n)]


def _per_day(days, dates):
    counts = dict.fromkeys(days, 0)
    for d in dates:
        if d and d[:10] in counts:
            counts[d[:10]] += 1
    return [{"day": d, "n": n} for d, n in counts.items()]


def _top(names, limit=6):
    counts = {}
    for n in names:
        if n:
            counts[n] = counts.get(n, 0) + 1
    return [{"name": n, "n": c} for n, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]]


def build(cfg, db, days, end=None):
    """Numbers for the `days` days up to and including `end` (today, UTC)."""
    end = end or util.now()
    day_list = _days(end, days)
    since = day_list[0] + "T00:00:00Z"
    until = (end + timedelta(days=1)).strftime("%Y-%m-%d") + "T00:00:00Z"
    span = (since, until)

    major = db.q("""SELECT id, published, vendor, product, kev, poc, score FROM cves
                    WHERE important=1 AND published >= ? AND published < ?""", span)
    kev = db.q("SELECT id, date_added FROM kev WHERE date_added >= ? AND date_added < ?", span)
    victims = db.q("SELECT discovered, grp, rank, data FROM victims WHERE discovered >= ? AND discovered < ?", span)
    breaches = db.q("SELECT data FROM breaches WHERE added >= ? AND added < ? ORDER BY count DESC", span)
    min_sources = cfg["news"]["min_sources"]
    stories = [s for s in _stories(cfg, db, days) if len(s["sources"]) >= min_sources and s["first"] >= since]

    # The same vendor is written in different ways ("microsoft", "Microsoft"): count them under one name
    vendor = lambda r: (r["vendor"] or r["product"] or "").strip()
    canon = {}
    for r in major:
        v = vendor(r)
        if v and (v.lower() not in canon or canon[v.lower()].islower()):
            canon[v.lower()] = v
    max_rank = cfg["ransomware"]["max_rank"]
    notable = sorted((dict(v["data"], rank=v["rank"]) for v in victims if v["rank"] and v["rank"] <= max_rank),
                     key=lambda v: v["rank"])
    return {
        "days": days,
        "from": day_list[0],
        "to": day_list[-1],
        "totals": {
            "major": len(major),
            "exploited": len(kev),
            "poc": sum(1 for r in major if r["poc"]),
            "victims": len(victims),
            "breaches": len(breaches),
            "accounts": sum(b["data"]["count"] for b in breaches),
            "packages": db.q("SELECT COUNT(DISTINCT id) n FROM packages WHERE published >= ? AND published < ?", span)[0]["n"],
        },
        "major_per_day": _per_day(day_list, [r["published"] for r in major]),
        "victims_per_day": _per_day(day_list, [v["discovered"] for v in victims]),
        "top_vendors": _top(canon.get(vendor(r).lower()) for r in major),
        "top_groups": _top(v["grp"] for v in victims),
        "breaches": [{k: b["data"][k] for k in ("name", "title", "count", "added", "breach_date", "data_classes")}
                     for b in breaches[:10]],
        "notable_victims": [{k: v.get(k) for k in ("victim", "site", "grp", "country", "sector", "discovered", "url",
                                                  "rank")} for v in notable[:10]],
        "packages": [dict(p["data"]) for p in db.q("""SELECT data FROM packages WHERE published >= ? AND published < ?
                      AND downloads >= ? ORDER BY downloads DESC LIMIT 10""", span + (cfg["packages"]["min_weekly_downloads"],))],
        "stories": [{"title": s["title"], "sources": len(s["sources"]), "link": s["items"][0]["link"]}
                    for s in stories[:5]],
    }


def _stories(cfg, db, days):
    from .news import News
    return News(cfg, db, None).stories(days=days)


def weekly_message(r):
    t = r["totals"]
    lines = [f"Major CVEs: {t['major']} · {t['exploited']} newly exploited · {t['poc']} with public exploit"]
    if r["top_vendors"]:
        lines.append("Top vendors: " + ", ".join(f"{v['name']} {v['n']}" for v in r["top_vendors"][:3]))
    if t["victims"]:
        lines.append(f"Ransomware: {t['victims']} claimed victims"
                     + (" · most active: " + ", ".join(f"{g['name']} {g['n']}" for g in r["top_groups"][:3])
                        if r["top_groups"] else ""))
    if r["notable_victims"]:
        lines.append("Notable: " + ", ".join(v["victim"] for v in r["notable_victims"][:3]))
    if t["breaches"]:
        big = r["breaches"][0]
        lines.append(f"Breaches: {t['breaches']} · {count_text(t['accounts'])} accounts · biggest: "
                     f"{big['title']} ({count_text(big['count'])})")
    if r["stories"]:
        lines += ["", "Biggest stories:"] + [f"• {util.shorten(s['title'], 90)}" for s in r["stories"][:3]]
    return "\n".join(lines)
