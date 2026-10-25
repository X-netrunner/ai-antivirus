#!/usr/bin/env python3
"""Summarize AI Antivirus alerts for the two-week alert-only soak (docs/SOAK.md).

Read-only: it only reads alert JSON lines. It never talks to the daemons and changes nothing.

  sudo -u ai-antivirus ai-antivirus alerts -n 100000 --json | python3 scripts/soak-report.py
  python3 scripts/soak-report.py alerts.jsonl                  # a saved copy
  python3 scripts/soak-report.py alerts.jsonl --csv review.csv # blank table to label every alert
  python3 scripts/soak-report.py --rate review.csv             # false-positive rate from the labeled table

Labels for the `verdict` column: tp (real threat), fp (harmless, should not have alerted), ok (expected, you did it on
purpose, e.g. a test). Rows with an empty verdict are counted as unreviewed.
"""
import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

SEV = ["info", "low", "medium", "high", "critical"]


def sev_rank(s):
    return SEV.index(s) if s in SEV else -1


def what(a):
    d = a.get("detail") or {}
    for k in ("exe", "path"):
        v = d.get(k)
        if isinstance(v, str):
            return v
        if v is not None:
            return json.dumps(v, sort_keys=True)
    return "-"


def day(a):
    ts = a.get("ts_ns")
    # Wall-clock Unix nanoseconds are around 1.7e18; anything much smaller is not a calendar time.
    if isinstance(ts, int) and ts > 10**17:
        return datetime.fromtimestamp(ts / 1e9, tz=timezone.utc).strftime("%Y-%m-%d")
    return "unknown"


def load(stream):
    alerts, bad = [], 0
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            a = json.loads(line)
        except json.JSONDecodeError:
            bad += 1
            continue
        if isinstance(a, dict) and "rule_id" in a:
            alerts.append(a)
        else:
            bad += 1
    return alerts, bad


def report(alerts, bad, min_sev):
    print(f"alerts: {len(alerts)}" + (f"   (skipped {bad} lines that are not alerts)" if bad else ""))
    if not alerts:
        print("Nothing to report. Zero alerts is the goal, but check that the engine ran: ai-antivirus db-stats")
        return
    days = Counter(day(a) for a in alerts)
    dated = sorted(d for d in days if d != "unknown")
    if dated:
        print(f"span: {dated[0]} .. {dated[-1]}   days with alerts: {len(dated)}" + (f"   (+{days['unknown']} undated)" if "unknown" in days else ""))
    print("\nby severity:")
    sev = Counter(a.get("severity", "?") for a in alerts)
    for s in sorted(sev, key=lambda x: -sev_rank(x)):
        print(f"  {s:<9}{sev[s]:>7}")

    by_rule = defaultdict(list)
    for a in alerts:
        by_rule[a["rule_id"]].append(a)
    print("\nby rule (count, distinct programs/paths, newest example):")
    for rid, rows in sorted(by_rule.items(), key=lambda kv: -len(kv[1])):
        distinct = len({what(a) for a in rows})
        newest = max(rows, key=lambda a: a.get("id", 0))
        print(f"  {rid:<14}{len(rows):>6}  {distinct:>4}  {what(newest)[:60]}   [{newest.get('title', '')[:50]}]")

    print("\nper day:")
    for d in sorted(days):
        print(f"  {d}  {days[d]:>6}")

    pairs = Counter((a["rule_id"], what(a)) for a in alerts)
    print("\nrepeat offenders (same rule, same program/path), top 10 - tune these first:")
    for (rid, w), n in pairs.most_common(10):
        print(f"  {n:>5}  {rid:<14} {w[:80]}")

    loud = [a for a in alerts if sev_rank(a.get("severity", "")) >= sev_rank(min_sev)]
    print(f"\nreview list: {len(loud)} alerts at '{min_sev}' or above (newest 25):")
    for a in sorted(loud, key=lambda a: -a.get("id", 0))[:25]:
        print(f"  #{a.get('id')}  {day(a)}  {a.get('severity', '?'):<8} {a['rule_id']:<14} {what(a)[:70]}")


def write_csv(alerts, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "day", "severity", "rule_id", "what", "title", "verdict", "note"])
        for a in sorted(alerts, key=lambda a: a.get("id", 0)):
            w.writerow([a.get("id"), day(a), a.get("severity", ""), a["rule_id"], what(a), a.get("title", ""), "", ""])
    print(f"wrote {path}: fill the `verdict` column with tp, fp or ok, then run --rate {path}")


def rate(path):
    tot, per = Counter(), defaultdict(Counter)
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            v = (row.get("verdict") or "").strip().lower()
            per[row["rule_id"]][v or "unreviewed"] += 1
            tot[v or "unreviewed"] += 1
    n = sum(tot.values())
    reviewed = n - tot["unreviewed"]
    print(f"alerts: {n}   reviewed: {reviewed}   unreviewed: {tot['unreviewed']}")
    if reviewed == 0:
        print("Label some rows first (tp / fp / ok).")
        return
    print(f"  tp {tot['tp']}   fp {tot['fp']}   ok {tot['ok']}")
    print(f"false-positive share of reviewed alerts: {100 * tot['fp'] / reviewed:.1f} %")
    print("\nper rule:                 tp    fp    ok  unrev")
    for rid, c in sorted(per.items()):
        print(f"  {rid:<20}{c['tp']:>5}{c['fp']:>6}{c['ok']:>6}{c['unreviewed']:>7}")
    print("\nA rule with any fp needs an exclusion or a fix before you leave alert-only. Report days, not just totals.")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("file", nargs="?", help="alerts as JSON lines (default: stdin)")
    p.add_argument("--min-severity", default="medium", choices=SEV, help="review list threshold (default medium)")
    p.add_argument("--csv", metavar="OUT", help="write a table to label alerts by hand")
    p.add_argument("--rate", metavar="CSV", help="compute the false-positive rate from a labeled table")
    a = p.parse_args()
    if a.rate:
        rate(a.rate)
        return
    stream = open(a.file) if a.file else sys.stdin
    if stream is sys.stdin and sys.stdin.isatty():
        p.error("pipe alerts in, or pass a file (see the examples above)")
    alerts, bad = load(stream)
    report(alerts, bad, a.min_severity)
    if a.csv:
        write_csv(alerts, a.csv)


if __name__ == "__main__":
    main()
