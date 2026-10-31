"""Command-line entry point for ThreatMgr.

Usage:
  python -m threatmgr collect [--insecure] [--feeds a,b,c]
  python -m threatmgr serve   [--host H] [--port N]
  python -m threatmgr watch   [--interval SECONDS] [--host H] [--port N]
  python -m threatmgr scan    FILE [FILE ...]
  python -m threatmgr lookup  VALUE
  python -m threatmgr stats
  python -m threatmgr feeds
"""
from __future__ import annotations

import argparse
import sys
import threading
import time

from .store import Store
from .collector import collect_once
from .matcher import Matcher
from . import feeds as feedmod
from . import server as srv
from . import ingest as ing
from .correlator import Correlator
from .dispatch import Notifier


def _store(args) -> Store:
    return Store(args.db)


def cmd_collect(args):
    enabled = args.feeds.split(",") if args.feeds else None
    collect_once(_store(args), enabled=enabled, insecure=args.insecure)


def cmd_serve(args):
    srv.serve(_store(args), host=args.host, port=args.port)


def cmd_watch(args):
    """Collect on a loop AND serve the dashboard — the 'always on' SIEM mode."""
    store = _store(args)
    enabled = args.feeds.split(",") if args.feeds else None

    def loop():
        while True:
            print(f"\n[watch] refreshing feeds @ {time.strftime('%X')}")
            try:
                collect_once(store, enabled=enabled, insecure=args.insecure)
            except Exception as e:
                print(f"[watch] collection error: {e}")
            time.sleep(args.interval)

    threading.Thread(target=loop, daemon=True).start()
    srv.serve(store, host=args.host, port=args.port)


def _build_notifier(args):
    n = Notifier.from_args(args)
    return n if n.enabled else None


def cmd_ingest(args):
    """Run as a syslog server: ingest logs from devices and match in real time."""
    correlator = None if args.no_correlate else Correlator()
    notifier = _build_notifier(args)
    ing.serve_syslog(
        _store(args), host=args.host, port=args.port,
        udp=not args.tcp_only, tcp=not args.udp_only,
        echo=not args.quiet, reload_every=args.reload_every,
        correlator=correlator, notifier=notifier,
    )


def cmd_test_alert(args):
    """Send a synthetic alert through the configured dispatch channels."""
    n = Notifier.from_args(args)
    n.min = 0  # force-send regardless of severity gate
    if not n.enabled:
        print("No dispatch channel configured. Set --webhook / THREATMGR_WEBHOOK "
              "or SMTP flags + THREATMGR_SMTP_PASSWORD.")
        return
    n.notify({
        "observable": "203.0.113.66", "threat": "ThreatMgr dispatch test",
        "severity": "critical", "source": "test-alert", "ioc_type": "ip",
        "context": "synthetic alert to verify delivery",
    })
    print("Test alert sent via:",
          ", ".join(c for c, on in [("webhook", n.webhook_url),
                                     ("email", n.smtp_host and n.mail_to)] if on))


def cmd_scan(args):
    store = _store(args)
    m = Matcher(store)
    grand = 0
    for path in args.files:
        try:
            res = m.scan_file(path)
        except OSError as e:
            print(f"  ! cannot read {path}: {e}")
            continue
        grand += res["alert_count"]
        print(f"\n{path}: {res['lines_scanned']} lines, {res['alert_count']} alert(s)")
        for a in res["alerts"]:
            ioc = a["ioc"]
            print(f"  [!] {a['observable']:<40} {ioc.get('severity','').upper():<9} "
                  f"{ioc.get('threat','')}  (src={ioc.get('source')})")
    print(f"\n[scan] total alerts: {grand}")
    sys.exit(1 if grand else 0)


def cmd_lookup(args):
    hits = Matcher(_store(args)).check(args.value)
    if not hits:
        print(f"{args.value}: CLEAN (no match in threat intel)")
        return
    print(f"{args.value}: {len(hits)} MATCH(es)")
    for h in hits:
        print(f"  - {h['severity'].upper():<9} {h.get('threat','')}  "
              f"[{h['ioc_type']}] src={h['source']} conf={h['confidence']}")


def cmd_stats(args):
    s = _store(args).stats()
    print(f"Total IOCs : {s['total_iocs']}")
    print(f"Open alerts: {s['open_alerts']}")
    print("By type    :", ", ".join(f"{k}={v}" for k, v in s["by_type"].items()) or "-")
    print("By severity:", ", ".join(f"{k}={v}" for k, v in s["by_severity"].items()) or "-")
    print("By source  :")
    for k, v in s["by_source"].items():
        print(f"   {k:<16} {v}")


def cmd_feeds(args):
    print("Configured feeds:")
    for fid, spec in feedmod.FEEDS.items():
        print(f"  {fid:<16} {spec['name']}")
        print(f"   {'':16} {spec['url']}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="threatmgr",
                                description="Threat-intel aggregation & SIEM monitoring")
    p.add_argument("--db", default="threatintel.db", help="SQLite database path")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="pull all feeds once")
    c.add_argument("--feeds", help="comma-separated feed ids (default: all)")
    c.add_argument("--insecure", action="store_true", help="skip TLS verification")
    c.set_defaults(func=cmd_collect)

    s = sub.add_parser("serve", help="run the web console")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.set_defaults(func=cmd_serve)

    w = sub.add_parser("watch", help="collect on an interval + serve console")
    w.add_argument("--interval", type=int, default=3600, help="seconds between refreshes")
    w.add_argument("--feeds", help="comma-separated feed ids")
    w.add_argument("--insecure", action="store_true")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8787)
    w.set_defaults(func=cmd_watch)

    def add_alert_flags(sp):
        g = sp.add_argument_group("alert dispatch")
        g.add_argument("--webhook", help="webhook URL (Slack-compatible); "
                       "or set THREATMGR_WEBHOOK")
        g.add_argument("--min-severity", default="high",
                       choices=["low", "medium", "high", "critical"],
                       help="minimum severity to dispatch (default high)")
        g.add_argument("--smtp-host", help="SMTP server for email alerts")
        g.add_argument("--smtp-port", type=int, default=587)
        g.add_argument("--smtp-user", help="SMTP username")
        g.add_argument("--smtp-ssl", action="store_true", help="use SMTPS (implicit TLS)")
        g.add_argument("--mail-from", help="email From address")
        g.add_argument("--mail-to", help="email To address (enables email dispatch)")

    ig = sub.add_parser("ingest", help="run a syslog server; ingest device logs and match live")
    ig.add_argument("--host", default="0.0.0.0", help="bind address (default: all interfaces)")
    ig.add_argument("--port", type=int, default=5140,
                    help="syslog port (default 5140; use 514 to run as root)")
    ig.add_argument("--udp-only", action="store_true", help="listen UDP only")
    ig.add_argument("--tcp-only", action="store_true", help="listen TCP only")
    ig.add_argument("--quiet", action="store_true", help="don't echo alerts to stdout")
    ig.add_argument("--reload-every", type=int, default=300,
                    help="seconds between CIDR cache refreshes (default 300)")
    ig.add_argument("--no-correlate", action="store_true",
                    help="disable the correlation/threshold rules")
    add_alert_flags(ig)
    ig.set_defaults(func=cmd_ingest)

    ta = sub.add_parser("test-alert", help="send a synthetic alert to verify dispatch")
    add_alert_flags(ta)
    ta.set_defaults(func=cmd_test_alert)

    sc = sub.add_parser("scan", help="scan log file(s) against the IOC store")
    sc.add_argument("files", nargs="+")
    sc.set_defaults(func=cmd_scan)

    lk = sub.add_parser("lookup", help="check a single IP/domain/url/hash/cve")
    lk.add_argument("value")
    lk.set_defaults(func=cmd_lookup)

    sub.add_parser("stats", help="show summary").set_defaults(func=cmd_stats)
    sub.add_parser("feeds", help="list configured feeds").set_defaults(func=cmd_feeds)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
