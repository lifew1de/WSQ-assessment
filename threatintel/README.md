# ThreatMgr — Threat-Intelligence Aggregation & SIEM-style Monitoring

A lightweight, self-contained threat-management platform for SOC analysts. It
pulls indicators of compromise (IOCs) from public threat-intelligence feeds on
the internet, stores them in a searchable index, and lets you **proactively
monitor** your own logs by matching observables (IPs, domains, URLs, file
hashes, CVEs) against that intel — raising alerts the way a SIEM would.

> **Pure Python standard library.** No `pip install`, no external services.
> Runs anywhere with Python 3.8+.

## Why

SOC teams need to know, *before* an incident, which infrastructure is already
flagged as malicious. ThreatMgr continuously aggregates open threat feeds and
turns them into a detection layer you can point at firewall / proxy / DNS / auth
logs.

```
 ┌──────────────┐   collect    ┌────────────┐   match    ┌──────────────┐
 │ Public threat │ ──────────▶ │  IOC store  │ ◀───────── │  Your logs    │
 │ intel feeds   │   (normalize)│  (SQLite)  │   (scan)   │  (fw/dns/...) │
 └──────────────┘              └─────┬──────┘            └──────────────┘
                                     │ serve
                               ┌─────▼──────┐
                               │ SOC console │  (web dashboard + JSON API)
                               └────────────┘
```

## Feeds included

All free / open feeds commonly used in SOCs. Each is parsed into a common IOC
schema (value, type, threat label, source, confidence, severity):

| id | source | IOC type |
|----|--------|----------|
| `cisa_kev` | CISA Known Exploited Vulnerabilities | CVE |
| `feodo_c2` | abuse.ch Feodo Tracker (botnet C2) | IP |
| `threatfox` | abuse.ch ThreatFox (recent IOCs) | IP/domain/url/hash |
| `urlhaus` | abuse.ch URLhaus (malware URLs) | URL |
| `sslbl` | abuse.ch SSL Blacklist | IP |
| `et_compromised` | Emerging Threats compromised IPs | IP |
| `blocklist_de` | blocklist.de attacking hosts | IP |
| `cins_army` | CINS Army (CI Badguys) | IP |
| `openphish` | OpenPhish phishing feed | URL |

Add your own in `threatmgr/feeds.py` — a feed is just a URL plus a parser that
yields IOC dicts.

## Quick start

```bash
# 1. Pull all feeds into the local IOC store (threatintel.db)
python -m threatmgr collect

# 2. Launch the SOC console (dashboard + API) at http://127.0.0.1:8787
python -m threatmgr serve

# --- or do both continuously (refresh feeds hourly + keep console up) ---
python -m threatmgr watch --interval 3600
```

Then open <http://127.0.0.1:8787>. The console shows live counts, lets you
search IOCs, scan pasted log lines, and acknowledge alerts.

## Run as a log server (syslog ingestion)

Turn ThreatMgr into a network log server that devices ship to. Every received
line is matched against the intel in real time and hits become alerts.

```bash
# Listen for syslog on UDP+TCP (default port 5140, all interfaces)
python -m threatmgr ingest

# Classic syslog port 514 (needs root/sudo)
sudo python -m threatmgr ingest --port 514

# UDP only, quieter
python -m threatmgr ingest --udp-only --quiet
```

Point your devices at `udp://<this-host>:5140` (or TCP). Examples:

- **Linux rsyslog** — in `/etc/rsyslog.d/threatmgr.conf`:
  `*.*  @<host>:5140`  (one `@` = UDP, `@@` = TCP), then restart rsyslog.
- **Cisco ASA / IOS** — `logging host <host> udp 5140`
- **pfSense / OPNsense** — Status ▸ System Logs ▸ Settings ▸ Remote Logging → `<host>:5140`
- **Fortinet / Palo Alto** — add a syslog server pointing at `<host>:5140`

Run the console (`serve`) against the **same `--db`** in another terminal to watch
alerts stream into the dashboard. The syslog engine refreshes its CIDR cache
every few minutes (`--reload-every`), so IOCs added by later `collect` runs are
picked up without a restart.

> Ports below 1024 (e.g. 514) require root. The default 5140 avoids that.

## Proactive monitoring from the CLI

```bash
# Check a single observable
python -m threatmgr lookup 185.220.101.1
python -m threatmgr lookup CVE-2021-44228

# Scan whole log files — exits non-zero if anything matches (CI / cron friendly)
python -m threatmgr scan /var/log/suricata/eve.log /var/log/squid/access.log

# Summary of what's in the store
python -m threatmgr stats
```

Wire `scan` into cron or a log-shipping pipeline to get continuous detection:

```cron
*/15 * * * *  cd /opt/threatmgr && python -m threatmgr scan /var/log/firewall.log >> /var/log/threatmgr/hits.log 2>&1
0    * * * *  cd /opt/threatmgr && python -m threatmgr collect
```

## JSON API

| method | endpoint | purpose |
|--------|----------|---------|
| GET | `/api/stats` | summary counts |
| GET | `/api/iocs?q=&type=&severity=&source=&limit=` | search the index |
| GET | `/api/feeds` | feed run status |
| GET | `/api/alerts?open=1` | alerts |
| GET | `/api/lookup?value=` | check one observable |
| POST | `/api/scan` | `{"lines":[...]}` → alerts |
| POST | `/api/ack` | `{"id":<alert_id>}` |

Example:

```bash
curl -s -X POST localhost:8787/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"lines":["src=10.0.0.5 dst=185.220.101.1 GET http://evil.example/x"]}'
```

## Network / proxy notes

The collector honours `HTTP_PROXY` / `HTTPS_PROXY` and handles unreachable feeds
gracefully — one failed feed never stops the others, and the failure is recorded
in feed status. If a corporate proxy does TLS interception and breaks
verification, you can (at your own risk) pass `--insecure` to `collect` / `watch`.

## Layout

```
threatintel/
├── threatmgr/
│   ├── feeds.py       feed definitions + parsers
│   ├── store.py       SQLite IOC index, feed metadata, alerts
│   ├── collector.py   concurrent fetch → parse → upsert
│   ├── matcher.py     observable extraction + IOC matching (detection)
│   ├── ingest.py      syslog server (UDP/TCP) — ingest device logs live
│   ├── server.py      web console + JSON API
│   └── cli.py         command-line entry point
└── README.md
```

## Scope & ethics

This is a **defensive** tool: it aggregates public threat intelligence and
matches it against logs you are authorised to monitor. Only point it at systems
and logs you own or have permission to analyse.
