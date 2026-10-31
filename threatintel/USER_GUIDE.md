# ThreatMgr — User Guide

A step-by-step guide to running and using ThreatMgr, from a cold start to a
full always-on deployment. ThreatMgr is a lightweight, SIEM-style threat-
management platform for SOC analysts: it **pulls threat intelligence from the
internet**, **ingests logs from your devices**, **matches and correlates** them
in real time, **deduplicates and suppresses** noise, and **alerts you** via a web
console, webhook/Slack, or email.

> **No installation, no dependencies.** Pure Python standard library. If you have
> Python 3.8+ you can run everything in this guide.

---

## Table of contents

1. [Concepts in 60 seconds](#1-concepts-in-60-seconds)
2. [Requirements & setup](#2-requirements--setup)
3. [Quick start (3 commands)](#3-quick-start-3-commands)
4. [Step-by-step walkthrough](#4-step-by-step-walkthrough)
   - [4.1 Pull threat intel](#41-pull-threat-intel-collect)
   - [4.2 Open the console](#42-open-the-console-serve)
   - [4.3 Check a single indicator](#43-check-a-single-indicator-lookup)
   - [4.4 Scan a log file](#44-scan-a-log-file-scan)
   - [4.5 Run as a log server](#45-run-as-a-log-server-ingest)
   - [4.6 Turn on alerting](#46-turn-on-alerting-webhook--email)
   - [4.7 Tune correlation, dedup & suppression](#47-tune-correlation-dedup--suppression)
5. [Connecting your devices (syslog)](#5-connecting-your-devices-syslog)
6. [The web console](#6-the-web-console)
7. [Command reference](#7-command-reference)
8. [JSON API reference](#8-json-api-reference)
9. [Production deployment](#9-production-deployment)
10. [Try it right now (offline demo)](#10-try-it-right-now-offline-demo)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Concepts in 60 seconds

| Term | Meaning |
|------|---------|
| **IOC** | Indicator of Compromise — a known-bad IP, domain, URL, file hash, or CVE. |
| **Feed** | A public source of IOCs (CISA, abuse.ch, …). ThreatMgr pulls 9 of them. |
| **Observable** | Anything ThreatMgr pulls out of your logs (an IP, domain, etc.) to check. |
| **Match** | An observable that equals (or falls inside) a known IOC → raises an alert. |
| **Correlation** | A *behavioural* alert from many log lines (brute force, port scan). |
| **Suppression** | An allowlist that mutes known-good / noisy things. |
| **Deduplication** | Collapsing repeated identical alerts into one counted alert. |

The data flow:

```
 Internet feeds ──collect──▶ IOC store (SQLite) ──match──▶ ┐
                                                           ├─▶ alert pipeline ──▶ console
 Your devices ───syslog───▶ ingest ──extract observables──┘    (suppress →         webhook
                                   └─▶ correlate ───────────▶   dedup → store)      email
```

---

## 2. Requirements & setup

- **Python 3.8 or newer.** Check with `python3 --version`.
- Nothing to install — no `pip`, no virtualenv needed.
- Internet access **only** for pulling feeds (`collect`). Everything else works offline.

Get the code and move into the project folder:

```bash
cd threatintel        # the folder containing the threatmgr/ package
```

All commands are run from here as `python3 -m threatmgr <command>`.

> Replace `python3` with `python` on systems where that is Python 3.

---

## 3. Quick start (3 commands)

```bash
cd threatintel

# 1. Pull threat intelligence into a local database (threatintel.db)
python3 -m threatmgr collect

# 2. Start the SOC console
python3 -m threatmgr serve
#    → open http://127.0.0.1:8787 in your browser

# 3. (optional) Check anything against the intel
python3 -m threatmgr lookup 185.220.101.1
```

That's a working threat-intel console. The rest of this guide adds log ingestion,
alerting, and tuning.

---

## 4. Step-by-step walkthrough

### 4.1 Pull threat intel (`collect`)

Downloads all 9 feeds, normalizes them, and stores the IOCs.

```bash
python3 -m threatmgr collect
```

Expected output (one line per feed):

```
  ✓ cisa_kev         1300 IOCs
  ✓ feodo_c2         700 IOCs
  ✓ threatfox        500 IOCs
  ...
[collector] 9/9 feeds ok, 12345 IOCs processed in 6.4s
```

- Run it whenever you want fresh intel. A failed feed never stops the others.
- Pick specific feeds: `--feeds cisa_kev,feodo_c2`
- See all feeds: `python3 -m threatmgr feeds`
- See what's stored: `python3 -m threatmgr stats`

### 4.2 Open the console (`serve`)

```bash
python3 -m threatmgr serve                 # http://127.0.0.1:8787
python3 -m threatmgr serve --host 0.0.0.0 --port 8080   # expose on the network
```

Leave it running and open the URL. See [section 6](#6-the-web-console) for a tour.

### 4.3 Check a single indicator (`lookup`)

The fastest way to ask "is this known-bad?":

```bash
python3 -m threatmgr lookup 185.220.101.1
python3 -m threatmgr lookup evil-domain.com
python3 -m threatmgr lookup CVE-2021-44228
```

Output is either `CLEAN` or every matching IOC with its threat, severity, source,
and confidence.

### 4.4 Scan a log file (`scan`)

Point it at any log file(s). It extracts observables from every line and reports
matches. It **exits non-zero if anything matched**, so it drops straight into
cron or CI.

```bash
python3 -m threatmgr scan /var/log/firewall.log
python3 -m threatmgr scan /var/log/squid/access.log /var/log/auth.log
```

Example cron entry (hourly intel refresh + 15-minute scans):

```cron
0   * * * *  cd /opt/threatintel && python3 -m threatmgr collect
*/15 * * * * cd /opt/threatintel && python3 -m threatmgr scan /var/log/firewall.log >> /var/log/threatmgr/hits.log 2>&1
```

### 4.5 Run as a log server (`ingest`)

This is the real-time heart of the SIEM. It listens for **syslog** over UDP and
TCP; every line devices send is matched and correlated live.

```bash
python3 -m threatmgr ingest                 # UDP+TCP on port 5140 (all interfaces)
sudo python3 -m threatmgr ingest --port 514 # classic syslog port (needs root)
```

You'll see a banner showing what's active, then alerts stream in:

```
[ingest] syslog UDP listening on 0.0.0.0:5140
[ingest] syslog TCP listening on 0.0.0.0:5140
[ingest] matching against threat intel + 4 correlation rule(s) + dedup 300s. Ctrl-C to stop.
  [ALERT] 10.0.0.9        185.220.101.1    HIGH   Emotet C2 (src=feodo_c2)
[ingest] 1500 msgs / 3 alerts from 4 device(s) (deduped 27, suppressed 5)
```

Run `serve` in a second terminal against the **same database** to watch these
alerts in the console at the same time.

### 4.6 Turn on alerting (webhook / email)

Push high-severity alerts out in real time. **Secrets come from environment
variables**, never command-line flags.

**Slack / webhook:**
```bash
export THREATMGR_WEBHOOK='https://hooks.slack.com/services/XXX/YYY/ZZZ'
python3 -m threatmgr ingest --min-severity high
```

**Email:**
```bash
export THREATMGR_SMTP_PASSWORD='your-app-password'
python3 -m threatmgr ingest \
  --smtp-host smtp.gmail.com --smtp-port 587 \
  --smtp-user soc@example.com --mail-from soc@example.com \
  --mail-to soc-team@example.com \
  --min-severity critical
```

**Test delivery** without waiting for a real alert:
```bash
python3 -m threatmgr test-alert --webhook "$THREATMGR_WEBHOOK"
```

`--min-severity` (`low`|`medium`|`high`|`critical`) controls what gets sent.

### 4.7 Tune correlation, dedup & suppression

These all attach to `ingest`:

```bash
python3 -m threatmgr ingest \
  --dedup-window 600 \                      # collapse repeat alerts for 10 min
  --suppress-file suppression.json \        # mute known-good / noisy things
  --no-correlate                            # (optional) turn off behaviour rules
```

- **Correlation** is on by default — catches brute force, port scans, and bursts
  (see [command reference](#7-command-reference) for the rule table). Disable
  with `--no-correlate`.
- **Deduplication** is on by default (300s). The same alert within the window
  becomes one alert with a count (`×N` in the console). Disable with `--no-dedup`.
- **Suppression** needs a file. Copy and edit the sample:

```bash
cp suppression.sample.json suppression.json
```

A suppression file is a JSON list of rules. Each matching alert is dropped:

```json
[
  {"type": "cidr",          "match": "10.0.0.0/8",   "note": "internal network"},
  {"type": "value",         "match": "8.8.8.8",      "note": "Google DNS"},
  {"type": "value_regex",   "match": "^scanner\\d+\\."},
  {"type": "source",        "match": "denied_burst", "note": "too noisy here"},
  {"type": "threat_substr", "match": "test"},
  {"type": "severity_below","match": "medium"},
  {"type": "cidr", "match": "203.0.113.0/24", "until": 1767225600, "note": "maintenance window"}
]
```

Add `"until": <epoch seconds>` to any rule to make it a **temporary mute** that
auto-expires (handy for maintenance windows).

---

## 5. Connecting your devices (syslog)

Start the log server (`python3 -m threatmgr ingest`), then point each device at
`<threatmgr-host>:5140`. Common examples:

| Device | Configuration |
|--------|---------------|
| **Linux (rsyslog)** | In `/etc/rsyslog.d/threatmgr.conf`: `*.*  @<host>:5140` (one `@` = UDP, `@@` = TCP), then `systemctl restart rsyslog` |
| **Cisco ASA / IOS** | `logging host <host> udp 5140` |
| **pfSense / OPNsense** | Status ▸ System Logs ▸ Settings ▸ Remote Logging → `<host>:5140` |
| **Fortinet (FortiGate)** | `config log syslogd setting` → `set server <host>` / `set port 5140` |
| **Palo Alto** | Device ▸ Server Profiles ▸ Syslog → add `<host>:5140`, attach to log-forwarding |
| **Windows** | Use a syslog agent (e.g. NXLog) forwarding to `<host>:5140` |

Quick manual test from any machine:

```bash
logger -n <threatmgr-host> -P 5140 -d "test from $(hostname)"
```

> Ports below 1024 (like 514) require root. The default **5140** avoids that.

---

## 6. The web console

Open `http://<host>:8787` after `serve` (or `watch`). Panels:

- **Stat cards** — totals: IOCs, open alerts, counts by severity and type.
- **Proactive log scan** — paste log lines and click **Scan** to check them against
  the intel instantly; matches appear below.
- **IOC search** — filter the indicator database by text, type, and severity.
- **Open alerts** — the live alert queue. Recurring alerts show `×N` (dedup count).
  Click **ack** to acknowledge and clear one.
- **Feed status** — when each feed last ran, its status, and how many IOCs it returned.

The console auto-refreshes every 30 seconds.

---

## 7. Command reference

```
python3 -m threatmgr [--db PATH] <command> [options]
```

`--db` sets the database file (default `threatintel.db`). Use the **same `--db`**
across `collect`, `serve`, and `ingest` so they share data.

| Command | Purpose | Key options |
|---------|---------|-------------|
| `collect` | Pull all feeds once | `--feeds a,b,c`, `--insecure` |
| `serve` | Web console + API | `--host`, `--port` |
| `watch` | Collect on a loop **and** serve | `--interval`, `--host`, `--port` |
| `ingest` | Syslog server (live matching) | see below |
| `scan FILE…` | Scan log file(s); non-zero exit on hit | — |
| `lookup VALUE` | Check one IP/domain/URL/hash/CVE | — |
| `stats` | Summary of the database | — |
| `feeds` | List configured feeds | — |
| `test-alert` | Send a synthetic alert to test dispatch | `--webhook`, SMTP flags |

**`ingest` options:** `--host`, `--port`, `--udp-only`, `--tcp-only`, `--quiet`,
`--reload-every`, `--no-correlate`, `--dedup-window`, `--no-dedup`,
`--suppress-file`, plus the alert-dispatch group `--webhook`, `--min-severity`,
`--smtp-host`, `--smtp-port`, `--smtp-user`, `--smtp-ssl`, `--mail-from`, `--mail-to`.

**Built-in correlation rules:**

| Rule | Fires when | Default |
|------|-----------|---------|
| `ssh_bruteforce` | failed logins from one source IP | ≥5 in 60s |
| `port_scan` | one source hits many distinct dest ports | ≥15 ports in 30s |
| `web_bruteforce` | repeated 401/403 on login URLs from one IP | ≥20 in 60s |
| `denied_burst` | firewall denies from one source | ≥50 in 60s |

Edit thresholds/windows in `threatmgr/correlator.py`.

**Environment variables:** `THREATMGR_WEBHOOK`, `THREATMGR_SMTP_PASSWORD`,
and standard `HTTP_PROXY` / `HTTPS_PROXY` (honoured by `collect`).

---

## 8. JSON API reference

Served by `serve` / `watch` alongside the console.

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/stats` | summary counts |
| GET | `/api/iocs?q=&type=&severity=&source=&limit=` | search indicators |
| GET | `/api/feeds` | feed run status |
| GET | `/api/alerts?open=1` | alerts (open only when `open=1`) |
| GET | `/api/lookup?value=` | check one observable |
| POST | `/api/scan` | body `{"lines":[...]}` → matches |
| POST | `/api/ack` | body `{"id":<alert_id>}` → acknowledge |

Example:

```bash
curl -s -X POST localhost:8787/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"lines":["src=10.0.0.5 dst=185.220.101.1 GET http://evil.example/x"]}'
```

---

## 9. Production deployment

A typical always-on setup uses two long-running processes sharing one database,
plus a cron refresh.

**Terminal / service 1 — log server with full alerting:**
```bash
export THREATMGR_WEBHOOK='https://hooks.slack.com/services/XXX/YYY/ZZZ'
python3 -m threatmgr --db /var/lib/threatmgr/ti.db ingest \
  --host 0.0.0.0 --port 5140 \
  --suppress-file /etc/threatmgr/suppression.json \
  --dedup-window 600 --min-severity high
```

**Terminal / service 2 — console for analysts:**
```bash
python3 -m threatmgr --db /var/lib/threatmgr/ti.db serve --host 0.0.0.0 --port 8787
```

**Cron — keep intel fresh:**
```cron
0 * * * * cd /opt/threatintel && python3 -m threatmgr --db /var/lib/threatmgr/ti.db collect
```

The `ingest` process reloads new IOCs automatically every few minutes
(`--reload-every`), so the hourly `collect` is picked up without a restart.

As a `systemd` service, wrap each long-running command in a unit with
`Restart=always` and an `EnvironmentFile` holding the secrets.

> **Security:** bind the console (`serve`) to a trusted interface or put it behind
> a reverse proxy with authentication — it has no built-in auth. Only ingest and
> analyse logs you are authorised to monitor.

---

## 10. Try it right now (offline demo)

No internet / feeds unreachable? Seed a couple of indicators and exercise the
whole pipeline locally:

```bash
cd threatintel

# 1. seed demo IOCs
python3 -c "
from threatmgr.store import Store
Store('demo.db').upsert_iocs([
 {'value':'185.220.101.1','ioc_type':'ip','threat':'Emotet C2','source':'demo','confidence':90,'severity':'high'},
 {'value':'malicious.example','ioc_type':'domain','threat':'Phishing','source':'demo','confidence':80,'severity':'high'},
 {'value':'CVE-2021-44228','ioc_type':'cve','threat':'Log4Shell','source':'demo','confidence':95,'severity':'critical'},
])
print('seeded 3 demo IOCs')"

# 2. command-line checks
python3 -m threatmgr --db demo.db lookup 185.220.101.1
echo "fw src=10.0.0.5 dst=185.220.101.1 url=http://malicious.example/x" > sample.log
python3 -m threatmgr --db demo.db scan sample.log

# 3. open the console
python3 -m threatmgr --db demo.db serve
#    → http://127.0.0.1:8787  (paste a log line into the scan box)
```

To watch live ingestion + dedup locally, in one terminal:
```bash
python3 -m threatmgr --db demo.db ingest --port 5140 --dedup-window 600
```
and in another:
```bash
for i in 1 2 3; do logger -n 127.0.0.1 -P 5140 -d "fw dst=185.220.101.1"; done
```
You'll see **one** alert with a count of 3 (the repeats are deduplicated).

---

## 11. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `collect` shows every feed `✗ network` | No outbound internet, or a proxy is blocking the feed hosts. Set `HTTP_PROXY`/`HTTPS_PROXY`. If a proxy breaks TLS, `--insecure` (at your own risk). Use the [offline demo](#10-try-it-right-now-offline-demo) to test without feeds. |
| `No module named threatmgr` | You're not in the `threatintel/` folder. `cd` into it and rerun. |
| Console is empty | No IOCs yet — run `collect` (or seed demo data). Check `stats`. |
| `ingest` can't bind port 514 | Ports < 1024 need root. Use the default `5140` or `sudo`. |
| Devices send logs but no alerts | Confirm the DB has IOCs (`stats`), the device targets the right host/port/protocol, and a firewall allows UDP/TCP to that port. Test with `logger -n <host> -P 5140 -d test`. |
| Too many alerts from one source | Add it to a `--suppress-file`, or raise `--min-severity`, or increase `--dedup-window`. |
| Webhook/email not arriving | Run `test-alert`; verify `THREATMGR_WEBHOOK` / `THREATMGR_SMTP_PASSWORD` are exported and `--min-severity` isn't filtering it out. |

---

*ThreatMgr is a defensive tool. Only collect intelligence from sources you may
use, and only ingest and analyse logs from systems you own or are authorised to
monitor.*
