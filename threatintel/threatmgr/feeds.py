"""Public threat-intelligence feed definitions and parsers.

Every feed is described declaratively. A feed produces a list of normalized IOC
dicts with keys: value, ioc_type, threat, source, confidence, severity, reference.

All feeds here are free / open and commonly used by SOC teams. Parsers are
defensive: a malformed line is skipped, never fatal.
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Callable, List


# --- helpers ---------------------------------------------------------------
_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_CIDR_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$")


def _sev_from_conf(conf: int) -> str:
    if conf >= 90:
        return "critical"
    if conf >= 70:
        return "high"
    if conf >= 40:
        return "medium"
    return "low"


# --- parsers ---------------------------------------------------------------
def parse_ip_lines(text: str, source: str, threat: str, severity: str,
                   confidence: int) -> List[dict]:
    """Plain-text feed with one IP (or CIDR) per line, '#' comments."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        token = line.split()[0].split(",")[0].strip()
        if _IP_RE.match(token) or _CIDR_RE.match(token):
            out.append({
                "value": token,
                "ioc_type": "cidr" if "/" in token else "ip",
                "threat": threat, "source": source,
                "confidence": confidence, "severity": severity,
            })
    return out


def parse_domain_lines(text: str, source: str, threat: str, severity: str,
                       confidence: int) -> List[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # hosts-file style "0.0.0.0 domain" or bare domain
        parts = line.split()
        dom = parts[-1].strip().lower()
        if "." in dom and " " not in dom and not _IP_RE.match(dom):
            out.append({
                "value": dom, "ioc_type": "domain", "threat": threat,
                "source": source, "confidence": confidence, "severity": severity,
            })
    return out


def parse_url_lines(text: str, source: str, threat: str, severity: str,
                    confidence: int) -> List[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("http://") or line.startswith("https://"):
            out.append({
                "value": line, "ioc_type": "url", "threat": threat,
                "source": source, "confidence": confidence, "severity": severity,
            })
    return out


def parse_cisa_kev(text: str, source: str, **_) -> List[dict]:
    """CISA Known Exploited Vulnerabilities catalog (JSON) -> CVE IOCs."""
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID")
        if not cve:
            continue
        out.append({
            "value": cve, "ioc_type": "cve",
            "threat": v.get("vulnerabilityName") or v.get("product"),
            "source": source, "confidence": 95, "severity": "critical",
            "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        })
    return out


def parse_feodo_json(text: str, source: str, **_) -> List[dict]:
    """abuse.ch Feodo Tracker botnet C2 IP blocklist (JSON)."""
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for row in data:
        ip = row.get("ip_address")
        if not ip:
            continue
        out.append({
            "value": ip, "ioc_type": "ip",
            "threat": row.get("malware", "Feodo/Emotet C2"),
            "source": source, "confidence": 90, "severity": "high",
            "reference": "https://feodotracker.abuse.ch/",
        })
    return out


def parse_threatfox_json(text: str, source: str, **_) -> List[dict]:
    """abuse.ch ThreatFox recent IOC dump (JSON object keyed by id)."""
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    items = data.values() if isinstance(data, dict) else data
    for group in items:
        for row in (group if isinstance(group, list) else [group]):
            ioc = row.get("ioc_value") or row.get("ioc")
            if not ioc:
                continue
            itype = (row.get("ioc_type") or "").lower()
            if "ip" in itype:
                t = "ip"
            elif "domain" in itype:
                t = "domain"
            elif "url" in itype:
                t = "url"
            elif "md5" in itype:
                t = "md5"
            elif "sha256" in itype:
                t = "sha256"
            else:
                t = "unknown"
            conf = int(row.get("confidence_level", 75) or 75)
            out.append({
                "value": ioc.split(":")[0] if t == "ip" else ioc,
                "ioc_type": t, "threat": row.get("malware_printable") or row.get("threat_type"),
                "source": source, "confidence": conf, "severity": _sev_from_conf(conf),
                "reference": "https://threatfox.abuse.ch/",
            })
    return out


def parse_urlhaus_csv(text: str, source: str, **_) -> List[dict]:
    """abuse.ch URLhaus recent malicious URLs (CSV with # comment header)."""
    out = []
    reader = csv.reader(io.StringIO(
        "\n".join(l for l in text.splitlines() if not l.startswith("#"))))
    for row in reader:
        if len(row) < 3:
            continue
        url = row[2].strip('"')
        if url.startswith("http"):
            out.append({
                "value": url, "ioc_type": "url",
                "threat": (row[5].strip('"') if len(row) > 5 else "malware"),
                "source": source, "confidence": 85, "severity": "high",
                "reference": "https://urlhaus.abuse.ch/",
            })
    return out


# --- feed registry ---------------------------------------------------------
# Each entry: id -> dict(name, url, parser, kwargs)
# Parsers that take threat/severity/confidence get them from kwargs.
FEEDS = {
    "cisa_kev": {
        "name": "CISA Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "parser": parse_cisa_kev, "kwargs": {},
    },
    "feodo_c2": {
        "name": "abuse.ch Feodo Tracker (botnet C2 IPs)",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "parser": parse_feodo_json, "kwargs": {},
    },
    "threatfox": {
        "name": "abuse.ch ThreatFox (recent IOCs)",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "parser": parse_threatfox_json, "kwargs": {},
    },
    "urlhaus": {
        "name": "abuse.ch URLhaus (malware URLs)",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "parser": parse_urlhaus_csv, "kwargs": {},
    },
    "sslbl": {
        "name": "abuse.ch SSL Blacklist (malicious IPs)",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "parser": parse_ip_lines,
        "kwargs": {"threat": "Malicious SSL C2", "severity": "high", "confidence": 80},
    },
    "et_compromised": {
        "name": "Emerging Threats compromised IPs",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "parser": parse_ip_lines,
        "kwargs": {"threat": "Compromised host", "severity": "high", "confidence": 75},
    },
    "blocklist_de": {
        "name": "blocklist.de (attacking IPs)",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "parser": parse_ip_lines,
        "kwargs": {"threat": "Attacking host", "severity": "medium", "confidence": 65},
    },
    "cins_army": {
        "name": "CINS Army (CI Badguys)",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "parser": parse_ip_lines,
        "kwargs": {"threat": "Known bad actor", "severity": "medium", "confidence": 70},
    },
    "openphish": {
        "name": "OpenPhish (phishing URLs)",
        "url": "https://openphish.com/feed.txt",
        "parser": parse_url_lines,
        "kwargs": {"threat": "Phishing", "severity": "high", "confidence": 80},
    },
}


def run_parser(feed_id: str, text: str) -> List[dict]:
    spec = FEEDS[feed_id]
    kwargs = dict(spec["kwargs"])
    return spec["parser"](text, source=feed_id, **kwargs)
