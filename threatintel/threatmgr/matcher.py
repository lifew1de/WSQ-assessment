"""Matcher: the 'detection' half of the SIEM.

Takes observables (IPs, domains, URLs, hashes pulled out of log lines) and checks
them against the IOC store. Any hit becomes an alert. This is what gives SOC
analysts proactive monitoring: feed it your firewall / proxy / DNS / auth logs
and it flags any contact with known-bad infrastructure.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable, List

from .store import Store

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _url_host(url: str) -> str:
    host = url.split("://", 1)[-1].split("/", 1)[0]
    host = host.split("@")[-1].split(":")[0]  # strip creds + port
    return host.lower()


def extract_observables(line: str) -> set:
    """Pull candidate indicators out of a raw log line."""
    obs = set()
    urls = set(URL_RE.findall(line))
    obs |= urls
    # a URL's hostname is itself an observable (match domain/ip IOCs)
    for u in urls:
        h = _url_host(u)
        if h:
            obs.add(h)
    obs |= set(IP_RE.findall(line))
    obs |= set(SHA256_RE.findall(line))
    obs |= set(MD5_RE.findall(line))
    obs |= {c.upper() for c in CVE_RE.findall(line)}
    for d in DOMAIN_RE.findall(line):
        obs.add(d.lower())
    return obs


class Matcher:
    def __init__(self, store: Store):
        self.store = store
        self._cidrs = self._load_cidrs()

    def _load_cidrs(self):
        nets = []
        for row in self.store.search(ioc_type="cidr", limit=100000):
            try:
                nets.append((ipaddress.ip_network(row["value"], strict=False), row))
            except ValueError:
                continue
        return nets

    def check(self, observable: str) -> List[dict]:
        hits = self.store.lookup(observable)
        # CIDR containment check for IPs
        try:
            ip = ipaddress.ip_address(observable)
            for net, row in self._cidrs:
                if ip in net:
                    hits.append(row)
        except ValueError:
            pass
        return hits

    def scan_line(self, line: str, context: str = "") -> List[dict]:
        alerts = []
        for obs in extract_observables(line):
            for ioc in self.check(obs):
                alert_id = self.store.add_alert(obs, ioc, context or line.strip()[:500])
                alerts.append({"alert_id": alert_id, "observable": obs, "ioc": ioc})
        return alerts

    def scan_lines(self, lines: Iterable[str], source_label: str = "") -> dict:
        total, hits = 0, []
        for line in lines:
            total += 1
            hits += self.scan_line(line, context=f"[{source_label}] {line.strip()[:400]}"
                                   if source_label else line.strip()[:400])
        return {"lines_scanned": total, "alerts": hits, "alert_count": len(hits)}

    def scan_file(self, path: str) -> dict:
        with open(path, "r", errors="replace") as f:
            return self.scan_lines(f, source_label=path)
