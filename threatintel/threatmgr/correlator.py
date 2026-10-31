"""Correlation / threshold engine.

IOC matching catches contact with *known* bad infrastructure. Correlation
catches *behaviour* — patterns across many log lines that no single line reveals:
brute-force bursts, port scans, repeated IOC hits from one source.

Each rule keeps a per-key sliding time window and fires when a threshold is
crossed. Stdlib only (re, collections, threading).
"""
from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque
from typing import List, Optional


class ThresholdRule:
    """Fire when `threshold` events for the same key occur within `window` secs.

    match    : regex deciding a line is relevant to this rule
    key      : regex whose group(1) is the entity to count against (e.g. src IP)
    distinct : optional regex whose group(1) must be *distinct* to count
               (e.g. distinct dst ports -> port scan). If None, every match
               counts as one event.
    cooldown : seconds to suppress re-firing for the same key after it fires.
    """

    def __init__(self, name: str, match: str, key: str, threshold: int,
                 window: int, severity: str, threat: str,
                 distinct: Optional[str] = None, cooldown: Optional[int] = None):
        self.name = name
        self.match = re.compile(match, re.I)
        self.key = re.compile(key, re.I)
        self.distinct = re.compile(distinct, re.I) if distinct else None
        self.threshold = threshold
        self.window = window
        self.severity = severity
        self.threat = threat
        self.cooldown = cooldown if cooldown is not None else window

    def key_of(self, line: str) -> Optional[str]:
        m = self.key.search(line)
        return m.group(1) if m else None

    def distinct_of(self, line: str) -> str:
        if not self.distinct:
            return ""                      # occurrence counting
        m = self.distinct.search(line)
        return m.group(1) if m else ""


def default_rules() -> List[ThresholdRule]:
    return [
        ThresholdRule(
            name="ssh_bruteforce",
            match=r"(failed password|authentication failure|invalid user|failed login)",
            key=r"(?:from|src=?|rhost=)\s*((?:\d{1,3}\.){3}\d{1,3})",
            threshold=5, window=60, severity="high",
            threat="Possible SSH/credential brute force",
        ),
        ThresholdRule(
            name="port_scan",
            match=r"(dpt=|dst_?port=?|dport=)",
            key=r"(?:src=?|from)\s*((?:\d{1,3}\.){3}\d{1,3})",
            distinct=r"(?:dpt=|dst_?port=?|dport=)\s*(\d{1,5})",
            threshold=15, window=30, severity="high",
            threat="Possible port scan (many distinct ports)",
        ),
        ThresholdRule(
            name="web_bruteforce",
            match=r'"(?:POST|GET)\s+\S*(login|signin|wp-login|admin)\S*.*"\s+(401|403)',
            key=r"^((?:\d{1,3}\.){3}\d{1,3})",
            threshold=20, window=60, severity="medium",
            threat="Possible web login brute force",
        ),
        ThresholdRule(
            name="denied_burst",
            match=r"\b(deny|denied|drop|dropped|block(?:ed)?|reject(?:ed)?)\b",
            key=r"(?:src=?|from)\s*((?:\d{1,3}\.){3}\d{1,3})",
            threshold=50, window=60, severity="medium",
            threat="Firewall deny burst from single source",
        ),
    ]


class Correlator:
    def __init__(self, rules: Optional[List[ThresholdRule]] = None):
        self.rules = rules if rules is not None else default_rules()
        self._events = defaultdict(deque)     # (rule, key) -> deque[(ts, distinct)]
        self._last_fire = {}                  # (rule, key) -> ts
        self._lock = threading.Lock()

    def observe(self, line: str, device: str = "") -> List[dict]:
        """Feed one log line; return a list of fired correlation alerts."""
        now = time.time()
        fired = []
        with self._lock:
            for rule in self.rules:
                if not rule.match.search(line):
                    continue
                key = rule.key_of(line)
                if not key:
                    continue
                bucket = (rule.name, key)
                dq = self._events[bucket]
                dq.append((now, rule.distinct_of(line)))
                cutoff = now - rule.window
                while dq and dq[0][0] < cutoff:
                    dq.popleft()
                count = len({d for _, d in dq}) if rule.distinct else len(dq)
                if count >= rule.threshold:
                    last = self._last_fire.get(bucket, 0)
                    if now - last >= rule.cooldown:
                        self._last_fire[bucket] = now
                        fired.append(self._alert(rule, key, count, device))
        return fired

    @staticmethod
    def _alert(rule: ThresholdRule, key: str, count: int, device: str) -> dict:
        return {
            "observable": key,
            "ioc": {
                "value": key,
                "ioc_type": "correlation",
                "threat": rule.threat,
                "severity": rule.severity,
                "source": rule.name,
                "confidence": 80,
            },
            "context": (f"[{device}] rule={rule.name} count={count} "
                        f"within {rule.window}s key={key}"),
        }
