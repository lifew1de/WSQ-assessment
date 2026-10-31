"""Alert suppression — an allowlist / mute layer so known-good or
operationally-noisy things never raise alerts.

Rules are loaded from a JSON file (list of rule objects). Each rule matches an
alert and, if it matches, the alert is dropped. Supported rule `type`s:

  {"type": "value",        "match": "8.8.8.8"}          exact observable
  {"type": "cidr",         "match": "10.0.0.0/8"}       observable IP in range
  {"type": "value_regex",  "match": "^scanner\\d+\\."}   observable regex
  {"type": "source",       "match": "denied_burst"}     mute a feed / rule
  {"type": "threat_substr","match": "test"}             substring in threat
  {"type": "severity_below","match": "high"}            drop low/medium

Any rule may carry an optional "until" (epoch seconds) to make it a temporary
maintenance-window mute that auto-expires, and an optional "note".
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
from typing import List, Optional, Tuple

SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class SuppressionList:
    def __init__(self, rules: Optional[List[dict]] = None):
        self.rules = rules or []
        self._cidrs = []
        self._regexes = {}
        for i, r in enumerate(self.rules):
            if r.get("type") == "cidr":
                try:
                    self._cidrs.append((i, ipaddress.ip_network(r["match"], strict=False)))
                except ValueError:
                    pass
            elif r.get("type") == "value_regex":
                try:
                    self._regexes[i] = re.compile(r["match"], re.I)
                except re.error:
                    pass

    @classmethod
    def from_file(cls, path: Optional[str]) -> "SuppressionList":
        if not path:
            return cls([])
        with open(path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):            # allow {"rules": [...]}
            data = data.get("rules", [])
        return cls(data)

    def is_suppressed(self, alert: dict) -> Tuple[bool, Optional[str]]:
        now = time.time()
        obs = str(alert.get("observable", ""))
        for i, r in enumerate(self.rules):
            until = r.get("until")
            if until and now > until:
                continue                      # expired maintenance window
            t = r.get("type")
            hit = False
            if t == "value":
                hit = obs == r.get("match")
            elif t == "cidr":
                hit = self._ip_in(i, obs)
            elif t == "value_regex":
                rx = self._regexes.get(i)
                hit = bool(rx and rx.search(obs))
            elif t == "source":
                hit = alert.get("source") == r.get("match")
            elif t == "threat_substr":
                hit = r.get("match", "").lower() in str(alert.get("threat", "")).lower()
            elif t == "severity_below":
                floor = SEV_ORDER.get(r.get("match", "high"), 3)
                hit = SEV_ORDER.get(str(alert.get("severity", "")).lower(), 0) < floor
            if hit:
                return True, (r.get("note") or f"{t}:{r.get('match')}")
        return False, None

    def _ip_in(self, idx: int, obs: str) -> bool:
        try:
            ip = ipaddress.ip_address(obs)
        except ValueError:
            return False
        for i, net in self._cidrs:
            if i == idx and ip in net:
                return True
        return False
