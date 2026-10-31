"""AlertSink — the single pipeline every candidate alert flows through before it
becomes a stored/dispatched alert.

Order of operations for each candidate:
    1. suppression  -> drop silently (allowlist / maintenance window)
    2. deduplication -> collapse repeats into one counted alert within a window
    3. persist to store + dispatch (new alerts only)

This is what keeps a noisy source from flooding the console and the webhook:
the first hit alerts, repeats just bump a counter until the dedup window lapses.
"""
from __future__ import annotations

import threading
import time
from typing import Optional

from .store import Store
from .suppression import SuppressionList
from .dispatch import Notifier


class Deduper:
    def __init__(self, window: int = 300):
        self.window = window
        self._seen = {}
        self._lock = threading.Lock()

    def seen(self, key) -> tuple:
        """Return (status, entry) where status is 'new' or 'dup'."""
        now = time.time()
        with self._lock:
            e = self._seen.get(key)
            if e and now - e["last"] <= self.window:
                e["last"] = now
                e["count"] += 1
                return "dup", e
            e = {"first": now, "last": now, "count": 1, "alert_id": None}
            self._seen[key] = e
            return "new", e

    def prune(self):
        now = time.time()
        with self._lock:
            dead = [k for k, e in self._seen.items() if now - e["last"] > self.window]
            for k in dead:
                del self._seen[k]


class AlertSink:
    def __init__(self, store: Store, suppression: Optional[SuppressionList] = None,
                 deduper: Optional[Deduper] = None, notifier: Optional[Notifier] = None,
                 echo: bool = False):
        self.store = store
        self.suppression = suppression
        self.deduper = deduper
        self.notifier = notifier
        self.echo = echo
        self._lock = threading.Lock()
        self.new = 0
        self.suppressed = 0
        self.deduped = 0

    def handle(self, observable: str, ioc: dict, context: str) -> Optional[int]:
        alert = {
            "observable": observable,
            "threat": ioc.get("threat"),
            "severity": ioc.get("severity"),
            "source": ioc.get("source"),
            "ioc_type": ioc.get("ioc_type"),
            "context": context,
        }

        # 1) suppression
        if self.suppression:
            sup, reason = self.suppression.is_suppressed(alert)
            if sup:
                with self._lock:
                    self.suppressed += 1
                return None

        # 2) deduplication
        if self.deduper:
            key = (ioc.get("ioc_type"), observable, ioc.get("source"))
            status, entry = self.deduper.seen(key)
            if status == "dup":
                if entry.get("alert_id"):
                    self.store.bump_alert(entry["alert_id"])
                with self._lock:
                    self.deduped += 1
                return None

        # 3) new alert -> persist + dispatch
        alert_id = self.store.add_alert(observable, ioc, context)
        if self.deduper:
            entry["alert_id"] = alert_id
        with self._lock:
            self.new += 1
        if self.echo:
            dev = context.split("]")[0].strip("[") if "]" in context else ""
            print(f"  [ALERT] {dev:<15} {observable:<38} "
                  f"{str(ioc.get('severity') or '').upper():<9} "
                  f"{ioc.get('threat','')} (src={ioc.get('source')})", flush=True)
        if self.notifier:
            self.notifier.notify(alert)
        return alert_id

    def summary(self) -> dict:
        return {"new": self.new, "deduped": self.deduped, "suppressed": self.suppressed}
