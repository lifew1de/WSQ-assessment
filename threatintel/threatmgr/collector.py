"""Collector: fetches each enabled feed, parses it, and upserts IOCs into the
store. Runs feeds concurrently and tolerates individual feed failures.

Honours standard proxy environment variables (HTTP_PROXY / HTTPS_PROXY), so it
works behind corporate egress proxies.
"""
from __future__ import annotations

import concurrent.futures as futures
import gzip
import io
import ssl
import time
import urllib.request
import urllib.error

from . import feeds as feedmod
from .store import Store

USER_AGENT = "ThreatMgr/1.0 (+SOC threat-intel collector)"
TIMEOUT = 45


def fetch(url: str, insecure: bool = False) -> str:
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "gzip",
    })
    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        raw = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip" or raw[:2] == b"\x1f\x8b":
            try:
                raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
            except OSError:
                pass
    return raw.decode("utf-8", errors="replace")


class Collector:
    def __init__(self, store: Store, enabled: list | None = None,
                 insecure: bool = False, workers: int = 6):
        self.store = store
        self.enabled = enabled or list(feedmod.FEEDS.keys())
        self.insecure = insecure
        self.workers = workers

    def _run_one(self, feed_id: str) -> dict:
        spec = feedmod.FEEDS[feed_id]
        result = {"feed": feed_id, "name": spec["name"], "count": 0,
                  "status": "ok", "error": None}
        try:
            text = fetch(spec["url"], insecure=self.insecure)
            iocs = feedmod.run_parser(feed_id, text)
            n = self.store.upsert_iocs(iocs)
            result["count"] = n
            self.store.record_feed_run(feed_id, spec["name"], spec["url"], "ok", n)
        except urllib.error.URLError as e:
            result.update(status="error", error=f"network: {e.reason}")
            self.store.record_feed_run(feed_id, spec["name"], spec["url"],
                                       f"error: {e.reason}", 0)
        except Exception as e:  # parser / decode errors
            result.update(status="error", error=f"{type(e).__name__}: {e}")
            self.store.record_feed_run(feed_id, spec["name"], spec["url"],
                                       f"error: {e}", 0)
        return result

    def collect(self) -> list:
        results = []
        with futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            future_map = {ex.submit(self._run_one, fid): fid
                          for fid in self.enabled}
            for fut in futures.as_completed(future_map):
                results.append(fut.result())
        return sorted(results, key=lambda r: r["feed"])


def collect_once(store: Store, enabled=None, insecure=False, verbose=True) -> list:
    start = time.time()
    results = Collector(store, enabled=enabled, insecure=insecure).collect()
    if verbose:
        total = sum(r["count"] for r in results)
        ok = sum(1 for r in results if r["status"] == "ok")
        for r in results:
            mark = "✓" if r["status"] == "ok" else "✗"
            detail = f"{r['count']} IOCs" if r["status"] == "ok" else r["error"]
            print(f"  {mark} {r['feed']:<16} {detail}")
        print(f"\n[collector] {ok}/{len(results)} feeds ok, "
              f"{total} IOCs processed in {time.time()-start:.1f}s")
    return results
