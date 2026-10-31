"""Syslog ingestion server — turns ThreatMgr into a log server that devices
ship to over the network.

Listens for syslog messages on UDP and/or TCP (newline-delimited, RFC3164/5424
tolerant) and runs every received line through the Matcher in real time. Any
contact with a known IOC becomes an alert in the store.

Point your firewalls / routers / servers / EDR at this host:port and you get
continuous, proactive detection — the "log server" half of a SIEM.

Stdlib only (socketserver).
"""
from __future__ import annotations

import re
import socketserver
import threading
import time

from .store import Store
from .matcher import Matcher
from .correlator import Correlator
from .dispatch import Notifier

# strip a leading syslog priority like "<134>" and an optional version digit
_PRI_RE = re.compile(r"^<\d{1,3}>\d?\s*")


class _Stats:
    def __init__(self):
        self.messages = 0
        self.alerts = 0
        self.by_device = {}
        self.lock = threading.Lock()

    def record(self, device: str, n_alerts: int):
        with self.lock:
            self.messages += 1
            self.alerts += n_alerts
            self.by_device[device] = self.by_device.get(device, 0) + 1


class _Engine:
    """Shared matcher + correlator + notifier, with periodic CIDR reload."""
    def __init__(self, store: Store, reload_every: int = 300, echo: bool = True,
                 correlator: Correlator = None, notifier: Notifier = None):
        self.store = store
        self.matcher = Matcher(store)
        self.correlator = correlator
        self.notifier = notifier
        self.stats = _Stats()
        self.echo = echo
        self._last_reload = time.time()
        self._reload_every = reload_every
        self._lock = threading.Lock()

    def process(self, raw: bytes, device: str):
        # one datagram / line may contain one message
        line = _PRI_RE.sub("", raw.decode("utf-8", errors="replace").strip())
        if not line:
            return
        self._maybe_reload()
        n = 0
        # 1) IOC matches (contact with known-bad infrastructure)
        for a in self.matcher.scan_line(line, context=f"[{device}] {line[:400]}"):
            self._emit(a["observable"], a["ioc"], f"[{device}] {line[:400]}")
            n += 1
        # 2) correlation (behavioural patterns across many lines)
        if self.correlator:
            for ev in self.correlator.observe(line, device):
                self.store.add_alert(ev["observable"], ev["ioc"], ev["context"])
                self._emit(ev["observable"], ev["ioc"], ev["context"])
                n += 1
        self.stats.record(device, n)

    def _emit(self, observable: str, ioc: dict, context: str):
        if self.echo:
            print(f"  [ALERT] {str(context.split(']')[0].strip('[')):<15} "
                  f"{observable:<38} {(ioc.get('severity') or '').upper():<9} "
                  f"{ioc.get('threat','')} (src={ioc.get('source')})", flush=True)
        if self.notifier:
            self.notifier.notify({
                "observable": observable, "threat": ioc.get("threat"),
                "severity": ioc.get("severity"), "source": ioc.get("source"),
                "ioc_type": ioc.get("ioc_type"), "context": context,
            })

    def _maybe_reload(self):
        now = time.time()
        if now - self._last_reload >= self._reload_every:
            with self._lock:
                if now - self._last_reload >= self._reload_every:
                    self.matcher.reload()
                    self._last_reload = now


# socketserver wiring -------------------------------------------------------
class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        self.server.engine.process(data, self.client_address[0])


class _TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        device = self.client_address[0]
        for line in self.rfile:          # newline-delimited syslog over TCP
            self.server.engine.process(line, device)


class _UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve_syslog(store: Store, host: str = "0.0.0.0", port: int = 5140,
                 udp: bool = True, tcp: bool = True, echo: bool = True,
                 reload_every: int = 300, correlator: Correlator = None,
                 notifier: Notifier = None):
    engine = _Engine(store, reload_every=reload_every, echo=echo,
                     correlator=correlator, notifier=notifier)
    servers = []

    if udp:
        u = _UDPServer((host, port), _UDPHandler)
        u.engine = engine
        servers.append(("UDP", u))
    if tcp:
        t = _TCPServer((host, port), _TCPHandler)
        t.engine = engine
        servers.append(("TCP", t))

    if not servers:
        raise ValueError("enable at least one of udp/tcp")

    threads = []
    for proto, s in servers:
        th = threading.Thread(target=s.serve_forever, daemon=True)
        th.start()
        threads.append(th)
        print(f"[ingest] syslog {proto} listening on {host}:{port}")

    extras = []
    if correlator:
        extras.append(f"{len(correlator.rules)} correlation rule(s)")
    if notifier and notifier.enabled:
        extras.append("alert dispatch ON")
    print("[ingest] matching against threat intel"
          + (" + " + " + ".join(extras) if extras else "")
          + ". Ctrl-C to stop.")

    # periodic throughput line
    try:
        while True:
            time.sleep(30)
            st = engine.stats
            print(f"[ingest] {st.messages} msgs / {st.alerts} alerts "
                  f"from {len(st.by_device)} device(s)", flush=True)
    except KeyboardInterrupt:
        print("\n[ingest] stopping...")
        for _, s in servers:
            s.shutdown()
            s.server_close()
        st = engine.stats
        print(f"[ingest] total: {st.messages} messages, {st.alerts} alerts")
