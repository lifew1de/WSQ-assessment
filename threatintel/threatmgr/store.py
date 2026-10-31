"""SQLite-backed storage for indicators of compromise (IOCs), feed metadata,
and alerts. Designed as the central 'index' of the SIEM.
"""
from __future__ import annotations

import sqlite3
import time
import threading
from contextlib import contextmanager
from typing import Iterable, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    value         TEXT NOT NULL,              -- the indicator itself (ip, domain, url, hash, cve)
    ioc_type      TEXT NOT NULL,              -- ip | domain | url | md5 | sha256 | cve
    threat        TEXT,                       -- malware family / threat label
    source        TEXT NOT NULL,              -- feed id the IOC came from
    confidence    INTEGER DEFAULT 50,         -- 0-100
    severity      TEXT DEFAULT 'medium',      -- low | medium | high | critical
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    reference     TEXT,                       -- optional URL / context
    UNIQUE(value, ioc_type, source)
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_sev   ON iocs(severity);

CREATE TABLE IF NOT EXISTS feeds (
    id            TEXT PRIMARY KEY,
    name          TEXT,
    url           TEXT,
    last_run      REAL,
    last_status   TEXT,
    last_count    INTEGER DEFAULT 0,
    total_runs    INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,
    observable    TEXT NOT NULL,              -- the thing that matched (from a log line etc.)
    ioc_id        INTEGER,
    ioc_value     TEXT,
    ioc_type      TEXT,
    threat        TEXT,
    severity      TEXT,
    source        TEXT,
    context       TEXT,                       -- raw log line / where it was seen
    acknowledged  INTEGER DEFAULT 0,
    count         INTEGER DEFAULT 1,          -- how many times deduplicated into this
    last_ts       REAL                        -- most recent occurrence
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
"""


class Store:
    def __init__(self, path: str = "threatintel.db"):
        self.path = path
        self._local = threading.local()
        with self._conn() as c:
            c.executescript(SCHEMA)
            self._migrate(c)

    @staticmethod
    def _migrate(c):
        """Add columns introduced after the first release to existing DBs."""
        cols = {r[1] for r in c.execute("PRAGMA table_info(alerts)").fetchall()}
        if "count" not in cols:
            c.execute("ALTER TABLE alerts ADD COLUMN count INTEGER DEFAULT 1")
        if "last_ts" not in cols:
            c.execute("ALTER TABLE alerts ADD COLUMN last_ts REAL")

    def _get(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    @contextmanager
    def _conn(self):
        conn = self._get()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # ---- IOC upserts ----------------------------------------------------
    def upsert_iocs(self, iocs: Iterable[dict]) -> int:
        now = time.time()
        rows = 0
        with self._conn() as c:
            for ioc in iocs:
                val = (ioc.get("value") or "").strip()
                if not val:
                    continue
                c.execute(
                    """
                    INSERT INTO iocs (value, ioc_type, threat, source, confidence,
                                      severity, first_seen, last_seen, reference)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(value, ioc_type, source) DO UPDATE SET
                        last_seen  = excluded.last_seen,
                        threat     = COALESCE(excluded.threat, iocs.threat),
                        confidence = excluded.confidence,
                        severity   = excluded.severity,
                        reference  = COALESCE(excluded.reference, iocs.reference)
                    """,
                    (
                        val,
                        ioc.get("ioc_type", "unknown"),
                        ioc.get("threat"),
                        ioc.get("source", "unknown"),
                        int(ioc.get("confidence", 50)),
                        ioc.get("severity", "medium"),
                        now,
                        now,
                        ioc.get("reference"),
                    ),
                )
                rows += 1
        return rows

    # ---- lookups --------------------------------------------------------
    def lookup(self, value: str) -> list:
        with self._conn() as c:
            cur = c.execute("SELECT * FROM iocs WHERE value = ?", (value.strip(),))
            return [dict(r) for r in cur.fetchall()]

    def search(self, q: Optional[str] = None, ioc_type: Optional[str] = None,
               severity: Optional[str] = None, source: Optional[str] = None,
               limit: int = 200) -> list:
        clauses, params = [], []
        if q:
            clauses.append("(value LIKE ? OR threat LIKE ?)")
            params += [f"%{q}%", f"%{q}%"]
        if ioc_type:
            clauses.append("ioc_type = ?"); params.append(ioc_type)
        if severity:
            clauses.append("severity = ?"); params.append(severity)
        if source:
            clauses.append("source = ?"); params.append(source)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._conn() as c:
            cur = c.execute(
                f"SELECT * FROM iocs {where} ORDER BY last_seen DESC LIMIT ?",
                params + [limit],
            )
            return [dict(r) for r in cur.fetchall()]

    def stats(self) -> dict:
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            by_type = {r[0]: r[1] for r in c.execute(
                "SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type").fetchall()}
            by_sev = {r[0]: r[1] for r in c.execute(
                "SELECT severity, COUNT(*) FROM iocs GROUP BY severity").fetchall()}
            by_source = {r[0]: r[1] for r in c.execute(
                "SELECT source, COUNT(*) FROM iocs GROUP BY source ORDER BY 2 DESC").fetchall()}
            open_alerts = c.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
        return {
            "total_iocs": total,
            "by_type": by_type,
            "by_severity": by_sev,
            "by_source": by_source,
            "open_alerts": open_alerts,
        }

    # ---- feed metadata --------------------------------------------------
    def record_feed_run(self, feed_id: str, name: str, url: str,
                        status: str, count: int):
        with self._conn() as c:
            c.execute(
                """
                INSERT INTO feeds (id, name, url, last_run, last_status, last_count, total_runs)
                VALUES (?,?,?,?,?,?,1)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, url=excluded.url,
                    last_run=excluded.last_run, last_status=excluded.last_status,
                    last_count=excluded.last_count, total_runs=feeds.total_runs+1
                """,
                (feed_id, name, url, time.time(), status, count),
            )

    def feeds(self) -> list:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM feeds ORDER BY last_run DESC").fetchall()]

    # ---- alerts ---------------------------------------------------------
    def add_alert(self, observable: str, ioc: dict, context: str = "") -> int:
        now = time.time()
        with self._conn() as c:
            cur = c.execute(
                """
                INSERT INTO alerts (ts, observable, ioc_id, ioc_value, ioc_type,
                                    threat, severity, source, context, count, last_ts)
                VALUES (?,?,?,?,?,?,?,?,?,1,?)
                """,
                (now, observable, ioc.get("id"), ioc.get("value"),
                 ioc.get("ioc_type"), ioc.get("threat"), ioc.get("severity"),
                 ioc.get("source"), context, now),
            )
            return cur.lastrowid

    def bump_alert(self, alert_id: int):
        """Increment the occurrence count of an existing (deduplicated) alert."""
        with self._conn() as c:
            c.execute(
                "UPDATE alerts SET count = count + 1, last_ts = ? WHERE id = ?",
                (time.time(), alert_id),
            )

    def alerts(self, limit: int = 100, only_open: bool = False) -> list:
        where = "WHERE acknowledged=0" if only_open else ""
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                f"SELECT * FROM alerts {where} ORDER BY ts DESC LIMIT ?",
                (limit,)).fetchall()]

    def acknowledge(self, alert_id: int):
        with self._conn() as c:
            c.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
