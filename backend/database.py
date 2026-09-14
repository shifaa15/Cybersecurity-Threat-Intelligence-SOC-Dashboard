"""
database.py

Lightweight SQLite persistence. Event volume in this simulation is a
few per second, so synchronous sqlite3 calls (guarded by a lock) are
fine and keep the project dependency-free — swap for Postgres/Timescale
in a real deployment without touching the API layer above it.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path

# Configurable so a Docker volume (or any persistent disk) can be mounted at
# a "data" directory without touching the app code — see docker-compose.yml.
DB_PATH = Path(os.environ.get("SOC_DB_PATH", Path(__file__).parent / "data" / "soc.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
_lock = threading.Lock()


def _connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


_conn = _connect()


def init_db(reset: bool = True):
    with _lock:
        cur = _conn.cursor()
        if reset:
            cur.execute("DROP TABLE IF EXISTS events")
            cur.execute("DROP TABLE IF EXISTS incidents")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                event_type TEXT,
                source TEXT,
                src_ip TEXT,
                dest_ip TEXT,
                user TEXT,
                asset TEXT,
                asset_criticality TEXT,
                description TEXT,
                raw_confidence REAL,
                timestamp TEXT,
                mitre_techniques TEXT,
                severity_score REAL,
                severity_label TEXT,
                incident_id TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT,
                src_ip TEXT,
                asset TEXT,
                started_at TEXT,
                last_seen_at TEXT,
                event_ids TEXT,
                max_severity_score REAL,
                max_severity_label TEXT,
                tactics_observed TEXT,
                status TEXT
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_incident ON events(incident_id)")
        _conn.commit()


def insert_event(e: dict):
    with _lock:
        _conn.execute(
            """INSERT INTO events
            (id, event_type, source, src_ip, dest_ip, user, asset, asset_criticality,
             description, raw_confidence, timestamp, mitre_techniques, severity_score,
             severity_label, incident_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                e["id"], e["event_type"], e["source"], e["src_ip"], e.get("dest_ip"),
                e.get("user"), e["asset"], e["asset_criticality"], e["description"],
                e["raw_confidence"], e["timestamp"], json.dumps(e["mitre_techniques"]),
                e["severity_score"], e["severity_label"], e.get("incident_id"),
            ),
        )
        _conn.commit()


def upsert_incident(i: dict):
    with _lock:
        _conn.execute(
            """INSERT INTO incidents
            (id, title, src_ip, asset, started_at, last_seen_at, event_ids,
             max_severity_score, max_severity_label, tactics_observed, status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                last_seen_at=excluded.last_seen_at,
                event_ids=excluded.event_ids,
                max_severity_score=excluded.max_severity_score,
                max_severity_label=excluded.max_severity_label,
                tactics_observed=excluded.tactics_observed,
                status=excluded.status
            """,
            (
                i["id"], i["title"], i["src_ip"], i["asset"], i["started_at"],
                i["last_seen_at"], json.dumps(i["event_ids"]), i["max_severity_score"],
                i["max_severity_label"], json.dumps(i["tactics_observed"]), i["status"],
            ),
        )
        _conn.commit()


def get_events(limit: int = 100, severity: str | None = None, search: str | None = None) -> list[dict]:
    with _lock:
        q = "SELECT * FROM events"
        clauses, params = [], []
        if severity and severity != "all":
            clauses.append("severity_label = ?")
            params.append(severity)
        if search:
            clauses.append("(description LIKE ? OR asset LIKE ? OR src_ip LIKE ? OR event_type LIKE ?)")
            like = f"%{search}%"
            params += [like, like, like, like]
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = _conn.execute(q, params).fetchall()
        return [_row_to_event(r) for r in rows]


def _row_to_event(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["mitre_techniques"] = json.loads(d["mitre_techniques"] or "[]")
    return d


def _row_to_incident(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["event_ids"] = json.loads(d["event_ids"] or "[]")
    d["tactics_observed"] = json.loads(d["tactics_observed"] or "[]")
    return d


def get_incidents(limit: int = 50) -> list[dict]:
    with _lock:
        rows = _conn.execute(
            "SELECT * FROM incidents ORDER BY last_seen_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_row_to_incident(r) for r in rows]


def get_incident_events(incident_id: str) -> list[dict]:
    with _lock:
        rows = _conn.execute(
            "SELECT * FROM events WHERE incident_id = ? ORDER BY timestamp ASC", (incident_id,)
        ).fetchall()
        return [_row_to_event(r) for r in rows]


def get_stats() -> dict:
    with _lock:
        total = _conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        by_sev = _conn.execute(
            "SELECT severity_label, COUNT(*) c FROM events GROUP BY severity_label"
        ).fetchall()
        open_incidents = _conn.execute(
            "SELECT COUNT(*) c FROM incidents WHERE status != 'closed'"
        ).fetchone()["c"]
        top_sources = _conn.execute(
            "SELECT src_ip, COUNT(*) c FROM events GROUP BY src_ip ORDER BY c DESC LIMIT 5"
        ).fetchall()
        avg_score = _conn.execute("SELECT AVG(severity_score) a FROM events").fetchone()["a"]
        return {
            "total_events": total,
            "by_severity": {r["severity_label"]: r["c"] for r in by_sev},
            "open_incidents": open_incidents,
            "top_sources": [{"src_ip": r["src_ip"], "count": r["c"]} for r in top_sources],
            "avg_severity_score": round(avg_score or 0, 1),
        }


def get_mitre_counts() -> dict[str, int]:
    with _lock:
        rows = _conn.execute("SELECT mitre_techniques FROM events").fetchall()
    counts: dict[str, int] = {}
    for r in rows:
        for t in json.loads(r["mitre_techniques"] or "[]"):
            counts[t["id"]] = counts.get(t["id"], 0) + 1
    return counts


def get_timeline(minutes: int = 30, bucket_seconds: int = 30) -> list[dict]:
    """Bucketed event counts by severity for the attack-timeline chart."""
    cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
    with _lock:
        rows = _conn.execute(
            "SELECT timestamp, severity_label FROM events WHERE timestamp >= ? ORDER BY timestamp ASC",
            (cutoff,),
        ).fetchall()

    buckets: dict[str, dict] = {}
    for r in rows:
        ts = datetime.fromisoformat(r["timestamp"])
        bucket_ts = ts.replace(
            second=(ts.second // bucket_seconds) * bucket_seconds, microsecond=0
        )
        key = bucket_ts.isoformat()
        if key not in buckets:
            buckets[key] = {"timestamp": key, "Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        buckets[key][r["severity_label"]] += 1

    return sorted(buckets.values(), key=lambda b: b["timestamp"])
