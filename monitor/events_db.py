"""Append-only SQLite event history.

Every serious alert is also written here so the dashboard can show trends and
weekly summaries - things the rotating CSV logs can't do. This is additive:
the CSVs remain the operational logs; this is the long-term history.
"""

import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
DB_PATH = ROOT_DIR / "events.db"
_lock = threading.Lock()


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ts TEXT NOT NULL,"
        "day TEXT NOT NULL,"
        "kind TEXT NOT NULL,"
        "severity TEXT,"
        "title TEXT,"
        "detail TEXT)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_day ON events(day)")
    return conn


def record_event(kind, severity, title, detail=""):
    now = datetime.now()
    try:
        with _lock:
            conn = _connect()
            conn.execute(
                "INSERT INTO events (ts, day, kind, severity, title, detail) VALUES (?,?,?,?,?,?)",
                (now.strftime("%Y-%m-%d %H:%M:%S"), now.strftime("%Y-%m-%d"),
                 kind, str(severity or ""), str(title or "")[:300], str(detail or "")[:500]),
            )
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[EVENTS] Could not record event: {e}")


def get_daily_counts(days=14):
    """Return [{'date','label','count'}] for the last `days` days, gaps filled."""
    today = datetime.now().date()
    start = today - timedelta(days=days - 1)
    counts = {}
    try:
        with _lock:
            conn = _connect()
            for day, n in conn.execute(
                "SELECT day, COUNT(*) FROM events WHERE day >= ? GROUP BY day",
                (start.strftime("%Y-%m-%d"),),
            ):
                counts[day] = n
            conn.close()
    except Exception as e:
        print(f"[EVENTS] Could not read daily counts: {e}")

    out = []
    for i in range(days):
        d = start + timedelta(days=i)
        key = d.strftime("%Y-%m-%d")
        out.append({"date": key, "label": d.strftime("%m/%d"), "count": counts.get(key, 0)})
    return out


def get_events(days=7, limit=500):
    """Return recent events as dicts, newest first."""
    since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    rows = []
    try:
        with _lock:
            conn = _connect()
            for ts, kind, severity, title, detail in conn.execute(
                "SELECT ts, kind, severity, title, detail FROM events "
                "WHERE ts >= ? ORDER BY ts DESC LIMIT ?", (since, limit),
            ):
                rows.append({"ts": ts, "kind": kind, "severity": severity or "",
                             "title": title or "", "detail": detail or ""})
            conn.close()
    except Exception as e:
        print(f"[EVENTS] Could not read events: {e}")
    return rows


def get_summary(days=7):
    """Totals for the last `days` days, broken down by kind and severity."""
    since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    summary = {"days": days, "total": 0, "by_kind": {}, "by_severity": {}}
    try:
        with _lock:
            conn = _connect()
            row = conn.execute("SELECT COUNT(*) FROM events WHERE ts >= ?", (since,)).fetchone()
            summary["total"] = row[0] if row else 0
            for kind, n in conn.execute(
                "SELECT kind, COUNT(*) FROM events WHERE ts >= ? GROUP BY kind ORDER BY 2 DESC", (since,)
            ):
                summary["by_kind"][kind] = n
            for sev, n in conn.execute(
                "SELECT severity, COUNT(*) FROM events WHERE ts >= ? GROUP BY severity", (since,)
            ):
                summary["by_severity"][sev or "unknown"] = n
            conn.close()
    except Exception as e:
        print(f"[EVENTS] Could not read summary: {e}")
    return summary
