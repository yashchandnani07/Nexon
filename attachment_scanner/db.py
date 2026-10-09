# attachment_scanner/db.py
# PostgreSQL persistence layer for scan history
#
# Uses psycopg2 with a connection pool.
# If PostgreSQL is unavailable, all functions degrade gracefully
# so the scanner continues to work without persistence.

import os
import json
import traceback

try:
    import psycopg2
    from psycopg2 import pool as pg_pool
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    print("WARNING: psycopg2 not installed — scan history disabled")

# ── Connection config ─────────────────────────────────────────────────────────

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://dlp:dlp@postgres:5432/dlp"
)

_pool = None


def _get_pool():
    global _pool
    if _pool is not None:
        return _pool
    try:
        _pool = pg_pool.SimpleConnectionPool(1, 5, DATABASE_URL)
        return _pool
    except Exception as e:
        print(f"[DB] Connection pool error: {e}")
        return None


# ── Schema ────────────────────────────────────────────────────────────────────

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS attachment_scan_history (
    id               SERIAL PRIMARY KEY,
    filename         TEXT    NOT NULL,
    file_size_kb     FLOAT,
    risk_label       TEXT,
    risk_score       INT     DEFAULT 0,
    critical_count   INT     DEFAULT 0,
    high_count       INT     DEFAULT 0,
    medium_count     INT     DEFAULT 0,
    low_count        INT     DEFAULT 0,
    total_findings   INT     DEFAULT 0,
    human_summary    TEXT,
    recommended_action TEXT,
    analysis_time_ms FLOAT,
    scanned_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
"""


def init_db() -> bool:
    """
    Create the scan_history table if it doesn't exist.
    Called once at server startup.
    Returns True on success.
    """
    if not PSYCOPG2_AVAILABLE:
        return False

    p = _get_pool()
    if p is None:
        return False

    conn = None
    try:
        conn = p.getconn()
        with conn.cursor() as cur:
            cur.execute(CREATE_TABLE_SQL)
        conn.commit()
        print("[DB] attachment_scan_history table ready")
        return True
    except Exception as e:
        print(f"[DB] init_db error: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn and p:
            p.putconn(conn)


# ── Write ─────────────────────────────────────────────────────────────────────

INSERT_SQL = """
INSERT INTO attachment_scan_history
    (filename, file_size_kb, risk_label, risk_score,
     critical_count, high_count, medium_count, low_count,
     total_findings, human_summary, recommended_action, analysis_time_ms)
VALUES
    (%(filename)s, %(file_size_kb)s, %(risk_label)s, %(risk_score)s,
     %(critical_count)s, %(high_count)s, %(medium_count)s, %(low_count)s,
     %(total_findings)s, %(human_summary)s, %(recommended_action)s, %(analysis_time_ms)s)
RETURNING id, scanned_at;
"""


def save_scan(result: dict) -> dict | None:
    """
    Persist a completed scan result.
    Returns the saved record's id and timestamp, or None on failure.
    """
    if not PSYCOPG2_AVAILABLE:
        return None

    p = _get_pool()
    if p is None:
        return None

    conn = None
    try:
        conn = p.getconn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(INSERT_SQL, {
                "filename":           result.get("filename", "unknown"),
                "file_size_kb":       result.get("file_size_kb"),
                "risk_label":         result.get("risk_label"),
                "risk_score":         result.get("risk_score", 0),
                "critical_count":     result.get("critical_count", 0),
                "high_count":         result.get("high_count", 0),
                "medium_count":       result.get("medium_count", 0),
                "low_count":          result.get("low_count", 0),
                "total_findings":     result.get("total_findings", 0),
                "human_summary":      result.get("human_summary"),
                "recommended_action": result.get("recommended_action"),
                "analysis_time_ms":   result.get("analysis_time_ms"),
            })
            row = cur.fetchone()
        conn.commit()
        return dict(row) if row else None
    except Exception as e:
        print(f"[DB] save_scan error: {e}")
        if conn:
            conn.rollback()
        return None
    finally:
        if conn and p:
            p.putconn(conn)


# ── Read ──────────────────────────────────────────────────────────────────────

HISTORY_SQL = """
SELECT
    id,
    filename,
    file_size_kb,
    risk_label,
    risk_score,
    critical_count,
    high_count,
    medium_count,
    low_count,
    total_findings,
    human_summary,
    recommended_action,
    analysis_time_ms,
    scanned_at
FROM attachment_scan_history
ORDER BY scanned_at DESC
LIMIT %(limit)s;
"""

STATS_SQL = """
SELECT
    COUNT(*)                                        AS total_scans,
    COUNT(*) FILTER (WHERE risk_label != 'Clean')   AS total_malicious,
    COUNT(*) FILTER (WHERE risk_label = 'Critical') AS critical_count,
    COUNT(*) FILTER (WHERE risk_label = 'High')     AS high_count,
    COUNT(*) FILTER (WHERE risk_label = 'Clean')    AS clean_count
FROM attachment_scan_history;
"""


def get_history(limit: int = 50) -> list:
    """Return the most recent scan records."""
    if not PSYCOPG2_AVAILABLE:
        return []

    p = _get_pool()
    if p is None:
        return []

    conn = None
    try:
        conn = p.getconn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(HISTORY_SQL, {"limit": limit})
            rows = cur.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DB] get_history error: {e}")
        return []
    finally:
        if conn and p:
            p.putconn(conn)


def get_stats() -> dict:
    """Return aggregate stats across all stored scans."""
    if not PSYCOPG2_AVAILABLE:
        return {}

    p = _get_pool()
    if p is None:
        return {}

    conn = None
    try:
        conn = p.getconn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(STATS_SQL)
            row = cur.fetchone()
        return dict(row) if row else {}
    except Exception as e:
        print(f"[DB] get_stats error: {e}")
        return {}
    finally:
        if conn and p:
            p.putconn(conn)
