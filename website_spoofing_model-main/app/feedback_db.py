"""
feedback_db.py – SQLite persistence layer for PhishGuard scan results & feedback.
Tables:
  url_scans      – every scan result (stores scan_id for feedback reference)
  url_feedback   – human corrections on scan results
  url_retraining – corrections queued for model retraining
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

_DB_DIR = Path(__file__).parent.parent / "outputs"
_DB_DIR.mkdir(parents=True, exist_ok=True)
_DB_PATH = _DB_DIR / "phishguard_feedback.db"


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


_SCHEMA = """
CREATE TABLE IF NOT EXISTS url_scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   TEXT    DEFAULT CURRENT_TIMESTAMP,
    url          TEXT    NOT NULL,
    domain       TEXT,
    verdict      TEXT,
    risk_score   REAL,
    risk_reasons TEXT,
    ml_label     TEXT,
    ml_prob      REAL,
    analysis_ms  INTEGER
);

CREATE TABLE IF NOT EXISTS url_feedback (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT    DEFAULT CURRENT_TIMESTAMP,
    scan_id         INTEGER NOT NULL,
    url             TEXT,
    model_verdict   TEXT,
    correct_verdict TEXT    NOT NULL,
    was_correct     INTEGER DEFAULT 0,
    reviewer_id     TEXT    DEFAULT 'user',
    notes           TEXT,
    queued_retrain  INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES url_scans(id)
);

CREATE TABLE IF NOT EXISTS url_retraining (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT    DEFAULT CURRENT_TIMESTAMP,
    scan_id         INTEGER,
    url             TEXT,
    correct_verdict TEXT,
    source          TEXT    DEFAULT 'human_feedback',
    used_in_run     INTEGER DEFAULT 0
);
"""


def init_db():
    conn = _get_conn()
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def save_scan(result: dict) -> int:
    """Persist a scan result. Returns the new scan_id."""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO url_scans
            (url, domain, verdict, risk_score, risk_reasons, ml_label, ml_prob, analysis_ms)
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            result.get("url", ""),
            result.get("domain", ""),
            result.get("verdict", "UNKNOWN"),
            result.get("risk_score", 0.0),
            json.dumps(result.get("risk_reasons", [])),
            result.get("details", {}).get("ml_model", {}).get("label", ""),
            result.get("details", {}).get("ml_model", {}).get("probability", 0.0),
            int(result.get("analysis_time_ms", 0)),
        ))
        scan_id = cur.lastrowid
        conn.commit()
        return scan_id
    finally:
        conn.close()


def save_feedback(
    scan_id: int,
    url: str,
    model_verdict: str,
    correct_verdict: str,
    reviewer_id: str = "user",
    notes: str = "",
) -> dict:
    """Save human feedback. Queues to retraining if the model was wrong."""
    was_correct = (model_verdict.upper() == correct_verdict.upper())
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO url_feedback
            (scan_id, url, model_verdict, correct_verdict, was_correct,
             reviewer_id, notes, queued_retrain)
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            scan_id, url, model_verdict, correct_verdict,
            int(was_correct), reviewer_id, notes, int(not was_correct),
        ))

        if not was_correct:
            cur.execute("""
                INSERT INTO url_retraining (scan_id, url, correct_verdict, source)
                VALUES (?,?,?,?)
            """, (scan_id, url, correct_verdict, "human_feedback"))

        conn.commit()
        return {
            "scan_id": scan_id,
            "was_correct": was_correct,
            "correct_verdict": correct_verdict,
            "queued_for_retraining": not was_correct,
        }
    finally:
        conn.close()


def get_feedback_stats() -> dict:
    conn = _get_conn()
    try:
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM url_scans")
        total_scans = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM url_feedback")
        total_feedback = cur.fetchone()[0]

        cur.execute("SELECT SUM(was_correct), COUNT(*) FROM url_feedback")
        row = cur.fetchone()
        accuracy = round(row[0] / row[1] * 100, 1) if row[1] else None

        cur.execute("SELECT COUNT(*) FROM url_retraining WHERE used_in_run=0")
        queue_size = cur.fetchone()[0]

        cur.execute("""
            SELECT correct_verdict, COUNT(*) FROM url_feedback
            WHERE was_correct=0 GROUP BY correct_verdict
        """)
        errors = dict(cur.fetchall())

        return {
            "total_scans": total_scans,
            "total_feedback": total_feedback,
            "accuracy": accuracy,
            "retraining_queue_size": queue_size,
            "false_positives": errors.get("SAFE", 0),
            "false_negatives": errors.get("DANGEROUS", 0) + errors.get("SUSPICIOUS", 0),
        }
    finally:
        conn.close()


def get_retraining_queue(limit: int = 200) -> list:
    """Return pending retraining samples."""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT r.id, r.created_at, r.url, r.correct_verdict,
                   f.model_verdict, f.notes
            FROM url_retraining r
            LEFT JOIN url_feedback f ON f.scan_id = r.scan_id
            WHERE r.used_in_run=0
            ORDER BY r.created_at DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def mark_retraining_used():
    conn = _get_conn()
    try:
        conn.execute("UPDATE url_retraining SET used_in_run=1 WHERE used_in_run=0")
        conn.commit()
    finally:
        conn.close()


# Initialize on import
init_db()
