# src/db.py  –  PostgreSQL (with SQLite fallback) database layer
"""
Centralized database layer for FraudShield Voice.
Tries PostgreSQL first; falls back to SQLite so the service still runs locally.
Tables:
  voice_predictions  – every scan result + audio bytes
  voice_feedback     – human corrections
  voice_retraining   – corrections queued for retraining
"""
import os
import json
import hashlib
from datetime import datetime
from pathlib import Path

# ── Try psycopg2 / PostgreSQL ──────────────────────────────────────────────
try:
    import psycopg2
    import psycopg2.extras
    _PG_DSN = os.getenv(
        "DATABASE_URL",
        "postgresql://aegisai:aegisai@localhost:5432/aegisai"
    )
    _USE_PG = True
except ImportError:
    _USE_PG = False

# ── SQLite fallback ────────────────────────────────────────────────────────
import sqlite3
_OUTPUTS = Path(__file__).parent.parent / "outputs"
_OUTPUTS.mkdir(parents=True, exist_ok=True)
_SQLITE_PATH = _OUTPUTS / "fraudshield.db"


# ══════════════════════════════════════════════════════════════════════════
#  Internal helpers
# ══════════════════════════════════════════════════════════════════════════
def _get_conn():
    if _USE_PG:
        try:
            return psycopg2.connect(_PG_DSN), "pg"
        except Exception:
            pass
    conn = sqlite3.connect(str(_SQLITE_PATH))
    conn.row_factory = sqlite3.Row
    return conn, "sqlite"


def _placeholder(backend: str, idx: int = 1) -> str:
    return "%s" if backend == "pg" else "?"


# ══════════════════════════════════════════════════════════════════════════
#  Schema init
# ══════════════════════════════════════════════════════════════════════════
_CREATE_PREDICTIONS = """
CREATE TABLE IF NOT EXISTS voice_predictions (
    id            SERIAL PRIMARY KEY,
    created_at    TIMESTAMP  NOT NULL DEFAULT NOW(),
    file_name     TEXT,
    file_hash     TEXT,
    audio_bytes   BYTEA,
    duration_s    REAL,
    verdict       TEXT,
    risk_score    INTEGER,
    tier          TEXT,
    action_rec    TEXT,
    deep_score    REAL,
    rf_score      REAL,
    final_score   REAL,
    top_indicators TEXT,
    explanation   TEXT,
    chunks_analyzed INTEGER,
    processing_ms  INTEGER,
    caller_id     TEXT  DEFAULT '',
    channel       TEXT  DEFAULT 'upload'
)
"""
_CREATE_PREDICTIONS_SQLITE = _CREATE_PREDICTIONS.replace(
    "SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT"
).replace("BYTEA", "BLOB").replace("TIMESTAMP", "TEXT").replace(" DEFAULT NOW()", " DEFAULT CURRENT_TIMESTAMP")

_CREATE_FEEDBACK = """
CREATE TABLE IF NOT EXISTS voice_feedback (
    id              SERIAL PRIMARY KEY,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    prediction_id   INTEGER   NOT NULL,
    reviewer_id     TEXT      DEFAULT 'analyst',
    correct_label   TEXT,
    was_correct     BOOLEAN,
    notes           TEXT,
    queued_retrain  BOOLEAN   DEFAULT FALSE
)
"""
_CREATE_FEEDBACK_SQLITE = _CREATE_FEEDBACK.replace(
    "SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT"
).replace("TIMESTAMP", "TEXT").replace(" DEFAULT NOW()", " DEFAULT CURRENT_TIMESTAMP").replace("BOOLEAN", "INTEGER")

_CREATE_RETRAIN = """
CREATE TABLE IF NOT EXISTS voice_retraining (
    id              SERIAL PRIMARY KEY,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    prediction_id   INTEGER,
    correct_label   TEXT,
    source          TEXT      DEFAULT 'human_review',
    used_in_run     BOOLEAN   DEFAULT FALSE
)
"""
_CREATE_RETRAIN_SQLITE = _CREATE_RETRAIN.replace(
    "SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT"
).replace("TIMESTAMP", "TEXT").replace(" DEFAULT NOW()", " DEFAULT CURRENT_TIMESTAMP").replace("BOOLEAN", "INTEGER")


def init_db():
    conn, backend = _get_conn()
    try:
        cur = conn.cursor()
        if backend == "pg":
            cur.execute(_CREATE_PREDICTIONS)
            cur.execute(_CREATE_FEEDBACK)
            cur.execute(_CREATE_RETRAIN)
        else:
            cur.execute(_CREATE_PREDICTIONS_SQLITE)
            cur.execute(_CREATE_FEEDBACK_SQLITE)
            cur.execute(_CREATE_RETRAIN_SQLITE)
        conn.commit()
        print(f"[DB] Initialized ({backend})")
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════════════════
#  Predictions
# ══════════════════════════════════════════════════════════════════════════
def save_prediction(result: dict, audio_bytes: bytes = b"", file_name: str = "") -> int:
    conn, backend = _get_conn()
    p = "%" if backend == "pg" else ""
    try:
        cur = conn.cursor()
        fhash = hashlib.md5(audio_bytes or b"").hexdigest()
        indicators_json = json.dumps(result.get("top_indicators", []))
        if backend == "pg":
            cur.execute(f"""
                INSERT INTO voice_predictions
                (file_name, file_hash, audio_bytes, duration_s, verdict,
                 risk_score, tier, action_rec, deep_score, rf_score, final_score,
                 top_indicators, explanation, chunks_analyzed, processing_ms, caller_id, channel)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING id
            """, (
                file_name, fhash, psycopg2.Binary(audio_bytes),
                result.get("duration_s", 0),
                result.get("verdict"), result.get("risk_score"), result.get("tier"),
                result.get("action"), result.get("deep_score"), result.get("rf_score"),
                result.get("final_score"), indicators_json, result.get("explanation",""),
                result.get("chunks_analyzed", 0), result.get("processing_ms", 0),
                result.get("caller_id",""), result.get("channel","upload"),
            ))
            row = cur.fetchone()
            pred_id = row[0] if isinstance(row, tuple) else row["id"]
        else:
            cur.execute("""
                INSERT INTO voice_predictions
                (file_name, file_hash, audio_bytes, duration_s, verdict,
                 risk_score, tier, action_rec, deep_score, rf_score, final_score,
                 top_indicators, explanation, chunks_analyzed, processing_ms, caller_id, channel)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                file_name, fhash, audio_bytes,
                result.get("duration_s", 0),
                result.get("verdict"), result.get("risk_score"), result.get("tier"),
                result.get("action"), result.get("deep_score"), result.get("rf_score"),
                result.get("final_score"), indicators_json, result.get("explanation",""),
                result.get("chunks_analyzed", 0), result.get("processing_ms", 0),
                result.get("caller_id",""), result.get("channel","upload"),
            ))
            pred_id = cur.lastrowid
        conn.commit()
        return pred_id
    finally:
        conn.close()


def get_scan_history(limit: int = 30) -> list:
    conn, backend = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(f"""
            SELECT id, created_at, file_name, verdict, risk_score, tier,
                   action_rec, deep_score, rf_score, final_score,
                   top_indicators, explanation, processing_ms, channel
            FROM voice_predictions
            ORDER BY created_at DESC
            LIMIT {'%s' if backend == 'pg' else '?'}
        """ , (limit,))
        rows = cur.fetchall()
        out = []
        for r in rows:
            if backend == "pg":
                d = dict(r)
            else:
                d = dict(r)
            try:
                d["top_indicators"] = json.loads(d.get("top_indicators") or "[]")
            except Exception:
                d["top_indicators"] = []
            out.append(d)
        return out
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════════════════
#  Feedback
# ══════════════════════════════════════════════════════════════════════════
def save_feedback(prediction_id: int, correct_label: str,
                  reviewer_id: str = "analyst", notes: str = "", verdict: str = "") -> dict:
    was_correct = (verdict == correct_label)
    conn, backend = _get_conn()
    try:
        cur = conn.cursor()
        if backend == "pg":
            cur.execute("""
                INSERT INTO voice_feedback
                (prediction_id, reviewer_id, correct_label, was_correct, notes, queued_retrain)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (prediction_id, reviewer_id, correct_label, was_correct, notes, not was_correct))
            if not was_correct:
                cur.execute("""
                    INSERT INTO voice_retraining (prediction_id, correct_label, source)
                    VALUES (%s,%s,%s)
                """, (prediction_id, correct_label, "human_review"))
        else:
            cur.execute("""
                INSERT INTO voice_feedback
                (prediction_id, reviewer_id, correct_label, was_correct, notes, queued_retrain)
                VALUES (?,?,?,?,?,?)
            """, (prediction_id, reviewer_id, correct_label, int(was_correct), notes, int(not was_correct)))
            if not was_correct:
                cur.execute("""
                    INSERT INTO voice_retraining (prediction_id, correct_label, source)
                    VALUES (?,?,?)
                """, (prediction_id, correct_label, "human_review"))
        conn.commit()
        return {
            "prediction_id": prediction_id,
            "was_correct": was_correct,
            "correct_label": correct_label,
            "queued_for_retraining": not was_correct,
        }
    finally:
        conn.close()


def get_feedback_stats() -> dict:
    conn, backend = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM voice_predictions")
        total_preds = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM voice_feedback")
        total_fb = cur.fetchone()[0]

        cur.execute("SELECT SUM(CAST(was_correct AS INTEGER)), COUNT(*) FROM voice_feedback")
        row = cur.fetchone()
        accuracy = round(row[0] / row[1] * 100, 1) if row[1] else None

        cur.execute("SELECT COUNT(*) FROM voice_retraining WHERE used_in_run=FALSE OR used_in_run=0")
        queue_size = cur.fetchone()[0]

        return {
            "total_predictions": total_preds,
            "total_feedback": total_fb,
            "accuracy": accuracy,
            "retraining_queue_size": queue_size,
        }
    finally:
        conn.close()


def mark_retraining_used():
    conn, _ = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE voice_retraining SET used_in_run=TRUE WHERE used_in_run=FALSE OR used_in_run=0")
        conn.commit()
    finally:
        conn.close()


init_db()
