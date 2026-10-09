# email_monitoring/email_db.py
# PostgreSQL persistence layer for the Email Monitor service.
# Graceful degradation: if postgres is unavailable, all functions
# return empty/None — the API keeps running with in-memory data only.

import os
import json
import traceback
from datetime import datetime, timezone

try:
    import psycopg2
    from psycopg2 import pool as pg_pool
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    print("WARNING: psycopg2 not installed — email history disabled")

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://dlp:dlp@postgres:5432/dlp")

_pool = None


def _get_pool():
    global _pool
    if _pool is not None:
        return _pool
    if not PSYCOPG2_AVAILABLE:
        return None
    try:
        _pool = pg_pool.SimpleConnectionPool(1, 8, DATABASE_URL)
        return _pool
    except Exception as e:
        print(f"[EmailDB] Pool error: {e}")
        return None


# ── Schema ────────────────────────────────────────────────────────────────────

INIT_SQL = """
CREATE TABLE IF NOT EXISTS email_inbox (
    id              SERIAL PRIMARY KEY,
    message_id      TEXT UNIQUE,
    subject         TEXT,
    sender          TEXT,
    receiver        TEXT,
    reply_to        TEXT,
    date_str        TEXT,
    headers         JSONB    DEFAULT '{}'::jsonb,
    body_text       TEXT,
    body_html       TEXT,
    urls            JSONB    DEFAULT '[]'::jsonb,
    has_attachments BOOLEAN  DEFAULT FALSE,
    attachment_count INT     DEFAULT 0,
    is_read         BOOLEAN  DEFAULT FALSE,
    is_flagged      BOOLEAN  DEFAULT FALSE,
    risk_score      INT      DEFAULT 0,
    risk_tier       TEXT     DEFAULT 'UNKNOWN',
    analysis        JSONB    DEFAULT NULL,
    received_at     TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS email_attachments (
    id              SERIAL PRIMARY KEY,
    email_id        INT REFERENCES email_inbox(id) ON DELETE CASCADE,
    filename        TEXT,
    content_type    TEXT,
    size_bytes      INT,
    content         BYTEA,
    analysis        JSONB    DEFAULT NULL,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS email_feedback (
    id              SERIAL PRIMARY KEY,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    email_id        INT REFERENCES email_inbox(id) ON DELETE SET NULL,
    model_verdict   TEXT,
    correct_verdict TEXT    NOT NULL,
    was_correct     BOOLEAN DEFAULT FALSE,
    module          TEXT    DEFAULT 'phishing',
    reviewer_id     TEXT    DEFAULT 'user',
    notes           TEXT,
    queued_retrain  BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS email_retraining (
    id              SERIAL PRIMARY KEY,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    email_id        INT,
    subject         TEXT,
    correct_verdict TEXT,
    module          TEXT    DEFAULT 'phishing',
    source          TEXT    DEFAULT 'human_feedback',
    used_in_run     BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_email_received  ON email_inbox(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_sender    ON email_inbox(sender);
CREATE INDEX IF NOT EXISTS idx_email_risk      ON email_inbox(risk_tier);
CREATE INDEX IF NOT EXISTS idx_att_email_id    ON email_attachments(email_id);
CREATE INDEX IF NOT EXISTS idx_efeedback_email ON email_feedback(email_id);
CREATE INDEX IF NOT EXISTS idx_eretrain_used   ON email_retraining(used_in_run);
"""


def init_db() -> bool:
    p = _get_pool()
    if p is None:
        return False
    conn = None
    try:
        conn = p.getconn()
        with conn.cursor() as cur:
            cur.execute(INIT_SQL)
        conn.commit()
        print("[EmailDB] Schema ready")
        return True
    except Exception as e:
        print(f"[EmailDB] init_db error: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn and p:
            p.putconn(conn)


# ── Write ─────────────────────────────────────────────────────────────────────

def save_email(data: dict) -> dict | None:
    """Insert a parsed email into email_inbox. Returns saved row or None."""
    p = _get_pool()
    if p is None:
        return None
    conn = None
    try:
        conn = p.getconn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                INSERT INTO email_inbox
                    (message_id, subject, sender, receiver, reply_to, date_str,
                     headers, body_text, body_html, urls,
                     has_attachments, attachment_count)
                VALUES
                    (%(message_id)s, %(subject)s, %(sender)s, %(receiver)s,
                     %(reply_to)s, %(date_str)s,
                     %(headers)s::jsonb, %(body_text)s, %(body_html)s,
                     %(urls)s::jsonb, %(has_attachments)s, %(attachment_count)s)
                ON CONFLICT (message_id) DO NOTHING
                RETURNING id, received_at
            """, {
                "message_id":      data.get("message_id", ""),
                "subject":         data.get("subject", "(no subject)"),
                "sender":          data.get("sender", ""),
                "receiver":        data.get("receiver", ""),
                "reply_to":        data.get("reply_to", ""),
                "date_str":        data.get("date_str", ""),
                "headers":         json.dumps(data.get("headers", {})),
                "body_text":       data.get("body_text", ""),
                "body_html":       data.get("body_html", ""),
                "urls":            json.dumps(data.get("urls", [])),
                "has_attachments": data.get("has_attachments", False),
                "attachment_count":data.get("attachment_count", 0),
            })
            row = cur.fetchone()
        conn.commit()
        return dict(row) if row else None
    except Exception as e:
        print(f"[EmailDB] save_email error: {e}")
        if conn:
            conn.rollback()
        return None
    finally:
        if conn and p:
            p.putconn(conn)


def save_attachment(email_id: int, att: dict) -> int | None:
    """Insert attachment row. Returns attachment id or None."""
    p = _get_pool()
    if p is None:
        return None
    conn = None
    try:
        conn = p.getconn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO email_attachments (email_id, filename, content_type, size_bytes, content)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (
                email_id,
                att.get("filename", "attachment"),
                att.get("content_type", "application/octet-stream"),
                att.get("size_bytes", 0),
                psycopg2.Binary(att.get("content", b"")),
            ))
            row = cur.fetchone()
        conn.commit()
        return row[0] if row else None
    except Exception as e:
        print(f"[EmailDB] save_attachment error: {e}")
        if conn:
            conn.rollback()
        return None
    finally:
        if conn and p:
            p.putconn(conn)


def update_email_analysis(email_id: int, analysis: dict, risk_score: int, risk_tier: str):
    p = _get_pool()
    if p is None:
        return
    conn = None
    try:
        conn = p.getconn()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE email_inbox
                SET analysis = %s::jsonb, risk_score = %s, risk_tier = %s
                WHERE id = %s
            """, (json.dumps(analysis), risk_score, risk_tier, email_id))
        conn.commit()
    except Exception as e:
        print(f"[EmailDB] update_analysis error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn and p:
            p.putconn(conn)


def update_attachment_analysis(att_id: int, analysis: dict):
    p = _get_pool()
    if p is None:
        return
    conn = None
    try:
        conn = p.getconn()
        with conn.cursor() as cur:
            cur.execute("UPDATE email_attachments SET analysis = %s::jsonb WHERE id = %s",
                        (json.dumps(analysis), att_id))
        conn.commit()
    except Exception as e:
        print(f"[EmailDB] update_att_analysis error: {e}")
    finally:
        if conn and p:
            p.putconn(conn)


def mark_read(email_id: int):
    p = _get_pool()
    if p is None:
        return
    conn = None
    try:
        conn = p.getconn()
        with conn.cursor() as cur:
            cur.execute("UPDATE email_inbox SET is_read = TRUE WHERE id = %s", (email_id,))
        conn.commit()
    finally:
        if conn and p:
            p.putconn(conn)


def toggle_flag(email_id: int) -> bool:
    p = _get_pool()
    if p is None:
        return False
    conn = None
    try:
        conn = p.getconn()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE email_inbox SET is_flagged = NOT is_flagged WHERE id = %s RETURNING is_flagged
            """, (email_id,))
            row = cur.fetchone()
        conn.commit()
        return row[0] if row else False
    except Exception as e:
        print(f"[EmailDB] toggle_flag error: {e}")
        return False
    finally:
        if conn and p:
            p.putconn(conn)


# ── Read ──────────────────────────────────────────────────────────────────────

def get_emails(limit=50, offset=0, risk_filter=None, search=None,
               unread_only=False, flagged_only=False) -> list:
    p = _get_pool()
    if p is None:
        return [], 0
    conn = None
    try:
        conn = p.getconn()
        conditions = []
        params = []
        # risk_filter may be a single tier OR comma-separated list (e.g. "LOW,MEDIUM")
        if risk_filter and risk_filter != "ALL":
            tiers = [t.strip().upper() for t in risk_filter.split(',') if t.strip()]
            if len(tiers) == 1:
                conditions.append("risk_tier = %s")
                params.append(tiers[0])
            elif len(tiers) > 1:
                placeholders = ','.join(['%s'] * len(tiers))
                conditions.append(f"risk_tier IN ({placeholders})")
                params.extend(tiers)
        if unread_only:
            conditions.append("is_read = FALSE")
        if flagged_only:
            conditions.append("is_flagged = TRUE")
        if search:
            conditions.append("(subject ILIKE %s OR sender ILIKE %s OR body_text ILIKE %s)")
            s = f"%{search}%"
            params.extend([s, s, s])

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.extend([limit, offset])

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(f"""
                SELECT id, message_id, subject, sender, receiver, date_str,
                       has_attachments, attachment_count, is_read, is_flagged,
                       risk_score, risk_tier, received_at,
                       COALESCE(analysis->>'source', 'IMAP') AS email_source,
                       analysis->>'threat_type'    AS threat_type,
                       analysis->>'combined_score' AS gateway_score,
                       analysis->>'explanation'    AS explanation,
                       left(
                           CASE
                               WHEN length(trim(body_text)) > 20 THEN
                                   regexp_replace(trim(body_text), '\\s+', ' ', 'g')
                               ELSE
                                   regexp_replace(
                                       regexp_replace(body_html, E'<[^>]+>', ' ', 'g'),
                                       '\\s+', ' ', 'g')
                           END,
                           200
                       ) AS body_preview
                FROM email_inbox
                {where}
                ORDER BY received_at DESC
                LIMIT %s OFFSET %s
            """, params)
            rows = cur.fetchall()

        # Count
        with conn.cursor() as cur:
            count_params = params[:-2]
            cur.execute(f"SELECT COUNT(*) FROM email_inbox {where}", count_params)
            total = cur.fetchone()[0]

        return [dict(r) for r in rows], total
    except Exception as e:
        print(f"[EmailDB] get_emails error: {e}")
        return [], 0
    finally:
        if conn and p:
            p.putconn(conn)


def get_email(email_id: int) -> dict | None:
    p = _get_pool()
    if p is None:
        return None
    conn = None
    try:
        conn = p.getconn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT e.*,
                       COALESCE(
                           json_agg(
                               json_build_object(
                                   'id', a.id, 'filename', a.filename,
                                   'content_type', a.content_type,
                                   'size_bytes', a.size_bytes,
                                   'analysis', a.analysis
                               )
                           ) FILTER (WHERE a.id IS NOT NULL),
                           '[]'::json
                       ) AS attachments
                FROM email_inbox e
                LEFT JOIN email_attachments a ON a.email_id = e.id
                WHERE e.id = %s
                GROUP BY e.id
            """, (email_id,))
            row = cur.fetchone()
        return dict(row) if row else None
    except Exception as e:
        print(f"[EmailDB] get_email error: {e}")
        return None
    finally:
        if conn and p:
            p.putconn(conn)


def get_attachment_content(att_id: int) -> dict | None:
    p = _get_pool()
    if p is None:
        return None
    conn = None
    try:
        conn = p.getconn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, email_id, filename, content_type, size_bytes, content, analysis
                FROM email_attachments WHERE id = %s
            """, (att_id,))
            row = cur.fetchone()
        return dict(row) if row else None
    except Exception as e:
        print(f"[EmailDB] get_attachment error: {e}")
        return None
    finally:
        if conn and p:
            p.putconn(conn)


def get_stats() -> dict:
    p = _get_pool()
    if p is None:
        return {}
    conn = None
    try:
        conn = p.getconn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    COUNT(*)                                                    AS total,
                    COUNT(*) FILTER (WHERE is_read  = FALSE)                   AS unread,
                    COUNT(*) FILTER (WHERE is_flagged = TRUE)                  AS flagged,
                    COUNT(*) FILTER (WHERE risk_tier IN ('CRITICAL','HIGH'))   AS high_risk,
                    COUNT(*) FILTER (WHERE has_attachments = TRUE)             AS with_attachments,
                    COUNT(*) FILTER (WHERE risk_tier = 'CRITICAL')             AS critical,
                    COUNT(*) FILTER (WHERE risk_tier = 'HIGH')                 AS high,
                    COUNT(*) FILTER (WHERE risk_tier = 'MEDIUM')               AS medium,
                    COUNT(*) FILTER (WHERE risk_tier = 'LOW')                  AS low,
                    COUNT(*) FILTER (WHERE risk_tier = 'UNKNOWN')              AS unknown_tier
                FROM email_inbox
            """)
            return dict(cur.fetchone())
    except Exception as e:
        print(f"[EmailDB] get_stats error: {e}")
        return {}
    finally:
        if conn and p:
            p.putconn(conn)


# ── Feedback & Retraining ─────────────────────────────────────────────────────

def save_email_feedback(
    email_id: int,
    model_verdict: str,
    correct_verdict: str,
    module: str = "phishing",
    reviewer_id: str = "user",
    notes: str = "",
    subject: str = "",
) -> dict:
    """Save analyst feedback. Queues incorrect predictions for retraining."""
    was_correct = (model_verdict.upper() == correct_verdict.upper())
    p = _get_pool()
    if p is None:
        return {"error": "Database unavailable", "was_correct": was_correct,
                "queued_for_retraining": False}
    conn = None
    try:
        conn = p.getconn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO email_feedback
                (email_id, model_verdict, correct_verdict, was_correct,
                 module, reviewer_id, notes, queued_retrain)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                email_id, model_verdict, correct_verdict, was_correct,
                module, reviewer_id, notes, not was_correct,
            ))
            if not was_correct:
                cur.execute("""
                    INSERT INTO email_retraining
                    (email_id, subject, correct_verdict, module, source)
                    VALUES (%s,%s,%s,%s,%s)
                """, (email_id, subject, correct_verdict, module, "human_feedback"))
        conn.commit()
        return {
            "email_id": email_id,
            "was_correct": was_correct,
            "correct_verdict": correct_verdict,
            "queued_for_retraining": not was_correct,
        }
    except Exception as e:
        print(f"[EmailDB] save_email_feedback error: {e}")
        if conn:
            conn.rollback()
        return {"error": str(e), "was_correct": was_correct, "queued_for_retraining": False}
    finally:
        if conn and p:
            p.putconn(conn)


def get_feedback_stats() -> dict:
    """Aggregate feedback statistics for the email module."""
    p = _get_pool()
    if p is None:
        return {}
    conn = None
    try:
        conn = p.getconn()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM email_inbox")
            total_scans = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM email_feedback")
            total_feedback = cur.fetchone()[0]

            cur.execute("""
                SELECT SUM(CASE WHEN was_correct THEN 1 ELSE 0 END), COUNT(*)
                FROM email_feedback
            """)
            row = cur.fetchone()
            accuracy = round(row[0] / row[1] * 100, 1) if row[1] else None

            cur.execute("SELECT COUNT(*) FROM email_retraining WHERE used_in_run=FALSE")
            queue_size = cur.fetchone()[0]

            cur.execute("""
                SELECT correct_verdict, COUNT(*) FROM email_feedback
                WHERE was_correct=FALSE GROUP BY correct_verdict
            """)
            errors = dict(cur.fetchall())

        return {
            "total_scans": total_scans,
            "total_feedback": total_feedback,
            "accuracy": accuracy,
            "retraining_queue_size": queue_size,
            "false_positives": errors.get("LOW", 0) + errors.get("SAFE", 0),
            "false_negatives": errors.get("CRITICAL", 0) + errors.get("HIGH", 0),
        }
    except Exception as e:
        print(f"[EmailDB] get_feedback_stats error: {e}")
        return {}
    finally:
        if conn and p:
            p.putconn(conn)


def mark_email_retraining_used():
    """Mark all pending retraining items as consumed."""
    p = _get_pool()
    if p is None:
        return
    conn = None
    try:
        conn = p.getconn()
        with conn.cursor() as cur:
            cur.execute("UPDATE email_retraining SET used_in_run=TRUE WHERE used_in_run=FALSE")
        conn.commit()
    except Exception as e:
        print(f"[EmailDB] mark_retraining_used error: {e}")
    finally:
        if conn and p:
            p.putconn(conn)
