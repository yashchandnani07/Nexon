"""
Database layer — PostgreSQL (with SQLite fallback) for the SMTP Gateway audit log.
Every SMTP decision is stored as an immutable record with full SHAP explainability.
"""
import os
import json
from pathlib import Path

try:
    import psycopg2
    import psycopg2.extras
    _PG_DSN = os.getenv("DATABASE_URL", "postgresql://dlp:dlp@postgres:5432/dlp")
    _USE_PG = True
except ImportError:
    _USE_PG = False

import sqlite3
_DATA = Path(__file__).parent.parent / "data"
_DATA.mkdir(parents=True, exist_ok=True)
_SQLITE_PATH = _DATA / "gateway.db"


_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS smtp_decisions (
    id                   SERIAL PRIMARY KEY,
    created_at           TIMESTAMP NOT NULL DEFAULT NOW(),
    sender               TEXT,
    recipients           TEXT,
    subject              TEXT,
    fraud_score          REAL,
    decision             TEXT,
    threat_type          TEXT,
    risk_tier            TEXT DEFAULT 'LOW',
    shap_values          TEXT,
    features             TEXT,
    top_contributors     TEXT,
    processing_ms        INTEGER,
    raw_email            TEXT,
    analyst_action       TEXT,
    source               TEXT DEFAULT 'SMTP',
    ml_analysis          TEXT,
    ml_classification    TEXT,
    ml_confidence        REAL,
    detected_languages   TEXT,
    explanation          TEXT,
    ai_generated_prob    REAL DEFAULT 0.0,
    ai_written           BOOLEAN DEFAULT FALSE,
    llama_analysis       TEXT,
    credential_findings  TEXT,
    url_findings         TEXT,
    attachment_findings  TEXT,
    homograph_findings   TEXT,
    combined_score       REAL DEFAULT 0.0,
    factor_explanations  TEXT,
    module_risk_scores   TEXT
)
"""

_CREATE_TABLE_SQLITE = (
    _CREATE_TABLE
    .replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
    .replace("TIMESTAMP", "TEXT")
    .replace(" DEFAULT NOW()", " DEFAULT CURRENT_TIMESTAMP")
)

# Migration: columns added in this version
_NEW_COLUMNS = [
    ("source",              "TEXT DEFAULT 'SMTP'"),
    ("risk_tier",           "TEXT DEFAULT 'LOW'"),
    ("ml_analysis",         "TEXT"),
    ("ml_classification",   "TEXT"),
    ("ml_confidence",       "REAL"),
    ("detected_languages",  "TEXT"),
    ("explanation",         "TEXT"),
    ("ai_generated_prob",   "REAL DEFAULT 0.0"),
    ("ai_written",          "BOOLEAN DEFAULT FALSE"),
    ("llama_analysis",      "TEXT"),
    ("credential_findings", "TEXT"),
    ("url_findings",        "TEXT"),
    ("attachment_findings", "TEXT"),
    ("homograph_findings",  "TEXT"),
    ("combined_score",      "REAL DEFAULT 0.0"),
    ("factor_explanations", "TEXT"),
    ("module_risk_scores",  "TEXT"),
]


def _conn():
    if _USE_PG:
        try:
            c = psycopg2.connect(_PG_DSN)
            c.cursor_factory = psycopg2.extras.RealDictCursor
            return c, "pg"
        except Exception:
            pass
    c = sqlite3.connect(str(_SQLITE_PATH))
    c.row_factory = sqlite3.Row
    return c, "sqlite"


def init_db():
    c, be = _conn()
    try:
        cur = c.cursor()
        cur.execute(_CREATE_TABLE if be == "pg" else _CREATE_TABLE_SQLITE)
        for col_name, col_type in _NEW_COLUMNS:
            try:
                if be == "pg":
                    cur.execute(f"ALTER TABLE smtp_decisions ADD COLUMN IF NOT EXISTS {col_name} {col_type}")
                else:
                    cur.execute(f"ALTER TABLE smtp_decisions ADD COLUMN {col_name} {col_type}")
            except Exception:
                pass
        c.commit()
        print(f"[DB] Gateway audit log ready ({be})")
    finally:
        c.close()


def save_decision(sender, recipients, subject, fraud_score, decision,
                  threat_type, shap_values, features, top_contributors,
                  processing_ms, raw_email=None, source="SMTP",
                  risk_tier="LOW", ml_analysis=None, ml_classification=None,
                  ml_confidence=None, detected_languages=None, explanation=None,
                  ai_generated_prob=0.0, ai_written=False, llama_analysis=None,
                  credential_findings=None, url_findings=None,
                  attachment_findings=None, homograph_findings=None,
                  combined_score=0.0, factor_explanations=None,
                  module_risk_scores=None):
    c, be = _conn()
    try:
        cur = c.cursor()
        recip  = json.dumps(recipients) if isinstance(recipients, list) else str(recipients)
        shap_s = json.dumps(shap_values)
        feat_s = json.dumps(features)
        top_s  = json.dumps(top_contributors or [])
        ml_s   = json.dumps(ml_analysis)   if ml_analysis   else None
        lang_s = json.dumps(detected_languages) if isinstance(detected_languages, list) else detected_languages
        lam_s  = json.dumps(llama_analysis) if llama_analysis else None
        cred_s = json.dumps(credential_findings) if credential_findings else None
        url_s  = json.dumps(url_findings)   if url_findings   else None
        att_s  = json.dumps(attachment_findings) if attachment_findings else None
        hom_s  = json.dumps(homograph_findings)  if homograph_findings  else None
        fe_s   = json.dumps(factor_explanations) if factor_explanations else None
        mrs_s  = json.dumps(module_risk_scores)  if module_risk_scores  else None

        if be == "pg":
            cur.execute("""
                INSERT INTO smtp_decisions
                (sender, recipients, subject, fraud_score, decision, threat_type,
                 risk_tier, shap_values, features, top_contributors, processing_ms,
                 raw_email, source, ml_analysis, ml_classification, ml_confidence,
                 detected_languages, explanation, ai_generated_prob, ai_written,
                 llama_analysis, credential_findings, url_findings,
                 attachment_findings, homograph_findings, combined_score,
                 factor_explanations, module_risk_scores)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING id
            """, (sender, recip, subject, fraud_score, decision, threat_type,
                  risk_tier, shap_s, feat_s, top_s, processing_ms,
                  raw_email, source, ml_s, ml_classification, ml_confidence,
                  lang_s, explanation, ai_generated_prob, ai_written,
                  lam_s, cred_s, url_s, att_s, hom_s, combined_score,
                  fe_s, mrs_s))
            return cur.fetchone()["id"]
        else:
            cur.execute("""
                INSERT INTO smtp_decisions
                (sender, recipients, subject, fraud_score, decision, threat_type,
                 risk_tier, shap_values, features, top_contributors, processing_ms,
                 raw_email, source, ml_analysis, ml_classification, ml_confidence,
                 detected_languages, explanation, ai_generated_prob, ai_written,
                 llama_analysis, credential_findings, url_findings,
                 attachment_findings, homograph_findings, combined_score,
                 factor_explanations, module_risk_scores)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (sender, recip, subject, fraud_score, decision, threat_type,
                  risk_tier, shap_s, feat_s, top_s, processing_ms,
                  raw_email, source, ml_s, ml_classification, ml_confidence,
                  lang_s, explanation, ai_generated_prob, ai_written,
                  lam_s, cred_s, url_s, att_s, hom_s, combined_score,
                  fe_s, mrs_s))
            c.commit()
            return cur.lastrowid
    finally:
        c.commit()
        c.close()


def _row_to_dict(row, json_fields=("shap_values", "features", "top_contributors", "recipients",
                                   "ml_analysis", "detected_languages", "llama_analysis",
                                   "credential_findings", "url_findings",
                                   "attachment_findings", "homograph_findings",
                                   "factor_explanations", "module_risk_scores")):
    d = dict(row)
    for f in json_fields:
        try:
            d[f] = json.loads(d.get(f) or "{}")
        except Exception:
            pass
    # Serialize datetime for JSON
    if "created_at" in d and hasattr(d["created_at"], "isoformat"):
        d["created_at"] = d["created_at"].isoformat()
    return d



def get_decisions(limit=50, decision_filter=None, source_filter=None,
                  risk_tier_filter=None):
    c, be = _conn()
    try:
        cur = c.cursor()
        # Return all columns for rich frontend display
        cols = ("id, created_at, sender, recipients, subject, fraud_score, "
                "decision, threat_type, risk_tier, shap_values, features, top_contributors, "
                "processing_ms, analyst_action, source, "
                "ml_analysis, ml_classification, ml_confidence, detected_languages, "
                "explanation, ai_generated_prob, ai_written, llama_analysis, "
                "credential_findings, url_findings, attachment_findings, "
                "homograph_findings, combined_score, factor_explanations, module_risk_scores")
        ph = "%s" if be == "pg" else "?"
        conditions = []
        params = []
        if decision_filter:
            conditions.append(f"decision = {ph}")
            params.append(decision_filter)
        if source_filter:
            conditions.append(f"source = {ph}")
            params.append(source_filter)
        if risk_tier_filter:
            if isinstance(risk_tier_filter, list):
                placeholders = ",".join([ph] * len(risk_tier_filter))
                conditions.append(f"risk_tier IN ({placeholders})")
                params.extend(risk_tier_filter)
            else:
                conditions.append(f"risk_tier = {ph}")
                params.append(risk_tier_filter)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur.execute(
            f"SELECT {cols} FROM smtp_decisions {where} ORDER BY created_at DESC LIMIT {ph}",
            params,
        )
        return [_row_to_dict(r) for r in cur.fetchall()]
    finally:
        c.close()



def get_decision_by_id(did: int):
    c, be = _conn()
    try:
        cur = c.cursor()
        ph = "%s" if be == "pg" else "?"
        cur.execute(f"SELECT * FROM smtp_decisions WHERE id = {ph}", (did,))
        row = cur.fetchone()
        return _row_to_dict(row) if row else None
    finally:
        c.close()


def get_stats():
    c, be = _conn()
    try:
        cur = c.cursor()
        cur.execute("SELECT COUNT(*) as cnt FROM smtp_decisions")
        total = cur.fetchone()["cnt"] if be == "pg" else cur.fetchone()[0]
        stats = {"total_processed": total}

        for dec in ("ACCEPT", "TAG", "QUARANTINE", "REJECT"):
            ph = "%s" if be == "pg" else "?"
            cur.execute(f"SELECT COUNT(*) as cnt FROM smtp_decisions WHERE decision = {ph}", (dec,))
            r = cur.fetchone()
            stats[dec.lower()] = r["cnt"] if be == "pg" else r[0]

        cur.execute("SELECT AVG(fraud_score) as avg_s FROM smtp_decisions")
        r = cur.fetchone()
        val = r["avg_s"] if be == "pg" else r[0]
        stats["avg_fraud_score"] = round(float(val), 4) if val else 0

        cur.execute("SELECT AVG(processing_ms) as avg_l FROM smtp_decisions")
        r = cur.fetchone()
        val = r["avg_l"] if be == "pg" else r[0]
        stats["avg_latency_ms"] = round(float(val), 1) if val else 0

        # Threat breakdown
        cur.execute(
            "SELECT threat_type, COUNT(*) as cnt FROM smtp_decisions "
            "WHERE threat_type IS NOT NULL AND threat_type != 'CLEAN' AND threat_type != '' "
            "GROUP BY threat_type ORDER BY COUNT(*) DESC"
        )
        if be == "pg":
            stats["threat_breakdown"] = {row["threat_type"]: row["cnt"] for row in cur.fetchall()}
        else:
            stats["threat_breakdown"] = {row[0]: row[1] for row in cur.fetchall()}

        return stats
    finally:
        c.close()


def release_email(did: int):
    c, be = _conn()
    try:
        cur = c.cursor()
        ph = "%s" if be == "pg" else "?"
        cur.execute(f"SELECT sender, recipients, raw_email FROM smtp_decisions WHERE id = {ph}", (did,))
        row = cur.fetchone()
        if not row:
            return None
        cur.execute(
            f"UPDATE smtp_decisions SET analyst_action = 'RELEASED', decision = 'ACCEPT' WHERE id = {ph}",
            (did,),
        )
        c.commit()
        d = dict(row)
        try:
            d["recipients"] = json.loads(d.get("recipients", "[]"))
        except Exception:
            d["recipients"] = []
        return d
    finally:
        c.close()


def confirm_rejection(did: int):
    c, be = _conn()
    try:
        cur = c.cursor()
        ph = "%s" if be == "pg" else "?"
        cur.execute(
            f"UPDATE smtp_decisions SET analyst_action = 'CONFIRMED_REJECT' WHERE id = {ph}",
            (did,),
        )
        c.commit()
    finally:
        c.close()
