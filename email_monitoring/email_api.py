# email_monitoring/email_api.py
# FastAPI server for the Email Monitor service.
# Exposes REST endpoints for the React mailbox frontend.
# Port: 8009

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional, List

import uvicorn
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

# ── Path setup so src/ modules are importable ──────────────────────────────────
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE / "src"))
sys.path.insert(0, str(_HERE))

from email_db import (
    init_db, get_emails, get_email, get_attachment_content,
    update_email_analysis, update_attachment_analysis,
    mark_read, toggle_flag, get_stats,
    save_email_feedback, get_feedback_stats, mark_email_retraining_used,
    save_email,
)
from imap_worker import start_worker

app = FastAPI(title="Email Monitor API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    init_db()
    # start_worker() # Disabled: we now rely completely on direct SMTP proxy pushes
    print("[EmailAPI] Ready — IMAP worker disabled (relying on direct SMTP integration)")


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "email-monitor"}


# ══════════════════════════════════════════════════════════════════════════════
#  Email Threat Analysis — unified 4-module pipeline
# ══════════════════════════════════════════════════════════════════════════════

class EmailThreatRequest(BaseModel):
    from_name:   str        = Field(default="",  description="Sender display name")
    from_email:  str        = Field(default="",  description="Sender email address")
    subject:     str        = Field(default="",  description="Email subject line")
    body:        str        = Field(default="",  description="Plain-text email body")
    attachments: List[str]  = Field(default_factory=list,
                                    description="Attachment filenames or absolute paths")
    urls:        List[str]  = Field(default_factory=list,
                                    description="URLs found in the email")


@app.post("/analyze/email")
def analyze_email_threat(payload: EmailThreatRequest):
    """
    Unified email threat analysis endpoint (legacy / direct-submit path).

    Runs all 4 modules in parallel/sequence:
      1. Phishing Detection     — DistilBERT on subject + body
      2. Voice Deepfake         — best_eer_v2.pt + XGBoost MFCC ensemble
      3. Sensitive Data         — Regex + spaCy NER
      4. URL Security Scanner   — PhishGuard 6-layer pipeline

    Body (JSON):
      {
        "from_name":   "John Smith",
        "from_email":  "john@example.com",
        "subject":     "Urgent: Verify your account",
        "body":        "Dear customer...",
        "attachments": ["/abs/path/to/call.wav", "invoice.pdf"],
        "urls":        ["https://example.com/login"]
      }

    Returns the unified threat analysis JSON as per the FraudShield spec.
    """
    try:
        from email_threat_analyzer import analyze_email
        result = analyze_email(payload.model_dump())
        return JSONResponse(content=result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
#  Full Phishing Analysis — all individual scores for the phishing tab
# ══════════════════════════════════════════════════════════════════════════════

class PhishingAnalysisRequest(BaseModel):
    from_name:   str = Field(default="", description="Sender display name")
    from_email:  str = Field(default="", description="Sender email address")
    reply_to:    str = Field(default="", description="Reply-To header value")
    subject:     str = Field(default="", description="Email subject line")
    raw_headers: str = Field(default="", description="Raw email headers block")
    body:        str = Field(default="", description="Plain-text or HTML email body")


@app.post("/analyze/phishing")
def analyze_phishing_full(payload: PhishingAnalysisRequest):
    """
    Full phishing analysis pipeline — returns all individual risk scores.

    Runs in parallel:
      1. DistilBERT score     — fine-tuned BERT phishing classifier (bert_phishing)
      2. RoBERTa / ML score   — llama3:latest mimicking ML model reasoning
      3. Rule-based check     — 15+ deterministic phishing rules with weights
      4. AI-text probability  — llama3:latest AI-generated content detection
      5. Header analysis      — SPF/DKIM/DMARC + From/Reply-To mismatches
      6. LLM threat analysis  — llama3:latest specific threat extraction
      7. Credential leakage   — regex + NER sensitive data extraction

    Returns all scores + overall composite score.
    """
    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed

    t0      = time.time()
    body    = payload.body
    subject = payload.subject
    sender  = payload.from_email or payload.from_name

    results = {}

    # ── 1. DistilBERT score ─────────────────────────────────────────────────
    def _run_distilbert():
        try:
            from bert_detector import DistilBertEmailDetector
            det  = DistilBertEmailDetector()
            text = f"{subject}\n\n{body}"
            res  = det.predict(text)
            # Parse confidence percentage
            raw_conf = res.get("confidence", "0%")
            if isinstance(raw_conf, str):
                conf_f = float(raw_conf.strip("%"))
            else:
                conf_f = float(raw_conf) * 100 if float(raw_conf) <= 1 else float(raw_conf)
            prob_str = res.get("probabilities", {}).get("phishing", "0%")
            if isinstance(prob_str, str):
                phish_pct = float(prob_str.strip("%"))
            else:
                phish_pct = float(prob_str) * 100 if float(prob_str) <= 1 else float(prob_str)
            return {
                "score":       round(phish_pct, 1),
                "label":       res.get("label", "legitimate"),
                "confidence":  round(conf_f, 1),
                "risk_level":  res.get("risk_level", "LOW RISK 🟢"),
                "note":        res.get("note", ""),
                "model":       res.get("model", "distilbert-finetuned"),
                "available":   True,
            }
        except Exception as exc:
            return {"score": 0, "label": "unknown", "confidence": 0,
                    "risk_level": "UNKNOWN", "note": str(exc),
                    "model": "distilbert-finetuned", "available": False, "error": str(exc)}

    # ── 2. RoBERTa / ML score via llama:latest ──────────────────────────────
    def _run_roberta():
        try:
            from llama_analyzer import get_roberta_score
            return get_roberta_score(body, subject, sender)
        except Exception as exc:
            return {"score": 0, "label": "unknown", "confidence": 0,
                    "key_features": [], "reasoning": "", "model": "llama3:latest",
                    "available": False, "error": str(exc)}

    # ── 3. Rule-based check ─────────────────────────────────────────────────
    def _run_rules():
        try:
            from rule_based_checker import check_email
            return check_email(
                body=body, subject=subject,
                from_email=payload.from_email,
                from_name=payload.from_name,
                reply_to=payload.reply_to,
                headers=payload.raw_headers,
            )
        except Exception as exc:
            return {"score": 0, "triggered_rules": [], "rule_count": 0,
                    "severity": "LOW", "error": str(exc)}

    # ── 4. AI-text probability via llama:latest ──────────────────────────────
    def _run_ai_text():
        try:
            from llama_analyzer import get_ai_text_probability
            return get_ai_text_probability(body)
        except Exception as exc:
            return {"score": 0, "probability": 0.0, "verdict": "unknown",
                    "ai_indicators": [], "model": "llama3:latest",
                    "available": False, "error": str(exc)}

    # ── 5. Header analysis ──────────────────────────────────────────────────
    def _run_header():
        try:
            headers_raw = payload.raw_headers.lower()
            issues      = []
            score       = 0

            # SPF check
            if "spf=pass" in headers_raw:
                spf = "pass"
            elif "spf=fail" in headers_raw or "spf=softfail" in headers_raw:
                spf = "fail"; score += 25; issues.append("SPF authentication failed")
            elif "spf=neutral" in headers_raw:
                spf = "neutral"; score += 10
            else:
                spf = "unknown"; score += 5

            # DKIM check
            if "dkim=pass" in headers_raw:
                dkim = "pass"
            elif "dkim=fail" in headers_raw:
                dkim = "fail"; score += 25; issues.append("DKIM signature invalid")
            else:
                dkim = "unknown"; score += 5

            # DMARC check
            if "dmarc=pass" in headers_raw:
                dmarc = "pass"
            elif "dmarc=fail" in headers_raw:
                dmarc = "fail"; score += 20; issues.append("DMARC policy failed")
            else:
                dmarc = "unknown"; score += 5

            # From / Reply-To mismatch
            from_domain_mismatch = False
            if payload.from_email and payload.reply_to:
                try:
                    fd = payload.from_email.split("@")[-1].lower().strip(">")
                    rd = payload.reply_to.split("@")[-1].lower().strip(">")
                    from_domain_mismatch = (fd != rd)
                    if from_domain_mismatch:
                        score += 20
                        issues.append(f"Reply-To domain ({rd}) differs from From domain ({fd})")
                except Exception:
                    pass

            # Display name vs domain mismatch
            name_domain_mismatch = False
            if payload.from_name and payload.from_email:
                import re as _re
                known = ["paypal","microsoft","apple","amazon","netflix","google","facebook","bank","chase","wells","citi","support","security","helpdesk"]
                name_l  = payload.from_name.lower()
                email_l = payload.from_email.lower()
                for brand in known:
                    if brand in name_l and brand not in email_l:
                        name_domain_mismatch = True
                        score += 15
                        issues.append(f"Display name '{payload.from_name}' impersonates brand not in sender domain")
                        break

            # Suspicious received headers
            if payload.raw_headers:
                import re as _re
                suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq"]
                for tld in suspicious_tlds:
                    if tld in headers_raw:
                        score += 10
                        issues.append(f"Suspicious TLD '{tld}' found in headers")
                        break

            score = min(score, 100)
            return {
                "score":                score,
                "spf":                  spf,
                "dkim":                 dkim,
                "dmarc":                dmarc,
                "from_domain_mismatch": from_domain_mismatch,
                "name_domain_mismatch": name_domain_mismatch,
                "issues":               issues,
            }
        except Exception as exc:
            return {"score": 0, "spf": "unknown", "dkim": "unknown", "dmarc": "unknown",
                    "from_domain_mismatch": False, "name_domain_mismatch": False,
                    "issues": [], "error": str(exc)}

    # ── 6. LLM Threat Analysis via llama:latest ──────────────────────────────
    def _run_threats():
        try:
            from llama_analyzer import get_threat_analysis
            return get_threat_analysis(body, subject, sender)
        except Exception as exc:
            return {"threat_type": "UNKNOWN", "urgency_level": "LOW",
                    "specific_threats": [], "social_engineering_tactics": [],
                    "summary": "", "risk_score": 0, "model": "llama3:latest",
                    "available": False, "error": str(exc)}

    # ── 7. Credential leakage ───────────────────────────────────────────────
    def _run_credentials():
        try:
            from sensitive_data_extractor import extract_sensitive_data
            return extract_sensitive_data(subject=subject, body=body)
        except Exception as exc:
            return {"extracted_emails": [], "extracted_phones": [],
                    "extracted_account_numbers": [], "extracted_names": [],
                    "sensitive_data_found": False, "error": str(exc)}

    # ── Run all modules in parallel ─────────────────────────────────────────
    task_map = {
        "distilbert":    _run_distilbert,
        "roberta_ml":    _run_roberta,
        "rule_based":    _run_rules,
        "ai_text":       _run_ai_text,
        "header":        _run_header,
        "llm_threats":   _run_threats,
        "credentials":   _run_credentials,
    }

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fn): key for key, fn in task_map.items()}
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result(timeout=60)
            except Exception as e:
                results[key] = {"error": str(e)}

    # ── Compute overall score ────────────────────────────────────────────────
    bert_score   = float(results.get("distilbert",  {}).get("score",       0))
    ml_score     = float(results.get("roberta_ml",  {}).get("score",       0))
    rule_score   = float(results.get("rule_based",  {}).get("score",       0))
    ai_score     = float(results.get("ai_text",     {}).get("score",       0))
    header_score = float(results.get("header",      {}).get("score",       0))
    threat_score = float(results.get("llm_threats", {}).get("risk_score",  0))

    # Weighted combination
    overall = (
        bert_score   * 0.30 +
        ml_score     * 0.25 +
        rule_score   * 0.20 +
        header_score * 0.15 +
        ai_score     * 0.05 +
        threat_score * 0.05
    )
    overall = round(min(overall, 100.0), 1)

    # Boost if credentials detected
    cred = results.get("credentials", {})
    if cred.get("sensitive_data_found"):
        overall = min(overall + 10, 100)

    if overall >= 70:
        risk_level     = "HIGH"
        risk_emoji     = "🔴"
        recommendation = "BLOCK"
    elif overall >= 40:
        risk_level     = "MEDIUM"
        risk_emoji     = "🟡"
        recommendation = "REVIEW"
    else:
        risk_level     = "LOW"
        risk_emoji     = "🟢"
        recommendation = "ALLOW"

    processing_ms = round((time.time() - t0) * 1000)

    return JSONResponse(content={
        "overall_score":      overall,
        "risk_level":         risk_level,
        "risk_emoji":         risk_emoji,
        "recommendation":     recommendation,
        "distilbert":         results.get("distilbert",  {}),
        "roberta_ml":         results.get("roberta_ml",  {}),
        "rule_based":         results.get("rule_based",  {}),
        "ai_text":            results.get("ai_text",     {}),
        "header_analysis":    results.get("header",      {}),
        "llm_threat_analysis":results.get("llm_threats", {}),
        "credentials":        results.get("credentials", {}),
        "processing_ms":      processing_ms,
    })


@app.post("/analyze-email")
def analyze_email_full_pipeline(payload: EmailThreatRequest):
    """
    Full pipeline email analysis via pipeline_controller.

    Runs:
      1. Ollama qwen3:8b      — content understanding, entity extraction
      2. URL Analyzer         — PhishGuard 6-layer (WHOIS/SSL/cookie/XGBoost/HTML/encoding)
      3. Attachment Scanner   — rule-based + microservice check
      4. Voice Analyzer       — dual-model deepfake detection
      5. Credential Scanner   — regex + NER sensitive data extraction
      6. FraudShield ML       — RoBERTa + rule-based phishing score
      7. Risk Aggregation     — unified score, flags, recommendation

    Returns STRICT output JSON per the FraudShield spec.
    """
    try:
        sys.path.insert(0, str(_HERE / "src"))
        from pipeline_controller import run_email_pipeline

        # Build attachment list — payload.attachments may be file paths or names
        att_list = []
        for item in payload.attachments:
            att_list.append({
                "filename": Path(item).name if item else "unknown",
                "path":     item if (item and Path(item).exists()) else None,
                "content":  None,
            })

        result = run_email_pipeline(
            sender=payload.from_email or payload.from_name,
            subject=payload.subject,
            body=payload.body,
            attachments=att_list,
            urls=payload.urls or None,
        )
        return JSONResponse(content=result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pipeline failed: {exc}")


# ── Email list ────────────────────────────────────────────────────────────────

@app.get("/emails")
def list_emails(
    limit:        int  = Query(50,  ge=1, le=200),
    offset:       int  = Query(0,   ge=0),
    risk_filter:  str  = Query("ALL"),
    search:       Optional[str] = Query(None),
    unread_only:  bool = Query(False),
    flagged_only: bool = Query(False),
):
    rows, total = get_emails(
        limit=limit, offset=offset,
        risk_filter=risk_filter,
        search=search,
        unread_only=unread_only,
        flagged_only=flagged_only,
    )
    for r in rows:
        if r.get("received_at"):
            r["received_at"] = r["received_at"].isoformat()
    return {"emails": rows, "total": total, "limit": limit, "offset": offset}


@app.get("/stats")
def email_stats():
    return get_stats()


# ── Single email ──────────────────────────────────────────────────────────────

@app.get("/emails/{email_id}")
def get_email_detail(email_id: int):
    row = get_email(email_id)
    if not row:
        raise HTTPException(404, "Email not found")
    mark_read(email_id)
    if row.get("received_at"):
        row["received_at"] = row["received_at"].isoformat()
    # Parse JSONB fields returned as strings
    for field in ("headers", "urls", "analysis", "attachments"):
        if isinstance(row.get(field), str):
            try:
                row[field] = json.loads(row[field])
            except Exception:
                pass
    return row


@app.post("/emails/{email_id}/flag")
def flag_email(email_id: int):
    new_state = toggle_flag(email_id)
    return {"email_id": email_id, "is_flagged": new_state}


# ── Attachment download ────────────────────────────────────────────────────────

@app.get("/emails/{email_id}/attachments/{att_id}/download")
def download_attachment(email_id: int, att_id: int):
    att = get_attachment_content(att_id)
    if not att or att.get("email_id") != email_id:
        raise HTTPException(404, "Attachment not found")
    content = bytes(att["content"]) if att["content"] else b""
    return Response(
        content=content,
        media_type=att.get("content_type", "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="{att["filename"]}"'},
    )


# ── Full email security analysis ──────────────────────────────────────────────

@app.post("/emails/{email_id}/analyze/full")
def analyze_email_full_pipeline(email_id: int):
    """
    🔥 Full 7-layer analysis pipeline — mirrors Streamlit app.py exactly.

    Pipeline:
      1. Attachment extraction + Voice deepfake scan
      2. Rule-based fraud check
      3. Metadata extraction (URLs & Credentials)
      4. LLM deep analysis (Ollama qwen3:8b)
      5. AI-generated content detection
      6. ML score fusion (RoBERTa → DistilBERT → heuristic)
      7. n8n incident webhook (HIGH/CRITICAL only)

    Returns unified JSON with: fused_score_details, unified_score,
    fraud_analysis (llm_based), ai_detection, credential_scan,
    n8n_incident, routing.
    """
    row = get_email(email_id)
    if not row:
        raise HTTPException(404, "Email not found")

    # Parse JSONB fields
    for field in ("headers", "urls", "analysis", "attachments"):
        if isinstance(row.get(field), str):
            try:
                row[field] = json.loads(row[field])
            except Exception:
                pass

    # Build a minimal email.message object from row fields so
    # attachment_analyzer.analyze_email() can use it
    import email as _email_lib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    msg = MIMEMultipart()
    msg['From']     = row.get("sender", "")
    msg['To']       = row.get("receiver", "")
    msg['Subject']  = row.get("subject", "")
    if row.get("reply_to"):
        msg['Reply-To'] = row["reply_to"]
    msg.attach(MIMEText(row.get("body_text", "") or "", 'plain'))
    if row.get("body_html"):
        msg.attach(MIMEText(row["body_html"], 'html'))

    # Add attachment bytes from DB if available
    atts_db = row.get("attachments") or []
    for att_meta in atts_db:
        att_content = get_attachment_content(att_meta.get("id", -1))
        if att_content and att_content.get("content"):
            from email.mime.base import MIMEBase
            from email import encoders as _encoders
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(bytes(att_content["content"]))
            _encoders.encode_base64(part)
            part.add_header('Content-Disposition',
                            f'attachment; filename="{att_meta.get("filename","file")}"')
            msg.attach(part)

    try:
        # Run the full Streamlit pipeline
        src_dir = str(_HERE / "src")
        if src_dir not in sys.path:
            sys.path.insert(0, src_dir)

        from attachment_analyzer import analyze_email as _full_analyze
        result = _full_analyze(
            email_message=msg,
            sender=row.get("sender", ""),
            subject=row.get("subject", ""),
            body=row.get("body_text", ""),
        )

        # Persist the unified score back to DB for caching
        unified = result.get("unified_score", {})
        update_email_analysis(
            email_id,
            result,
            unified.get("final_score", 0),
            unified.get("tier", "UNKNOWN"),
        )

        mark_read(email_id)
        return JSONResponse(content=result)

    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Full pipeline failed: {exc}")


@app.post("/emails/{email_id}/analyze")
def analyze_email_endpoint(email_id: int, background_tasks: BackgroundTasks):
    row = get_email(email_id)
    if not row:
        raise HTTPException(404, "Email not found")

    for field in ("headers", "urls", "analysis"):
        if isinstance(row.get(field), str):
            try:
                row[field] = json.loads(row[field])
            except Exception:
                pass

    # Return cached if available
    if row.get("analysis") and row["analysis"].get("phishing"):
        return row["analysis"]

    # Run analysis synchronously (results cached after)
    result = _run_full_analysis(row)
    update_email_analysis(email_id, result,
                          result.get("overall_risk_score", 0),
                          result.get("overall_risk_tier", "UNKNOWN"))
    return result


def _run_full_analysis(row: dict) -> dict:
    """Run all analysis modules and return combined result dict.

    NOTE: Ollama-heavy modules (AI-text detection, LLM threat analysis) are
    intentionally omitted here — the frontend populates those panels from the
    faster /analyze/phishing endpoint (phishingScores state) to avoid queueing
    multiple sequential Ollama calls that would exceed the nginx proxy timeout.
    This endpoint focuses on: ML phishing score, credential scan, URL scan,
    rule-based checks, and voice analysis.
    """
    t0 = time.time()

    subject  = row.get("subject", "") or ""
    sender   = row.get("sender", "") or ""
    receiver = row.get("receiver", "") or ""
    reply_to = row.get("reply_to", "") or ""
    body     = row.get("body_text", "") or ""
    headers  = row.get("headers", {}) or {}
    urls     = row.get("urls", []) or []

    spf_pass  = _check_spf(headers)
    dkim_pass = _check_dkim(headers)

    result = {
        "email_id":     row.get("id"),
        "subject":      subject,
        "analyzed_at":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # ── 1. Phishing / ML Score ────────────────────────────────────────────────
    try:
        from fraudshield_scorer import score_email
        ph = score_email(
            email_text=body, subject=subject, sender=sender,
            receiver=receiver, reply_to=reply_to,
            spf_pass=spf_pass, dkim_pass=dkim_pass,
        )
        result["phishing"] = ph
    except Exception as e:
        result["phishing"] = {
            "risk_score": 0, "verdict": "UNKNOWN", "tier": "LOW",
            "top_indicators": [], "error": str(e)
        }

    # ── 2. Credential scanner ─────────────────────────────────────────────────
    try:
        _add_cred_scanner_path()
        cred_mod = _get_cred_mod()
        if cred_mod:
            cred = cred_mod.full_scan(f"{subject}\n\n{body}", "email", sender)
        else:
            cred = _fallback_cred_scan(body)
        result["credentials"] = cred
    except Exception as e:
        result["credentials"] = {"total_findings": 0, "findings": [], "error": str(e)}

    # ── 3. URL / web-spoofing scan ────────────────────────────────────────────
    url_results = []
    if urls:
        try:
            from url_scanner import fast_scan
            for url in urls[:10]:
                try:
                    res = fast_scan(url)
                    url_results.append(res)
                except Exception as url_err:
                    import logging
                    logging.warning(f"URL scan failed for {url}: {url_err}")
                    url_results.append({"url": url, "verdict": "ERROR", "risk_score_pct": 0,
                                        "risk_reasons": [str(url_err)]})
        except Exception as e:
            url_results = [{"url": u, "verdict": "SKIPPED", "error": str(e)} for u in urls[:10]]
    result["url_scan"] = url_results

    # ── 4. Rule-based check ───────────────────────────────────────────────────
    try:
        from attachment_analyzer import rule_based_fraud_check
        rule = rule_based_fraud_check(body, sender)
        result["rule_check"] = rule
    except Exception as e:
        result["rule_check"] = {"is_suspicious": False, "score": 0, "reasons": []}

    # ── 5. Voice deepfake detection (audio attachments) ───────────────────────
    try:
        from email_db import get_email as _get_email_row
        email_row = _get_email_row(row.get("id", 0)) or {}
        raw_atts = email_row.get("attachments") or []
        if isinstance(raw_atts, str):
            try:
                import json as _json
                raw_atts = _json.loads(raw_atts)
            except Exception:
                raw_atts = []

        from voice_analyzer import analyze_voice_attachments, AUDIO_EXTENSIONS
        from pathlib import Path as _Path

        voice_att_list = []
        for att in (raw_atts if isinstance(raw_atts, list) else []):
            fname = att.get("filename", "")
            ext   = _Path(fname).suffix.lower()
            if ext in AUDIO_EXTENSIONS:
                try:
                    from email_db import get_attachment_content
                    att_data = get_attachment_content(att.get("id", -1))
                    content  = bytes(att_data["content"]) if att_data and att_data.get("content") else None
                except Exception:
                    content = None
                voice_att_list.append({"filename": fname, "content": content, "path": None})

        voice_results = analyze_voice_attachments(voice_att_list) if voice_att_list else []
        result["voice_analysis"] = {
            "total_audio_files": len(voice_results),
            "scanned":     sum(1 for v in voice_results if "SKIPPED" not in str(v.get("verdict", ""))),
            "skipped":     sum(1 for v in voice_results if "SKIPPED" in str(v.get("verdict", ""))),
            "flagged_as_fake": sum(1 for v in voice_results if "FAKE" in str(v.get("verdict", "")).upper()),
            "results":     voice_results,
        }
    except Exception as e:
        result["voice_analysis"] = {
            "total_audio_files": 0, "scanned": 0, "skipped": 0,
            "flagged_as_fake": 0, "results": [], "error": str(e),
        }

    # ── Overall risk aggregation ──────────────────────────────────────────────
    ph_score   = result["phishing"].get("risk_score", 0)
    url_max    = max((u.get("risk_score_pct", u.get("risk_score", 0) * 100) for u in url_results), default=0)
    cred_hits  = result["credentials"].get("total_findings", 0)
    voice_max  = max((v.get("risk_score", 0) for v in result["voice_analysis"].get("results", [])), default=0)

    overall = int(
        ph_score  * 0.40 +
        url_max   * 0.35 +
        min(cred_hits * 10, 100) * 0.15 +
        voice_max * 0.10
    )
    overall = max(overall, int(ph_score * 0.5))
    if cred_hits > 0:
        overall = max(overall, 50 + min(cred_hits * 5, 30))
    overall = min(overall, 100)

    tier = _score_to_tier(overall)
    result["overall_risk_score"] = overall
    result["overall_risk_tier"]  = tier
    result["processing_ms"]      = round((time.time() - t0) * 1000)

    return result


# ── Attachment analysis ────────────────────────────────────────────────────────

@app.post("/emails/{email_id}/attachments/{att_id}/analyze")
def analyze_attachment_endpoint(email_id: int, att_id: int, scan_type: str = "static"):
    att = get_attachment_content(att_id)
    if not att or att.get("email_id") != email_id:
        raise HTTPException(404, "Attachment not found")

    # Return cached
    if isinstance(att.get("analysis"), str):
        try:
            att["analysis"] = json.loads(att["analysis"])
        except Exception:
            pass

    if att.get("analysis") and att["analysis"].get(scan_type):
        return att["analysis"][scan_type]

    content = bytes(att["content"]) if att["content"] else b""
    filename = att.get("filename", "attachment")

    if scan_type == "static":
        res = _run_static_attachment_scan(content, filename)
    else:
        res = _run_deep_attachment_scan(content, filename, att_id)

    # Merge into existing analysis cache
    existing = att.get("analysis") or {}
    existing[scan_type] = res
    update_attachment_analysis(att_id, existing)

    return res


def _run_static_attachment_scan(content: bytes, filename: str) -> dict:
    """Reuse attachment_scanner's 4-phase analysis pipeline."""
    try:
        # Call the attachment scanner service via HTTP (already running at :8007)
        import requests
        files = {"file": (filename, content, "application/octet-stream")}
        resp = requests.post(
            "http://attachment-scanner:8007/analyze",
            files=files,
            timeout=30
        )
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"Scanner returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e), "filename": filename}


def _run_deep_attachment_scan(content: bytes, filename: str, att_id: int) -> dict:
    """Deep content analysis: extract text and run full pipeline.
    For audio files: calls the voice-scanner container API.
    For documents: extracts text and runs llama3:latest phishing analysis.
    """
    t0 = time.time()
    result = {"filename": filename, "scan_type": "deep"}

    ext = Path(filename).suffix.lower()

    # ── Audio files: call voice-scanner API ────────────────────────────────
    AUDIO_EXTS = {".wav", ".mp3", ".mp4", ".m4a", ".flac", ".ogg", ".aac", ".wma", ".opus"}
    if ext in AUDIO_EXTS:
        try:
            import requests as _req
            files = {"file": (filename, content, "application/octet-stream")}
            resp = _req.post(
                "http://voice-scanner:8008/analyze",
                files=files,
                timeout=120,
            )
            if resp.status_code == 200:
                voice_data = resp.json()
                result["voice_analysis"] = voice_data
                result["risk_score"] = voice_data.get("risk_score", 0)
                result["risk_tier"] = _score_to_tier(result["risk_score"])
                result["processing_ms"] = round((time.time() - t0) * 1000)
                return result
            else:
                result["voice_analysis"] = {"error": f"Voice scanner returned {resp.status_code}"}
        except Exception as exc:
            result["voice_analysis"] = {"error": f"Voice scanner unavailable: {exc}"}
        result["risk_score"] = 0
        result["risk_tier"] = "UNKNOWN"
        result["processing_ms"] = round((time.time() - t0) * 1000)
        return result

    extracted_text = _extract_text_from_bytes(content, filename)

    if not extracted_text:
        return {"filename": filename, "scan_type": "deep",
                "error": "Could not extract text content", "processing_ms": 0}

    # Phishing/fraud check on extracted text
    try:
        from attachment_analyzer import rule_based_fraud_check
        rule = rule_based_fraud_check(extracted_text)
        result["fraud_check"] = rule
    except Exception:
        result["fraud_check"] = {}

    # Credential scan
    try:
        _add_cred_scanner_path()
        cred_mod = _get_cred_mod()
        if cred_mod:
            cred = cred_mod.full_scan(extracted_text, "attachment", filename)
            result["credentials"] = cred
    except Exception:
        pass

    # URL extraction + scan
    url_re = __import__("re").compile(r'https?://[^\s<>"\'()\[\]{}|\\^`]*', __import__("re").IGNORECASE)
    urls = list(dict.fromkeys(url_re.findall(extracted_text)))
    result["urls_found"] = urls[:20]

    url_results = []
    if urls:
        try:
            from url_scanner import fast_scan
            for url in urls[:5]:
                try:
                    url_results.append(fast_scan(url))
                except Exception:
                    pass
        except Exception:
            pass
    result["url_scan"] = url_results

    # AI text detection
    try:
        from ai_text_detector import detect_ai_text
        result["ai_detection"] = detect_ai_text(extracted_text[:2000])
    except Exception:
        result["ai_detection"] = _fallback_ai_detect(extracted_text)

    # ── LLM Deep Content Analysis via llama3:latest ─────────────────────────────
    # For PDF, Word, and text files: pass content to llama for full security analysis
    DEEP_ANALYSIS_EXTS = {".pdf", ".doc", ".docx", ".txt", ".csv", ".log", ".rtf", ".odt"}
    if ext in DEEP_ANALYSIS_EXTS and extracted_text.strip():
        try:
            sys.path.insert(0, str(_HERE / "src"))
            from llama_analyzer import analyze_content_for_phishing
            llama_result = analyze_content_for_phishing(
                content=extracted_text[:4000],
                filename=filename,
            )
            result["llm_analysis"] = llama_result
        except Exception as exc:
            result["llm_analysis"] = {
                "phishing_score": 0,
                "verdict": "UNKNOWN",
                "credentials_found": [],
                "links_found": [],
                "sensitive_data": [],
                "threats_detected": [],
                "summary": f"LLM analysis unavailable: {exc}",
                "model": "llama3:latest",
                "available": False,
                "error": str(exc),
            }

    # Score — incorporate llm_analysis if available
    rule_score = result.get("fraud_check", {}).get("score", 0)
    url_max = max((u.get("risk_score_pct", 0) for u in url_results), default=0)
    cred_hits = result.get("credentials", {}).get("total_findings", 0)
    llm_score = result.get("llm_analysis", {}).get("phishing_score", 0)

    overall = max(rule_score, int(url_max * 0.6), llm_score)
    if cred_hits > 0:
        overall = max(overall, 50 + min(cred_hits * 5, 40))
    result["risk_score"] = min(overall, 100)
    result["risk_tier"] = _score_to_tier(overall)
    result["processing_ms"] = round((time.time() - t0) * 1000)

    return result


# ── Feedback & Retraining Endpoints ──────────────────────────────────────────

from pydantic import BaseModel

class EmailFeedbackBody(BaseModel):
    model_verdict:   str
    correct_verdict: str
    module:          str  = "phishing"
    reviewer_id:     str  = "user"
    notes:           str  = ""


@app.post("/emails/{email_id}/feedback")
def submit_email_feedback(email_id: int, body: EmailFeedbackBody):
    """Submit analyst feedback on an email analysis result."""
    row = get_email(email_id)
    subject = row.get("subject", "") if row else ""
    result = save_email_feedback(
        email_id=email_id,
        model_verdict=body.model_verdict,
        correct_verdict=body.correct_verdict,
        module=body.module,
        reviewer_id=body.reviewer_id,
        notes=body.notes,
        subject=subject,
    )
    return result


@app.get("/feedback/stats")
def email_feedback_stats():
    """Return aggregate email feedback statistics."""
    return get_feedback_stats()


@app.post("/admin/retrain")
def trigger_email_retraining():
    """Admin: trigger retraining on queued email model corrections."""
    stats = get_feedback_stats()
    queue_size = stats.get("retraining_queue_size", 0)

    if queue_size == 0:
        return {"status": "skipped", "reason": "No new corrections in queue", "queue_size": 0}

    mark_email_retraining_used()

    retrain_log = []
    status = "queued"
    try:
        from src.train_bert import retrain_from_feedback
        retrain_log = retrain_from_feedback()
        status = "started"
    except Exception as e:
        retrain_log = [
            f"Retraining queued — {queue_size} email correction(s) saved.",
            f"Run train_bert.py to apply. ({e})",
        ]
        status = "queued"

    return {
        "status": status,
        "queue_size": queue_size,
        "log": retrain_log,
        "message": f"Email model retraining initiated on {queue_size} correction(s).",
    }


@app.get("/admin/retrain/status")
def email_retrain_status():
    """Return email retraining queue status."""
    stats = get_feedback_stats()
    return {
        "queue_size":     stats.get("retraining_queue_size", 0),
        "total_scans":    stats.get("total_scans", 0),
        "total_feedback": stats.get("total_feedback", 0),
        "accuracy":       stats.get("accuracy"),
        "false_positives": stats.get("false_positives", 0),
        "false_negatives": stats.get("false_negatives", 0),
    }


# ── Utility helpers ───────────────────────────────────────────────────────────

def _score_to_tier(score: int) -> str:
    if score >= 90: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


def _check_spf(headers: dict) -> Optional[bool]:
    for key in ("Authentication-Results", "Received-SPF"):
        val = headers.get(key, "").lower()
        if "spf=pass" in val:
            return True
        if "spf=fail" in val or "spf=softfail" in val:
            return False
    return None


def _check_dkim(headers: dict) -> Optional[bool]:
    val = headers.get("Authentication-Results", "").lower()
    if "dkim=pass" in val:
        return True
    if "dkim=fail" in val:
        return False
    return None


def _fallback_ai_detect(text: str) -> dict:
    import re
    ai_pattern_labels = [
        (r"\bcertainly\b",                       "formal filler: 'certainly'"),
        (r"\bof course\b",                        "formal filler: 'of course'"),
        (r"\bplease do not hesitate\b",           "AI boilerplate: 'please do not hesitate'"),
        (r"\bshould you (have|need|require)\b",   "AI boilerplate: 'should you need/have'"),
        (r"\bfeel free to\b",                     "AI boilerplate: 'feel free to'"),
        (r"\bi hope this (email|message|finds)\b","AI opener: 'I hope this email...'"),
        (r"\babsolutely\b",                        "over-formal: 'absolutely'"),
        (r"\bkindly\b",                            "over-formal: 'kindly'"),
        (r"\brest assured\b",                      "AI filler: 'rest assured'"),
        (r"\bwe regret to inform\b",               "template phrase: 'we regret to inform'"),
    ]
    matched = [label for pattern, label in ai_pattern_labels
               if re.search(pattern, text, re.IGNORECASE)]
    prob = min(0.9, len(matched) * 0.15)
    return {
        "ai_generated_probability": prob,
        "is_ai_generated": prob >= 0.5,
        "method": "heuristic",
        "model": "heuristic-fallback",
        "indicators": matched,
    }


_cred_mod = None

def _add_cred_scanner_path():
    cs_dir = str(_HERE.parent / "Credential_Scanner-main")
    if cs_dir not in sys.path:
        sys.path.insert(0, cs_dir)

def _get_cred_mod():
    global _cred_mod
    if _cred_mod is not None:
        return _cred_mod
    try:
        import importlib.util
        cs_path = _HERE.parent / "Credential_Scanner-main" / "main.py"
        spec = importlib.util.spec_from_file_location("_cred_scanner", str(cs_path))
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _cred_mod = mod
        return mod
    except Exception:
        return None


def _fallback_cred_scan(text: str) -> dict:
    import re
    findings = []
    patterns = {
        "EMAIL":       r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        "CREDIT_CARD": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        "SORT_CODE":   r'\b\d{2}-\d{2}-\d{2}\b',
        "API_KEY":     r'\b[A-Za-z0-9]{32,44}\b',
    }
    for kind, pat in patterns.items():
        for match in re.findall(pat, text):
            findings.append({"type": kind, "value": match, "severity": "medium"})
    total = len(findings)
    risk  = min(total * 10, 100)
    if risk >= 70:
        label = "High"
    elif risk >= 30:
        label = "Medium"
    elif total > 0:
        label = "Low"
    else:
        label = "Clean"
    return {"total_findings": total, "findings": findings[:20],
            "risk_score": risk, "risk_label": label}


def _extract_text_from_bytes(content: bytes, filename: str) -> str:
    ext = Path(filename).suffix.lower()
    try:
        if ext == ".pdf":
            import fitz
            doc = fitz.open(stream=content, filetype="pdf")
            return "\n".join(page.get_text() for page in doc)
        elif ext in (".doc", ".docx"):
            from docx import Document
            import io
            doc = Document(io.BytesIO(content))
            return "\n".join(p.text for p in doc.paragraphs)
        elif ext in (".txt", ".csv", ".log", ".py", ".js", ".html", ".xml", ".json"):
            return content.decode("utf-8", errors="replace")
        else:
            return content.decode("utf-8", errors="replace")
    except Exception:
        return ""


# ══════════════════════════════════════════════════════════════════════════════
#  SMTP Gateway Ingest — receives intercepted emails from smtp-fraud-gateway
# ══════════════════════════════════════════════════════════════════════════════

class SmtpIngestRequest(BaseModel):
    message_id:    str = Field(default="", description="Email Message-ID header")
    sender:        str = Field(default="", description="Envelope sender")
    recipients:    List[str] = Field(default_factory=list)
    subject:       str = Field(default="", description="Subject line")
    reply_to:      str = Field(default="", description="Reply-To header")
    body_text:     str = Field(default="", description="Plain-text body")
    body_html:     str = Field(default="", description="HTML body")
    raw_headers:   str = Field(default="", description="Raw email headers")
    date_str:      str = Field(default="", description="Date header string")
    urls:          List[str] = Field(default_factory=list)
    from_name:     str = Field(default="", description="Sender display name")
    gateway_score: float = Field(default=0, description="Pre-computed XGBoost score from SMTP gateway (0-100)")
    gateway_tier:  str = Field(default="", description="Pre-computed risk tier from SMTP gateway")
    decision:      str = Field(default="", description="SMTP gateway decision (BLOCK/FLAG/ALLOW)")


def _run_background_analysis(email_id: int, payload_dict: dict):
    """Background task: run full 7-module analysis and update the email in DB."""
    try:
        phishing_req = PhishingAnalysisRequest(
            from_name=payload_dict.get("from_name", ""),
            from_email=payload_dict.get("sender", ""),
            reply_to=payload_dict.get("reply_to", ""),
            subject=payload_dict.get("subject", ""),
            raw_headers=payload_dict.get("raw_headers", ""),
            body=payload_dict.get("body_text") or payload_dict.get("body_html") or "",
        )
        analysis_response = analyze_phishing_full(phishing_req)
        analysis = json.loads(analysis_response.body.decode("utf-8"))

        overall_score = float(analysis.get("overall_score", 0))
        risk_tier = _score_to_tier(int(round(overall_score)))

        update_email_analysis(
            email_id=email_id,
            analysis=analysis,
            risk_score=int(round(overall_score)),
            risk_tier=risk_tier,
        )
        print(f"[SMTP-Ingest] Background analysis done for email {email_id}: score={overall_score}, tier={risk_tier}")
    except Exception as e:
        print(f"[SMTP-Ingest] Background analysis failed for email {email_id}: {e}")
        # Still update with error info so the email doesn't stay UNKNOWN forever
        update_email_analysis(
            email_id=email_id,
            analysis={"error": str(e), "source": "SMTP_GATEWAY"},
            risk_score=payload_dict.get("gateway_score", 0),
            risk_tier=payload_dict.get("gateway_tier", "UNKNOWN"),
        )


@app.post("/ingest/smtp")
def ingest_smtp_email(payload: SmtpIngestRequest, background_tasks: BackgroundTasks):
    """
    Ingest an email intercepted by the SMTP Fraud Gateway.

    1. Saves the email to email_inbox (PostgreSQL) immediately
    2. Applies the gateway's XGBoost score as an initial risk_score
    3. Kicks off full 7-module analysis in the background
    4. Returns instantly so the SMTP handler isn't blocked

    The SMTP gateway uses its own local XGBoost model for the instant
    BLOCK/ALLOW decision. The full analysis updates the DB later, and
    the Mailbox UI picks it up on next refresh.
    """
    import uuid
    t0 = time.time()

    msg_id = payload.message_id or f"<smtp-gw-{uuid.uuid4().hex[:12]}@aegisai>"

    # Determine initial tier from gateway_score (provided by SMTP handler)
    gw_score = getattr(payload, "gateway_score", 0) or 0
    gw_tier = getattr(payload, "gateway_tier", "") or ""
    if not gw_tier:
        gw_tier = _score_to_tier(int(round(gw_score)))

    # ── Step 1: Save email to DB immediately ────────────────────────────────
    email_data = {
        "message_id":       msg_id,
        "subject":          payload.subject,
        "sender":           payload.sender,
        "receiver":         ", ".join(payload.recipients) if payload.recipients else "",
        "reply_to":         payload.reply_to,
        "date_str":         payload.date_str,
        "headers":          {"raw": payload.raw_headers[:5000]} if payload.raw_headers else {},
        "body_text":        payload.body_text,
        "body_html":        payload.body_html,
        "urls":             payload.urls,
        "has_attachments":  False,
        "attachment_count": 0,
    }

    saved = save_email(email_data)
    email_id = saved["id"] if saved else None

    # ── Step 2: Set initial score from gateway (fast) ───────────────────────
    if email_id and gw_score > 0:
        update_email_analysis(
            email_id=email_id,
            analysis={"source": "SMTP_GATEWAY", "gateway_score": gw_score, "status": "analyzing"},
            risk_score=int(round(gw_score)),
            risk_tier=gw_tier,
        )

    # ── Step 3: Kick off full analysis in background ────────────────────────
    if email_id:
        payload_dict = {
            "from_name":    payload.from_name,
            "sender":       payload.sender,
            "reply_to":     payload.reply_to,
            "subject":      payload.subject,
            "raw_headers":  payload.raw_headers,
            "body_text":    payload.body_text,
            "body_html":    payload.body_html,
            "gateway_score": gw_score,
            "gateway_tier":  gw_tier,
        }
        background_tasks.add_task(_run_background_analysis, email_id, payload_dict)

    processing_ms = round((time.time() - t0) * 1000)

    return JSONResponse(content={
        "email_id":      email_id,
        "overall_score": gw_score,
        "risk_tier":     gw_tier,
        "decision":      "BLOCK" if gw_score >= 90 else ("FLAG" if gw_score >= 70 else ("REVIEW" if gw_score >= 40 else "ALLOW")),
        "processing_ms": processing_ms,
        "status":        "saved_analyzing",
        "source":        "SMTP_GATEWAY",
    })


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("email_api:app", host="0.0.0.0", port=8009, reload=False)
