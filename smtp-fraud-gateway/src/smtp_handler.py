"""
aiosmtpd SMTP handler — intercepts every inbound email at port 2525.

Full analysis pipeline per email:
  1. Parse MIME message
  2. XGBoost local scoring  (~15 ms)
  3. URL reputation scoring (~1 ms)
  4. Multilingual + advanced threat analysis (~50-300 ms)
     - Homograph/IDN attack detection
     - Credential exposure scanning (15+ patterns + Shannon entropy)
     - Suspicious domain/URL analysis (brand impersonation, TLD abuse)
     - Language-based phishing detection
     - Statistical AI content detection (burstiness, uniformity)
     - Attachment risk analysis (extension tiers, dangerous context)
     - BEC / 419-scam pattern matching
  5. Compute combined risk score from all signals
  6. Determine SMTP decision (REJECT / QUARANTINE / TAG / ACCEPT) and risk_tier
  7. Return SMTP response to sender
  8. Background thread:
       a. Write to shared PostgreSQL email_inbox with full analysis
       b. Scan MIME attachments via attachment-scanner service
       c. Run Llama 3 deep content analysis + AI detection + explanation
       d. Update email_inbox with Llama 3 results
       e. Save to smtp_decisions audit table with ALL analysis data
"""
import email as email_lib
import email.utils
import json
import os
import re
import time
import threading
import uuid
from email.policy import default as default_policy

try:
    import psycopg2
    import psycopg2.extras
    _PG_OK = True
except ImportError:
    _PG_OK = False

from features import extract_features
from scorer import score_email
from url_reputation import score_urls
from db import save_decision
from forwarder import forward_to_downstream

# ── Configuration ─────────────────────────────────────────────────────────────
BLOCK_THRESHOLD  = float(os.getenv("REJECT_THRESHOLD",    "0.70"))
HIGH_THRESHOLD   = float(os.getenv("QUARANTINE_THRESHOLD","0.40"))
MEDIUM_THRESHOLD = float(os.getenv("TAG_THRESHOLD",       "0.20"))

DATABASE_URL           = os.getenv("DATABASE_URL",           "postgresql://dlp:dlp@postgres:5432/dlp")
EMAIL_MONITOR_URL      = os.getenv("EMAIL_MONITOR_URL",      "http://email-monitor:8009")
ATTACHMENT_SCANNER_URL = os.getenv("ATTACHMENT_SCANNER_URL", "http://attachment-scanner:8007")

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


# ── JSON helpers ───────────────────────────────────────────────────────────────

def _safe_json(obj):
    return json.loads(json.dumps(
        obj, default=lambda x: float(x) if hasattr(x, '__float__') else str(x)
    ))


# ── Combined score calculation ─────────────────────────────────────────────────

def _compute_combined_score(xgb_score_0_100: float, url_boost: float,
                             ml_analysis: dict) -> float:
    """
    Merge XGBoost + URL reputation + multilingual analysis into one 0-100 score.
    Uses weighted contribution from each analysis module.
    """
    base = xgb_score_0_100 + url_boost   # existing pipeline score (0-99)

    rs = ml_analysis.get("risk_scores", {}) if ml_analysis else {}

    # Each ML signal adds a capped boost
    boosts = 0.0
    boosts += rs.get("homograph",           0.0) * 40   # homograph → up to +40
    boosts += rs.get("credential_exposure", 0.0) * 30   # cred leak  → up to +30
    boosts += rs.get("url_suspicion",       0.0) * 20   # susp URL   → up to +20
    boosts += rs.get("attachment",          0.0) * 35   # attachment → up to +35
    boosts += rs.get("bec",                 0.0) * 30   # BEC wire   → up to +30
    boosts += rs.get("scam_419",            0.0) * 25   # scam 419   → up to +25
    boosts += rs.get("language_phishing",   0.0) * 15   # lang phish → up to +15
    boosts += rs.get("ai_generated",        0.0) * 10   # AI content → up to +10

    # Cap boosts at 60 so the ML side doesn't overwhelm XGBoost
    boosts = min(boosts, 60.0)

    combined = base + boosts
    return round(min(combined, 99.0), 1)


def _score_to_tier(score_0_100: float) -> str:
    """Map 0-100 score to risk tier."""
    if score_0_100 >= 90:
        return "CRITICAL"
    if score_0_100 >= 70:
        return "HIGH"
    if score_0_100 >= 40:
        return "MEDIUM"
    return "LOW"


def _tier_to_decision(tier: str) -> str:
    return {
        "CRITICAL": "REJECT",
        "HIGH":     "QUARANTINE",
        "MEDIUM":   "TAG",
        "LOW":      "ACCEPT",
    }.get(tier, "ACCEPT")


# ── PostgreSQL helpers ─────────────────────────────────────────────────────────

def _pg_save_email(data: dict, risk_score: int, risk_tier: str,
                   analysis: dict) -> "int | None":
    if not _PG_OK:
        return None
    try:
        analysis_json = json.dumps(_safe_json(analysis))
        conn = psycopg2.connect(DATABASE_URL)
        conn.cursor_factory = psycopg2.extras.RealDictCursor
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO email_inbox
                        (message_id, subject, sender, receiver, reply_to, date_str,
                         headers, body_text, body_html, urls,
                         has_attachments, attachment_count,
                         risk_score, risk_tier, analysis, is_flagged)
                    VALUES
                        (%(message_id)s, %(subject)s, %(sender)s, %(receiver)s,
                         %(reply_to)s, %(date_str)s,
                         %(headers)s::jsonb, %(body_text)s, %(body_html)s,
                         %(urls)s::jsonb, %(has_attachments)s, %(attachment_count)s,
                         %(risk_score)s, %(risk_tier)s, %(analysis)s::jsonb,
                         %(is_flagged)s)
                    ON CONFLICT (message_id) DO UPDATE
                        SET risk_score = EXCLUDED.risk_score,
                            risk_tier  = EXCLUDED.risk_tier,
                            analysis   = EXCLUDED.analysis
                    RETURNING id
                """, {
                    "message_id":       data.get("message_id", ""),
                    "subject":          data.get("subject", "(no subject)"),
                    "sender":           data.get("sender", ""),
                    "receiver":         data.get("receiver", ""),
                    "reply_to":         data.get("reply_to", ""),
                    "date_str":         data.get("date_str", ""),
                    "headers":          json.dumps(data.get("headers", {})),
                    "body_text":        data.get("body_text", ""),
                    "body_html":        data.get("body_html", ""),
                    "urls":             json.dumps(data.get("urls", [])),
                    "has_attachments":  data.get("has_attachments", False),
                    "attachment_count": data.get("attachment_count", 0),
                    "risk_score":       risk_score,
                    "risk_tier":        risk_tier,
                    "analysis":         analysis_json,
                    "is_flagged":       risk_tier in ("HIGH", "CRITICAL"),
                })
                row = cur.fetchone()
        conn.close()
        return row["id"] if row else None
    except Exception as e:
        print(f"[Gateway] DB save error: {e}", flush=True)
        return None


def _pg_update_email_analysis(email_id: int, message_id: str,
                               updated_analysis: dict, new_risk_score: int = None,
                               new_risk_tier: str = None):
    """Merge additional analysis results into an existing email_inbox row."""
    if not _PG_OK:
        return
    try:
        payload = json.dumps(_safe_json(updated_analysis))
        conn = psycopg2.connect(DATABASE_URL)
        with conn:
            with conn.cursor() as cur:
                if new_risk_score is not None and new_risk_tier:
                    cur.execute("""
                        UPDATE email_inbox
                        SET analysis   = analysis || %(aj)s::jsonb,
                            risk_score = %(rs)s,
                            risk_tier  = %(rt)s,
                            is_flagged = %(fl)s
                        WHERE id = %(eid)s OR message_id = %(mid)s
                    """, {"aj": payload, "rs": new_risk_score,
                          "rt": new_risk_tier, "fl": new_risk_tier in ("HIGH", "CRITICAL"),
                          "eid": email_id, "mid": message_id})
                else:
                    cur.execute("""
                        UPDATE email_inbox
                        SET analysis = analysis || %(aj)s::jsonb
                        WHERE id = %(eid)s OR message_id = %(mid)s
                    """, {"aj": payload, "eid": email_id, "mid": message_id})
        conn.close()
    except Exception as e:
        print(f"[Gateway] DB update error: {e}", flush=True)


def _pg_update_attachment_findings(email_id: int, message_id: str,
                                    scan_results: list, max_att_score: int):
    if not _PG_OK or not scan_results:
        return
    try:
        att_payload = _safe_json({
            "attachment_scan": {
                "scanned_at":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "attachment_count": len(scan_results),
                "max_risk_score":   max_att_score,
                "results":          scan_results,
            }
        })
        needs_upgrade = max_att_score >= 70
        upgrade_tier  = "CRITICAL" if max_att_score >= 70 else "HIGH"

        conn = psycopg2.connect(DATABASE_URL)
        with conn:
            with conn.cursor() as cur:
                if needs_upgrade:
                    cur.execute("""
                        UPDATE email_inbox
                        SET analysis        = analysis || %(aj)s::jsonb,
                            has_attachments = TRUE,
                            risk_tier       = %(tier)s,
                            risk_score      = GREATEST(risk_score, %(score)s),
                            is_flagged      = TRUE
                        WHERE id = %(eid)s OR message_id = %(mid)s
                    """, {"aj": json.dumps(att_payload), "tier": upgrade_tier,
                          "score": max_att_score, "eid": email_id, "mid": message_id})
                else:
                    cur.execute("""
                        UPDATE email_inbox
                        SET analysis        = analysis || %(aj)s::jsonb,
                            has_attachments = TRUE
                        WHERE id = %(eid)s OR message_id = %(mid)s
                    """, {"aj": json.dumps(att_payload), "eid": email_id, "mid": message_id})
        conn.close()
        print(f"[Gateway] Attachment findings saved: {len(scan_results)} scanned, max={max_att_score}", flush=True)
    except Exception as e:
        print(f"[Gateway] DB attachment update error: {e}", flush=True)


# ── Attachment helpers ─────────────────────────────────────────────────────────

def _extract_attachments(msg) -> list:
    attachments = []
    seen = set()
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename    = part.get_filename()
        ct          = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))
        is_attachment = "attachment" in disposition or (
            filename and ct not in ("text/plain", "text/html")
        )
        if not is_attachment:
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        if not filename:
            ext = ct.split("/")[1] if "/" in ct else "bin"
            filename = f"attachment_{len(attachments)}.{ext}"
        base = filename
        while base in seen:
            base = f"_{len(attachments)}{filename}"
        seen.add(base)
        attachments.append({"filename": base, "content_type": ct, "payload": payload})
    return attachments


def _scan_attachments_and_update_db(attachments: list, email_id: int, message_id: str):
    """Background: submit each attachment to attachment-scanner service, then update DB."""
    if not attachments:
        return
    scan_results = []
    max_att_score = 0
    try:
        import requests as req_lib
    except ImportError:
        print("[Gateway] requests not available — attachment scan skipped", flush=True)
        return

    for att in attachments:
        try:
            resp = req_lib.post(
                f"{ATTACHMENT_SCANNER_URL}/analyze",
                files={"file": (att["filename"], att["payload"], att["content_type"])},
                timeout=60,
            )
            if resp.status_code == 200:
                r = resp.json()
                att_score = r.get("risk_score", 0)
                scan_results.append({
                    "filename":       att["filename"],
                    "content_type":   att["content_type"],
                    "risk_score":     att_score,
                    "risk_label":     r.get("risk_label", "Unknown"),
                    "human_summary":  r.get("human_summary", ""),
                    "total_findings": r.get("total_findings", 0),
                    "critical_count": r.get("critical_count", 0),
                    "high_count":     r.get("high_count", 0),
                })
                max_att_score = max(max_att_score, att_score)
                print(
                    f"[Gateway] Attachment '{att['filename']}' → "
                    f"{r.get('risk_label', '?')} ({att_score}/100)",
                    flush=True,
                )
        except Exception as e:
            print(f"[Gateway] Attachment scan error ({att['filename']}): {e}", flush=True)

    if scan_results:
        _pg_update_attachment_findings(email_id, message_id, scan_results, max_att_score)


# ── Email body extractor ───────────────────────────────────────────────────────

def _get_body(msg):
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct      = part.get_content_type()
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            text = payload.decode("utf-8", errors="replace")
            if ct == "text/plain":
                plain += text
            elif ct == "text/html":
                html += text
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            text = payload.decode("utf-8", errors="replace")
            if msg.get_content_type() == "text/html":
                html = text
            else:
                plain = text
    return plain, html


# ── aiosmtpd handler ───────────────────────────────────────────────────────────

class FraudDetectionHandler:
    """
    aiosmtpd DATA handler: runs full multi-layer analysis on every inbound email.

    Pipeline:
      1. XGBoost ML scoring (16 features, SHAP explainability)
      2. URL reputation scoring (16 signals, zero external calls)
      3. Multilingual analysis:
         - Homograph/IDN detection
         - Credential exposure scanning (15+ regex + entropy)
         - Suspicious domain/URL analysis
         - Language phishing detection
         - Statistical AI content detection
         - Attachment risk analysis (extension tiers + dangerous context)
         - BEC pattern matching
         - 419 scam pattern matching
      4. Combined risk score → REJECT/QUARANTINE/TAG/ACCEPT
      5. Background: email_inbox DB save
      6. Background: attachment deep scan via attachment-scanner service
      7. Background: Llama 3 deep content analysis + AI detection
      8. Background: smtp_decisions audit log save with ALL analysis data
    """

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        start = time.time()

        raw = envelope.content
        raw_str = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw

        # ── Parse MIME ────────────────────────────────────────────────────────
        msg        = email_lib.message_from_string(raw_str, policy=default_policy)
        sender     = envelope.mail_from or str(msg.get("From", ""))
        recipients = list(envelope.rcpt_tos)
        subject    = str(msg.get("Subject", ""))
        reply_to   = str(msg.get("Reply-To", ""))
        message_id = str(msg.get("Message-ID", "")) or f"<smtp-gw-{uuid.uuid4().hex[:12]}@aegisai>"
        date_str   = str(msg.get("Date", ""))
        from_name, from_email = email.utils.parseaddr(str(msg.get("From", sender)))

        plain, html  = _get_body(msg)
        body_text    = plain or ""
        body_html    = html or ""
        attachments  = _extract_attachments(msg)
        attachment_names = [a["filename"] for a in attachments]

        raw_headers = ""
        for key in ("Authentication-Results", "Received", "Received-SPF",
                    "DKIM-Signature", "X-Mailer", "X-Originating-IP", "Return-Path"):
            for v in (msg.get_all(key) or []):
                raw_headers += f"{key}: {v}\n"

        urls = _URL_RE.findall(f"{subject} {body_text} {body_html}")

        # ── Step 1: XGBoost scoring (~15 ms) ─────────────────────────────────
        features  = extract_features(msg, sender)
        local     = score_email(features)
        score_01  = local["fraud_score"]
        xgb_score = score_01 * 100

        # ── Step 2: URL Reputation (~1 ms) ────────────────────────────────────
        url_rep  = score_urls(urls)
        url_max  = url_rep.get("url_risk_score", 0)
        if url_max >= 80:
            url_boost = 35.0
        elif url_max >= 55:
            url_boost = 25.0
        elif url_max >= 35:
            url_boost = 15.0
        elif url_max >= 20:
            url_boost = 8.0
        else:
            url_boost = 0.0

        # ── Step 3: Multilingual + advanced analysis (~50-300 ms) ─────────────
        ml_analysis = None
        try:
            from multilingual_analyzer import analyze_email as ml_analyze
            ml_analysis = ml_analyze(
                subject=subject,
                body=body_text or body_html[:2000],
                sender=from_email or sender,
                attachment_filenames=attachment_names,
            )
        except Exception as e:
            print(f"[Gateway] ML analysis error (non-fatal): {e}", flush=True)

        # ── Step 4: Compute combined score & run Llama synchronously ──────────
        base_combined = _compute_combined_score(xgb_score, url_boost, ml_analysis)

        llama_result = None
        explanation = None
        ai_written = False
        ai_confidence = 0.0
        try:
            from llama_analyzer import analyze_email_content, generate_risk_explanation
            llama_result = analyze_email_content(
                subject=subject,
                body=body_text or body_html[:3000],
                sender=from_email or sender,
                existing_analysis=ml_analysis,
            )
            ai_written     = llama_result.get("ai_written", False)
            ai_confidence  = llama_result.get("ai_confidence", 0.0)
            
            # Incorporate Llama's score
            llama_score = llama_result.get("risk_score", 0)
            combined = max(base_combined, llama_score)
            
            risk_tier     = _score_to_tier(combined)
            smtp_decision = _tier_to_decision(risk_tier)

            explanation_data = generate_risk_explanation(
                subject=subject,
                body=body_text[:500],
                sender=from_email or sender,
                combined_score=combined,
                risk_tier=risk_tier,
                all_analysis={"ml_analysis": ml_analysis,
                              "xgboost": {"top_contributors": local.get("top_contributors", [])}},
            )
            explanation = explanation_data.get("overall_explanation", "")
            factor_explanations = explanation_data.get("factor_explanations", {})
            print(f"[Gateway] Llama analysis complete: score={llama_score} base={base_combined:.1f} final={combined:.1f}", flush=True)
        except Exception as e:
            print(f"[Gateway] Llama analysis error (non-fatal): {e}", flush=True)
            combined = base_combined
            risk_tier     = _score_to_tier(combined)
            smtp_decision = _tier_to_decision(risk_tier)
            explanation = (ml_analysis or {}).get("summary", "")
            # Use rule-based factor explanations from multilingual_analyzer as fallback
            factor_explanations = (ml_analysis or {}).get("factor_explanations", {})

        elapsed_ms = int((time.time() - start) * 1000)

        # ── Step 5: Background DB write & attachment scan ─────────────────────
        def _store():
            # Build initial analysis payload
            ml_rs = (ml_analysis or {}).get("risk_scores", {})
            ml_analysis_detail = (ml_analysis or {}).get("analysis", {})

            # Merge Llama factor_explanations with rule-based ones from ml_analysis
            # Rule-based ones are always complete (cover all 8 modules with explanations)
            rule_based_expl = (ml_analysis or {}).get("factor_explanations", {})
            # Llama explanations override rule-based where available and non-empty
            merged_factor_explanations = dict(rule_based_expl)
            for k, v in factor_explanations.items():
                if v and v.strip():
                    merged_factor_explanations[k] = v

            # Build 0-100 module risk score dict for direct DB storage
            module_risk_scores = {
                "xgboost":             round(xgb_score, 1),
                "url_reputation":      round(url_max, 1),
                "homograph":           round(ml_rs.get("homograph", 0) * 100, 1),
                "credential_exposure": round(ml_rs.get("credential_exposure", 0) * 100, 1),
                "url_suspicion":       round(ml_rs.get("url_suspicion", 0) * 100, 1),
                "attachment":          round(ml_rs.get("attachment", 0) * 100, 1),
                "bec":                 round(ml_rs.get("bec", 0) * 100, 1),
                "scam_419":            round(ml_rs.get("scam_419", 0) * 100, 1),
                "language_phishing":   round(ml_rs.get("language_phishing", 0) * 100, 1),
                "ai_generated":        round(ml_rs.get("ai_generated", 0) * 100, 1),
            }

            analysis_payload = {
                "source":              "SMTP_GATEWAY",
                "gateway_score":       round(combined, 1),
                "combined_score":      round(combined, 1),
                "xgboost_score":       round(xgb_score, 1),
                "gateway_tier":        risk_tier,
                "smtp_decision":       smtp_decision,
                "threat_type":         local.get("threat_type", ""),
                "ml_classification":   (ml_analysis or {}).get("classification", ""),
                "ml_confidence":       (ml_analysis or {}).get("confidence", 0),
                "ml_verdict":          (ml_analysis or {}).get("verdict", ""),
                "top_contributors":    local.get("top_contributors", []),
                "features":            features,
                "url_reputation":      url_rep,
                "processing_ms":       elapsed_ms,
                "status":              "gateway_scored",
                "attachment_count":    len(attachments),
                "risk_scores":         module_risk_scores,
                "homograph_analysis":  ml_analysis_detail.get("homograph", {}),
                "credential_analysis": ml_analysis_detail.get("credentials", {}),
                "url_analysis":        ml_analysis_detail.get("urls", {}),
                "attachment_analysis": ml_analysis_detail.get("attachments", {}),
                "language_analysis":   ml_analysis_detail.get("languages", {}),
                "ai_detection":        ml_analysis_detail.get("ai_detection", {}),
                "ai_detection_llama": {
                    "ai_written":   ai_written,
                    "confidence":   ai_confidence,
                    "reasoning":    (llama_result or {}).get("ai_reasoning", ""),
                    "intent":       (llama_result or {}).get("intent", ""),
                    "tactics":      (llama_result or {}).get("manipulation_tactics", []),
                    "urgency":      (llama_result or {}).get("urgency_level", ""),
                    "impersonation": (llama_result or {}).get("impersonated_entity"),
                    "threat_explanation": (llama_result or {}).get("threat_explanation", ""),
                    "recommended_action": (llama_result or {}).get("recommended_action", ""),
                    "risk_score":   (llama_result or {}).get("risk_score", 0),
                },
                "bec_patterns":        ml_analysis_detail.get("bec_patterns", []),
                "scam_patterns":       ml_analysis_detail.get("scam_patterns", []),
                "ml_summary":          (ml_analysis or {}).get("summary", ""),
                "explanation":         explanation,
                "factor_explanations": merged_factor_explanations,
            }

            # Save to email_inbox
            email_id = _pg_save_email(
                data={
                    "message_id":      message_id,
                    "subject":         subject,
                    "sender":          from_email or sender,
                    "receiver":        ", ".join(recipients),
                    "reply_to":        reply_to,
                    "date_str":        date_str,
                    "headers":         {"raw": raw_headers[:5000]},
                    "body_text":       body_text[:50000],
                    "body_html":       body_html[:50000],
                    "urls":            urls[:50],
                    "has_attachments": len(attachments) > 0,
                    "attachment_count": len(attachments),
                },
                risk_score=int(round(combined)),
                risk_tier=risk_tier,
                analysis=analysis_payload,
            )

            if email_id:
                print(f"[Gateway] Saved id={email_id} score={combined:.1f} tier={risk_tier}", flush=True)
            # ── Save complete audit record to smtp_decisions ───────────────────
            save_decision(
                sender=from_email or sender,
                recipients=recipients,
                subject=subject,
                fraud_score=score_01,
                decision=smtp_decision,
                threat_type=local.get("threat_type", ""),
                risk_tier=risk_tier,
                shap_values=local.get("shap_values", {}),
                features=features,
                top_contributors=local.get("top_contributors", []),
                processing_ms=elapsed_ms,
                raw_email=raw_str[:5000] if smtp_decision in ("QUARANTINE", "REJECT") else None,
                source="SMTP",
                ml_analysis=ml_analysis,
                ml_classification=(ml_analysis or {}).get("classification"),
                ml_confidence=(ml_analysis or {}).get("confidence"),
                detected_languages=(ml_analysis or {}).get("analysis", {}).get("languages", {}).get("languages_found"),
                explanation=explanation,
                ai_generated_prob=ai_confidence,
                ai_written=ai_written,
                llama_analysis=llama_result,
                credential_findings=ml_analysis_detail.get("credentials") if ml_analysis_detail else None,
                url_findings=ml_analysis_detail.get("urls") if ml_analysis_detail else None,
                attachment_findings=ml_analysis_detail.get("attachments") if ml_analysis_detail else None,
                homograph_findings=ml_analysis_detail.get("homograph") if ml_analysis_detail else None,
                combined_score=combined,
                factor_explanations=merged_factor_explanations,
                module_risk_scores=module_risk_scores,
            )

            # ── Scan MIME attachments ─────────────────────────────────────────
            if attachments and email_id:
                _scan_attachments_and_update_db(attachments, email_id, message_id)

        threading.Thread(target=_store, daemon=True).start()

        # ── Step 6: Forward clean emails to downstream ────────────────────────
        if smtp_decision in ("ACCEPT", "TAG"):
            def _forward():
                try:
                    forward_to_downstream(raw_str, sender, recipients)
                except Exception as e:
                    print(f"[Gateway] Forward error: {e}", flush=True)
            threading.Thread(target=_forward, daemon=True).start()

        # Console log
        colours = {"ACCEPT": "\033[92m", "TAG": "\033[93m",
                   "QUARANTINE": "\033[33m", "REJECT": "\033[91m"}
        col = colours.get(smtp_decision, "")
        url_info = f" | url={url_max}" if url_max > 0 else ""
        att_info = f" | atts={len(attachments)}" if attachments else ""
        print(
            f"[Gateway] {col}{smtp_decision}\033[0m | score={combined:.1f}/100 "
            f"| {risk_tier} | from={from_email or sender} | subj={subject[:40]}"
            f"{url_info}{att_info} | {elapsed_ms}ms",
            flush=True,
        )

        if smtp_decision == "REJECT":
            return f"550 5.7.1 Message rejected: risk score {combined:.0f}/100 ({risk_tier})".encode()
        return b"250 OK"
