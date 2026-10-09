"""
SMTP Fraud Detection Gateway — Pre-delivery email interception & ML scoring.
FastAPI REST API (port 8010) + aiosmtpd SMTP server (port 2525).
"""
import asyncio
import os
import time
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from aiosmtpd.controller import Controller

from smtp_handler import FraudDetectionHandler
from scorer import load_model, score_email
from features import extract_features
from db import init_db, get_decisions, get_stats, get_decision_by_id, release_email, confirm_rejection, save_decision
from multilingual_analyzer import analyze_email as ml_analyze_email, generate_explanation

SMTP_PORT = int(os.getenv("GATEWAY_SMTP_PORT", "2525"))
# Thresholds on 0-1 scale (for local XGBoost scoring in /score-raw, /inbound-webhook)
# SMTP handler uses 0-100 scale from email-monitor pipeline
REJECT_THRESHOLD = float(os.getenv("REJECT_THRESHOLD", "0.70"))
QUARANTINE_THRESHOLD = float(os.getenv("QUARANTINE_THRESHOLD", "0.40"))
TAG_THRESHOLD = float(os.getenv("TAG_THRESHOLD", "0.20"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    load_model()
    controller = Controller(
        FraudDetectionHandler(),
        hostname="0.0.0.0",
        port=SMTP_PORT,
    )
    controller.start()
    print(f"[Gateway] SMTP listening on :{SMTP_PORT}")
    print(f"[Gateway] REST API ready on :8010")
    yield
    controller.stop()


app = FastAPI(title="SMTP Fraud Gateway", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "service": "smtp-fraud-gateway", "smtp_port": SMTP_PORT}


# ── Decision log ─────────────────────────────────────────────────────────────
@app.get("/decisions")
def list_decisions(limit: int = 50, decision: str = None, source: str = None,
                   risk_tier: str = None):
    """List SMTP gateway decisions with full analysis data.
    risk_tier: single tier (CRITICAL/HIGH/MEDIUM/LOW) or comma-separated list."""
    tier_filter = None
    if risk_tier:
        tiers = [t.strip().upper() for t in risk_tier.split(",") if t.strip()]
        tier_filter = tiers if len(tiers) > 1 else (tiers[0] if tiers else None)
    return get_decisions(limit=limit, decision_filter=decision,
                         source_filter=source, risk_tier_filter=tier_filter)


@app.get("/decisions/{decision_id}")
def get_one_decision(decision_id: int):
    row = get_decision_by_id(decision_id)
    if not row:
        raise HTTPException(404, "Decision not found")
    return row


# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/stats")
def stats():
    base = get_stats()
    # Add per-tier counts for frontend tab badges
    from db import _conn
    extra = {}
    try:
        c, be = _conn()
        cur = c.cursor()
        ph = "%s" if be == "pg" else "?"
        for tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            cur.execute(
                f"SELECT COUNT(*) as cnt FROM smtp_decisions WHERE risk_tier = {ph}",
                (tier,),
            )
            r = cur.fetchone()
            extra[tier.lower()] = r["cnt"] if be == "pg" else r[0]
        c.close()
    except Exception:
        pass
    base.update(extra)
    return base


# ── Analyst actions ──────────────────────────────────────────────────────────
@app.post("/quarantine/{decision_id}/release")
def release_quarantined(decision_id: int):
    result = release_email(decision_id)
    if result and result.get("raw_email"):
        from forwarder import forward_to_downstream
        try:
            forward_to_downstream(result["raw_email"], result.get("sender", ""), result.get("recipients", []))
        except Exception as e:
            print(f"[Gateway] Forward after release failed: {e}")
    return {"status": "released", "decision_id": decision_id}


@app.post("/quarantine/{decision_id}/reject")
def reject_quarantined(decision_id: int):
    confirm_rejection(decision_id)
    return {"status": "rejected", "decision_id": decision_id}


# ── Multilingual Threat Analysis ─────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    email_id: str = ""
    subject: str = ""
    body: str = ""
    sender: str = ""
    attachments: list = []

class BatchAnalyzeRequest(BaseModel):
    emails: List[AnalyzeRequest]
    include_explanation: bool = False


@app.post("/analyze")
def analyze_single(payload: AnalyzeRequest):
    """Run full multilingual threat analysis on a single email."""
    start = __import__("time").time()
    result = ml_analyze_email(
        subject=payload.subject,
        body=payload.body,
        sender=payload.sender,
        attachment_filenames=payload.attachments,
    )
    elapsed = int((__import__("time").time() - start) * 1000)
    result["email_id"] = payload.email_id
    result["processing_ms"] = elapsed
    return result


@app.post("/analyze-explain")
def analyze_with_explanation(payload: AnalyzeRequest):
    """Run full analysis + Ollama natural language explanation."""
    start = __import__("time").time()
    result = ml_analyze_email(
        subject=payload.subject,
        body=payload.body,
        sender=payload.sender,
        attachment_filenames=payload.attachments,
    )
    explanation = generate_explanation(result, payload.subject, payload.body[:300])
    result["explanation"] = explanation
    result["email_id"] = payload.email_id
    result["processing_ms"] = int((__import__("time").time() - start) * 1000)
    return result


@app.post("/validate")
def validate_batch(payload: BatchAnalyzeRequest):
    """Process a batch of emails for validation. Returns all results."""
    results = []
    total_start = __import__("time").time()
    for em in payload.emails:
        start = __import__("time").time()
        result = ml_analyze_email(
            subject=em.subject,
            body=em.body,
            sender=em.sender,
            attachment_filenames=em.attachments,
        )
        elapsed = int((__import__("time").time() - start) * 1000)
        if payload.include_explanation:
            result["explanation"] = generate_explanation(result, em.subject, em.body[:300])
        result["email_id"] = em.email_id
        result["processing_ms"] = elapsed
        results.append(result)
    total_elapsed = int((__import__("time").time() - total_start) * 1000)
    return {
        "total_emails": len(results),
        "total_processing_ms": total_elapsed,
        "avg_processing_ms": round(total_elapsed / max(len(results), 1), 1),
        "results": results,
        "summary": {
            "classifications": _count_field(results, "classification"),
            "verdicts": _count_field(results, "verdict"),
        }
    }


def _count_field(results, field):
    counts = {}
    for r in results:
        v = r.get(field, "UNKNOWN")
        counts[v] = counts.get(v, 0) + 1
    return counts


# ── Test email sender ────────────────────────────────────────────────────────
class TestEmailRequest(BaseModel):
    sender: str = "attacker@phishing-domain.com"
    recipient: str = "employee@barclays.com"
    subject: str = "Urgent: Verify Your Account"
    body: str = "Please click here to verify your account immediately."
    reply_to: str = ""


class RawEmailScoreRequest(BaseModel):
    raw_email: str = ""
    sender: str = ""
    subject: str = ""
    body: str = ""
    reply_to: str = ""


@app.post("/score-raw")
def score_raw_email(payload: RawEmailScoreRequest):
    """Score a raw email (or field dict) without going through SMTP.
    Used by the email-monitor service to score every fetched email."""
    import email as email_lib
    start = __import__("time").time()

    if payload.raw_email:
        msg = email_lib.message_from_string(payload.raw_email)
        sender = payload.sender or str(msg.get("From", ""))
    else:
        # Build a minimal message from fields
        from email.mime.text import MIMEText
        msg = MIMEText(payload.body or "")
        msg["From"] = payload.sender
        msg["Subject"] = payload.subject
        if payload.reply_to:
            msg["Reply-To"] = payload.reply_to
        sender = payload.sender

    features = extract_features(msg, sender)
    result = score_email(features)

    subject = str(msg.get("Subject", payload.subject or ""))
    body    = payload.body or ""
    if not body and payload.raw_email:
        # Extract body from raw email
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                raw_payload = part.get_payload(decode=True)
                if raw_payload:
                    body = raw_payload.decode("utf-8", errors="replace")
                    break

    # Run multilingual analysis so all 8 module scores are populated
    ml_analysis = None
    try:
        ml_analysis = ml_analyze_email(
            subject=subject,
            body=body,
            sender=sender,
            attachment_filenames=[],
        )
    except Exception as e:
        print(f"[score-raw] ML analysis error: {e}", flush=True)

    ml_rs = (ml_analysis or {}).get("risk_scores", {})
    xgb_score = result["fraud_score"] * 100
    url_max   = 0.0
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
    factor_explanations = (ml_analysis or {}).get("factor_explanations", {})

    elapsed_ms = int((__import__("time").time() - start) * 1000)

    fraud_score = result["fraud_score"]
    decision = (
        "REJECT" if fraud_score >= REJECT_THRESHOLD else
        "QUARANTINE" if fraud_score >= QUARANTINE_THRESHOLD else
        "TAG" if fraud_score >= TAG_THRESHOLD else
        "ACCEPT"
    )
    recipients = [str(msg.get("To", ""))]

    save_decision(
        sender=sender,
        recipients=recipients,
        subject=subject,
        fraud_score=fraud_score,
        decision=decision,
        threat_type=result["threat_type"],
        shap_values=result["shap_values"],
        features=features,
        top_contributors=result["top_contributors"],
        processing_ms=elapsed_ms,
        raw_email=None,
        source="IMAP-SCAN",
        ml_analysis=ml_analysis,
        ml_classification=(ml_analysis or {}).get("classification"),
        ml_confidence=(ml_analysis or {}).get("confidence"),
        explanation=(ml_analysis or {}).get("summary", ""),
        factor_explanations=factor_explanations,
        module_risk_scores=module_risk_scores,
        combined_score=xgb_score,
    )

    return {
        "fraud_score": fraud_score,
        "decision": decision,
        "threat_type": result["threat_type"],
        "top_contributors": result["top_contributors"],
        "processing_ms": elapsed_ms,
        "module_risk_scores": module_risk_scores,
        "factor_explanations": factor_explanations,
        "ml_classification": (ml_analysis or {}).get("classification"),
    }


# ── Inbound webhook (Mailgun / SendGrid Inbound Parse compatible) ────────────
@app.post("/inbound-webhook")
async def inbound_webhook(request: Request):
    """Accepts inbound email from Mailgun/SendGrid Inbound Parse or raw JSON."""
    import email as email_lib

    content_type = request.headers.get("content-type", "")
    start = __import__("time").time()

    if "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        form = await request.form()
        sender  = form.get("sender") or form.get("from") or form.get("From") or ""
        subject = form.get("subject") or form.get("Subject") or ""
        body    = form.get("body-plain") or form.get("text") or form.get("body") or ""
        reply_to = form.get("Reply-To") or form.get("reply_to") or ""
        raw     = form.get("email") or ""
    else:
        data = await request.json()
        sender  = data.get("sender", "") or data.get("from", "")
        subject = data.get("subject", "")
        body    = data.get("body-plain", "") or data.get("text", "") or data.get("body", "")
        reply_to = data.get("reply_to", "") or data.get("Reply-To", "")
        raw     = data.get("email", "") or data.get("raw_email", "")

    if raw:
        msg = email_lib.message_from_string(raw)
        sender = sender or str(msg.get("From", ""))
    else:
        from email.mime.text import MIMEText
        msg = MIMEText(body)
        msg["From"] = sender
        msg["Subject"] = subject
        if reply_to:
            msg["Reply-To"] = reply_to

    features = extract_features(msg, sender)
    result = score_email(features)
    elapsed_ms = int((__import__("time").time() - start) * 1000)

    fraud_score = result["fraud_score"]
    decision = (
        "REJECT" if fraud_score >= REJECT_THRESHOLD else
        "QUARANTINE" if fraud_score >= QUARANTINE_THRESHOLD else
        "TAG" if fraud_score >= TAG_THRESHOLD else
        "ACCEPT"
    )

    save_decision(
        sender=sender,
        recipients=["inbound-webhook"],
        subject=subject,
        fraud_score=fraud_score,
        decision=decision,
        threat_type=result["threat_type"],
        shap_values=result["shap_values"],
        features=features,
        top_contributors=result["top_contributors"],
        processing_ms=elapsed_ms,
        raw_email=raw[:5000] if raw else None,
        source="WEBHOOK",
    )

    return {
        "status": "ok",
        "fraud_score": fraud_score,
        "decision": decision,
        "threat_type": result["threat_type"],
        "processing_ms": elapsed_ms,
    }


# ── Public Demo Page (served at /demo) ──────────────────────────────────────
DEMO_HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AegisAI SMTP Fraud Gateway</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border-radius:16px;padding:40px;max-width:600px;width:90%;box-shadow:0 25px 50px rgba(0,0,0,.5)}
h1{color:#38bdf8;font-size:1.6rem;margin-bottom:8px}
p.sub{color:#94a3b8;margin-bottom:24px;font-size:.9rem}
label{display:block;color:#94a3b8;font-size:.85rem;margin-bottom:4px;margin-top:14px}
input,textarea{width:100%;padding:10px 14px;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;font-size:.95rem}
textarea{height:120px;resize:vertical}
button{margin-top:20px;width:100%;padding:12px;border-radius:8px;border:none;background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:#fff;font-size:1rem;font-weight:600;cursor:pointer}
button:hover{opacity:.9}
.result{margin-top:20px;padding:16px;border-radius:8px;font-family:monospace;font-size:.85rem;white-space:pre-wrap}
.ACCEPT{background:#064e3b;border:1px solid #10b981}.REJECT{background:#7f1d1d;border:1px solid #ef4444}
.QUARANTINE{background:#78350f;border:1px solid #f59e0b}.TAG{background:#1e3a5f;border:1px solid #3b82f6}
.badge{display:inline-block;padding:4px 12px;border-radius:20px;font-weight:700;font-size:1.1rem;margin-bottom:8px}
.badge.ACCEPT{background:#10b981;color:#fff}.badge.REJECT{background:#ef4444;color:#fff}
.badge.QUARANTINE{background:#f59e0b;color:#000}.badge.TAG{background:#3b82f6;color:#fff}
.tpls{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.tpl{padding:6px 12px;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#94a3b8;font-size:.75rem;cursor:pointer}
.tpl:hover{border-color:#3b82f6;color:#e2e8f0}
</style></head><body><div class="card">
<h1>&#128737; AegisAI SMTP Fraud Gateway</h1>
<p class="sub">Pre-delivery email interception &middot; XGBoost ML scoring &middot; SHAP Explainability</p>
<div class="tpls">
<div class="tpl" onclick="fill('phish')">&#127907; Phishing</div>
<div class="tpl" onclick="fill('bec')">&#128188; BEC</div>
<div class="tpl" onclick="fill('legit')">&#9989; Legitimate</div>
<div class="tpl" onclick="fill('malware')">&#128190; Malware</div>
<div class="tpl" onclick="fill('spear')">&#127919; Spear Phishing</div></div>
<label>Sender Email</label><input id="s" placeholder="attacker@phishing-domain.com">
<label>Subject</label><input id="su" placeholder="URGENT: Verify your account">
<label>Email Body</label><textarea id="b" placeholder="Email content..."></textarea>
<label>Reply-To (optional)</label><input id="r" placeholder="different-address@evil.com">
<button onclick="go()">&#9889; Intercept &amp; Score</button>
<div id="out"></div></div>
<script>
const T={
phish:{s:'security@barclays-verify.com',su:'URGENT: Verify your account immediately',b:'Dear Customer,\\nSuspicious activity detected. Verify immediately:\\nhttps://barclays-secure-login.phishing.ru/verify\\nFailure = account suspension.\\nBarclays Security',r:'steal@darkweb.com'},
bec:{s:'ceo@barclays-group.com',su:'Wire Transfer - Confidential',b:'Hi,\\nProcess urgent wire transfer 250,000 GBP to:\\nAccount: 12345678\\nSort Code: 00-11-22\\nConfidential.\\nCEO',r:'ceo-real@gmail.com'},
legit:{s:'newsletter@linkedin.com',su:'Your weekly professional update',b:'Hi,\\nTop stories this week:\\n- Better Team Collaboration Tips\\n- Industry Trends 2026\\nhttps://linkedin.com/feed\\nLinkedIn Team',r:''},
malware:{s:'support@microsoft-update.com',su:'Critical Security Patch Required',b:'Dear User,\\nCritical vulnerability. Download patch:\\nhttps://microsoft-update.malware.xyz/patch.exe\\nApply within 2 hours.\\nMicrosoft Support',r:''},
spear:{s:'hr@barclays.co.uk',su:'Updated Compensation Package',b:'Dear Employee,\\nComp package updated Q2 2026. Review:\\nhttps://barclays-hr-portal.phishing.net/compensation\\nComplete by Friday.\\nHR',r:'hr-fake@external.com'}};
function fill(k){var t=T[k];document.getElementById('s').value=t.s;document.getElementById('su').value=t.su;document.getElementById('b').value=t.b;document.getElementById('r').value=t.r;document.getElementById('out').innerHTML=''}
async function go(){var btn=document.querySelector('button');btn.disabled=true;btn.textContent='Scoring...';
try{var res=await fetch('inbound-webhook',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sender:document.getElementById('s').value,subject:document.getElementById('su').value,body:document.getElementById('b').value,reply_to:document.getElementById('r').value})});
var d=await res.json();document.getElementById('out').innerHTML='<div class="result '+d.decision+'"><span class="badge '+d.decision+'">'+d.decision+'</span>\\nFraud Score: '+(d.fraud_score*100).toFixed(1)+'%\\nThreat Type: '+d.threat_type+'\\nProcessing: '+d.processing_ms+'ms</div>'}
catch(e){document.getElementById('out').innerHTML='<div class="result REJECT">Error: '+e.message+'</div>'}
btn.disabled=false;btn.textContent='\\u26a1 Intercept & Score'}</script></body></html>"""


@app.get("/demo", response_class=HTMLResponse)
def demo_page():
    return DEMO_HTML


@app.post("/test-email")
def send_test_email(payload: TestEmailRequest):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    msg = MIMEMultipart("alternative")
    msg["From"] = payload.sender
    msg["To"] = payload.recipient
    msg["Subject"] = payload.subject
    if payload.reply_to:
        msg["Reply-To"] = payload.reply_to
    msg.attach(MIMEText(payload.body, "plain"))

    try:
        with smtplib.SMTP("localhost", SMTP_PORT) as smtp:
            smtp.send_message(msg)
        return {"status": "sent", "message": "Email accepted by gateway"}
    except smtplib.SMTPDataError as e:
        # Gateway rejected the email — this is expected for high-fraud emails
        return {"status": "rejected", "message": f"Gateway rejected: {e.smtp_error.decode('utf-8', errors='replace')}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/test-templates")
def get_test_templates():
    return [
        {
            "name": "Phishing — Credential Harvest",
            "sender": "security@barclays-verify.com",
            "recipient": "john.smith@barclays.com",
            "subject": "URGENT: Verify your account immediately",
            "body": (
                "Dear Customer,\n\n"
                "Your Barclays account has been temporarily suspended due to suspicious activity. "
                "Please verify your identity by clicking the link below within 24 hours:\n\n"
                "https://barclays-secure-login.com/verify?id=8a7f3e\n"
                "https://barclay5-portal.com/confirm\n\n"
                "Failure to act immediately will result in permanent account suspension.\n\n"
                "Barclays Security Team"
            ),
            "reply_to": "hacker@evil-domain.com",
        },
        {
            "name": "BEC — Wire Transfer Fraud",
            "sender": "ceo@barcIays.com",
            "recipient": "finance@barclays.com",
            "subject": "Re: Urgent Wire Transfer Required",
            "body": (
                "Hi,\n\n"
                "I need you to process an urgent wire transfer of £250,000 to the following account. "
                "This is time-sensitive and must be completed before end of day.\n\n"
                "Bank: Deutsche Bank\n"
                "Account: DE89370400440532013000\n"
                "Beneficiary: Global Consulting Ltd\n"
                "SWIFT: DEUTDEFF\n\n"
                "Please confirm once done. Do not discuss this with anyone else.\n\n"
                "Regards,\nJohn"
            ),
            "reply_to": "john.fake@gmail.com",
        },
        {
            "name": "Legitimate — Team Update",
            "sender": "newsletter@company.com",
            "recipient": "employee@barclays.com",
            "subject": "Monthly Team Update — March 2025",
            "body": (
                "Hi Team,\n\n"
                "Here's our monthly update for March 2025.\n\n"
                "Key achievements:\n"
                "- Successfully migrated 3 services to the new platform\n"
                "- Customer satisfaction score improved to 94%\n"
                "- New hires onboarded across 2 departments\n\n"
                "Please review the attached presentation for more details.\n\n"
                "Best regards,\nHR Team"
            ),
            "reply_to": "",
        },
        {
            "name": "Malware — Macro Invoice",
            "sender": "invoice@supplier-uk.net",
            "recipient": "accounts@barclays.com",
            "subject": "Invoice #INV-2025-0892 — Payment Overdue",
            "body": (
                "Dear Accounts Team,\n\n"
                "Please find attached the overdue invoice INV-2025-0892 for £15,750.00.\n\n"
                "This invoice was due on March 15, 2025. Please process payment immediately "
                "to avoid service disruption.\n\n"
                "The attached Excel document contains full details. "
                "Please enable macros to view the breakdown.\n\n"
                "Regards,\nAccounts Department\nGlobal Suppliers UK Ltd"
            ),
            "reply_to": "",
        },
        {
            "name": "Spear Phishing — IT Support",
            "sender": "it-support@barcIays-helpdesk.com",
            "recipient": "analyst@barclays.com",
            "subject": "Action Required: Password Expiry Notice",
            "body": (
                "Dear Employee,\n\n"
                "Your corporate password will expire in 2 hours. "
                "To avoid losing access to all Barclays systems, please reset your password now:\n\n"
                "https://barclays-password-reset.com/renew\n\n"
                "If you do not act within 2 hours your account will be locked and you will need to "
                "contact IT support in person with photo ID.\n\n"
                "IT Helpdesk\nBarclays Technology Services"
            ),
            "reply_to": "helpdesk-fake@outlook.com",
        },
    ]
