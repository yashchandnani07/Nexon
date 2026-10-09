# src/pipeline_controller.py
"""
pipeline_controller.py — Master email threat analysis orchestrator.

Flow:
  1. Ollama (qwen3:8b)    → content understanding, entity extraction
  2. URL Analyzer         → PhishGuard 6-layer scan per URL (WHOIS/SSL/cookie/XGBoost)
  3. Attachment Scanner   → rule-based + microservice attachment check
  4. Voice Analyzer       → dual-model deepfake detection for audio files
  5. Credential Scanner   → regex + NER sensitive data extraction
  6. Risk Aggregation     → unified score + flags

Returns the STRICT output JSON:
{
  "risk_score": int,
  "summary": str,
  "credentials_detected": [],
  "urls": [{url, whois, ssl, cookies, prediction, confidence, ...}],
  "attachments": [],
  "voice_analysis": {},
  "flags": [],
  "llm_analysis": {...},         # full Ollama output
  "phishing": {...},             # FraudShield ML scorer
  "overall_risk_tier": str,
  "processing_ms": int
}
"""
from __future__ import annotations
import re
import sys
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

# Ensure src/ is on the path
_HERE = Path(__file__).parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))


# ── Helpers ────────────────────────────────────────────────────────────────────

def _score_to_tier(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


def _extract_urls_from_text(text: str) -> List[str]:
    """Fallback URL extractor from raw text."""
    pattern = r'https?://[^\s<>"\')\]]+' 
    return list(dict.fromkeys(re.findall(pattern, text)))[:20]


def _flatten_url_result(res: dict) -> dict:
    """
    Normalise a url_scanner result to the strict output format:
      { url, whois, ssl, cookies, prediction, confidence, risk_score_pct, verdict, details }
    """
    d       = res.get("details", {}) or {}
    ml      = d.get("ml_model", {})  or {}
    ssl_d   = d.get("ssl", {})       or {}
    whois_d = d.get("whois", {})     or {}
    cookie_d= d.get("cookies", {})   or {}

    prediction  = ml.get("label", "unknown").lower()
    if prediction not in ("phishing", "safe", "legitimate"):
        verdict = (res.get("verdict") or "UNKNOWN").upper()
        prediction = "phishing" if verdict in ("DANGEROUS", "SUSPICIOUS") else "safe"

    confidence = float(ml.get("probability") or 0)

    return {
        "url":           res.get("url", ""),
        "verdict":       res.get("verdict", "UNKNOWN"),
        "risk_score_pct": float(res.get("risk_score_pct", 0)),
        "prediction":    prediction,
        "confidence":    round(confidence, 2),
        "whois":         whois_d,
        "ssl":           ssl_d,
        "cookies":       cookie_d,
        "encoding":      d.get("encoding", {}),
        "html":          d.get("html", {}),
        "ml_model":      ml,
        "risk_reasons":  res.get("risk_reasons", []),
        "details":       d,     # keep full details for rich UI
        "metrics":       res.get("metrics", {}),
        "domain":        res.get("domain", ""),
        "scan_type":     res.get("scan_type", "fast"),
    }


# ── Main controller ────────────────────────────────────────────────────────────

def run_email_pipeline(
    sender:      str,
    subject:     str,
    body:        str,
    attachments: Optional[List[Dict]] = None,
    urls:        Optional[List[str]]  = None,
    email_id:    Optional[int]        = None,
) -> dict:
    """
    Full email threat analysis pipeline.

    Parameters
    ----------
    sender      : sender email / display string
    subject     : email subject line
    body        : plain-text body
    attachments : list of { filename, content (bytes), path (str) }
    urls        : list of URLs found in the email (auto-extracted if None)
    email_id    : optional DB email_id for reference

    Returns
    -------
    Strict JSON dict as per the spec.
    """
    t0          = time.time()
    attachments = attachments or []
    text        = f"Subject: {subject}\n\n{body}"

    # ── 1. Ollama LLM content analysis ────────────────────────────────────────
    print("[Pipeline] Running Ollama content analysis…")
    try:
        from ollama_service import analyze_email_content
        llm_analysis = analyze_email_content(sender, subject, body)
    except Exception as exc:
        llm_analysis = {
            "ollama_available": False, "error": str(exc),
            "threat_type": "UNKNOWN", "summary": "",
            "flags": [], "overall_risk_score": 0, "recommendation": "REVIEW",
            "extracted_entities": {"emails":[], "accounts":[], "phones":[], "names":[]},
        }

    # ── 2. URL extraction + analysis ──────────────────────────────────────────
    if urls is None:
        # First use Ollama-extracted URLs, then regex fallback
        ollama_urls = (llm_analysis.get("extracted_entities") or {}).get("urls", [])
        urls = ollama_urls or _extract_urls_from_text(text)

    print(f"[Pipeline] Scanning {len(urls)} URL(s)…")
    try:
        from url_analyzer import analyze_urls
        raw_url_results = analyze_urls(urls)
    except Exception as exc:
        raw_url_results = [{"url": u, "verdict": "ERROR", "risk_score_pct": 0, "error": str(exc)} for u in urls]

    url_results = [_flatten_url_result(r) for r in raw_url_results]

    # ── 3. Attachment scanning ─────────────────────────────────────────────────
    print(f"[Pipeline] Scanning {len(attachments)} attachment(s)…")
    try:
        from attachment_scanner import scan_attachments
        att_results = scan_attachments(attachments)
    except Exception as exc:
        att_results = [{"filename": a.get("filename","?"), "error": str(exc)} for a in attachments]

    # ── 4. Voice deepfake detection ────────────────────────────────────────────
    print("[Pipeline] Running voice deepfake detection…")
    try:
        from voice_analyzer import analyze_voice_attachments
        voice_results = analyze_voice_attachments(attachments)
    except Exception as exc:
        voice_results = []

    # ── 5. Credential / sensitive data scan ───────────────────────────────────
    print("[Pipeline] Running credential scan…")
    try:
        _cs_path = _HERE.parent / "Credential_Scanner-main" / "main.py"
        import importlib.util
        spec = importlib.util.spec_from_file_location("_cs_main", str(_cs_path))
        if spec:
            mod = importlib.util.module_from_spec(spec)
            _saved = sys.path[:]
            sys.path.insert(0, str(_cs_path.parent))
            spec.loader.exec_module(mod)
            sys.path = _saved
            cred_result = mod.full_scan(text, "email", sender)
        else:
            raise ImportError("spec is None")
    except Exception:
        try:
            from attachment_analyzer import extract_metadata
            meta = extract_metadata(text)
            creds = meta.get("credentials", [])
            cred_result = {
                "total_findings": len(creds),
                "findings": creds,
                "risk_score": min(len(creds) * 10, 100),
                "risk_label": "HIGH" if len(creds) > 3 else "MEDIUM" if len(creds) > 0 else "LOW",
                "human_summary": f"{len(creds)} credential(s) detected via regex scan.",
            }
        except Exception as exc2:
            cred_result = {"total_findings": 0, "findings": [], "risk_score": 0, "error": str(exc2)}

    credentials_detected = cred_result.get("findings", [])

    # ── 6. FraudShield ML phishing score ──────────────────────────────────────
    print("[Pipeline] Running FraudShield phishing scorer…")
    try:
        from fraudshield_scorer import score_email
        ph = score_email(
            email_text=body, subject=subject, sender=sender,
            receiver="", reply_to="", spf_pass=False, dkim_pass=False,
        )
    except Exception as exc:
        ph = {"risk_score": 0, "verdict": "UNKNOWN", "tier": "LOW",
              "top_indicators": [], "error": str(exc)}

    # ── 7. Risk aggregation ────────────────────────────────────────────────────
    ph_score     = float(ph.get("risk_score", 0))
    url_max      = max((u.get("risk_score_pct", 0) for u in url_results), default=0.0)
    cred_score   = float(cred_result.get("risk_score", 0))
    llm_score    = float(llm_analysis.get("overall_risk_score", 0))
    voice_max    = max((v.get("risk_score", 0) for v in voice_results), default=0)

    # Weighted combination
    risk_score = int(
        ph_score    * 0.30 +
        url_max     * 0.25 +
        llm_score   * 0.20 +
        cred_score  * 0.15 +
        voice_max   * 0.10
    )
    risk_score = max(risk_score, int(ph_score * 0.5))  # at least half the ML phishing score
    risk_score = min(risk_score, 100)

    overall_tier = _score_to_tier(risk_score)

    # ── Build flags ────────────────────────────────────────────────────────────
    flags: List[str] = list(llm_analysis.get("flags", []))

    if ph.get("verdict", "").upper() in ("PHISHING", "HIGH", "CRITICAL"):
        flags.append("PHISHING_DETECTED")
    if any(u.get("verdict", "").upper() == "DANGEROUS" for u in url_results):
        flags.append("MALICIOUS_URL")
    if any(u.get("verdict", "").upper() == "SUSPICIOUS" for u in url_results):
        flags.append("SUSPICIOUS_URL")
    if cred_result.get("total_findings", 0) > 0:
        flags.append("CREDENTIAL_LEAK")
    if any(a.get("is_suspicious") for a in att_results):
        flags.append("MALICIOUS_ATTACHMENT")
    if any("FAKE" in str(v.get("verdict", "")).upper() for v in voice_results):
        flags.append("DEEPFAKE_VOICE")
    if llm_analysis.get("urgency_level") in ("HIGH", "CRITICAL"):
        flags.append("HIGH_URGENCY")
    if llm_analysis.get("threat_type") in ("PHISHING", "FRAUD", "SCAM"):
        flags.append(f"LLM_{llm_analysis['threat_type']}")

    flags = list(dict.fromkeys(flags))  # deduplicate, preserve order

    # ── Build recommendation ───────────────────────────────────────────────────
    if risk_score >= 70 or "PHISHING_DETECTED" in flags or "MALICIOUS_URL" in flags:
        recommendation = "BLOCK"
    elif risk_score >= 40 or flags:
        recommendation = "REVIEW"
    else:
        recommendation = "ALLOW"

    # ── Build summary ──────────────────────────────────────────────────────────
    summary = llm_analysis.get("summary") or ""
    if not summary:
        parts = []
        if ph.get("verdict"):
            parts.append(f"ML verdict: {ph['verdict']} (score {ph_score:.0f}/100).")
        if url_results:
            dangerous_urls = sum(1 for u in url_results if u.get("verdict","").upper() == "DANGEROUS")
            if dangerous_urls:
                parts.append(f"{dangerous_urls} dangerous URL(s) detected.")
        if cred_result.get("total_findings", 0) > 0:
            parts.append(f"{cred_result['total_findings']} credential(s) found.")
        summary = " ".join(parts) or "No major threats detected."

    # ── Assemble final output ──────────────────────────────────────────────────
    processing_ms = round((time.time() - t0) * 1000)

    return {
        # Strict spec fields
        "risk_score":            risk_score,
        "summary":               summary,
        "credentials_detected":  credentials_detected,
        "urls":                  url_results,
        "attachments":           att_results,
        "voice_analysis": {
            "total_audio_files": len(voice_results),
            "scanned":   sum(1 for v in voice_results if "SKIPPED" not in str(v.get("verdict",""))),
            "skipped":   sum(1 for v in voice_results if "SKIPPED" in str(v.get("verdict",""))),
            "flagged_as_fake": sum(1 for v in voice_results if "FAKE" in str(v.get("verdict","")).upper()),
            "results":   voice_results,
        },
        "flags": flags,

        # Extended fields for rich UI
        "llm_analysis":       llm_analysis,
        "phishing":           ph,
        "credentials":        cred_result,
        "overall_risk_tier":  overall_tier,
        "overall_risk_score": risk_score,
        "recommendation":     recommendation,
        "processing_ms":      processing_ms,
        "email_id":           email_id,
    }
