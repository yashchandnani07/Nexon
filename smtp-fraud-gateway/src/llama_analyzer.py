"""
Llama 3 Deep Content Analyzer
===============================
Uses Llama 3 (via Ollama) for:
  1. Deep email content analysis — intent, tone, manipulation tactics
  2. AI-generated content detection — is this email written by AI?
  3. Document/attachment content analysis — semantic threat assessment

Falls back gracefully when Ollama is unavailable.
"""

import os
import json
import logging
import time
from typing import Optional

logger = logging.getLogger("llama_analyzer")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://sandbox_ollama:11434")
LLAMA_MODEL = os.environ.get("LLAMA_MODEL", "llama3")
TIMEOUT = int(os.environ.get("LLAMA_TIMEOUT", "45"))


def _call_ollama(prompt: str, model: str = None) -> Optional[str]:
    """Send a prompt to Ollama and return the response text, or None on failure."""
    try:
        import requests
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": model or LLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json().get("response", "").strip()
        logger.warning(f"[Llama] Ollama returned HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"[Llama] Ollama unavailable: {e}")
    return None


def analyze_email_content(subject: str, body: str, sender: str = "",
                           existing_analysis: dict = None) -> dict:
    """
    Deep content analysis using Llama 3.

    Combines:
      - AI authorship detection
      - Intent / manipulation analysis
      - Social engineering tactic identification
      - Threat explanation

    Returns a dict with all findings.
    """
    start = time.time()

    # Build context from existing analysis for richer prompting
    analysis_context = ""
    if existing_analysis:
        cls = existing_analysis.get("classification", "UNKNOWN")
        verdict = existing_analysis.get("verdict", "UNKNOWN")
        risk_scores = existing_analysis.get("risk_scores", {})
        summary = existing_analysis.get("summary", "")
        analysis_context = f"""
Prior automated analysis:
- Classification: {cls} | Verdict: {verdict}
- Risk scores: {json.dumps(risk_scores)}
- Summary: {summary}
"""

    # ── Prompt 1: AI detection + content analysis ────────────────────────────
    prompt_analysis = f"""You are an expert cybersecurity email analyst. Analyze the following email and provide a structured threat assessment.

From: {sender}
Subject: {subject}
Body:
{body[:2000]}
{analysis_context}

Respond with a valid JSON object (no markdown, no extra text) with these exact fields:
{{
  "ai_written": true/false,
  "ai_confidence": 0.0-1.0,
  "ai_reasoning": "brief explanation of why you think this is/isn't AI-written",
  "intent": "one of: PHISHING, BEC, SCAM, MALWARE_DELIVERY, CREDENTIAL_HARVEST, SPAM, LEGITIMATE, SOCIAL_ENGINEERING, UNKNOWN",
  "manipulation_tactics": ["list", "of", "tactics", "detected"],
  "urgency_level": "NONE/LOW/MEDIUM/HIGH/CRITICAL",
  "impersonation_detected": true/false,
  "impersonated_entity": "name of impersonated org/person or null",
  "threat_explanation": "2-3 sentence plain English explanation of the threat",
  "risk_score": 0-100,
  "recommended_action": "BLOCK/QUARANTINE/FLAG/ALLOW"
}}"""

    raw = _call_ollama(prompt_analysis)
    result = _parse_llama_json(raw)

    elapsed = round((time.time() - start) * 1000, 1)

    if result:
        result["llm_available"] = True
        result["analysis_ms"] = elapsed
        return result

    # ── Fallback: statistical AI detection already done, return minimal result ─
    return _fallback_analysis(subject, body, existing_analysis, elapsed)


def analyze_attachment_content(filename: str, text_content: str,
                                file_type: str = "document") -> dict:
    """
    Deep semantic analysis of attachment text content using Llama 3.
    Called for PDF, Word, text, etc. attachments after text extraction.
    """
    if not text_content or len(text_content.strip()) < 30:
        return {"threat_found": False, "summary": "No content to analyze", "risk_score": 0}

    start = time.time()

    prompt = f"""You are a cybersecurity analyst. Analyze the content of this {file_type} attachment named "{filename}" for threats.

Content (first 1500 chars):
{text_content[:1500]}

Respond with a valid JSON object (no markdown):
{{
  "threat_found": true/false,
  "threat_type": "one of: MALWARE_DROPPER, CREDENTIAL_HARVEST, SCAM, BEC, INVOICE_FRAUD, LEGITIMATE, SUSPICIOUS",
  "risk_score": 0-100,
  "suspicious_elements": ["list of suspicious phrases or elements"],
  "summary": "1-2 sentence description of what this document contains"
}}"""

    raw = _call_ollama(prompt)
    result = _parse_llama_json(raw)
    elapsed = round((time.time() - start) * 1000, 1)

    if result:
        result["analysis_ms"] = elapsed
        return result

    return {
        "threat_found": False,
        "threat_type": "UNKNOWN",
        "risk_score": 0,
        "suspicious_elements": [],
        "summary": f"Could not analyze {filename} — Llama unavailable",
        "analysis_ms": elapsed,
    }


def generate_risk_explanation(subject: str, body: str, sender: str,
                               combined_score: float, risk_tier: str,
                               all_analysis: dict) -> dict:
    """
    Generate a plain-English explanation of the risk assessment.
    Uses Llama 3 when available, falls back to rule-based summary.
    """
    # Build a concise summary of findings for the prompt
    findings = []
    ml = all_analysis.get("ml_analysis", {})
    if ml:
        rs = ml.get("risk_scores", {})
        if rs.get("homograph", 0) > 0.5:
            findings.append(f"homograph/IDN attack detected in URLs")
        if rs.get("credential_exposure", 0) > 0.5:
            findings.append(f"credential/secret exposure detected")
        if rs.get("url_suspicion", 0) > 0.5:
            findings.append(f"suspicious URLs present")
        if rs.get("attachment", 0) > 0.5:
            findings.append(f"dangerous attachments")
        if rs.get("bec", 0) > 0.4:
            findings.append(f"BEC (wire fraud) patterns")
        if rs.get("scam_419", 0) > 0.4:
            findings.append(f"419/advance-fee scam patterns")
        if rs.get("ai_generated", 0) > 0.6:
            findings.append(f"likely AI-generated content")

    xgb = all_analysis.get("xgboost", {})
    top = xgb.get("top_contributors", [])
    for c in top[:3]:
        if c.get("impact", 0) > 0:
            findings.append(c.get("description", ""))

    findings_str = "; ".join(findings) if findings else "multiple suspicious signals"

    prompt = f"""You are a cybersecurity email analyst.
Email from: {sender}
Subject: {subject}
Risk score: {combined_score:.0f}/100 — Severity: {risk_tier}
Key findings: {findings_str}

Respond with a valid JSON object strictly matching this structure:
{{
  "overall_explanation": "2-3 clear, non-technical sentences explaining why this email was flagged. Do not repeat raw numbers.",
  "factor_explanations": {{
    "credential_exposure": "1 sentence explaining any credential exposure risk if applicable, otherwise empty string",
    "homograph": "1 sentence explaining any homograph/IDN attack risk if applicable, otherwise empty string",
    "url_suspicion": "1 sentence explaining the malicious/suspicious URLs if applicable, otherwise empty string",
    "attachment": "1 sentence explaining the attachment risk if applicable, otherwise empty string",
    "bec": "1 sentence explaining the Business Email Compromise (BEC) patterns if applicable, otherwise empty string",
    "scam_419": "1 sentence explaining the 419/advance-fee scam signals if applicable, otherwise empty string",
    "language_phishing": "1 sentence explaining the urgent/manipulative language detected if applicable, otherwise empty string",
    "ai_generated": "1 sentence explaining the likelihood of AI generated content if applicable, otherwise empty string"
  }}
}}"""

    raw = _call_ollama(prompt)
    result = _parse_llama_json(raw)
    if result and "overall_explanation" in result:
        return result

    # Rule-based fallback
    fallback_factors = {}
    if ml:
        rs = ml.get("risk_scores", {})
        if rs.get("credential_exposure", 0) > 0.3:
            fallback_factors["credential_exposure"] = "Credentials, secrets, or API tokens were found exposed in the message content."
        if rs.get("homograph", 0) > 0.3:
            fallback_factors["homograph"] = "Homograph/IDN attack detected where URLs use look-alike characters to spoof legitimate domains."
        if rs.get("url_suspicion", 0) > 0.3:
            fallback_factors["url_suspicion"] = "Included URLs point to known suspicious domains, malicious IP addresses, or newly registered infrastructure."
        if rs.get("attachment", 0) > 0.3:
            fallback_factors["attachment"] = "A highly suspicious or dangerous attachment format was detected alongside the message."
        if rs.get("bec", 0) > 0.3:
            fallback_factors["bec"] = "Message contains wire fraud, urgent payment requests, or CEO impersonation patterns typical of Business Email Compromise."
        if rs.get("scam_419", 0) > 0.3:
            fallback_factors["scam_419"] = "The language strongly resembles 419 or advance-fee scams, often promising unrealistic windfalls."
        if rs.get("language_phishing", 0) > 0.3:
            fallback_factors["language_phishing"] = "High urgency, manipulative language, or threatening tone usually associated with phishing campaigns."
        if rs.get("ai_generated", 0) > 0.6:
            fallback_factors["ai_generated"] = "Statistical and structural analysis suggests the email text was likely generated by an AI model."

    return {
        "overall_explanation": (f"This email was flagged as {risk_tier} risk (score: {combined_score:.0f}/100) "
                                f"due to: {findings_str}. Exercise caution before clicking any links or "
                                f"opening attachments.") if findings else 
                               (f"This email received a risk score of {combined_score:.0f}/100 ({risk_tier} severity). "
                                f"Automated analysis detected suspicious patterns."),
        "factor_explanations": fallback_factors
    }


def _parse_llama_json(raw: Optional[str]) -> Optional[dict]:
    """Parse JSON from Llama response, handling common formatting issues."""
    if not raw:
        return None
    try:
        # Try direct parse
        return json.loads(raw)
    except Exception:
        pass
    # Try extracting JSON block
    try:
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(raw[start:end])
    except Exception:
        pass
    return None


def _fallback_analysis(subject: str, body: str,
                        existing_analysis: dict, elapsed: float) -> dict:
    """Rule-based fallback when Llama 3 is unavailable."""
    # Use the statistical AI detector result if available
    ai_prob = 0.0
    if existing_analysis:
        ai_det = existing_analysis.get("analysis", {}).get("ai_detection", {})
        ai_prob = ai_det.get("ai_probability", 0.0)

    # Infer intent from classification
    cls = (existing_analysis or {}).get("classification", "UNKNOWN")
    intent_map = {
        "PHISHING": "CREDENTIAL_HARVEST",
        "BEC": "BEC",
        "MALWARE": "MALWARE_DELIVERY",
        "SCAM_419": "SCAM",
        "CREDENTIAL_EXPOSURE": "CREDENTIAL_HARVEST",
        "SUSPICIOUS": "SOCIAL_ENGINEERING",
        "LEGITIMATE": "LEGITIMATE",
    }

    summary = (existing_analysis or {}).get("summary", "No analysis available.")

    return {
        "ai_written": ai_prob > 0.5,
        "ai_confidence": round(ai_prob, 3),
        "ai_reasoning": "Based on statistical analysis (Llama unavailable)",
        "intent": intent_map.get(cls, "UNKNOWN"),
        "manipulation_tactics": [],
        "urgency_level": "UNKNOWN",
        "impersonation_detected": False,
        "impersonated_entity": None,
        "threat_explanation": summary,
        "risk_score": 0,
        "recommended_action": "QUARANTINE" if cls not in ("LEGITIMATE", "UNKNOWN") else "ALLOW",
        "llm_available": False,
        "analysis_ms": elapsed,
    }
