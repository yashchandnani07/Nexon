"""
Multilingual Threat Analyzer — Main Orchestrator
==================================================
Calls all analysis modules and produces a composite threat assessment.
This is the central brain of the multilingual detection engine.
"""

import time
import os
import json
import logging
from typing import Dict, Optional

from homograph_detector import detect_homoglyphs
from credential_scanner import scan_credentials
from lang_detector import detect_languages
from suspicious_domain import analyze_urls
from ai_content_detector import detect_ai_content
from attachment_analyzer import analyze_attachments

logger = logging.getLogger("multilingual_analyzer")

# ── BEC (Business Email Compromise) patterns ────────────────────────────────
import re

BEC_PATTERNS = [
    (re.compile(r'wire\s*transfer|wire\s+the\s+funds', re.IGNORECASE), 0.4, "Wire transfer request"),
    (re.compile(r'bypass\s+(?:the\s+)?(?:standard|normal|regular)\s+(?:flow|process|procedure)', re.IGNORECASE), 0.5, "Bypass standard process"),
    (re.compile(r'(?:initiate|release|authorize|process)\s+(?:a\s+)?(?:payment|transfer|wire)', re.IGNORECASE), 0.4, "Payment initiation request"),
    (re.compile(r'(?:CEO|CFO|VP|Director|Chief)\s', re.IGNORECASE), 0.2, "Executive impersonation hint"),
    (re.compile(r'(?:do\s+not|don\'t)\s+delay', re.IGNORECASE), 0.3, "Anti-delay pressure"),
    (re.compile(r'routing\s+(?:number|details)', re.IGNORECASE), 0.3, "Routing number request"),
    (re.compile(r'approval\s+code|authorization\s+code', re.IGNORECASE), 0.3, "Approval code request"),
    (re.compile(r'\$\s*\d{2,3},?\d{3}', re.IGNORECASE), 0.2, "Large dollar amount"),
    (re.compile(r'(?:in\s+meetings?|tied\s+up|cannot\s+(?:access|log))', re.IGNORECASE), 0.3, "Unavailability excuse"),
    (re.compile(r'(?:reply|respond)\s+(?:urgently|immediately|asap)', re.IGNORECASE), 0.3, "Urgent response pressure"),
]

# 419 / Advance fee scam patterns
SCAM_PATTERNS = [
    (re.compile(r'(?:million|hundred\s+thousand)\s+(?:US\s+)?dollars', re.IGNORECASE), 0.5, "Large sum mention"),
    (re.compile(r'(?:beneficiary|foreign\s+beneficiary)', re.IGNORECASE), 0.5, "Beneficiary reference"),
    (re.compile(r'(?:banking\s+details|bank\s+account\s+(?:number|details))', re.IGNORECASE), 0.4, "Banking details request"),
    (re.compile(r'(?:confidential|strictly\s+confidential)\s+(?:business|proposition)', re.IGNORECASE), 0.5, "Confidential proposition"),
    (re.compile(r'(?:offshore\s+account|processing\s+fee)', re.IGNORECASE), 0.5, "419 scam markers"),
    (re.compile(r'(?:diplomat|inheritance|overdue\s+payment)', re.IGNORECASE), 0.5, "Advance fee markers"),
    (re.compile(r'(?:ATM\s+card|wire\s+transfer.*fee)', re.IGNORECASE), 0.4, "Fee-based scam"),
]


def analyze_email(subject: str, body: str, sender: str = "",
                  attachment_filenames: list = None) -> dict:
    """
    Run full multilingual threat analysis on an email.
    
    Returns comprehensive analysis dict with:
    - Individual module results
    - Composite threat classification
    - Risk scores per category
    - Overall verdict
    """
    start = time.time()
    full_text = f"{subject}\n{body}"

    # ── Run all analysis modules ─────────────────────────────────────────────
    homograph = detect_homoglyphs(full_text)
    credentials = scan_credentials(body)
    languages = detect_languages(body)
    urls = analyze_urls(full_text)
    ai_detection = detect_ai_content(body)
    attachments = analyze_attachments(body, attachment_filenames)

    # ── BEC detection ────────────────────────────────────────────────────────
    bec_hits = []
    bec_score = 0.0
    for pat_re, weight, desc in BEC_PATTERNS:
        if pat_re.search(full_text):
            bec_hits.append({"pattern": desc, "weight": weight})
            bec_score += weight
    bec_score = min(bec_score, 0.95)

    # ── 419 scam detection ───────────────────────────────────────────────────
    scam_hits = []
    scam_score = 0.0
    for pat_re, weight, desc in SCAM_PATTERNS:
        if pat_re.search(full_text):
            scam_hits.append({"pattern": desc, "weight": weight})
            scam_score += weight
    scam_score = min(scam_score, 0.95)

    # ── Composite classification ─────────────────────────────────────────────
    classification = _classify(
        homograph_risk=homograph["risk_score"],
        credential_risk=credentials["risk_score"],
        url_risk=urls["risk_score"],
        attachment_risk=attachments["risk_score"],
        language_risk=languages["risk_score"],
        bec_score=bec_score,
        scam_score=scam_score,
        ai_prob=ai_detection["ai_probability"],
    )

    elapsed = time.time() - start

    # ── Generate rule-based factor explanations ──────────────────────────────
    factor_explanations = _generate_module_explanations(
        risk_scores={
            "homograph":           homograph["risk_score"],
            "credential_exposure": credentials["risk_score"],
            "url_suspicion":       urls["risk_score"],
            "attachment":          attachments["risk_score"],
            "language_phishing":   languages["risk_score"],
            "bec":                 bec_score,
            "scam_419":            scam_score,
            "ai_generated":        ai_detection["ai_probability"],
        },
        homograph_detail=homograph,
        credential_detail=credentials,
        url_detail=urls,
        attachment_detail=attachments,
        language_detail=languages,
        ai_detail=ai_detection,
        bec_hits=bec_hits,
        scam_hits=scam_hits,
    )

    return {
        "classification": classification["label"],
        "confidence": classification["confidence"],
        "verdict": classification["verdict"],  # REJECT / QUARANTINE / ACCEPT
        "risk_scores": {
            "homograph": homograph["risk_score"],
            "credential_exposure": credentials["risk_score"],
            "url_suspicion": urls["risk_score"],
            "attachment": attachments["risk_score"],
            "language_phishing": languages["risk_score"],
            "bec": bec_score,
            "scam_419": scam_score,
            "ai_generated": ai_detection["ai_probability"],
        },
        "analysis": {
            "homograph": homograph,
            "credentials": credentials,
            "languages": languages,
            "urls": urls,
            "ai_detection": ai_detection,
            "attachments": attachments,
            "bec_patterns": bec_hits,
            "scam_patterns": scam_hits,
        },
        "summary": _build_summary(classification, homograph, credentials,
                                    languages, urls, attachments, bec_hits, scam_hits),
        "factor_explanations": factor_explanations,
        "analysis_time_ms": round(elapsed * 1000, 1),
    }


def _generate_module_explanations(risk_scores: dict, homograph_detail: dict,
                                    credential_detail: dict, url_detail: dict,
                                    attachment_detail: dict, language_detail: dict,
                                    ai_detail: dict, bec_hits: list,
                                    scam_hits: list) -> dict:
    """
    Generate a plain-English explanation for every analysis module.
    Always produces an entry for all 8 modules — even when the score is 0
    the explanation clarifies that no threats were found and why.
    """
    expl = {}

    # ── Credential Exposure ─────────────────────────────────────────────────
    cred_score = risk_scores.get("credential_exposure", 0)
    creds = credential_detail.get("credentials", [])
    if cred_score >= 0.6 and creds:
        types = ", ".join({c.get("type", "unknown") for c in creds[:4]})
        expl["credential_exposure"] = (
            f"High-severity credential exposure detected: {len(creds)} secret(s) found "
            f"({types}). These may include API keys, tokens, or passwords embedded in the message."
        )
    elif cred_score > 0 and creds:
        expl["credential_exposure"] = (
            f"Possible credential exposure: {len(creds)} pattern(s) matched "
            f"({', '.join(c.get('type','?') for c in creds[:3])}). Review carefully."
        )
    else:
        expl["credential_exposure"] = (
            "No credentials, API keys, or secrets were detected in the message body. "
            "Credential exposure risk is negligible."
        )

    # ── Homograph / IDN ─────────────────────────────────────────────────────
    hom_score = risk_scores.get("homograph", 0)
    if hom_score >= 0.7 and homograph_detail.get("has_homoglyphs"):
        chars = homograph_detail.get("confusable_chars", [])
        affected = homograph_detail.get("affected_domains", [])
        char_desc = ", ".join(f"'{c.get('char')}' ({c.get('name','?')})" for c in chars[:3])
        dom_desc  = ", ".join(d.get("original","?") for d in affected[:2])
        expl["homograph"] = (
            f"Homograph/IDN attack detected: look-alike Unicode characters ({char_desc}) "
            f"found in URL domains ({dom_desc}). These impersonate legitimate sites."
        )
    elif hom_score > 0:
        expl["homograph"] = (
            "Weak homograph signals detected — some non-ASCII characters were found in URLs "
            "that may be confusable with common Latin letters."
        )
    else:
        expl["homograph"] = (
            "No homograph or IDN (Internationalized Domain Name) spoofing was detected. "
            "All URLs use standard ASCII domain characters."
        )

    # ── URL Suspicion ────────────────────────────────────────────────────────
    url_score = risk_scores.get("url_suspicion", 0)
    susp_urls = url_detail.get("suspicious_urls", [])
    if url_score >= 0.6 and susp_urls:
        reasons = susp_urls[0].get("reasons", [])[:3] if susp_urls else []
        domain  = susp_urls[0].get("domain", "unknown") if susp_urls else "unknown"
        expl["url_suspicion"] = (
            f"Suspicious URLs detected — highest risk domain: {domain}. "
            f"Signals: {', '.join(reasons) or 'multiple risk indicators'}. "
            f"{len(susp_urls)} of {url_detail.get('total_urls', 0)} URLs flagged."
        )
    elif url_score > 0:
        expl["url_suspicion"] = (
            f"Mildly suspicious URL signals present ({len(susp_urls)} URL(s) flagged). "
            "URLs may use uncommon TLDs, excessive subdomains, or slightly elevated entropy."
        )
    elif url_detail.get("total_urls", 0) == 0:
        expl["url_suspicion"] = "No URLs were found in this message, so URL reputation scanning was skipped."
    else:
        expl["url_suspicion"] = (
            f"All {url_detail.get('total_urls', 0)} URL(s) in this message passed reputation "
            "checks. No suspicious domains, phishing patterns, or malicious indicators found."
        )

    # ── Attachment Risk ─────────────────────────────────────────────────────
    att_score = risk_scores.get("attachment", 0)
    atts = attachment_detail.get("attachments", [])
    if att_score >= 0.7 and atts:
        top = atts[0]
        expl["attachment"] = (
            f"High-risk attachment detected: '{top.get('filename','unknown')}' "
            f"(tier: {top.get('tier','?')}, score: {round(top.get('risk_score',0)*100)}%). "
            "This file type is commonly used to deliver malware or malicious macros."
        )
    elif att_score > 0 and atts:
        top = atts[0]
        expl["attachment"] = (
            f"Moderate attachment risk: '{top.get('filename','unknown')}' "
            f"(tier: {top.get('tier','?')}). The file type warrants caution before opening."
        )
    elif attachment_detail.get("has_attachments") and not atts:
        expl["attachment"] = "Attachments detected but risk assessment found no dangerous file types."
    else:
        expl["attachment"] = (
            "No attachments were detected in this message, or all present attachments "
            "are low-risk formats (plain text, standard images)."
        )

    # ── BEC Patterns ─────────────────────────────────────────────────────────
    bec_score = risk_scores.get("bec", 0)
    if bec_score >= 0.6 and bec_hits:
        patterns = [b["pattern"] for b in bec_hits[:3]]
        expl["bec"] = (
            f"Business Email Compromise (BEC) patterns detected: "
            f"{'; '.join(patterns)}. "
            "This strongly resembles wire-fraud or executive impersonation attacks."
        )
    elif bec_score > 0 and bec_hits:
        patterns = [b["pattern"] for b in bec_hits[:2]]
        expl["bec"] = (
            f"Weak BEC signals present: {'; '.join(patterns)}. "
            "Alone these are not conclusive, but combined with other signals they raise concern."
        )
    else:
        expl["bec"] = (
            "No Business Email Compromise patterns were found. "
            "No wire transfer requests, executive impersonation, or payment diversion language detected."
        )

    # ── 419 / Advance-Fee Scam ────────────────────────────────────────────────
    scam_score = risk_scores.get("scam_419", 0)
    if scam_score >= 0.6 and scam_hits:
        patterns = [s["pattern"] for s in scam_hits[:3]]
        expl["scam_419"] = (
            f"Strong 419/advance-fee scam signals: {'; '.join(patterns)}. "
            "These patterns are hallmarks of Nigerian Prince, lottery, or inheritance scams."
        )
    elif scam_score > 0 and scam_hits:
        patterns = [s["pattern"] for s in scam_hits[:2]]
        expl["scam_419"] = (
            f"Mild 419 scam indicators: {'; '.join(patterns)}. "
            "These alone are not definitive, but warrant caution."
        )
    else:
        expl["scam_419"] = (
            "No advance-fee scam or 419-type language was detected. "
            "No references to foreign funds, lottery winnings, beneficiaries, or processing fees."
        )

    # ── Language Phishing ─────────────────────────────────────────────────────
    lang_score = risk_scores.get("language_phishing", 0)
    urgency     = language_detail.get("urgency_hits", [])
    financial   = language_detail.get("financial_hits", [])
    cred_req    = language_detail.get("credential_request_hits", [])
    if lang_score >= 0.6:
        parts = []
        if urgency:    parts.append(f"urgency phrases ({len(urgency)} hit(s): '{urgency[0]}')")
        if financial:  parts.append(f"financial keywords ({len(financial)} hit(s): '{financial[0]}')")
        if cred_req:   parts.append(f"credential-harvesting language ({len(cred_req)} hit(s))")
        expl["language_phishing"] = (
            f"High phishing-language risk: {'; '.join(parts) or 'multiple strong signals'}. "
            "This pattern of language is consistently used in social-engineering attacks."
        )
    elif lang_score > 0:
        parts = []
        if urgency:   parts.append(f"urgency: '{urgency[0]}'")
        if financial: parts.append(f"financial: '{financial[0]}'")
        expl["language_phishing"] = (
            f"Mild phishing-language signals: {', '.join(parts)}. "
            "Some pressure or financial language present, but below the high-risk threshold."
        )
    else:
        expl["language_phishing"] = (
            "No phishing-characteristic language was detected. "
            "The message does not contain urgency pressure, credential-harvesting requests, "
            "or suspicious financial language."
        )

    # ── AI Generated Content ─────────────────────────────────────────────────
    ai_prob  = risk_scores.get("ai_generated", 0)
    markers  = ai_detail.get("markers", [])
    if ai_prob >= 0.7:
        top_markers = markers[:3] if markers else []
        expl["ai_generated"] = (
            f"Strong indicators of AI-generated text (probability: {round(ai_prob*100)}%). "
            f"Signals: {', '.join(top_markers) or 'uniform sentence length, low burstiness, formal tone'}. "
            "Automated text generation is common in large-scale phishing campaigns."
        )
    elif ai_prob > 0.3:
        expl["ai_generated"] = (
            f"Moderate AI-generation probability ({round(ai_prob*100)}%). "
            "Some statistical uniformity detected in sentence structure and vocabulary."
        )
    else:
        expl["ai_generated"] = (
            f"Text shows human-like writing characteristics (AI probability: {round(ai_prob*100)}%). "
            "High sentence-length variability and natural vocabulary diversity were observed."
        )

    return expl


def _classify(homograph_risk, credential_risk, url_risk, attachment_risk,
              language_risk, bec_score, scam_score, ai_prob) -> dict:
    """Determine primary classification and verdict."""

    # Priority-ordered classification
    # 1. Homograph attack in URL = almost certainly phishing
    if homograph_risk >= 0.9:
        return {"label": "PHISHING", "sub": "homograph_attack",
                "confidence": 0.98, "verdict": "REJECT"}

    # 2. Credential exposure = data leak (different from phishing)
    if credential_risk >= 0.8:
        return {"label": "CREDENTIAL_EXPOSURE", "sub": "credential_leak",
                "confidence": 0.95, "verdict": "QUARANTINE"}

    # 3. 419 / Advance fee scam
    if scam_score >= 0.7:
        return {"label": "SCAM_419", "sub": "advance_fee",
                "confidence": min(scam_score, 0.95), "verdict": "REJECT"}

    # 4. BEC (wire fraud)
    if bec_score >= 0.6:
        return {"label": "BEC", "sub": "wire_fraud",
                "confidence": min(bec_score, 0.95), "verdict": "REJECT"}

    # 5. Suspicious URL with phishing indicators
    if url_risk >= 0.6:
        if attachment_risk >= 0.5:
            return {"label": "PHISHING", "sub": "url_attachment_combo",
                    "confidence": 0.90, "verdict": "REJECT"}
        return {"label": "PHISHING", "sub": "suspicious_url",
                "confidence": min(url_risk, 0.90), "verdict": "REJECT"}

    # 6. Dangerous attachment
    if attachment_risk >= 0.7:
        return {"label": "MALWARE", "sub": "dangerous_attachment",
                "confidence": min(attachment_risk, 0.92), "verdict": "REJECT"}

    # 7. Mixed language + phishing patterns (require meaningful URL or attachment signal)
    if language_risk >= 0.5 and (url_risk >= 0.4 or attachment_risk >= 0.5):
        return {"label": "PHISHING", "sub": "multilingual_phishing",
                "confidence": 0.80, "verdict": "REJECT"}

    # 8. High-confidence language phishing alone (multiple strong patterns, no URL/attachment needed)
    if language_risk >= 0.75:
        return {"label": "SUSPICIOUS", "sub": "language_phishing",
                "confidence": language_risk, "verdict": "QUARANTINE"}

    # 9. Moderate suspicion = quarantine ONLY with corroborating signal
    # Language patterns alone are not enough — require URL or attachment risk too
    combined_risk = max(homograph_risk, url_risk, attachment_risk, bec_score * 0.7)
    lang_combined = language_risk if (url_risk >= 0.4 or attachment_risk >= 0.5) else 0.0
    overall = max(combined_risk, lang_combined)
    if overall >= 0.55:
        return {"label": "SUSPICIOUS", "sub": "moderate_risk",
                "confidence": overall, "verdict": "QUARANTINE"}

    # 10. Clean
    return {"label": "LEGITIMATE", "sub": "clean",
            "confidence": 1.0 - overall, "verdict": "ACCEPT"}


def _build_summary(classification, homograph, credentials, languages,
                   urls, attachments, bec_hits, scam_hits) -> str:
    """Build a human-readable summary of the analysis."""
    parts = []
    label = classification["label"]

    if label == "PHISHING":
        if homograph["has_homoglyphs"] and homograph["affected_urls"]:
            chars = ", ".join(f"{c['name']} ({c['char']}→{c['looks_like']})"
                            for c in homograph["confusable_chars"][:3])
            parts.append(f"⚠️ HOMOGRAPH ATTACK detected: {chars}")
            for u in homograph["affected_domains"][:2]:
                parts.append(f"   Fake domain: {u['original']} → real: {u['deconfused']}")
        if urls["suspicious_urls"]:
            for u in urls["suspicious_urls"][:2]:
                parts.append(f"🔗 Suspicious URL: {u['domain']} ({', '.join(u['reasons'][:2])})")
        if languages["is_mixed"]:
            parts.append(f"🌐 Mixed languages: {', '.join(languages['languages_found'])}")
        if attachments["has_attachments"]:
            for a in attachments["attachments"][:2]:
                parts.append(f"📎 Risky attachment: {a['filename']} [{a['tier']}]")

    elif label == "CREDENTIAL_EXPOSURE":
        for c in credentials["credentials"][:3]:
            parts.append(f"🔑 {c['type']}: {c['value']} [{c['severity']}]")

    elif label == "BEC":
        for b in bec_hits[:3]:
            parts.append(f"💼 BEC signal: {b['pattern']}")

    elif label == "SCAM_419":
        for s in scam_hits[:3]:
            parts.append(f"🎭 Scam signal: {s['pattern']}")

    elif label == "MALWARE":
        for a in attachments["attachments"][:2]:
            parts.append(f"🦠 Dangerous file: {a['filename']} [{a['tier']}]")
        for d in attachments["dangerous_context"][:2]:
            parts.append(f"   Context: {d['pattern']}")

    elif label == "LEGITIMATE":
        parts.append("✅ No significant threats detected")

    if not parts:
        parts.append(f"Classification: {label} (confidence: {classification['confidence']:.0%})")

    return "\n".join(parts)


# ── Ollama Explainability ────────────────────────────────────────────────────
def generate_explanation(analysis: dict, subject: str, body_preview: str = "") -> str:
    """
    Call Ollama qwen3:8b to generate natural language explanation.
    Falls back to rule-based summary if Ollama is unavailable.
    """
    try:
        import requests
        ollama_url = os.environ.get("OLLAMA_URL", "http://sandbox_ollama:11434")

        prompt = f"""You are a cybersecurity email analyst. Analyze this email and explain your threat assessment in 2-3 clear sentences.

Subject: {subject}
Body preview: {body_preview[:300]}

Analysis results:
- Classification: {analysis['classification']} ({analysis['confidence']:.0%} confidence)
- Verdict: {analysis['verdict']}
- Risk scores: {json.dumps(analysis['risk_scores'])}
- Key findings: {analysis['summary']}

Provide a concise, professional explanation of why this email is classified as {analysis['classification']}. Focus on the most critical evidence. Do not repeat the raw data — explain what it means for the recipient. /no_think"""

        resp = requests.post(
            f"{ollama_url}/api/generate",
            json={"model": "qwen3:8b", "prompt": prompt, "stream": False},
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json().get("response", analysis["summary"])
    except Exception as e:
        logger.warning(f"Ollama explanation failed: {e}")

    return analysis["summary"]
