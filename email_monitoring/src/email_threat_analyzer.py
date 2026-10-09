"""
email_threat_analyzer.py
────────────────────────────────────────────────────────────────────────────
Master Email Threat Analysis Pipeline

Accepts the unified email input schema and runs all 4 modules in sequence,
returning the exact unified JSON output defined in the spec.

Input schema:
  {
    "from_name": str,
    "from_email": str,
    "subject": str,
    "body": str,
    "attachments": ["filename.ext"],   # filenames or absolute paths
    "urls": ["https://..."]
  }

Modules:
  1. Phishing Detection      — DistilBERT (bert_detector.py)
  2. Voice Deepfake Analysis — best_eer_v2.pt + XGBoost/RF MFCC ensemble
  3. Sensitive Data          — Regex + spaCy NER
  4. URL Security Scanner    — PhishGuard 6-layer pipeline

Overall Risk Score:
  score = phishing_conf*0.35 + max(voice_risk)*0.30
        + max(url_ml_risk)*0.25 + (sensitive_data_found*10)*0.10
  ≥70 → HIGH 🔴 / BLOCK
  ≥40 → MEDIUM 🟡 / REVIEW
  <40 → LOW 🟢 / ALLOW
"""
from __future__ import annotations

import os
import sys
import time
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Path setup ────────────────────────────────────────────────────────────────
_SRC_DIR = Path(__file__).parent
sys.path.insert(0, str(_SRC_DIR))

# ── Audio formats ─────────────────────────────────────────────────────────────
_AUDIO_EXTENSIONS = {
    ".wav", ".flac", ".ogg", ".mp3",
    ".m4a", ".aac", ".wma", ".mp4",
    ".webm", ".3gp",
}
_NATIVE_AUDIO = {".wav", ".flac", ".ogg"}
_FFMPEG_AUDIO = {".mp3", ".m4a", ".aac", ".wma", ".mp4", ".webm", ".3gp"}


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 1 — Phishing Detection (DistilBERT)
# ─────────────────────────────────────────────────────────────────────────────

def _run_phishing_module(subject: str, body: str) -> Dict:
    """
    Run DistilBERT phishing classifier on subject + body.
    Returns Module 1 output block.
    """
    try:
        from bert_detector import DistilBertEmailDetector
        detector = DistilBertEmailDetector()
        text     = f"{subject}\n\n{body}"
        res      = detector.predict(text)

        # Normalise to spec schema
        raw_label = res.get("label", "legitimate")
        if raw_label == "phishing":
            verdict    = "THREAT 🚨"
            top_cat    = "Phishing"
            risk_level = res.get("risk_level", "HIGH 🔴")
        else:
            verdict    = "CLEAN ✅"
            top_cat    = "Legitimate Email"
            risk_level = res.get("risk_level", "LOW 🟢")

        # Parse confidence as float (handles "87.30%" or 0.873)
        raw_conf = res.get("confidence", "50%")
        conf_f   = _parse_percent(raw_conf)

        # Normalise risk_level emoji label
        if "HIGH" in risk_level.upper() or "CRITICAL" in risk_level.upper():
            risk_norm = "HIGH 🔴"
        elif "MEDIUM" in risk_level.upper():
            risk_norm = "MEDIUM 🟡"
        else:
            risk_norm = "LOW 🟢"

        return {
            "verdict":      verdict,
            "confidence":   f"{conf_f:.1f}%",
            "confidence_f": conf_f,          # float for risk formula
            "top_category": top_cat,
            "risk_level":   risk_norm,
            "note":         res.get("note", ""),
            "model":        res.get("model", "distilbert-finetuned"),
        }

    except Exception as exc:
        return {
            "verdict":      "CLEAN ✅",
            "confidence":   "0.0%",
            "confidence_f": 0.0,
            "top_category": "Legitimate Email",
            "risk_level":   "LOW 🟢",
            "note":         f"Phishing module error: {exc}",
            "model":        "error",
        }


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 2 — Voice Deepfake Detection
# ─────────────────────────────────────────────────────────────────────────────

def _run_voice_module(attachments: List[str]) -> Dict:
    """
    Analyse all audio attachments.
    Each attachment can be a filename (skipped with note) or an absolute path.
    Returns Module 2 output block.
    """
    try:
        from voice.evaluate import analyze_audio_file
    except ImportError as ie:
        return {
            "total_audio_files": 0,
            "scanned":           0,
            "skipped":           0,
            "flagged_as_fake":   0,
            "results":           [],
            "error":             f"Voice module unavailable: {ie}",
        }

    audio_files = [
        a for a in attachments
        if Path(a).suffix.lower() in _AUDIO_EXTENSIONS
    ]

    results: List[Dict] = []
    scanned  = 0
    skipped  = 0
    flagged  = 0

    ffmpeg_present = shutil.which("ffmpeg") is not None

    for att in audio_files:
        ext = Path(att).suffix.lower()
        fn  = Path(att).name

        # If it's not an absolute path, we can only report skipped
        if not os.path.isabs(att) and not os.path.exists(att):
            skip_reason = "File path not provided — only filename given"
            results.append({
                "filename":           fn,
                "format":             ext,
                "verdict":            "SKIPPED ⏭️",
                "risk_score":          0,
                "risk_tier":           "LOW 🟢",
                "confidence":          "0.0%",
                "best_eer_score":      0.0,
                "xgboost_score":       0.0,
                "mfcc_features_used":  40,
                "model_agreement":     False,
                "recommended_action":  "ALLOW",
                "skip_reason":         skip_reason,
            })
            skipped += 1
            continue

        # Check ffmpeg availability for formats that need it
        if ext in _FFMPEG_AUDIO and not ffmpeg_present:
            results.append({
                "filename":           fn,
                "format":             ext,
                "verdict":            "SKIPPED ⏭️",
                "risk_score":          0,
                "risk_tier":           "LOW 🟢",
                "confidence":          "0.0%",
                "best_eer_score":      0.0,
                "xgboost_score":       0.0,
                "mfcc_features_used":  40,
                "model_agreement":     False,
                "recommended_action":  "ALLOW",
                "skip_reason":         (
                    f"ffmpeg not installed — required to decode {ext} files. "
                    "Install from https://ffmpeg.org/download.html"
                ),
            })
            skipped += 1
            continue

        # Run analysis
        res = analyze_audio_file(att, filename=fn)
        results.append(res)
        scanned += 1

        if "FAKE" in res.get("verdict", ""):
            flagged += 1
        elif res.get("verdict", "").startswith("SKIPPED"):
            skipped += 1

    return {
        "total_audio_files": len(audio_files),
        "scanned":           scanned,
        "skipped":           skipped,
        "flagged_as_fake":   flagged,
        "results":           results,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 3 — Sensitive Data Extraction
# ─────────────────────────────────────────────────────────────────────────────

def _run_sensitive_data_module(subject: str, body: str) -> Dict:
    """Run regex + NER sensitive data extraction."""
    try:
        from sensitive_data_extractor import extract_sensitive_data
        return extract_sensitive_data(subject=subject, body=body)
    except Exception as exc:
        return {
            "extracted_emails":          [],
            "extracted_phones":          [],
            "extracted_account_numbers": [],
            "extracted_names":           [],
            "sensitive_data_found":      False,
            "error":                     str(exc),
        }


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 4 — URL Security Scanner
# ─────────────────────────────────────────────────────────────────────────────

def _run_url_module(urls: List[str]) -> Dict:
    """
    Run PhishGuard full-pipeline scan on all URLs concurrently.
    Returns Module 4 output block with per-URL schema from the spec.
    """
    if not urls:
        return {
            "total_urls":     0,
            "dangerous_count": 0,
            "max_ml_risk":    0.0,
            "results":        [],
        }

    try:
        from url_scanner import fast_scan
    except ImportError as ie:
        return {
            "total_urls":      len(urls),
            "dangerous_count": 0,
            "max_ml_risk":     0.0,
            "results":         [],
            "error":           f"URL scanner unavailable: {ie}",
        }

    raw_results: List[Dict] = []

    def _scan_one(url: str) -> Dict:
        try:
            return fast_scan(url)
        except Exception as ex:
            return {
                "url":          url,
                "verdict":      "ERROR",
                "risk_score":   0.5,
                "risk_score_pct": 50.0,
                "details":      {"ml_model": {"label": "error", "probability": 50.0}},
                "error":        str(ex),
            }

    with ThreadPoolExecutor(max_workers=min(len(urls), 5)) as ex:
        futures = {ex.submit(_scan_one, u): u for u in urls}
        for fut in as_completed(futures, timeout=30):
            try:
                raw_results.append(fut.result(timeout=30))
            except Exception:
                pass

    # Re-order to match input order
    url_map = {r.get("url", r.get("original_url", "")): r for r in raw_results}
    ordered = [url_map.get(u, {"url": u, "verdict": "ERROR"}) for u in urls]

    # Build per-URL spec schema
    per_url: List[Dict] = []
    max_ml_risk = 0.0
    dangerous   = 0

    for r in ordered:
        ml      = r.get("details", {}).get("ml_model", {})
        ssl_d   = r.get("details", {}).get("ssl",   {})
        whois_d = r.get("details", {}).get("whois", {})
        metrics = r.get("metrics", {})

        ml_conf_raw  = ml.get("probability", 0.0)
        ml_conf_f    = float(ml_conf_raw) / 100.0 if ml_conf_raw > 1 else float(ml_conf_raw)
        max_ml_risk  = max(max_ml_risk, ml_conf_f)

        raw_verdict  = r.get("verdict", "ERROR")
        ml_verdict   = (
            "PHISHING" if raw_verdict in ("DANGEROUS", "PHISHING") else
            "CLEAN"    if raw_verdict in ("SAFE", "CLEAN") else
            "ERROR"
        )
        is_dangerous = raw_verdict in ("DANGEROUS", "PHISHING") or ml_conf_f >= 0.70

        if is_dangerous:
            dangerous += 1

        ssl_status = ssl_d.get("status", "")
        if ssl_status in ("valid", "ok"):
            ssl_label = "Valid"
        elif ssl_status in ("expired",):
            ssl_label = "Expired"
        elif ssl_status in ("invalid", "error", "no_ssl", "no_https"):
            ssl_label = "Invalid"
        else:
            ssl_label = "Deep scan req."

        per_url.append({
            "url":                r.get("url", ""),
            "ml_verdict":         ml_verdict,
            "ml_confidence":      f"{ml_conf_f * 100:.1f}%",
            "ssl_status":         ssl_label,
            "domain_age_days":    whois_d.get("age_days", None),
            "whois_registrar":    whois_d.get("registrar", None),
            "domain_host":        r.get("domain", ""),
            "deep_scan_available": True,
            "is_dangerous":       is_dangerous,
        })

    return {
        "total_urls":      len(urls),
        "dangerous_count": dangerous,
        "max_ml_risk":     round(max_ml_risk, 4),
        "results":         per_url,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  OVERALL RISK SCORE
# ─────────────────────────────────────────────────────────────────────────────

def _compute_overall_risk(
    phish:      Dict,
    voice:      Dict,
    sensitive:  Dict,
    url_data:   Dict,
) -> Dict:
    """
    overall_risk_score = (
      phishing_confidence * 0.35
      + max(voice_risk_scores)  * 0.30
      + max(url_ml_risk)        * 0.25
      + sensitive_data_found * 10 * 0.10
    )
    ≥70 → HIGH 🔴 / BLOCK
    ≥40 → MEDIUM 🟡 / REVIEW
    <40 → LOW 🟢 / ALLOW
    """
    phish_conf = phish.get("confidence_f", 0.0) / 100.0  # stored as float %

    # Max voice risk (0-1 from risk_score 0-100)
    voice_scores = [
        r.get("risk_score", 0) / 100.0
        for r in voice.get("results", [])
        if not r.get("verdict", "").startswith("SKIPPED")
    ]
    max_voice = max(voice_scores) if voice_scores else 0.0

    # Max URL ML risk (already 0-1)
    max_url = float(url_data.get("max_ml_risk", 0.0))

    # Sensitive data flag (0 or 10, weight 0.10)
    sens_flag = 10.0 if sensitive.get("sensitive_data_found") else 0.0

    raw_score = (
        phish_conf   * 0.35
        + max_voice  * 0.30
        + max_url    * 0.25
        + sens_flag  * 0.10
    )
    # raw_score is 0-1 for the first 3 terms; sens adds at most 1.0 → cap
    overall = min(raw_score * 100, 100.0)

    if overall >= 70:
        risk_label = "HIGH 🔴"
        recommendation = "BLOCK"
    elif overall >= 40:
        risk_label = "MEDIUM 🟡"
        recommendation = "REVIEW"
    else:
        risk_label = "LOW 🟢"
        recommendation = "ALLOW"

    return {
        "overall_risk_score": round(overall, 1),
        "overall_risk":       risk_label,
        "final_recommendation": recommendation,
        "_components": {
            "phishing_contribution": round(phish_conf * 0.35 * 100, 1),
            "voice_contribution":    round(max_voice  * 0.30 * 100, 1),
            "url_contribution":      round(max_url    * 0.25 * 100, 1),
            "sensitive_contribution":round(sens_flag  * 0.10, 1),
        },
    }


def _generate_reasoning(
    phish: Dict, voice: Dict, sensitive: Dict,
    url_data: Dict, overall: Dict,
) -> str:
    """Generate a plain-English 2–3 line summary."""
    parts: List[str] = []

    risk_label = overall["overall_risk"]
    score      = overall["overall_risk_score"]
    verdict    = phish.get("verdict", "CLEAN ✅")

    # Lead sentence
    parts.append(
        f"This email has been assessed as {risk_label} "
        f"(overall risk score: {score:.0f}/100)."
    )

    # Phishing
    if "THREAT" in verdict:
        parts.append(
            f"The DistilBERT model classified the content as "
            f"{phish.get('top_category')} with "
            f"{phish.get('confidence')} confidence."
        )

    # Voice
    fake_count = voice.get("flagged_as_fake", 0)
    review_count = sum(
        1 for r in voice.get("results", [])
        if "REVIEW" in r.get("verdict", "")
    )
    if fake_count:
        parts.append(
            f"{fake_count} of {voice.get('scanned', 0)} audio attachment(s) "
            f"were flagged as AI-generated voice by the deepfake model."
        )
    elif review_count:
        parts.append(
            f"{review_count} audio attachment(s) require manual review "
            f"— the two MFCC models disagreed on their verdict."
        )

    # URLs
    dangerous_urls = url_data.get("dangerous_count", 0)
    if dangerous_urls:
        parts.append(
            f"{dangerous_urls} of {url_data.get('total_urls', 0)} URL(s) "
            f"were identified as dangerous by the PhishGuard scanner."
        )

    # Sensitive data
    if sensitive.get("sensitive_data_found"):
        types_found = []
        if sensitive.get("extracted_emails"):
            types_found.append("email addresses")
        if sensitive.get("extracted_phones"):
            types_found.append("phone numbers")
        if sensitive.get("extracted_account_numbers"):
            types_found.append("account/card numbers")
        if sensitive.get("extracted_names"):
            types_found.append("personal names")
        parts.append(
            f"Sensitive data detected: {', '.join(types_found)}."
        )

    # Clean summary
    if len(parts) == 1:
        parts.append(
            "No significant threat indicators were found across all analysis modules."
        )

    return " ".join(parts[:3])   # cap at 3 sentences per spec


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def analyze_email(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Master email threat analysis pipeline.

    Args:
        payload: dict matching the input schema:
          {
            "from_name":   str,
            "from_email":  str,
            "subject":     str,
            "body":        str,
            "attachments": list[str],   # filenames or absolute paths
            "urls":        list[str],
          }

    Returns:
        Unified JSON output matching the spec's final combined output schema.
    """
    t0 = time.time()

    from_name   = str(payload.get("from_name",   "") or "")
    from_email  = str(payload.get("from_email",  "") or "")
    subject     = str(payload.get("subject",     "") or "")
    body        = str(payload.get("body",        "") or "")
    attachments = list(payload.get("attachments", []) or [])
    urls        = list(payload.get("urls",        []) or [])

    # ── Run modules in parallel where independent ─────────────────────────
    phish_result: Dict  = {}
    voice_result: Dict  = {}
    sensitive_result: Dict = {}
    url_result: Dict    = {}

    with ThreadPoolExecutor(max_workers=3) as ex:
        fut_phish     = ex.submit(_run_phishing_module,    subject, body)
        fut_sensitive = ex.submit(_run_sensitive_data_module, subject, body)
        fut_url       = ex.submit(_run_url_module,         urls)
        # Voice is sequential (GPU), run after other futures start
        voice_result  = _run_voice_module(attachments)

        phish_result    = fut_phish.result()
        sensitive_result = fut_sensitive.result()
        url_result      = fut_url.result()

    # ── Compute overall risk ──────────────────────────────────────────────
    overall = _compute_overall_risk(phish_result, voice_result, sensitive_result, url_result)

    # ── Reasoning summary ─────────────────────────────────────────────────
    reasoning = _generate_reasoning(
        phish_result, voice_result, sensitive_result, url_result, overall
    )

    # ── Strip internal float field before returning ───────────────────────
    phish_public = {k: v for k, v in phish_result.items() if k != "confidence_f"}

    return {
        "email_metadata": {
            "from_name":          from_name,
            "from_email":         from_email,
            "subject":            subject,
            "overall_risk":       overall["overall_risk"],
            "overall_risk_score": overall["overall_risk_score"],
        },
        "phishing_analysis": phish_public,
        "voice_deepfake_analysis": {
            "total_audio_files": voice_result.get("total_audio_files", 0),
            "scanned":           voice_result.get("scanned",           0),
            "skipped":           voice_result.get("skipped",           0),
            "flagged_as_fake":   voice_result.get("flagged_as_fake",   0),
            "results":           voice_result.get("results",           []),
        },
        "sensitive_data": {
            "extracted_emails":          sensitive_result.get("extracted_emails",          []),
            "extracted_phones":          sensitive_result.get("extracted_phones",          []),
            "extracted_account_numbers": sensitive_result.get("extracted_account_numbers", []),
            "extracted_names":           sensitive_result.get("extracted_names",           []),
            "sensitive_data_found":      sensitive_result.get("sensitive_data_found",      False),
        },
        "url_analysis": {
            "total_urls":      url_result.get("total_urls",      0),
            "dangerous_count": url_result.get("dangerous_count", 0),
            "max_ml_risk":     url_result.get("max_ml_risk",     0.0),
            "results":         url_result.get("results",         []),
        },
        "final_recommendation": overall["final_recommendation"],
        "reasoning_summary":    reasoning,
        "_meta": {
            "processing_ms": round((time.time() - t0) * 1000),
            "risk_components": overall.get("_components", {}),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_percent(val) -> float:
    """Parse '87.30%', 0.873, or 87.3 → float percentage 0–100."""
    if isinstance(val, (int, float)):
        return float(val) * 100.0 if float(val) <= 1.0 else float(val)
    s = str(val).strip().rstrip("%")
    try:
        f = float(s)
        return f * 100.0 if f <= 1.0 else f
    except ValueError:
        return 0.0
