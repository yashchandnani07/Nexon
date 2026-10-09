# Attachment Scanner — Main Entry Point
# Rule-based malicious attachment detection with 4-phase structured output

import time
import uuid
from datetime import datetime, timezone

from magic_detector import detect
from pdf_analyzer import analyze as analyze_pdf
from office_analyzer import analyze as analyze_office
from pe_analyzer import analyze as analyze_pe
from zip_analyzer import analyze as analyze_zip
from pattern_engine import scan as scan_patterns
from hash_checker import check as check_hash
from html_analyzer import analyze as analyze_html
from image_analyzer import analyze as analyze_image
from credential_scanner import scan as scan_credentials

# Analyzers that are active per file type
PDF_EXTENSIONS   = {".pdf"}
OFFICE_EXTENSIONS = {
    ".doc", ".xls", ".ppt",
    ".docx", ".xlsx", ".pptx",
    ".docm", ".xlsm", ".pptm",
}
HTML_EXTENSIONS  = {".htm", ".html", ".xhtml", ".shtml", ".svg"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".tif", ".ico"}

# Risk tier ordering for comparisons
TIER_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def _tier_to_status(tier: str) -> str:
    """Convert risk tier label to a UI-friendly status string."""
    mapping = {
        "Critical": "critical",
        "High":     "high",
        "Medium":   "medium",
        "Low":      "low",
        "Info":     "info",
        "Clean":    "clean",
    }
    return mapping.get(tier, "clean")


def _parse_error_finding(analyzer_name: str, exc: Exception) -> dict:
    """
    Produce a graceful Info-level finding when an analyzer fails.
    Ensures malformed/corrupt files never crash the pipeline.
    """
    return {
        "stage":       analyzer_name,
        "rule":        "parse_error",
        "description": f"{analyzer_name} encountered a parse error: {type(exc).__name__}",
        "detail":      str(exc)[:200],
        "risk_tier":   "Info",
        "category":    "scanner_error",
        "context":     "",
        "why_flagged": "The file may be malformed or corrupt — partial analysis completed",
    }


def _findings_status(findings: list) -> str:
    """Derive highest-severity status from a list of findings."""
    if not findings:
        return "clean"
    best = max(
        (TIER_ORDER.get(f.get("risk_tier", "Low"), 1) for f in findings),
        default=0
    )
    reverse = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
    return reverse.get(best, "clean")


def _group_by_stage(findings: list) -> dict:
    """Group findings list into dict keyed by stage name."""
    groups = {}
    for f in findings:
        stage = f.get("stage", "Unknown")
        groups.setdefault(stage, []).append(f)
    return groups


def _fp_guard(score: int, all_findings: list, file_type: dict) -> int:
    """
    Dampen false positives for benign file types with low-signal findings.
    Called as the final step in score calculation.
    """
    mime = file_type.get("mime_type", "")
    is_benign_type = (
        mime.startswith("image/") or
        mime in ("text/html", "application/xhtml+xml", "text/plain")
    )
    severities = {f.get("risk_tier", "Low") for f in all_findings}
    stages     = {f.get("stage", "") for f in all_findings}
    has_mismatch = file_type.get("extension_mismatch", False)

    if has_mismatch:
        # Never dampen evasion — mismatch is always intentional
        return score

    # Benign type + only Low/Info findings → cap at 25 (Low verdict max)
    if is_benign_type and severities <= {"Low", "Info"}:
        return min(score, 25)

    # YARA-only match with no Critical findings → dampen by 30%
    # (YARA community rules have many low-fidelity generic signatures)
    if stages <= {"YARA Pattern Engine", "YARA-style Pattern Engine"} and "Critical" not in severities:
        return int(score * 0.70)

    # Single Low-tier finding on a benign MIME → Info, not Low
    if is_benign_type and len(all_findings) == 1 and severities == {"Low"}:
        return min(score, 5)

    return score


def calculate_final_risk(
    all_findings: list,
    file_type: dict,
    hash_result: dict,
    filename: str,
) -> dict:
    from magic_detector import HIGH_RISK_EXTENSIONS, MEDIUM_RISK_EXTENSIONS

    ext   = file_type.get("declared_extension", "")
    score = 0

    # Known malware hash — instant maximum
    if hash_result.get("known_malware"):
        score += 100

    # High-risk extension base score
    if ext in HIGH_RISK_EXTENSIONS:
        score += 50

    # Medium-risk extension base score (.pdf included via file-type risk)
    if ext in MEDIUM_RISK_EXTENSIONS:
        score += 20

    # PDF gets a small base since it carries its own deep analyzer
    if ext == ".pdf" or file_type.get("mime_type", "").startswith("application/pdf"):
        score += 10

    # Extension mismatch is a strong evasion indicator
    if file_type.get("extension_mismatch"):
        score += 40

    # High-risk MIME type detected (even without a risky extension)
    from magic_detector import HIGH_RISK_MIMES
    if file_type.get("mime_type") in HIGH_RISK_MIMES:
        score += 30

    # Finding severity weights — Critical findings carry extra weight
    tier_points = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3}

    # Bonus multiplier when multiple Critical findings are present
    critical_count = sum(
        1 for f in all_findings if f.get("risk_tier") == "Critical"
    )
    for finding in all_findings:
        pts = tier_points.get(finding.get("risk_tier", "Low"), 3)
        # 2nd+ critical findings score extra (layered attack signatures)
        if finding.get("risk_tier") == "Critical" and critical_count >= 2:
            pts = int(pts * 1.4)
        score += pts

    # Credential exposure bonus — adds urgency even if file type is benign
    cred_findings = [f for f in all_findings if f.get("stage") == "Credential Exposure Scanner"]
    cred_types    = {f.get("rule") for f in cred_findings}
    cred_bonus    = min(len(cred_types) * 20, 60)  # +20 per credential type, max +60
    score        += cred_bonus

    score = min(score, 100)

    # Apply false-positive guard before finalizing
    score = _fp_guard(score, all_findings, file_type)
    score = min(max(score, 0), 100)

    # Assign final label
    if score >= 80:
        label = "Critical"
    elif score >= 60:
        label = "High"
    elif score >= 35:
        label = "Medium"
    elif score > 0:
        label = "Low"
    else:
        label = "Clean"

    return {"score": score, "label": label}


def analyze_attachment(file_bytes: bytes, filename: str) -> dict:
    start_time = time.time()

    ext = (
        "." + filename.lower().rsplit(".", 1)[-1]
        if "." in filename else ""
    )

    # ── Phase 1: File Type Detection ──────────────────────────────────────────
    file_type = detect(file_bytes, filename)

    phase1_findings = []
    if file_type.get("extension_mismatch"):
        phase1_findings.append({
            "stage":       "File Type Detection",
            "rule":        "extension_mismatch",
            "description": file_type.get("mismatch_desc", "Extension mismatch detected"),
            "detail":      "Declared file extension does not match actual binary content",
            "risk_tier":   "Critical",
            "category":    "evasion",
            "context":     "",
            "why_flagged": "Extension mismatch is a deliberate evasion technique — the file pretends to be one type while containing another, bypassing filters that rely on extension alone",
        })

    # ── Phase 2: Deep Content Analysis ────────────────────────────────────────
    analyzers_run  = []
    deep_findings  = []

    is_pdf    = ext in PDF_EXTENSIONS or file_bytes[:4] == b"\x25\x50\x44\x46"
    is_office = ext in OFFICE_EXTENSIONS
    is_pe     = file_bytes[:2] == b"\x4d\x5a"
    is_zip    = file_bytes[:4] == b"\x50\x4b\x03\x04"
    is_html   = (
        ext in HTML_EXTENSIONS or
        file_type.get("mime_type", "").startswith("text/html") or
        file_type.get("mime_type") == "application/xhtml+xml" or
        file_bytes[:9].lower() in (b"<!doctype", b"<html>   ") or
        file_bytes[:5].lower() in (b"<html", b"<?xml")
    )
    is_image  = (
        ext in IMAGE_EXTENSIONS or
        (file_type.get("mime_type", "").startswith("image/") and not is_pe)
    )

    if is_pdf:
        try:
            pdf_findings = analyze_pdf(file_bytes)
        except Exception as e:
            pdf_findings = [_parse_error_finding("PDF Stream Analyzer", e)]
        analyzers_run.append({
            "name":            "PDF Stream Analyzer",
            "status":          _findings_status(pdf_findings),
            "findings_count":  len(pdf_findings),
            "findings":        pdf_findings,
            "description":     "4-layer PDF analysis: binary streams, object tree (pikepdf), metadata/URLs (PyMuPDF), stream text (pdfminer)",
        })
        deep_findings += pdf_findings

    if is_office:
        try:
            office_findings = analyze_office(file_bytes, filename)
        except Exception as e:
            office_findings = [_parse_error_finding("Office Macro Extractor", e)]
        analyzers_run.append({
            "name":            "Office Macro Extractor",
            "status":          _findings_status(office_findings),
            "findings_count":  len(office_findings),
            "findings":        office_findings,
            "description":     "Scans for VBA macros, DDE injection, remote templates, XLM legacy macros, and XML patterns",
        })
        deep_findings += office_findings

    if is_pe:
        try:
            pe_findings = analyze_pe(file_bytes)
        except Exception as e:
            pe_findings = [_parse_error_finding("PE Header Analyzer", e)]
        analyzers_run.append({
            "name":            "PE Header Analyzer",
            "status":          _findings_status(pe_findings),
            "findings_count":  len(pe_findings),
            "findings":        pe_findings,
            "description":     "Scans PE import table, section entropy, packer detection, suspicious strings and embedded URLs",
        })
        deep_findings += pe_findings

    if is_zip:
        try:
            zip_findings = analyze_zip(file_bytes)
        except Exception as e:
            zip_findings = [_parse_error_finding("ZIP/Archive Analyzer", e)]

        # Split into structural vs deep-scan findings for better UI grouping
        structural = [f for f in zip_findings if f.get("stage") != "ZIP Deep Scan"]
        deep_scan  = [f for f in zip_findings if f.get("stage") == "ZIP Deep Scan"]

        analyzers_run.append({
            "name":            "ZIP/Archive Analyzer",
            "status":          _findings_status(structural),
            "findings_count":  len(structural),
            "findings":        structural,
            "description":     "Inspects archive structure, filenames, and content signatures for bombs, path traversal, and executables",
        })
        if deep_scan:
            analyzers_run.append({
                "name":            "ZIP Deep Scan",
                "status":          _findings_status(deep_scan),
                "findings_count":  len(deep_scan),
                "findings":        deep_scan,
                "description":     "Recursively extracts inner files and runs HTML, image, PDF, Office, and credential analyzers on each",
            })
        deep_findings += zip_findings

    if is_html:
        try:
            html_findings = analyze_html(file_bytes)
        except Exception as e:
            html_findings = [_parse_error_finding("HTML Analyzer", e)]
        analyzers_run.append({
            "name":            "HTML Analyzer",
            "status":          _findings_status(html_findings),
            "findings_count":  len(html_findings),
            "findings":        html_findings,
            "description":     "5-layer HTML analysis: script tags, obfuscated JS (eval/atob/fromCharCode), credential-harvesting forms, hidden iframes, meta-refresh redirects",
        })
        deep_findings += html_findings

    if is_image:
        try:
            image_findings = analyze_image(file_bytes, filename)
        except Exception as e:
            image_findings = [_parse_error_finding("Image Analyzer", e)]
        analyzers_run.append({
            "name":            "Image Analyzer",
            "status":          _findings_status(image_findings),
            "findings_count":  len(image_findings),
            "findings":        image_findings,
            "description":     "4-layer image analysis: EXIF metadata (GPS, suspicious software), pixel entropy (steganography), QR code decode, metadata anomalies",
        })
        deep_findings += image_findings

    # YARA / pattern engine always runs
    try:
        pattern_findings = scan_patterns(file_bytes)
    except Exception as e:
        pattern_findings = [_parse_error_finding("YARA Pattern Engine", e)]
    analyzers_run.append({
        "name":            "YARA Pattern Engine",
        "status":          _findings_status(pattern_findings),
        "findings_count":  len(pattern_findings),
        "findings":        pattern_findings,
        "description":     "Matches against YARA community rules (1900+ signatures) covering ransomware, shellcode, LOLBins, macros and more",
    })
    deep_findings += pattern_findings

    # Credential exposure scanner — universal, runs on ALL file types
    try:
        cred_findings = scan_credentials(file_bytes)
    except Exception as e:
        cred_findings = [_parse_error_finding("Credential Exposure Scanner", e)]
    if cred_findings:
        analyzers_run.append({
            "name":            "Credential Exposure Scanner",
            "status":          _findings_status(cred_findings),
            "findings_count":  len(cred_findings),
            "findings":        cred_findings,
            "description":     "Universal cross-file credential scan: API keys, tokens, private keys, email:password pairs, connection strings",
        })
        deep_findings += cred_findings

    # Combine all findings (phase 1 evasion + deep analysis)
    all_findings = phase1_findings + deep_findings

    # ── Phase 3: Hash Reputation ───────────────────────────────────────────────
    hash_result = check_hash(file_bytes)

    # ── Phase 4: Risk Verdict ─────────────────────────────────────────────────
    risk               = calculate_final_risk(all_findings, file_type, hash_result, filename)
    human_summary      = _build_summary(all_findings, file_type, hash_result, risk)
    recommended_action = _build_action(risk["label"])

    # ── Count by severity ──────────────────────────────────────────────────────
    def count(tier):
        return sum(1 for f in all_findings if f.get("risk_tier") == tier)

    # ── Structured phase output ────────────────────────────────────────────────
    p1_status = "critical" if file_type.get("extension_mismatch") else _tier_to_status(file_type.get("risk_level", "Info"))

    phases = [
        {
            "id":      1,
            "name":    "File Type Detection",
            "icon":    "fingerprint",
            "status":  p1_status,
            "summary": _phase1_summary(file_type),
            "details": {
                "declared_extension": file_type.get("declared_extension"),
                "detected_type":      file_type.get("detected_type"),
                "mime_type":          file_type.get("mime_type"),
                "extension_mismatch": file_type.get("extension_mismatch", False),
                "mismatch_desc":      file_type.get("mismatch_desc", ""),
                "risk_level":         file_type.get("risk_level"),
                "detection_method":   file_type.get("detection_method"),
                "file_size_kb":       file_type.get("file_size_kb"),
            },
            "findings": phase1_findings,
        },
        {
            "id":             2,
            "name":           "Deep Content Analysis",
            "icon":           "search",
            "status":         _findings_status(deep_findings),
            "summary":        _phase2_summary(analyzers_run, deep_findings),
            "analyzers":      analyzers_run,
            "total_findings": len(deep_findings),
        },
        {
            "id":      3,
            "name":    "Hash Reputation Check",
            "icon":    "hash",
            "status":  "critical" if hash_result.get("known_malware") else "clean",
            "summary": _phase3_summary(hash_result),
            "details": {
                "md5":           hash_result.get("md5"),
                "sha1":          hash_result.get("sha1"),
                "sha256":        hash_result.get("sha256"),
                "verdict":       hash_result.get("verdict"),
                "known_malware": hash_result.get("known_malware"),
                "source":        hash_result.get("source"),
                "malware_details": hash_result.get("details"),
                "database_size": hash_result.get("database_size"),
                "mode":          hash_result.get("malwarebazaar"),
            },
        },
        {
            "id":                 4,
            "name":               "Risk Verdict",
            "icon":               "verdict",
            "status":             _tier_to_status(risk["label"]),
            "summary":            human_summary,
            "score":              risk["score"],
            "label":              risk["label"],
            "human_summary":      human_summary,
            "recommended_action": recommended_action,
            "severity_breakdown": {
                "critical": count("Critical"),
                "high":     count("High"),
                "medium":   count("Medium"),
                "low":      count("Low"),
            },
        },
    ]

    return {
        "module":             "Malicious Attachment Analyzer",
        "filename":           filename,
        "file_size_kb":       file_type["file_size_kb"],
        "phases":             phases,
        "all_findings":       all_findings,
        "total_findings":     len(all_findings),
        "critical_count":     count("Critical"),
        "high_count":         count("High"),
        "medium_count":       count("Medium"),
        "low_count":          count("Low"),
        "risk_score":         risk["score"],
        "risk_label":         risk["label"],
        "human_summary":      human_summary,
        "recommended_action": recommended_action,
        "analysis_time_ms":   round((time.time() - start_time) * 1000, 1),
        "scan_id":            str(uuid.uuid4()),
        "scanned_at":         datetime.now(timezone.utc).isoformat(),
    }


# ── Phase summary helpers ──────────────────────────────────────────────────────

def _phase1_summary(file_type: dict) -> str:
    ext      = file_type.get("declared_extension", "N/A")
    detected = file_type.get("detected_type", "Unknown")
    if file_type.get("extension_mismatch"):
        return f"⚠ Mismatch: {file_type.get('mismatch_desc', 'Extension mismatch')}"
    return f"{ext.upper().lstrip('.')} · {detected}"


def _phase2_summary(analyzers: list, findings: list) -> str:
    if not findings:
        return "No suspicious indicators detected in file content"
    active = [a for a in analyzers if a["findings_count"] > 0]
    names  = ", ".join(a["name"] for a in active)
    return f"{len(findings)} indicator(s) across {len(active)} analyzer(s): {names}"


def _phase3_summary(hash_result: dict) -> str:
    if hash_result.get("known_malware"):
        return f"MATCH: {hash_result['known_malware']} · Source: {hash_result.get('source', 'unknown')}"
    db = hash_result.get("database_size", "")
    return f"Not found in threat database · {db}"


def _build_summary(findings: list, file_type: dict, hash_result: dict, risk: dict) -> str:
    parts = []

    if not findings and not hash_result.get("known_malware"):
        return "No suspicious indicators detected. File appears safe."

    if hash_result.get("known_malware"):
        parts.append(f"Hash matches known malware: {hash_result['known_malware']}.")

    if file_type.get("extension_mismatch"):
        parts.append("File extension does not match actual content (evasion technique).")

    stages_seen: dict = {}
    for f in findings:
        stage = f.get("stage", "Unknown")
        stages_seen[stage] = stages_seen.get(stage, 0) + 1

    if stages_seen:
        stage_parts = [
            f"{cnt} finding(s) from {stage}"
            for stage, cnt in stages_seen.items()
        ]
        parts.append(
            f"Found {len(findings)} indicator(s): " + ", ".join(stage_parts) + "."
        )

    crit = sum(1 for f in findings if f.get("risk_tier") == "Critical")
    high = sum(1 for f in findings if f.get("risk_tier") == "High")
    if crit:
        parts.append(f"{crit} critical-severity indicator(s).")
    if high:
        parts.append(f"{high} high-severity indicator(s).")

    return " ".join(parts) if parts else "Scan complete."


def _build_action(label: str) -> str:
    actions = {
        "Clean":    "No action required. File appears safe to open.",
        "Low":      "Low risk — verify file origin before opening.",
        "Medium":   "Quarantine file and review with your security team.",
        "High":     "Block file immediately. Investigate source and alert SOC.",
        "Critical": "IMMEDIATE ACTION: Block, quarantine, escalate to SOC, notify compliance.",
    }
    return actions.get(label, "Review manually.")