# attachment_scanner/pdf_analyzer.py
# Layer 2a — PDF Analyzer
#
# Four-layer analysis:
#   Layer A — Binary stream scan       (rules loaded from pdf_rules.json)
#   Layer B — Deep structure parsing   (pikepdf)
#   Layer C — Metadata + URL scan      (PyMuPDF / fitz)
#   Layer D — Stream text extraction   (pdfminer)
#
# Safe — PDF is never rendered or executed at any point.

import json
import os
import re

# ── Rules loaded from pdf_rules.json sitting next to this file ───────────────
_RULES_PATH = os.path.join(os.path.dirname(__file__), "pdf_rules.json")

def _load_rules() -> list:
    try:
        with open(_RULES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"[pdf_analyzer] pdf_rules.json not found at {_RULES_PATH}. "
            "Place pdf_rules.json in the attachment_scanner/ folder."
        )
    except json.JSONDecodeError as e:
        raise ValueError(f"[pdf_analyzer] pdf_rules.json is invalid JSON: {e}")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_finding(rule, description, detail, risk, category, context="", position=None):
    finding = {
        "stage":       "PDF Stream Analyzer",
        "rule":        rule,
        "description": description,
        "detail":      detail,
        "risk_tier":   risk,
        "category":    category,
        "context":     context[:120],
    }
    if position is not None:
        finding["position"] = position
    return finding


def _context_around(file_bytes: bytes, pos: int, before=50, after=100) -> str:
    start = max(0, pos - before)
    end   = min(len(file_bytes), pos + after)
    return (
        file_bytes[start:end]
        .decode("latin-1", errors="ignore")
        .replace("\x00", "")
    )


# ── Layer A — Binary stream scan ─────────────────────────────────────────────

def _binary_scan(file_bytes: bytes, rules: list) -> list:
    findings   = []
    file_lower = file_bytes.lower()
    seen       = set()

    for rule in rules:
        pattern_str   = rule["pattern"]
        pattern_bytes = pattern_str.encode("utf-8", errors="ignore").lower()

        if pattern_bytes in seen:
            continue

        pos = file_lower.find(pattern_bytes)
        if pos == -1:
            continue

        seen.add(pattern_bytes)
        context = _context_around(file_bytes, pos)

        findings.append(_make_finding(
            rule        = pattern_str,
            description = rule["description"],
            detail      = rule["detail"],
            risk        = rule["risk"],
            category    = rule["category"],
            context     = context,
            position    = pos,
        ))

    return findings


# ── Layer B — Deep structure parsing (pikepdf) ───────────────────────────────

def _pikepdf_scan(file_bytes: bytes) -> list:
    try:
        import pikepdf
    except ImportError:
        return [_make_finding(
            rule        = "pikepdf_missing",
            description = "pikepdf not installed — deep structure scan skipped",
            detail      = "Run: pip install pikepdf",
            risk        = "Low",
            category    = "scanner_warning",
        )]

    import io
    findings = []

    try:
        pdf = pikepdf.open(io.BytesIO(file_bytes), suppress_warnings=True)
    except pikepdf.PasswordError:
        findings.append(_make_finding(
            rule        = "encrypted_pdf",
            description = "PDF is password-protected — contents cannot be inspected",
            detail      = "Encrypted PDFs are a common evasion technique to bypass scanners",
            risk        = "High",
            category    = "evasion",
        ))
        return findings
    except Exception as e:
        findings.append(_make_finding(
            rule        = "pdf_parse_error",
            description = f"PDF structure could not be parsed: {e}",
            detail      = "Malformed PDFs can crash vulnerable readers",
            risk        = "Medium",
            category    = "malformed",
        ))
        return findings

    if pdf.is_encrypted:
        findings.append(_make_finding(
            rule        = "encrypted_pdf",
            description = "PDF uses encryption — some content may be hidden",
            detail      = "Encrypted PDFs can hide malicious streams from AV tools",
            risk        = "Medium",
            category    = "evasion",
        ))

    js_count       = 0
    embedded_files = []
    action_count   = 0
    stream_count   = 0

    for obj in pdf.objects:
        if not isinstance(obj, pikepdf.Dictionary):
            continue

        obj_type = obj.get("/Type", None)

        # JavaScript actions
        if "/JavaScript" in obj or "/JS" in obj:
            js_count += 1
            js_src = ""
            try:
                js_val = obj.get("/JS") or obj.get("/JavaScript")
                if isinstance(js_val, pikepdf.Stream):
                    js_src = js_val.read_bytes().decode("latin-1", errors="ignore")[:200]
                elif isinstance(js_val, pikepdf.String):
                    js_src = str(js_val)[:200]
            except Exception:
                pass
            findings.append(_make_finding(
                rule        = "/JavaScript (pikepdf)",
                description = "JavaScript action object found in PDF structure",
                detail      = "Direct object-level JS — more reliable than binary scan",
                risk        = "Critical",
                category    = "js_execution",
                context     = js_src,
            ))

        # Actions
        for action_key in ("/OpenAction", "/AA", "/Launch", "/GoToR"):
            if action_key in obj:
                action_count += 1
                findings.append(_make_finding(
                    rule        = f"{action_key} (pikepdf)",
                    description = f"Action object {action_key} found in PDF structure",
                    detail      = "Confirmed via object tree — not just a binary match",
                    risk        = "High",
                    category    = "auto_execute",
                ))

        # Embedded files
        if str(obj_type) == "/Filespec" or "/EF" in obj:
            try:
                fname = str(obj.get("/F") or obj.get("/UF") or "unknown")
                embedded_files.append(fname)
            except Exception:
                embedded_files.append("unknown")

        # Object streams
        if str(obj_type) == "/ObjStm":
            stream_count += 1

        # XFA forms
        if "/XFA" in obj:
            findings.append(_make_finding(
                rule        = "/XFA (pikepdf)",
                description = "XFA form found in PDF object tree",
                detail      = "XFA forms can execute JS and make network requests",
                risk        = "Medium",
                category    = "form_script",
            ))

        # SubmitForm
        if "/SubmitForm" in obj:
            findings.append(_make_finding(
                rule        = "/SubmitForm (pikepdf)",
                description = "SubmitForm action found — can exfiltrate data silently",
                detail      = "PDF will POST form data to a remote server on trigger",
                risk        = "Medium",
                category    = "data_exfil",
            ))

    if embedded_files:
        findings.append(_make_finding(
            rule        = "embedded_files (pikepdf)",
            description = f"{len(embedded_files)} embedded file(s) found inside PDF",
            detail      = f"Filenames: {', '.join(embedded_files[:5])}",
            risk        = "High",
            category    = "embedded_payload",
            context     = ", ".join(embedded_files[:10]),
        ))

    if stream_count >= 3:
        findings.append(_make_finding(
            rule        = "heavy_objstm (pikepdf)",
            description = f"{stream_count} object streams — heavy compression/obfuscation",
            detail      = "Many ObjStm entries hide dangerous objects from basic scanners",
            risk        = "Medium",
            category    = "obfuscation",
        ))

    if js_count >= 3:
        findings.append(_make_finding(
            rule        = "multiple_js_objects (pikepdf)",
            description = f"{js_count} separate JavaScript objects found",
            detail      = "Multiple JS objects often indicate layered obfuscation",
            risk        = "Critical",
            category    = "js_execution",
        ))

    pdf.close()
    return findings


# ── Layer C — Metadata + URL scan (PyMuPDF) ──────────────────────────────────

SUSPICIOUS_CREATORS = [
    "msfvenom", "metasploit", "exploit", "shellcode",
    "meterpreter", "cobalt", "empire", "havoc",
]

SUSPICIOUS_URL_PATTERNS = [
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"https?://[^/]+\.tk/",
    r"https?://[^/]+\.ml/",
    r"https?://[^/]+\.ga/",
    r"https?://bit\.ly/",
    r"https?://tinyurl\.com/",
    r"https?://[^/]+/[a-f0-9]{32,}",
]

def _fitz_scan(file_bytes: bytes) -> list:
    try:
        import fitz
    except ImportError:
        return [_make_finding(
            rule        = "fitz_missing",
            description = "PyMuPDF not installed — metadata/URL scan skipped",
            detail      = "Run: pip install pymupdf",
            risk        = "Low",
            category    = "scanner_warning",
        )]

    import io
    findings = []

    try:
        doc = fitz.open(stream=file_bytes, filetype="pdf")
    except Exception as e:
        return [_make_finding(
            rule        = "fitz_parse_error",
            description = f"PyMuPDF could not open PDF: {e}",
            detail      = "Malformed or corrupt PDF",
            risk        = "Medium",
            category    = "malformed",
        )]

    # Metadata
    meta     = doc.metadata or {}
    creator  = (meta.get("creator")  or "").lower()
    producer = (meta.get("producer") or "").lower()

    for sus in SUSPICIOUS_CREATORS:
        if sus in creator or sus in producer:
            findings.append(_make_finding(
                rule        = "suspicious_creator_tool",
                description = f"PDF created by suspicious tool: '{meta.get('creator') or meta.get('producer')}'",
                detail      = "Known offensive security / exploit framework tool name in metadata",
                risk        = "Critical",
                category    = "metadata_threat",
                context     = f"creator={meta.get('creator')} producer={meta.get('producer')}",
            ))
            break

    if not any([meta.get("creator"), meta.get("producer"), meta.get("author")]):
        findings.append(_make_finding(
            rule        = "empty_metadata",
            description = "PDF has no metadata — common in programmatically generated malware",
            detail      = "Legitimate PDFs almost always have creator/producer metadata",
            risk        = "Low",
            category    = "metadata_threat",
        ))

    # Page count
    if doc.page_count == 0:
        findings.append(_make_finding(
            rule        = "zero_page_pdf",
            description = "PDF has 0 pages — only metadata/scripts, no content",
            detail      = "Pure-script PDFs with no visible pages are extremely suspicious",
            risk        = "High",
            category    = "malformed",
        ))

    # URLs
    all_urls = []
    for page in doc:
        for link in page.get_links():
            uri = link.get("uri", "")
            if uri:
                all_urls.append(uri)
        text  = page.get_text()
        found = re.findall(r"https?://[^\s\"\'<>]{4,200}", text)
        all_urls.extend(found)

    all_urls = list(set(all_urls))
    sus_urls = []
    for url in all_urls:
        for pat in SUSPICIOUS_URL_PATTERNS:
            if re.search(pat, url, re.IGNORECASE):
                sus_urls.append(url)
                break

    if sus_urls:
        findings.append(_make_finding(
            rule        = "suspicious_urls (fitz)",
            description = f"{len(sus_urls)} suspicious URL(s) embedded in PDF",
            detail      = "IP-based URLs, free domains, or URL shorteners detected",
            risk        = "High",
            category    = "external_url",
            context     = " | ".join(sus_urls[:5]),
        ))
    elif all_urls:
        findings.append(_make_finding(
            rule        = "embedded_urls (fitz)",
            description = f"{len(all_urls)} URL(s) embedded in PDF",
            detail      = "URLs present — review for phishing or C2 indicators",
            risk        = "Low",
            category    = "external_url",
            context     = " | ".join(all_urls[:5]),
        ))

    # Annotations
    total_annots = sum(
    len(list(page.annots())) if page.annots() else 0
    for page in doc
)
    if total_annots > 20:
        findings.append(_make_finding(
            rule        = "high_annotation_count (fitz)",
            description = f"{total_annots} annotations found — unusually high",
            detail      = "High annotation counts can indicate hidden data or exploit attempts",
            risk        = "Medium",
            category    = "obfuscation",
        ))

    doc.close()
    return findings


# ── Layer D — Stream text extraction (pdfminer) ──────────────────────────────

OBFUSCATION_PATTERNS = [
    (r"\\u[0-9a-fA-F]{4}",         "Unicode escape sequences — possible obfuscation"),
    (r"%[0-9a-fA-F]{2}",           "Percent-encoded characters in stream"),
    (r"String\.fromCharCode\(",     "String.fromCharCode() — classic JS obfuscation"),
    (r"[a-zA-Z0-9+/]{200,}={0,2}", "Long base64-like string — possible encoded payload"),
    (r"(\\x[0-9a-fA-F]{2}){10,}",  "Hex escape sequence chain — shellcode pattern"),
    (r"(\d{2,3},){20,}",            "Large comma-separated integer array — shellcode pattern"),
]

def _pdfminer_scan(file_bytes: bytes) -> list:
    try:
        from pdfminer.high_level import extract_text_to_fp
        from pdfminer.layout    import LAParams
        import io
    except ImportError:
        return [_make_finding(
            rule        = "pdfminer_missing",
            description = "pdfminer not installed — stream text scan skipped",
            detail      = "Run: pip install pdfminer.six",
            risk        = "Low",
            category    = "scanner_warning",
        )]

    findings = []

    try:
        buf = io.StringIO()
        extract_text_to_fp(
            io.BytesIO(file_bytes), buf,
            laparams=LAParams(), output_type="text", codec=None
        )
        text = buf.getvalue()
    except Exception:
        return []

    if not text.strip():
        return []

    for pattern, desc in OBFUSCATION_PATTERNS:
        match = re.search(pattern, text)
        if match:
            context = text[max(0, match.start()-40): match.end()+80]
            findings.append(_make_finding(
                rule        = "obfuscation_pattern",
                description = desc,
                detail      = "Detected in extracted PDF stream text via pdfminer",
                risk        = "High",
                category    = "obfuscation",
                context     = context[:120],
            ))

    return findings


# ── Deduplication ─────────────────────────────────────────────────────────────

def _dedupe(findings: list) -> list:
    TIER_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    seen = {}
    for f in findings:
        key      = (f["rule"].split(" (")[0].lower(), f["category"])
        existing = seen.get(key)
        if not existing:
            seen[key] = f
        else:
            if TIER_ORDER.get(f["risk_tier"], 0) > TIER_ORDER.get(existing["risk_tier"], 0):
                seen[key] = f
    return list(seen.values())


# ── Main entry point ──────────────────────────────────────────────────────────

def analyze(file_bytes: bytes) -> list:
    """
    Full 4-layer PDF analysis.
    Called by attachment_main.py — returns list of findings.
    """
    rules    = _load_rules()
    findings = []

    findings += _binary_scan(file_bytes, rules)   # Layer A
    findings += _pikepdf_scan(file_bytes)          # Layer B
    findings += _fitz_scan(file_bytes)             # Layer C
    findings += _pdfminer_scan(file_bytes)         # Layer D

    findings = _dedupe(findings)
    return findings