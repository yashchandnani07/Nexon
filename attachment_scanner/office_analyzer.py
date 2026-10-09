# attachment_scanner/office_analyzer.py
# Layer 2b — Office Document Analyzer
#
# Four-layer analysis:
#   Layer A — Binary/XML pattern scan     (rules from office_rules.json)
#   Layer B — VBA macro extraction        (oletools / olevba)
#   Layer C — Remote template injection   (.rels relationship scanning)
#   Layer D — Excel 4.0 XLM macro scan   (legacy macro sheet detection)
#
# Safe — file is never opened or executed at any point.

import json
import os
import re
import zipfile
import io

# ── Rules loaded from office_rules.json ──────────────────────────────────────
_RULES_PATH = os.path.join(os.path.dirname(__file__), "office_rules.json")

def _load_rules() -> list:
    try:
        with open(_RULES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"[office_analyzer] office_rules.json not found at {_RULES_PATH}."
        )
    except json.JSONDecodeError as e:
        raise ValueError(f"[office_analyzer] office_rules.json is invalid JSON: {e}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(rule, description, detail, risk, category, context=""):
    return {
        "stage":       "Office Macro Extractor",
        "rule":        rule,
        "description": description,
        "detail":      detail,
        "risk_tier":   risk,
        "category":    category,
        "context":     context[:120],
    }


# ── Layer A — Binary/XML pattern scan ────────────────────────────────────────

def _binary_scan(file_bytes: bytes, filename: str, rules: list) -> list:
    """
    Scan raw bytes and unpacked XML content against office_rules.json.
    Handles both legacy OLE (.doc/.xls) and modern ZIP (.docx/.xlsx) formats.
    """
    findings = []
    ext      = ("." + filename.lower().rsplit(".", 1)[-1]
                 if "." in filename else "")

    content = file_bytes

    # Modern Office = ZIP archive — unpack all internal content
    if ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"):
        try:
            all_content = b""
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                for name in z.namelist():
                    try:
                        all_content += z.read(name)
                    except Exception:
                        pass
            content = all_content
        except Exception:
            pass

    content_lower = content.lower()
    seen          = set()

    for rule in rules:
        pattern       = rule["pattern"].lower().encode("utf-8", errors="ignore")
        if pattern in seen:
            continue
        pos = content_lower.find(pattern)
        if pos == -1:
            continue
        seen.add(pattern)

        start   = max(0, pos - 30)
        end     = min(len(content), pos + 80)
        context = (
            content[start:end]
            .decode("latin-1", errors="ignore")
            .replace("\x00", " ")
            .strip()
        )

        findings.append(_make_finding(
            rule        = rule["pattern"],
            description = rule["description"],
            detail      = rule["detail"],
            risk        = rule["risk"],
            category    = rule["category"],
            context     = context,
        ))

    return findings


# ── Layer B — VBA macro extraction (oletools) ─────────────────────────────────

# Suspicious patterns to scan inside extracted VBA source code
VBA_SUSPICIOUS = [
    (r"Shell\s*\(",                          "Critical", "Shell() call in VBA source",           "shell_exec"),
    (r"WScript\.Shell",                      "Critical", "WScript.Shell in VBA source",           "shell_exec"),
    (r"powershell",                          "High",     "PowerShell in VBA source",              "powershell"),
    (r"URLDownloadToFile",                   "Critical", "File downloader in VBA source",         "downloader"),
    (r"CreateObject\s*\(",                   "High",     "CreateObject in VBA source",            "com_object"),
    (r"Declare\s+(Function|Sub)",            "High",     "Win32 API import in VBA source",        "win32_api"),
    (r"VirtualAlloc",                        "Critical", "Memory allocation — shellcode loader",  "shellcode"),
    (r"RtlMoveMemory",                       "Critical", "Memory copy — shellcode injection",     "shellcode"),
    (r"CallWindowProc",                      "Critical", "Shellcode execution via CallWindowProc","shellcode"),
    (r"(Chr\(\d+\)\s*&\s*){5,}",            "High",     "Chr() chain — string obfuscation",      "obfuscation"),
    (r"StrReverse\s*\(",                     "Medium",   "StrReverse() — string obfuscation",     "obfuscation"),
    (r"Base64",                              "Medium",   "Base64 reference in VBA",               "obfuscation"),
    (r"HKEY_(LOCAL_MACHINE|CURRENT_USER)",   "High",     "Registry key access in VBA",            "persistence"),
    (r"\.Run\s*\(",                          "High",     ".Run() method — command execution",      "shell_exec"),
    (r"environ\s*\(",                        "Low",      "Environment variable read",             "recon"),
]

def _olevba_scan(file_bytes: bytes) -> list:
    """
    Uses oletools olevba to extract actual VBA source code,
    then scans it for suspicious patterns.
    """
    try:
        from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML
    except ImportError:
        return [_make_finding(
            rule        = "oletools_missing",
            description = "oletools not installed — VBA extraction skipped",
            detail      = "Run: pip install oletools",
            risk        = "Low",
            category    = "scanner_warning",
        )]

    findings = []

    try:
        vba_parser = VBA_Parser("file", data=file_bytes)
    except Exception as e:
        return [_make_finding(
            rule        = "vba_parse_error",
            description = f"Could not parse file for VBA: {e}",
            detail      = "File may be corrupt or heavily obfuscated",
            risk        = "Medium",
            category    = "malformed",
        )]

    if not vba_parser.detect_vba_macros():
        vba_parser.close()
        return []

    # VBA macros confirmed present
    findings.append(_make_finding(
        rule        = "vba_macros_present",
        description = "VBA macros detected in document (confirmed by oletools)",
        detail      = "Document contains executable macro code",
        risk        = "Medium",
        category    = "macro_present",
    ))

    # Extract and scan all VBA source code
    all_vba_source = ""
    try:
        for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
            if vba_code:
                all_vba_source += vba_code + "\n"
    except Exception:
        pass

    if all_vba_source:
        seen_rules = set()
        for pattern, risk, desc, category in VBA_SUSPICIOUS:
            match = re.search(pattern, all_vba_source, re.IGNORECASE)
            if match and pattern not in seen_rules:
                seen_rules.add(pattern)
                start   = max(0, match.start() - 40)
                end     = min(len(all_vba_source), match.end() + 80)
                context = all_vba_source[start:end].strip()
                findings.append(_make_finding(
                    rule        = f"{desc} (olevba)",
                    description = desc,
                    detail      = f"Found in extracted VBA source — pattern: {pattern}",
                    risk        = risk,
                    category    = category,
                    context     = context,
                ))

    # Use oletools built-in IOC extraction
    try:
        for kw_type, keyword, description, _risk in vba_parser.analyze_macros():
            if kw_type in ("AutoExec", "Suspicious", "IOC", "Hex String", "Base64 String"):
                risk_map = {
                    "AutoExec":     "Critical",
                    "Suspicious":   "High",
                    "IOC":          "High",
                    "Hex String":   "Medium",
                    "Base64 String":"Medium",
                }
                findings.append(_make_finding(
                    rule        = f"{kw_type}: {keyword}",
                    description = description,
                    detail      = f"Detected by oletools built-in IOC analyzer ({kw_type})",
                    risk        = risk_map.get(kw_type, "Medium"),
                    category    = kw_type.lower().replace(" ", "_"),
                    context     = keyword[:120],
                ))
    except Exception:
        pass

    vba_parser.close()
    return findings


# ── Layer C — Remote template injection (.rels scanning) ─────────────────────

SUSPICIOUS_REL_TARGETS = [
    r"https?://",           # external HTTP/HTTPS URL
    r"\\\\",                # UNC path (SMB)
    r"ftp://",              # FTP
    r"file://",             # local file protocol
]

def _rels_scan(file_bytes: bytes) -> list:
    """
    Scans .rels relationship files inside Office ZIP archives.
    Detects remote template injection — a common macro-free attack.
    The document loads a remote template containing macros on open.
    """
    findings = []

    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
            rels_files = [n for n in z.namelist() if n.endswith(".rels")]

            for rels_file in rels_files:
                try:
                    content = z.read(rels_file).decode("utf-8", errors="ignore")
                except Exception:
                    continue

                # Find all Target= attributes
                targets = re.findall(r'Target\s*=\s*"([^"]+)"', content)

                for target in targets:
                    for sus_pat in SUSPICIOUS_REL_TARGETS:
                        if re.search(sus_pat, target, re.IGNORECASE):
                            findings.append(_make_finding(
                                rule        = "remote_template_injection",
                                description = f"Remote template reference in {rels_file}",
                                detail      = (
                                    "Document loads external template on open — "
                                    "classic macro-free code execution technique"
                                ),
                                risk        = "Critical",
                                category    = "remote_template",
                                context     = target[:120],
                            ))
                            break

    except zipfile.BadZipFile:
        pass  # Legacy OLE format — handled by binary scan
    except Exception:
        pass

    return findings


# ── Layer D — Excel 4.0 XLM macro detection ───────────────────────────────────

XLM_PATTERNS = [
    (b"EXEC(",        "Critical", "XLM EXEC() — executes programs from Excel 4.0 macro"),
    (b"CALL(",        "High",     "XLM CALL() — calls DLL functions from macro sheet"),
    (b"REGISTER(",    "High",     "XLM REGISTER() — registers DLL for execution"),
    (b"FORMULA(",     "Medium",   "XLM FORMULA() — writes formula to cell dynamically"),
    (b"HALT(",        "Low",      "XLM HALT() — stops macro execution"),
    (b"GET.WORKSPACE","Medium",   "XLM GET.WORKSPACE — system reconnaissance"),
    (b"GET.CELL",     "Low",      "XLM GET.CELL — cell data access"),
    (b"CHAR(",        "Medium",   "XLM CHAR() — character obfuscation in macro"),
    (b"RUN(",         "High",     "XLM RUN() — executes another macro or program"),
]

def _xlm_scan(file_bytes: bytes) -> list:
    """
    Detects Excel 4.0 XLM macros — a legacy format still
    heavily abused by malware because many AV tools miss it.
    """
    findings = []
    content  = file_bytes.upper()
    seen     = set()

    for pattern, risk, desc in XLM_PATTERNS:
        pat_upper = pattern.upper()
        if pat_upper in seen:
            continue
        if pat_upper in content:
            seen.add(pat_upper)
            pos     = content.find(pat_upper)
            start   = max(0, pos - 30)
            end     = min(len(file_bytes), pos + 80)
            context = (
                file_bytes[start:end]
                .decode("latin-1", errors="ignore")
                .replace("\x00", " ")
                .strip()
            )
            findings.append(_make_finding(
                rule        = pattern.decode("utf-8", errors="ignore"),
                description = desc,
                detail      = "Excel 4.0 XLM macro — legacy format abused to bypass AV",
                risk        = risk,
                category    = "xlm_macro",
                context     = context,
            ))

    if findings:
        findings.insert(0, _make_finding(
            rule        = "xlm_macro_sheet",
            description = "Excel 4.0 XLM macro sheet detected",
            detail      = "XLM macros are a heavily abused legacy feature — often missed by AV",
            risk        = "High",
            category    = "xlm_macro",
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

def analyze(file_bytes: bytes, filename: str) -> list:
    """
    Full 4-layer Office document analysis.
    Called by attachment_main.py — returns list of findings.
    """
    rules    = _load_rules()
    findings = []

    findings += _binary_scan(file_bytes, filename, rules)  # Layer A
    findings += _olevba_scan(file_bytes)                   # Layer B
    findings += _rels_scan(file_bytes)                     # Layer C
    findings += _xlm_scan(file_bytes)                      # Layer D

    findings = _dedupe(findings)
    return findings