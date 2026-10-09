# attachment_scanner/zip_analyzer.py
# Layer 2d — Archive Analyzer
#
# Five-layer analysis:
#   Layer A — Structure check      (password protection, corruption, zip bomb)
#   Layer B — Filename scan        (dangerous extensions, double extension, path traversal)
#   Layer C — Recursive unpack     (nested archives scanned recursively)
#   Layer D — Content scan         (scan file bytes inside archive)
#   Layer E — 7z support           (py7zr for .7z archives)
#
# Safe — files are never executed at any point.

import zipfile
import io
import math
import re
import os

# ── Constants ─────────────────────────────────────────────────────────────────

HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1",
    ".vbs", ".js",  ".jar", ".sh",  ".msi",
    ".scr", ".pif", ".com", ".hta", ".wsf",
    ".lnk", ".reg", ".inf", ".cpl", ".sys",
}

MEDIUM_RISK_EXTENSIONS = {
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
    ".pdf", ".rtf", ".iso", ".img",
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab"}

# Max sizes to prevent zip bomb memory exhaustion
MAX_SINGLE_FILE_SIZE = 50  * 1024 * 1024   # 50MB per file
MAX_TOTAL_SIZE       = 100 * 1024 * 1024   # 100MB total extracted
MAX_RECURSION_DEPTH  = 3                    # max nested archive depth


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(rule, description, detail, risk, category, context=""):
    return {
        "stage":       "ZIP Recursive Analyzer",
        "rule":        rule,
        "description": description,
        "detail":      detail,
        "risk_tier":   risk,
        "category":    category,
        "context":     context[:120],
    }

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return round(
        -sum((c / length) * math.log2(c / length)
             for c in freq.values()), 3
    )

def _get_ext(name: str) -> str:
    return ("." + name.lower().rsplit(".", 1)[-1]) if "." in name else ""


# ── Layer A — ZIP structure checks ────────────────────────────────────────────

def _structure_check(file_bytes: bytes, z: zipfile.ZipFile) -> list:
    findings = []

    # Password-protected archive
    for info in z.infolist():
        if info.flag_bits & 0x1:
            findings.append(_make_finding(
                rule        = "password_protected_archive",
                description = "Archive is password protected — contents hidden from scanners",
                detail      = "Password-protected ZIPs are used to bypass AV scanning",
                risk        = "High",
                category    = "evasion",
                context     = f"encrypted file: {info.filename}",
            ))
            break

    # Zip bomb detection — check compression ratio
    total_compressed   = sum(i.compress_size   for i in z.infolist())
    total_uncompressed = sum(i.file_size        for i in z.infolist())

    if total_compressed > 0:
        ratio = total_uncompressed / total_compressed
        if ratio > 100:
            findings.append(_make_finding(
                rule        = "zip_bomb",
                description = f"Extreme compression ratio: {ratio:.0f}x — possible zip bomb",
                detail      = "Zip bombs decompress to massive sizes to crash scanners/systems",
                risk        = "Critical",
                category    = "zip_bomb",
                context     = f"compressed={total_compressed} uncompressed={total_uncompressed}",
            ))
        elif ratio > 20:
            findings.append(_make_finding(
                rule        = "high_compression_ratio",
                description = f"High compression ratio: {ratio:.0f}x — suspicious",
                detail      = "Unusually high compression ratio may indicate zip bomb",
                risk        = "Medium",
                category    = "zip_bomb",
                context     = f"ratio={ratio:.1f}x",
            ))

    # Too many files — zip bomb variant
    file_count = len(z.infolist())
    if file_count > 1000:
        findings.append(_make_finding(
            rule        = "too_many_files",
            description = f"Archive contains {file_count} files — possible zip bomb",
            detail      = "Large file counts can overwhelm scanners and antivirus tools",
            risk        = "High",
            category    = "zip_bomb",
            context     = f"file_count={file_count}",
        ))

    return findings


# ── Layer B — Filename scan ───────────────────────────────────────────────────

def _filename_scan(names: list) -> list:
    findings = []
    seen     = set()

    for name in names:
        ext   = _get_ext(name)
        parts = name.lower().split(".")

        # High risk extension
        if ext in HIGH_RISK_EXTENSIONS and name not in seen:
            seen.add(name)
            findings.append(_make_finding(
                rule        = "dangerous_file_in_archive",
                description = f"High-risk file inside archive: {name}",
                detail      = f"Executable/script file '{ext}' found inside archive",
                risk        = "Critical",
                category    = "archive_threat",
                context     = name,
            ))

        # Double extension trick e.g. invoice.pdf.exe
        if len(parts) > 2 and ("." + parts[-1]) in HIGH_RISK_EXTENSIONS:
            findings.append(_make_finding(
                rule        = "double_extension_trick",
                description = f"Double extension evasion: {name}",
                detail      = "File uses fake safe extension to disguise executable",
                risk        = "Critical",
                category    = "evasion",
                context     = name,
            ))

        # Path traversal attack ../
        if ".." in name or name.startswith("/") or name.startswith("\\"):
            findings.append(_make_finding(
                rule        = "path_traversal",
                description = f"Path traversal in archive entry: {name}",
                detail      = "Zip Slip attack — file could be extracted outside target dir",
                risk        = "Critical",
                category    = "path_traversal",
                context     = name,
            ))

        # Symlink attack
        if name.endswith(".lnk"):
            findings.append(_make_finding(
                rule        = "lnk_in_archive",
                description = f"Windows shortcut (.lnk) inside archive: {name}",
                detail      = "LNK files can execute arbitrary commands when opened",
                risk        = "Critical",
                category    = "archive_threat",
                context     = name,
            ))

        # Suspicious unicode/homoglyph in filename
        if any(ord(c) > 127 for c in name):
            findings.append(_make_finding(
                rule        = "unicode_filename",
                description = f"Unicode characters in filename: {name}",
                detail      = "Unicode/homoglyph characters used to disguise file type",
                risk        = "Medium",
                category    = "evasion",
                context     = name,
            ))

        # Nested archive
        if ext in ARCHIVE_EXTENSIONS:
            findings.append(_make_finding(
                rule        = "nested_archive",
                description = f"Archive inside archive: {name}",
                detail      = "Nested archives are used to hide payloads from scanners",
                risk        = "Medium",
                category    = "zip_bomb",
                context     = name,
            ))

    return findings


# ── Layer C — Content scan (scan bytes of files inside archive) ───────────────

CONTENT_SIGNATURES = [
    (b"\x4d\x5a",           "PE executable (MZ header) inside archive",   "Critical", "archive_threat"),
    (b"#!/",                 "Unix shell script inside archive",            "High",     "archive_threat"),
    (b"powershell",          "PowerShell content inside archive",           "High",     "powershell"),
    (b"WScript.Shell",       "WScript.Shell in archived script",            "Critical", "shell_exec"),
    (b"URLDownloadToFile",   "File downloader in archived script",          "Critical", "downloader"),
    (b"cmd.exe",             "CMD reference in archived file",              "High",     "shell_exec"),
    (b"<script",             "Script tag in archived HTML/HTA",             "High",     "archive_threat"),
    (b"CreateObject",        "CreateObject in archived script",             "High",     "com_object"),
    (b"DDEAUTO",             "DDE auto-execute in archived document",       "Critical", "dde"),
    (b"AutoOpen",            "Auto-open macro in archived document",        "Critical", "auto_execute"),
]

def _content_scan(z: zipfile.ZipFile) -> list:
    findings     = []
    total_read   = 0
    seen_sigs    = set()

    for info in z.infolist():
        # Skip directories
        if info.filename.endswith("/"):
            continue

        # Skip if total extracted too large
        if total_read >= MAX_TOTAL_SIZE:
            findings.append(_make_finding(
                rule        = "extraction_limit_reached",
                description = "Content scan stopped — total size limit reached",
                detail      = f"Scanned up to {MAX_TOTAL_SIZE // (1024*1024)}MB of content",
                risk        = "Low",
                category    = "scanner_warning",
            ))
            break

        # Skip individual files that are too large
        if info.file_size > MAX_SINGLE_FILE_SIZE:
            continue

        try:
            data = z.read(info.filename)
        except Exception:
            continue

        total_read += len(data)

        # Scan content signatures
        data_lower = data[:2048].lower()  # scan first 2KB only for speed
        for sig, desc, risk, category in CONTENT_SIGNATURES:
            if sig.lower() in data_lower and sig not in seen_sigs:
                seen_sigs.add(sig)
                findings.append(_make_finding(
                    rule        = f"content_{sig.decode('latin-1', errors='ignore').strip()}",
                    description = f"{desc}: {info.filename}",
                    detail      = "Detected by scanning file content inside archive",
                    risk        = risk,
                    category    = category,
                    context     = info.filename,
                ))

        # High entropy file = encrypted/packed payload
        if len(data) > 256:
            ent = _entropy(data[:4096])
            if ent > 7.5:
                findings.append(_make_finding(
                    rule        = "high_entropy_file_in_archive",
                    description = f"High entropy file in archive: {info.filename} (entropy {ent})",
                    detail      = "Encrypted or packed payload hidden inside archive",
                    risk        = "High",
                    category    = "archive_threat",
                    context     = f"file={info.filename} entropy={ent}",
                ))

    return findings


# ── Layer D — Deep file scan (run specialized analyzers on inner files) ───────

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".ico"}
HTML_EXTENSIONS  = {".html", ".htm", ".hta", ".xhtml", ".svg"}
PDF_EXTENSIONS   = {".pdf"}
OFFICE_EXTENSIONS = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".docm", ".xlsm", ".pptm"}

MAX_DEEP_SCAN_FILES = 30  # cap on inner files to deep-scan per archive


def _deep_analyze_single(data: bytes, fname: str, ext: str, inner_path: str) -> list:
    """Run specialized analyzers on a single extracted file and tag findings."""
    inner_findings = []

    # HTML
    if ext in HTML_EXTENSIONS:
        try:
            from html_analyzer import analyze as _html_analyze
            inner_findings += _html_analyze(data)
        except Exception:
            pass

    # Image
    if ext in IMAGE_EXTENSIONS:
        try:
            from image_analyzer import analyze as _img_analyze
            inner_findings += _img_analyze(data, fname)
        except Exception:
            pass

    # PDF
    if ext in PDF_EXTENSIONS:
        try:
            from pdf_analyzer import analyze as _pdf_analyze
            inner_findings += _pdf_analyze(data)
        except Exception:
            pass

    # Office
    if ext in OFFICE_EXTENSIONS:
        try:
            from office_analyzer import analyze as _office_analyze
            inner_findings += _office_analyze(data, fname)
        except Exception:
            pass

    # Credential scan — universal, all extractable files
    if len(data) < 5_000_000:
        try:
            from credential_scanner import scan as _cred_scan
            inner_findings += _cred_scan(data)
        except Exception:
            pass

    # Tag every finding with archive context
    for f in inner_findings:
        orig_stage = f.get("stage", "Unknown")
        f["stage"]   = "ZIP Deep Scan"
        f["context"] = inner_path
        existing_why = f.get("why_flagged", "")
        f["why_flagged"] = (
            f"{existing_why} [Detected inside archive: {inner_path} by {orig_stage}]"
            if existing_why else
            f"Detected inside archive: {inner_path} by {orig_stage}"
        )

    return inner_findings

def _deep_file_scan(z: zipfile.ZipFile, archive_name: str = "archive", depth: int = 0) -> list:
    """
    Extract individual files from the archive and run the appropriate
    specialized analyzer on each one (HTML, image, PDF, Office, credential).
    Nested archives are recursively unpacked and deep-scanned.
    """
    if depth >= MAX_RECURSION_DEPTH:
        return [_make_finding(
            rule        = "max_recursion_depth",
            description = f"Max recursion depth ({MAX_RECURSION_DEPTH}) reached — deep scan stopped",
            detail      = "Deeply nested archives — possible zip bomb or evasion technique",
            risk        = "High",
            category    = "zip_bomb",
        )]

    findings = []
    total_read    = 0
    files_scanned = 0

    for info in z.infolist():
        if info.filename.endswith("/"):
            continue
        if files_scanned >= MAX_DEEP_SCAN_FILES:
            findings.append(_make_finding(
                rule        = "deep_scan_file_limit",
                description = f"Deep scan capped at {MAX_DEEP_SCAN_FILES} files",
                detail      = "Remaining files in archive were not deep-scanned",
                risk        = "Low",
                category    = "scanner_warning",
            ))
            break
        if info.file_size > MAX_SINGLE_FILE_SIZE:
            continue
        if total_read >= MAX_TOTAL_SIZE:
            break

        ext = _get_ext(info.filename)

        try:
            data = z.read(info.filename)
        except Exception:
            continue

        total_read += len(data)
        inner_path = f"{archive_name} → {info.filename}"

        inner_findings = []

        # Nested archive → recurse
        if ext in ARCHIVE_EXTENSIONS and ext == ".zip":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as nested_z:
                    inner_findings += _deep_file_scan(
                        nested_z, inner_path, depth + 1
                    )
            except Exception:
                pass

        # Run specialized analyzers on this file
        inner_findings += _deep_analyze_single(data, info.filename, ext, inner_path)

        findings += inner_findings
        if inner_findings:
            files_scanned += 1

    return findings


# ── Layer E — 7z support ──────────────────────────────────────────────────────

def _7z_scan(file_bytes: bytes) -> list:
    """
    Uses py7zr to scan .7z archives.
    Checks filenames, content signatures, and runs deep file analysis.
    """
    try:
        import py7zr
    except ImportError:
        return [_make_finding(
            rule        = "py7zr_missing",
            description = "py7zr not installed — 7z archive scan skipped",
            detail      = "Run: pip install py7zr",
            risk        = "Low",
            category    = "scanner_warning",
        )]

    findings = []

    try:
        with py7zr.SevenZipFile(io.BytesIO(file_bytes), mode="r") as z:
            all_files = z.getnames()

            # Filename scan
            findings += _filename_scan(all_files)

            # Content scan + deep file analysis
            try:
                extracted = z.readall()
                if extracted:
                    seen_sigs    = set()
                    total_read   = 0
                    files_deep   = 0
                    for fname, file_obj in extracted.items():
                        if total_read >= MAX_TOTAL_SIZE:
                            break
                        try:
                            data = file_obj.read(MAX_SINGLE_FILE_SIZE)
                            total_read += len(data)

                            # Signature scan (first 2KB)
                            data_lower = data[:2048].lower()
                            for sig, desc, risk, category in CONTENT_SIGNATURES:
                                if sig.lower() in data_lower and sig not in seen_sigs:
                                    seen_sigs.add(sig)
                                    findings.append(_make_finding(
                                        rule        = f"content_{sig.decode('latin-1', errors='ignore').strip()}",
                                        description = f"{desc}: {fname}",
                                        detail      = "Detected by scanning content inside 7z archive",
                                        risk        = risk,
                                        category    = category,
                                        context     = fname,
                                    ))

                            # Deep file analysis
                            if files_deep < MAX_DEEP_SCAN_FILES:
                                ext = _get_ext(fname)
                                inner_path = f"archive → {fname}"
                                inner_findings = _deep_analyze_single(
                                    data, fname, ext, inner_path
                                )
                                findings += inner_findings
                                if inner_findings:
                                    files_deep += 1
                        except Exception:
                            pass
            except Exception:
                pass

    except py7zr.Bad7zFile:
        findings.append(_make_finding(
            rule        = "corrupt_7z",
            description = "7z archive is corrupted — possible evasion attempt",
            detail      = "Corrupt archives can crash vulnerable extraction tools",
            risk        = "Medium",
            category    = "evasion",
        ))
    except Exception:
        pass

    return findings


# ── Deduplication ─────────────────────────────────────────────────────────────

def _dedupe(findings: list) -> list:
    TIER_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    seen = {}
    for f in findings:
        key      = (f["rule"].lower(), f.get("context", "")[:30])
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
    Full archive analysis — ZIP and 7z.
    Called by attachment_main.py — returns list of findings.
    """
    findings = []

    # ── ZIP format ────────────────────────────────────────────────────────────
    if file_bytes[:4] == b"\x50\x4b\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                findings += _structure_check(file_bytes, z)     # Layer A
                findings += _filename_scan(z.namelist())         # Layer B
                findings += _content_scan(z)                     # Layer C
                findings += _deep_file_scan(z, "archive")       # Layer D (deep scan)
        except zipfile.BadZipFile:
            findings.append(_make_finding(
                rule        = "corrupt_zip",
                description = "ZIP archive is corrupted — possible evasion attempt",
                detail      = "Corrupt archives can crash vulnerable extraction tools",
                risk        = "Medium",
                category    = "evasion",
            ))

    # ── 7z format ─────────────────────────────────────────────────────────────
    elif file_bytes[:6] == b"\x37\x7a\xbc\xaf\x27\x1c":
        findings += _7z_scan(file_bytes)                         # Layer E

    findings = _dedupe(findings)
    return findings