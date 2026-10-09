"""
Attachment Risk Analyzer
=========================
Scores attachment risk based on file extension, content-type,
and surrounding text context (e.g., "enable macros", "run the script").
"""

import re
from typing import Dict, List

# ── Risk tiers by file extension ─────────────────────────────────────────────
EXTENSION_RISK = {
    # CRITICAL: Executable / script files
    '.exe': ('CRITICAL', 1.0), '.bat': ('CRITICAL', 1.0), '.cmd': ('CRITICAL', 1.0),
    '.vbs': ('CRITICAL', 1.0), '.vbe': ('CRITICAL', 1.0), '.js': ('CRITICAL', 0.9),
    '.jse': ('CRITICAL', 1.0), '.wsf': ('CRITICAL', 1.0), '.wsh': ('CRITICAL', 1.0),
    '.ps1': ('CRITICAL', 1.0), '.psm1': ('CRITICAL', 1.0), '.psd1': ('CRITICAL', 1.0),
    '.scr': ('CRITICAL', 1.0), '.com': ('CRITICAL', 0.9), '.msi': ('CRITICAL', 0.9),
    '.dll': ('CRITICAL', 0.9), '.hta': ('CRITICAL', 1.0), '.cpl': ('CRITICAL', 1.0),
    '.reg': ('CRITICAL', 0.9), '.inf': ('CRITICAL', 0.8), '.lnk': ('CRITICAL', 0.9),
    '.pif': ('CRITICAL', 1.0),
    # HIGH: Archives and macro-enabled documents
    '.zip': ('HIGH', 0.4), '.rar': ('HIGH', 0.4), '.7z': ('HIGH', 0.4),
    '.tar': ('HIGH', 0.3), '.gz': ('HIGH', 0.3),
    '.docm': ('HIGH', 0.8), '.xlsm': ('HIGH', 0.8), '.pptm': ('HIGH', 0.8),
    '.dotm': ('HIGH', 0.8), '.xltm': ('HIGH', 0.8),
    '.html': ('HIGH', 0.7), '.htm': ('HIGH', 0.7),
    '.iso': ('HIGH', 0.7), '.img': ('HIGH', 0.7), '.vhd': ('HIGH', 0.7),
    # MEDIUM: Standard documents
    '.pdf': ('MEDIUM', 0.3), '.doc': ('MEDIUM', 0.3), '.docx': ('MEDIUM', 0.2),
    '.xls': ('MEDIUM', 0.3), '.xlsx': ('MEDIUM', 0.2),
    '.ppt': ('MEDIUM', 0.2), '.pptx': ('MEDIUM', 0.2),
    '.rtf': ('MEDIUM', 0.3), '.csv': ('MEDIUM', 0.2),
    # LOW: Media and plain text
    '.txt': ('LOW', 0.1), '.log': ('LOW', 0.1), '.md': ('LOW', 0.1),
    '.jpg': ('LOW', 0.05), '.jpeg': ('LOW', 0.05), '.png': ('LOW', 0.05),
    '.gif': ('LOW', 0.05), '.bmp': ('LOW', 0.05), '.svg': ('LOW', 0.1),
    '.mp3': ('LOW', 0.05), '.mp4': ('LOW', 0.05), '.wav': ('LOW', 0.05),
}

# ── Dangerous context phrases (near attachment mentions) ─────────────────────
DANGEROUS_CONTEXT = [
    (re.compile(r'enable\s+(?:content|macros?|editing)', re.IGNORECASE), 0.4, "Enable macros/content instruction"),
    (re.compile(r'run\s+(?:the\s+)?(?:script|file|program|batch)', re.IGNORECASE), 0.4, "Run script instruction"),
    (re.compile(r'execute\s+(?:the\s+)?(?:attached|file|script)', re.IGNORECASE), 0.4, "Execute instruction"),
    (re.compile(r'download\s+and\s+(?:run|execute|open)', re.IGNORECASE), 0.4, "Download and run instruction"),
    (re.compile(r'open\s+(?:the\s+)?(?:attached|enclosed)\s+(?:file|document)', re.IGNORECASE), 0.2, "Open attachment instruction"),
    (re.compile(r'(?:password|pwd)\s*(?:is|:)\s*\S+', re.IGNORECASE), 0.3, "Password-protected attachment"),
    (re.compile(r'secure\s+(?:document\s+)?viewer|protected\s+content\s+(?:viewer|reader)', re.IGNORECASE), 0.4, "Fake secure content viewer"),
    (re.compile(r'secure\s+archive', re.IGNORECASE), 0.3, "Secure archive reference"),
    (re.compile(r'open\s+.*\s+in\s+.*browser', re.IGNORECASE), 0.3, "Open in browser instruction"),
]

# ── Attachment filename detection in email body ──────────────────────────────
ATTACHMENT_RE = re.compile(
    r"(?:attach(?:ed|ment)?|enclosed|file)\s*:?\s*['\"]?([^\s'\"<>]{3,60}\.\w{2,5})['\"]?",
    re.IGNORECASE
)
# Also catch direct filename mentions
FILENAME_RE = re.compile(r'\b(\w[\w\s-]{0,40}\.\w{2,5})\b')


def analyze_attachments(text: str, attachment_filenames: List[str] = None) -> dict:
    """
    Analyze attachment risk from email body text and optional filenames list.
    
    Args:
        text: Email body
        attachment_filenames: Explicit list of attachment filenames (if available from MIME)
        
    Returns:
        {
            "has_attachments": bool,
            "attachment_count": int,
            "attachments": [{"filename": "...", "extension": ".bat", "tier": "CRITICAL", "risk": 1.0}],
            "dangerous_context": [{"pattern": "Enable macros", "weight": 0.4}],
            "risk_score": float
        }
    """
    # Gather filenames from explicit list + body text
    filenames = set()
    if attachment_filenames:
        filenames.update(attachment_filenames)

    # Extract filenames mentioned in body
    for match in ATTACHMENT_RE.finditer(text):
        fname = match.group(1).strip()
        if _looks_like_filename(fname):
            filenames.add(fname)

    # Also scan for direct filename patterns
    for match in FILENAME_RE.finditer(text):
        fname = match.group(1).strip()
        if _looks_like_filename(fname) and _has_known_extension(fname):
            filenames.add(fname)

    # Analyze each attachment
    attachments = []
    for fname in filenames:
        ext = _get_extension(fname)
        tier, risk = EXTENSION_RISK.get(ext, ('UNKNOWN', 0.2))
        attachments.append({
            "filename": fname,
            "extension": ext,
            "tier": tier,
            "risk": risk,
        })

    # Check for dangerous context phrases
    dangerous = []
    for pat_re, weight, desc in DANGEROUS_CONTEXT:
        if pat_re.search(text):
            dangerous.append({"pattern": desc, "weight": weight})

    # Overall risk
    max_attach_risk = max((a["risk"] for a in attachments), default=0.0)
    context_risk = sum(d["weight"] for d in dangerous)

    # Compound risk: attachment + dangerous context = amplified risk
    if max_attach_risk > 0 and context_risk > 0:
        risk = min(max_attach_risk + context_risk, 0.99)
    elif max_attach_risk > 0:
        risk = max_attach_risk
    else:
        risk = min(context_risk, 0.6)

    return {
        "has_attachments": len(attachments) > 0,
        "attachment_count": len(attachments),
        "attachments": sorted(attachments, key=lambda a: -a["risk"]),
        "dangerous_context": dangerous,
        "risk_score": round(risk, 2),
    }


def _get_extension(filename: str) -> str:
    """Extract lowercase extension."""
    idx = filename.rfind('.')
    if idx > 0:
        return filename[idx:].lower()
    return ''


def _looks_like_filename(s: str) -> bool:
    """Heuristic: does this string look like a filename?"""
    if '.' not in s:
        return False
    if len(s) < 3 or len(s) > 60:
        return False
    if ' ' in s and s.count(' ') > 3:
        return False
    # Reject domain-like strings: word.com, word.net, word.org etc.
    if re.match(r'^[\w-]+\.(com|net|org|io|co|uk|gov|edu|xyz|ru|tk)$', s, re.IGNORECASE):
        return False
    # Reject URL-like strings
    if '/' in s or s.startswith('http'):
        return False
    return bool(re.match(r'^[\w\s._-]+\.\w{2,5}$', s))


def _has_known_extension(s: str) -> bool:
    """Check if the string ends with a known extension."""
    ext = _get_extension(s)
    return ext in EXTENSION_RISK
