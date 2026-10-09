"""
Feature extraction pipeline — extracts 16 fraud detection signals from a parsed email.
Covers: authentication, sender reputation, header anomalies, NLP content, attachments.
"""
import re
import email.utils

# ── Patterns ──────────────────────────────────────────────────────────────────

URGENCY_PATTERNS = [
    r"\bact\s+now\b", r"\bimmediately\b", r"\burgent\b",
    r"\bwithin\s+\d+\s+hours?\b", r"\btime.?sensitive\b",
    r"\bexpir\w+\b", r"\bsuspend\w*\b", r"\bfinal\s+notice\b",
    r"\blast\s+chance\b", r"\bdo\s+not\s+delay\b",
    r"\baction\s+required\b", r"\brespond\s+immediately\b",
]

FINANCIAL_KEYWORDS = [
    "wire transfer", "swift", "bank details", "invoice", "payment",
    "remittance", "bank account", "routing number", "sort code",
    "iban", "beneficiary", "purchase order", "overdue",
    "outstanding balance", "funds transfer",
]

CREDENTIAL_PATTERNS = [
    r"\bverify\s+(your\s+)?(password|account|identity|details|information)\b",
    r"\bconfirm\s+(your\s+)?(account|login|credentials|identity)\b",
    r"\breset\s+(your\s+)?password\b",
    r"\bsign\s*in\s+(to\s+)?(verify|confirm|update|secure)\b",
    r"\benter\s+(your\s+)?(credentials|password|ssn|pin)\b",
    r"\bre.?enter\s+(your\s+)?(credentials|password|pin)\b",
    r"\bverify\s+(now|here|below|immediately)\b",
    r"\bclick\s+here\s+to\s+(verify|login|signin|reset|confirm)\b",
    r"\byour\s+(account|password|kyc|access)\s+(has\s+)?(expired|will\s+expire|is\s+blocked)\b",
    r"\bupdate\s+your\s+(kyc|account|details|credentials)\b",
    r"\bsecure\s+your\s+account\b",
    # NOTE: "enable macros" is intentionally NOT here — it sets has_macro, not credential_request
]

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# Barclays and common look-alike targets
_LOOKALIKE_TARGETS = ["barclays.com", "barclays.co.uk", "barclaysbank.com"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _levenshtein_ratio(s1: str, s2: str) -> float:
    """0 = identical, 1 = completely different."""
    if s1 == s2:
        return 0.0
    n, m = len(s1), len(s2)
    if n == 0 or m == 0:
        return 1.0
    dp = list(range(m + 1))
    for i in range(1, n + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, m + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            tmp = dp[j]
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev + cost)
            prev = tmp
    return dp[m] / max(n, m)


def _extract_domain(addr: str) -> str:
    if "@" in addr:
        return addr.split("@")[-1].strip().lower().rstrip(">")
    return addr.strip().lower()


def _get_body(msg) -> tuple:
    """Return (plain_text, html_text) from a message."""
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            text = payload.decode("utf-8", errors="replace")
            if ct == "text/plain":
                plain += text
            elif ct == "text/html":
                html += text
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            text = payload.decode("utf-8", errors="replace")
            if msg.get_content_type() == "text/html":
                html = text
            else:
                plain = text
    return plain, html


# ── Main extractor ────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "spf_pass", "dkim_valid", "dmarc_pass", "domain_age_days",
    "lookalike_score", "reply_to_mismatch", "display_name_spoof",
    "urgency_score", "financial_keyword_count", "credential_request",
    "phishing_url_count", "html_text_ratio", "external_image_count",
    "attachment_count", "has_macro", "body_length",
]


def extract_features(msg, envelope_sender: str) -> dict:
    """Extract all fraud-detection features from a parsed email.message.Message."""

    from_header = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    subject = str(msg.get("Subject", "") or "")

    from_name, from_email = email.utils.parseaddr(from_header)
    _, reply_email = email.utils.parseaddr(reply_to)

    from_domain = _extract_domain(from_email or envelope_sender)
    reply_domain = _extract_domain(reply_email) if reply_email else ""

    plain, html = _get_body(msg)
    full_text = (subject + " " + plain + " " + html).lower()

    # 1-3  Authentication (from Authentication-Results header)
    auth = str(msg.get("Authentication-Results", "")).lower()
    spf_pass = int("spf=pass" in auth)
    dkim_valid = int("dkim=pass" in auth)
    dmarc_pass = int("dmarc=pass" in auth)

    # 4  Domain age (placeholder — would query WHOIS in production)
    domain_age_days = 365

    # 5  Lookalike score (min distance to any Barclays variant)
    lookalike_score = min(_levenshtein_ratio(from_domain, t) for t in _LOOKALIKE_TARGETS)

    # 6  Reply-To mismatch
    reply_to_mismatch = int(bool(reply_domain and reply_domain != from_domain))

    # 7  Display-name spoofing
    display_name_spoof = 0
    name_lower = from_name.lower()
    if any(kw in name_lower for kw in ["barclays", "barclay", "brclay"]):
        if "barclays" not in from_domain:
            display_name_spoof = 1

    # 8  Urgency score
    urgency_hits = sum(1 for p in URGENCY_PATTERNS if re.search(p, full_text, re.I))
    urgency_score = round(min(urgency_hits / 5.0, 1.0), 4)

    # 9  Financial keyword count
    financial_keyword_count = sum(1 for kw in FINANCIAL_KEYWORDS if kw in full_text)

    # 10  Credential request
    credential_request = int(any(re.search(p, full_text, re.I) for p in CREDENTIAL_PATTERNS))

    # 11  Phishing URL count
    urls = URL_RE.findall(full_text)
    phishing_url_count = len(urls)

    # 12  HTML / text ratio
    html_text_ratio = round(len(html) / max(len(plain), 1), 2)

    # 13  External images
    external_image_count = len(re.findall(r"<img[^>]+src\s*=\s*[\"']https?://", html, re.I))

    # 14  Attachment count + macro detection (file attach OR text patterns in body)
    attachment_count = 0
    has_macro = 0
    if msg.is_multipart():
        for part in msg.walk():
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp:
                attachment_count += 1
                fname = (part.get_filename() or "").lower()
                if any(fname.endswith(e) for e in [".xlsm", ".docm", ".pptm", ".xls", ".doc"]):
                    has_macro = 1

    # Detect macro-related language in body text (even without actual attachment)
    _macro_patterns = ["enable macro", "enable content", "enable editing", "enable active",
                       ".xlsm", ".docm", ".pptm", ".exe", ".bat", ".vbs", ".ps1"]
    if any(p in full_text for p in _macro_patterns):
        has_macro = 1

    # Detect suspicious file extension URLs as additional phishing signal
    _sus_extensions = [".exe", ".xlsm", ".docm", ".bat", ".vbs", ".ps1", ".scr", ".pif"]
    for url in urls:
        if any(url.lower().endswith(ext) or f"{ext}?" in url.lower() for ext in _sus_extensions):
            has_macro = 1
            break

    # 16  Body length
    body_length = min(len(plain) + len(html), 10000)

    return {
        "spf_pass": spf_pass,
        "dkim_valid": dkim_valid,
        "dmarc_pass": dmarc_pass,
        "domain_age_days": domain_age_days,
        "lookalike_score": round(lookalike_score, 4),
        "reply_to_mismatch": reply_to_mismatch,
        "display_name_spoof": display_name_spoof,
        "urgency_score": urgency_score,
        "financial_keyword_count": financial_keyword_count,
        "credential_request": credential_request,
        "phishing_url_count": phishing_url_count,
        "html_text_ratio": min(html_text_ratio, 100.0),
        "external_image_count": external_image_count,
        "attachment_count": attachment_count,
        "has_macro": has_macro,
        "body_length": body_length,
    }
