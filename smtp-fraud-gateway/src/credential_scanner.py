"""
Credential Exposure Scanner
============================
Detects leaked credentials in email bodies using Shannon entropy analysis
combined with 15+ regex patterns for known credential formats.

Research basis: TruffleHog entropy detection + Secrets Patterns DB (mazinahmed)
"""

import re
import math
from typing import List, Dict

# ── Shannon Entropy ──────────────────────────────────────────────────────────

def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random = likely a secret."""
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


# ── Credential Regex Patterns ────────────────────────────────────────────────

CREDENTIAL_PATTERNS = [
    # Cloud provider keys
    {
        "name": "AWS Access Key",
        "regex": re.compile(r'(?:AWS_ACCESS_KEY_ID\s*[=:]\s*)?(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])'),
        "severity": "CRITICAL",
        "description": "AWS IAM Access Key ID",
    },
    {
        "name": "AWS Secret Key",
        "regex": re.compile(r'(?:AWS_SECRET_ACCESS_KEY\s*[=:]\s*)([A-Za-z0-9/+=]{40})'),
        "severity": "CRITICAL",
        "description": "AWS Secret Access Key (40-char base64)",
    },
    # API keys
    {
        "name": "GitHub Personal Access Token",
        "regex": re.compile(r'(ghp_[A-Za-z0-9]{36,})'),
        "severity": "CRITICAL",
        "description": "GitHub PAT (classic format)",
    },
    {
        "name": "GitHub Fine-Grained Token",
        "regex": re.compile(r'(github_pat_[A-Za-z0-9_]{82,})'),
        "severity": "CRITICAL",
        "description": "GitHub Fine-Grained PAT",
    },
    {
        "name": "OpenAI API Key",
        "regex": re.compile(r'(sk-(?:proj-)?[A-Za-z0-9]{20,})'),
        "severity": "CRITICAL",
        "description": "OpenAI API Key (sk-proj-... or sk-...)",
    },
    {
        "name": "Stripe Secret Key",
        "regex": re.compile(r'(sk_live_[A-Za-z0-9]{24,})'),
        "severity": "CRITICAL",
        "description": "Stripe Live Secret Key",
    },
    {
        "name": "Stripe Test Key",
        "regex": re.compile(r'(sk_test_[A-Za-z0-9]{24,})'),
        "severity": "MEDIUM",
        "description": "Stripe Test Secret Key",
    },
    {
        "name": "SendGrid API Key",
        "regex": re.compile(r'(SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,})'),
        "severity": "CRITICAL",
        "description": "SendGrid API Key",
    },
    {
        "name": "Slack Webhook",
        "regex": re.compile(r'(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)'),
        "severity": "HIGH",
        "description": "Slack Incoming Webhook URL",
    },
    {
        "name": "Slack Bot Token",
        "regex": re.compile(r'(xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+)'),
        "severity": "CRITICAL",
        "description": "Slack Bot OAuth Token",
    },
    # Database / connection strings
    {
        "name": "Database Connection String",
        "regex": re.compile(r'(?:postgres|mysql|mongodb)(?:ql)?://[^\s]{10,}'),
        "severity": "CRITICAL",
        "description": "Database connection URI with credentials",
    },
    # JWT tokens
    {
        "name": "JWT Token",
        "regex": re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'),
        "severity": "HIGH",
        "description": "JSON Web Token (JWT)",
    },
    # Generic patterns
    {
        "name": "Bearer Token",
        "regex": re.compile(r'[Bb]earer\s+([A-Za-z0-9_.-]{20,})'),
        "severity": "HIGH",
        "description": "HTTP Bearer Token",
    },
    {
        "name": "Private Key Header",
        "regex": re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
        "severity": "CRITICAL",
        "description": "PEM Private Key",
    },
    {
        "name": "Google API Key",
        "regex": re.compile(r'(AIza[A-Za-z0-9_-]{35})'),
        "severity": "HIGH",
        "description": "Google API Key",
    },
    # Password-like assignments
    {
        "name": "Hardcoded Password",
        "regex": re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})', re.IGNORECASE),
        "severity": "HIGH",
        "description": "Hardcoded password in text",
    },
]

# High-entropy string finder (catches unknown credential formats)
HIGH_ENTROPY_RE = re.compile(r'(?<![A-Za-z0-9_/+=.-])([A-Za-z0-9_/+=.-]{20,80})(?![A-Za-z0-9_/+=.-])')
ENTROPY_THRESHOLD = 4.5  # Strings above this are likely secrets
MIN_TOKEN_LENGTH = 20

# Skip common high-entropy non-secrets
_ENTROPY_SKIP = {
    'http', 'https', 'www.', '.com', '.org', '.net',
    'application/json', 'content-type', 'text/html',
}


def scan_credentials(text: str) -> dict:
    """
    Scan text for credential exposure using regex + entropy analysis.
    
    Returns:
        {
            "has_credentials": bool,
            "credential_count": int,
            "credentials": [{"type": "AWS Access Key", "value": "AKIA...", "severity": "CRITICAL", "description": "..."}],
            "high_entropy_strings": [{"value": "...", "entropy": 5.2}],
            "risk_score": float  # 0.0 - 1.0
        }
    """
    found = []
    seen_values = set()

    # Pattern-based detection
    for pattern in CREDENTIAL_PATTERNS:
        for match in pattern["regex"].finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            if value not in seen_values:
                seen_values.add(value)
                found.append({
                    "type": pattern["name"],
                    "value": _mask_credential(value),
                    "value_raw": value,  # keep for internal use
                    "severity": pattern["severity"],
                    "description": pattern["description"],
                    "entropy": round(_shannon_entropy(value), 2),
                })

    # Entropy-based detection for unknown patterns
    high_entropy = []
    for match in HIGH_ENTROPY_RE.finditer(text):
        token = match.group(1)
        if len(token) < MIN_TOKEN_LENGTH:
            continue
        if any(skip in token.lower() for skip in _ENTROPY_SKIP):
            continue
        if token in seen_values:
            continue
        ent = _shannon_entropy(token)
        if ent >= ENTROPY_THRESHOLD:
            # Check it's not already captured by regex
            if not any(token in c.get("value_raw", "") for c in found):
                high_entropy.append({
                    "value": _mask_credential(token),
                    "entropy": round(ent, 2),
                    "length": len(token),
                })

    count = len(found)
    # Risk scoring
    risk = 0.0
    if count > 0:
        max_severity = max(
            ({"CRITICAL": 0.95, "HIGH": 0.80, "MEDIUM": 0.50}.get(c["severity"], 0.3) for c in found),
            default=0.0
        )
        risk = max_severity
    if high_entropy:
        risk = max(risk, 0.60)

    return {
        "has_credentials": count > 0 or len(high_entropy) > 0,
        "credential_count": count,
        "credentials": [{k: v for k, v in c.items() if k != "value_raw"} for c in found],
        "high_entropy_strings": high_entropy[:5],  # Top 5
        "risk_score": round(risk, 2),
    }


def _mask_credential(value: str) -> str:
    """Mask credential for safe display: show first 8 and last 4 chars."""
    if len(value) <= 16:
        return value[:4] + "****" + value[-4:]
    return value[:8] + "..." + value[-4:]
