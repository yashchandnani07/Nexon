"""
URL Reputation Scoring — multi-signal offline analysis.
Detects phishing / malicious URLs without requiring external API calls.

Signals checked:
  1.  IP address as hostname
  2.  Suspicious free/abused TLDs
  3.  URL shorteners (obfuscate destination)
  4.  Excessive subdomain depth
  5.  Very long URLs
  6.  High domain entropy (DGA / obfuscated)
  7.  Punycode / IDN homograph attack
  8.  Phishing/scam keywords in any part of URL
  9.  Brand name used in subdomain (brand.attacker.com)
  10. Homoglyph lookalike patterns
  11. @ character in URL (browser confusion)
  12. Double-slash redirect trick
  13. data: / javascript: URI schemes
  14. "fake", "scam", "phish", "evil" in domain
  15. Brand name appearing with extra domain suffix
  16. Dash-abuse patterns (-secure, -login, -verify, -alert)
"""

import re
import math
import ipaddress
from urllib.parse import urlparse

# ── Known bad TLDs ────────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    # Free / frequently abused
    '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.xyz', '.top', '.click',
    '.link', '.zip', '.review', '.country', '.kim', '.science', '.work',
    '.party', '.download', '.accountant', '.stream', '.trade', '.win',
    '.men', '.loan', '.racing', '.rocks', '.space', '.website', '.bid',
    # Geographic TLDs widely abused for phishing
    '.ru', '.cn', '.su', '.ws', '.cc',
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'tiny.cc', 'tr.im', 'snipurl.com', 'cli.gs',
    'cutt.ly', 'rb.gy', 'shorturl.at', 's.id', 'rebrand.ly', 'lnkd.in',
    'url4.eu', 'qr.net',
}

# Keywords that are suspicious when found in domain/path (not just email body)
PHISHING_URL_KEYWORDS = [
    'verify', 'secure', 'security', 'login', 'signin', 'account', 'update',
    'password', 'credential', 'confirm', 'suspended', 'blocked', 'locked',
    'reset', 'authenticate', 'validation', 'helpdesk', 'support',
    # Brand names used as bait in URLs
    'paypal', 'barclays', 'amazon', 'google', 'microsoft', 'apple',
    'halifax', 'natwest', 'hsbc', 'lloyds', 'santander', 'wellsfargo',
    'chase', 'citibank', 'netflix', 'hdfc', 'sbi', 'paytm', 'icici',
    'dhl', 'fedex', 'ups', 'usps', 'tcs', 'infosys', 'tesla', 'office365',
]

# Clearly malicious words in domain
MALICIOUS_DOMAIN_WORDS = ['fake', 'scam', 'phish', 'evil', 'malware', 'attack']

# Brand names to detect in subdomains
TARGET_BRANDS = [
    'paypal', 'barclays', 'amazon', 'microsoft', 'google', 'apple',
    'halifax', 'natwest', 'hsbc', 'lloyds', 'santander', 'netflix',
    'hdfc', 'sbi', 'paytm', 'icici', 'dhl', 'fedex', 'office365',
]

# Homoglyph patterns (compiled once)
HOMOGLYPH_PATTERNS = [
    r'paypa[l1I]', r'g[o0]{2}g[l1]e', r'micr[o0]s[o0]ft', r'micr0soft',
    r'arnazon', r'amaz[o0]n', r'barcI', r'barciays',
    r'app1e', r'appl[e3]', r'faceb[o0]{2}k',
    r'hdfc-?sec', r'paytm-?v', r'office365-?sec',
]
_HOMOGLYPH_RE = [re.compile(p, re.I) for p in HOMOGLYPH_PATTERNS]

# Suspicious dash-patterns in domains (brand-keyword.attacker.com)
_DASH_ABUSE_RE = re.compile(
    r'(secure|login|verify|alert|update|reset|confirm|support|helpdesk|access|auth)'
    r'[-.]'
    r'|[-.]'
    r'(secure|login|verify|alert|update|reset|confirm|support|helpdesk|access|auth)',
    re.I
)

# Trusted root domains — never flag these
_TRUSTED = {
    'google.com', 'microsoft.com', 'amazon.com', 'apple.com', 'paypal.com',
    'linkedin.com', 'github.com', 'twitter.com', 'facebook.com',
    'barclays.com', 'barclays.co.uk', 'amazon.co.uk', 'amazon.in',
    'office.com', 'live.com', 'outlook.com', 'hotmail.com',
    'dhl.com', 'fedex.com', 'ups.com', 'tcs.com', 'netflix.com',
    'hdfc.com', 'hdfcbank.com', 'sbi.co.in', 'icicibank.com',
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    """Shannon entropy of a string (higher = more random)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _root_domain(host: str) -> str:
    """Return last two domain labels (e.g. 'evil.com')."""
    parts = host.split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else host


# ── Per-URL scorer ────────────────────────────────────────────────────────────

def score_url(url: str) -> dict:
    """Score a single URL (0-100) and return reasons."""
    reasons = []
    score   = 0

    if not url:
        return {"url": url, "score": 0, "risk": "LOW", "reasons": []}

    # data: / javascript: always dangerous
    if url.startswith('data:') or url.lower().startswith('javascript:'):
        return {"url": url[:80], "score": 92, "risk": "HIGH",
                "reasons": ["data:/javascript: URI — code execution risk"]}

    if not url.startswith(('http://', 'https://')):
        return {"url": url[:80], "score": 0, "risk": "LOW", "reasons": []}

    try:
        parsed = urlparse(url)
        host   = parsed.netloc.lower().split(':')[0]
        path   = parsed.path.lower()
        full   = url.lower()
    except Exception:
        return {"url": url[:80], "score": 5, "risk": "LOW", "reasons": ["malformed URL"]}

    root           = _root_domain(host)
    subdomain_count = host.count('.')

    # Skip known-good trusted roots
    if root in _TRUSTED:
        return {"url": url[:80], "score": 0, "risk": "LOW", "reasons": ["trusted domain"]}

    # 1. IP address as hostname
    if _is_ip(host):
        score += 45
        reasons.append("IP address used as hostname — no domain name")

    # 2. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 28
            reasons.append(f"Suspicious/abused TLD: {tld}")
            break

    # 3. URL shortener
    clean_host = host.replace('www.', '')
    if clean_host in URL_SHORTENERS:
        score += 20
        reasons.append(f"URL shortener hides destination: {clean_host}")

    # 4. Excessive subdomain depth (> 3 dots in host)
    if subdomain_count > 3:
        score += 15
        reasons.append(f"Excessive subdomain nesting ({subdomain_count} levels)")

    # 5. Very long URL
    if len(url) > 150:
        score += 10
        reasons.append(f"Unusually long URL ({len(url)} chars)")

    # 6. High domain entropy (DGA-style or obfuscated)
    domain_label = host.split('.')[0] if '.' in host else host
    if len(domain_label) > 6:
        ent = _entropy(domain_label)
        if ent > 3.8:
            score += 20
            reasons.append(f"High domain entropy ({ent:.1f}) — possible DGA/obfuscation")

    # 7. Punycode / IDN homograph attack
    if 'xn--' in host:
        score += 30
        reasons.append("Punycode (IDN) domain — possible homograph attack")

    # 8. Clearly malicious words in domain
    for word in MALICIOUS_DOMAIN_WORDS:
        if word in host:
            score += 40
            reasons.append(f"Malicious word in domain: '{word}'")
            break

    # 9. Phishing keywords anywhere in the hostname
    kw_hits = [k for k in PHISHING_URL_KEYWORDS if k in host]
    if kw_hits:
        score += min(len(kw_hits) * 8, 30)
        reasons.append(f"Phishing keywords in URL hostname: {', '.join(kw_hits[:4])}")

    # 10. Brand name in subdomain prefix (brand.attacker.com pattern)
    labels = host.split('.')
    non_root_labels = labels[:-2] if len(labels) > 2 else []
    brand_in_subdomain = any(b in '.'.join(non_root_labels) for b in TARGET_BRANDS)
    if brand_in_subdomain:
        score += 38
        reasons.append("Brand name used in subdomain — likely spoofed")

    # 11. Brand name in root domain with suspicious TLD (paypal.xyz, etc.)
    brand_in_root = any(b in root for b in TARGET_BRANDS)
    if brand_in_root and not any(root.endswith(t) for t in ['.com', '.org', '.net', '.co.uk', '.in']):
        score += 30
        reasons.append(f"Brand name in root domain with suspicious TLD: {root}")

    # 12. Dash-abuse pattern (secure-, -login, verify-, etc.)
    if _DASH_ABUSE_RE.search(host):
        score += 18
        reasons.append("Suspicious dash pattern in domain (e.g. -secure, -login, verify-)")

    # 13. Homoglyph lookalike
    for rgx in _HOMOGLYPH_RE:
        if rgx.search(host):
            score += 42
            reasons.append(f"Lookalike/homoglyph domain pattern: '{host}'")
            break

    # 14. @ in URL (browser credential confusion)
    if '@' in full:
        score += 30
        reasons.append("@ in URL — browser credential confusion attack")

    # 15. Double-slash redirect in path
    if '//' in path:
        score += 12
        reasons.append("Double slash in path — open redirect pattern")

    # 16. Numeric-heavy domain label
    digits = sum(c.isdigit() for c in domain_label)
    if len(domain_label) > 4 and digits / len(domain_label) > 0.5:
        score += 15
        reasons.append("Domain label mostly numeric — suspicious")

    score = min(score, 100)
    risk  = "HIGH" if score >= 55 else "MEDIUM" if score >= 28 else "LOW"

    return {"url": url[:120], "score": score, "risk": risk, "reasons": reasons}


# ── Batch URL scorer ──────────────────────────────────────────────────────────

def score_urls(urls: list) -> dict:
    """Score a list of URLs and return aggregate + per-URL breakdown."""
    if not urls:
        return {
            "url_risk_score":   0,
            "suspicious_count": 0,
            "high_count":       0,
            "medium_count":     0,
            "url_results":      [],
            "top_suspicious":   [],
        }

    results      = [score_url(u) for u in urls[:25]]
    max_score    = max((r["score"] for r in results), default=0)
    high_count   = sum(1 for r in results if r["risk"] == "HIGH")
    medium_count = sum(1 for r in results if r["risk"] == "MEDIUM")

    top_suspicious = sorted(
        [r for r in results if r["score"] > 0],
        key=lambda x: x["score"], reverse=True
    )[:5]

    return {
        "url_risk_score":   max_score,
        "suspicious_count": high_count + medium_count,
        "high_count":       high_count,
        "medium_count":     medium_count,
        "url_results":      results,
        "top_suspicious":   top_suspicious,
    }
