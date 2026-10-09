"""
Suspicious Domain / URL Analyzer
==================================
Analyzes URLs for phishing indicators: suspicious TLDs, homograph domains,
IP addresses, lookalike brand names, and known phishing patterns.
"""

import re
from typing import Dict, List

# ── URL extraction ───────────────────────────────────────────────────────────
URL_RE = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
DOMAIN_RE = re.compile(r'https?://([^/\s<>"\'?#:]+)', re.IGNORECASE)
IP_URL_RE = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

# ── Suspicious TLDs (common in phishing campaigns) ──────────────────────────
SUSPICIOUS_TLDS = {
    '.xyz': 0.6, '.tk': 0.7, '.ml': 0.6, '.ga': 0.6, '.cf': 0.6,
    '.gq': 0.6, '.top': 0.5, '.pw': 0.6, '.cc': 0.4, '.icu': 0.5,
    '.buzz': 0.5, '.club': 0.4, '.work': 0.4, '.click': 0.6,
    '.link': 0.4, '.info': 0.3, '.bid': 0.5, '.win': 0.5,
    '.review': 0.5, '.stream': 0.5, '.party': 0.5, '.science': 0.5,
    '.download': 0.6, '.racing': 0.5, '.date': 0.5, '.trade': 0.5,
    '.loan': 0.5, '.faith': 0.5, '.cricket': 0.5, '.accountant': 0.5,
}

# ── Known brand targets (brand names commonly spoofed) ──────────────────────
BRAND_KEYWORDS = {
    'apple', 'microsoft', 'google', 'amazon', 'paypal', 'netflix',
    'facebook', 'instagram', 'linkedin', 'twitter', 'dropbox',
    'icloud', 'outlook', 'office365', 'sharepoint', 'onedrive',
    'docusign', 'adobe', 'zoom', 'slack', 'github', 'bitbucket',
    'stripe', 'square', 'venmo', 'chase', 'wellsfargo', 'bankofamerica',
    'citibank', 'hsbc', 'barclays', 'usps', 'fedex', 'dhl', 'ups',
}

# ── Suspicious domain patterns ──────────────────────────────────────────────
SUSPICIOUS_PATTERNS = [
    (re.compile(r'secure[-_].*login|login[-_].*secure', re.IGNORECASE), 0.7, "Secure-login pattern"),
    (re.compile(r'auth[-_].*portal|portal[-_].*auth', re.IGNORECASE), 0.6, "Auth-portal pattern"),
    (re.compile(r'verify[-_].*account|account[-_].*verify', re.IGNORECASE), 0.6, "Verify-account pattern"),
    (re.compile(r'update[-_].*billing|billing[-_].*update', re.IGNORECASE), 0.6, "Billing-update pattern"),
    (re.compile(r'external[-_]auth|auth[-_]external', re.IGNORECASE), 0.7, "External-auth pattern"),
    (re.compile(r'[a-z]+-[a-z]+-[a-z]+\.\w+$', re.IGNORECASE), 0.3, "Multi-hyphen domain"),
    (re.compile(r'\d{5,}', re.IGNORECASE), 0.3, "Excessive numbers in domain"),
]

# Known legitimate domains (whitelist)
LEGITIMATE_DOMAINS = {
    'google.com', 'gmail.com', 'outlook.com', 'microsoft.com',
    'apple.com', 'amazon.com', 'github.com', 'linkedin.com',
    'drive.google.com', 'docs.google.com', 'slack.com',
    'hooks.slack.com', 'aws.amazon.com', 'jira.atlassian.com',
    'sharepoint.microsoft.com', 'docusign.net',
}


def analyze_urls(text: str) -> dict:
    """
    Analyze all URLs in text for phishing indicators.
    
    Returns:
        {
            "url_count": int,
            "suspicious_urls": [{"url": "...", "domain": "...", "reasons": [...], "risk": float}],
            "legitimate_urls": [{"url": "...", "domain": "..."}],
            "has_ip_urls": bool,
            "suspicious_tlds": ["xyz"],
            "brand_impersonation": [{"brand": "apple", "domain": "..."}],
            "risk_score": float
        }
    """
    urls = URL_RE.findall(text)
    if not urls:
        return {
            "url_count": 0, "suspicious_urls": [], "legitimate_urls": [],
            "has_ip_urls": False, "suspicious_tlds": [], "brand_impersonation": [],
            "risk_score": 0.0,
        }

    suspicious_urls = []
    legitimate_urls = []
    found_tlds = set()
    brand_hits = []
    has_ip = False

    for url in urls:
        dm_match = DOMAIN_RE.search(url)
        if not dm_match:
            continue
        domain = dm_match.group(1).lower().rstrip('.')
        reasons = []
        url_risk = 0.0

        # Check if it's an IP address URL
        if IP_URL_RE.match(url):
            has_ip = True
            reasons.append("IP address in URL")
            url_risk = max(url_risk, 0.7)

        # Check for known legitimate domain
        is_legit = any(domain == d or domain.endswith('.' + d) for d in LEGITIMATE_DOMAINS)

        # Check TLD
        tld = _get_tld(domain)
        if tld in SUSPICIOUS_TLDS:
            reasons.append(f"Suspicious TLD: {tld}")
            url_risk = max(url_risk, SUSPICIOUS_TLDS[tld])
            found_tlds.add(tld)

        # Check suspicious patterns in domain
        for pat_re, weight, desc in SUSPICIOUS_PATTERNS:
            if pat_re.search(domain):
                reasons.append(desc)
                url_risk = max(url_risk, weight)

        # Check for brand impersonation (brand name in domain but not the real domain)
        for brand in BRAND_KEYWORDS:
            if brand in domain and not is_legit:
                reasons.append(f"Brand impersonation: {brand}")
                brand_hits.append({"brand": brand, "domain": domain})
                url_risk = max(url_risk, 0.8)
                break

        # Check for external-auth or lookalike subdomains
        if '.com.' in domain or '.net.' in domain or '.org.' in domain:
            reasons.append("Subdomain mimics legitimate TLD")
            url_risk = max(url_risk, 0.8)

        if reasons:
            suspicious_urls.append({
                "url": url[:120],
                "domain": domain,
                "reasons": reasons,
                "risk": round(url_risk, 2),
            })
        elif is_legit:
            legitimate_urls.append({"url": url[:120], "domain": domain})

    # Overall risk
    max_risk = max((u["risk"] for u in suspicious_urls), default=0.0)

    return {
        "url_count": len(urls),
        "suspicious_urls": suspicious_urls,
        "legitimate_urls": legitimate_urls,
        "has_ip_urls": has_ip,
        "suspicious_tlds": sorted(found_tlds),
        "brand_impersonation": brand_hits,
        "risk_score": round(max_risk, 2),
    }


def _get_tld(domain: str) -> str:
    """Extract TLD from domain."""
    parts = domain.rsplit('.', 1)
    if len(parts) == 2:
        return '.' + parts[1]
    return ''
