# src/rule_based_checker.py
"""
Rule-based phishing detection for email analysis.

Applies 15+ deterministic rules with weighted scoring.
Returns a score 0-100 and list of triggered rules with details.
"""
from __future__ import annotations
import re
from typing import Dict, List, Any
from urllib.parse import urlparse


# ── Rule definitions ─────────────────────────────────────────────────────────
# Each rule: (id, name, pattern/function, weight, severity, description)

_URGENCY_PATTERNS = [
    r"\bact now\b", r"\burgent\b", r"\bimmediately\b", r"\bexpires? (today|soon|in \d)",
    r"\blast warning\b", r"\blimited time\b", r"\bdeadline\b", r"\bwithin 24 hours?\b",
    r"\byour account (will be|has been) (closed|suspended|terminated|blocked|disabled)",
    r"\bfinal notice\b", r"\bimportant notice\b", r"\battention required\b",
]

_CREDENTIAL_PATTERNS = [
    r"\bverify your (account|password|email|identity|information)\b",
    r"\bconfirm your (password|account|details|credentials|identity)\b",
    r"\benter your (password|pin|cvv|security code|details)\b",
    r"\bupdate your (password|payment|billing|account) (information|details)\b",
    r"\bclick (here|below|the link) to (verify|confirm|update|validate|access)\b",
    r"\bsign in to your account\b",
    r"\bprovide your (username|password|credentials)\b",
    r"\byour account (information|details) (is|are) required\b",
]

_FINANCIAL_PATTERNS = [
    r"\bwire transfer\b", r"\bwestern union\b", r"\bmoney gram\b",
    r"\bbitcoin\b", r"\bcryptocurrency\b", r"\bcrypto wallet\b",
    r"\bgift card(s)?\b", r"\biTunes card\b", r"\bgoogle play card\b",
    r"\btransfer (funds|money|amount)\b", r"\bbank account (number|details)\b",
    r"\bunclaimed (funds|money|prize)\b", r"\bpayment (pending|required|overdue)\b",
]

_THREAT_PATTERNS = [
    r"\blegal action\b", r"\blawsuit\b", r"\barrest(ed)?\b",
    r"\bpolice\b", r"\bfbi\b", r"\bcourt\b", r"\bpenalty\b",
    r"\bfine of \$\b", r"\bcriminal charges?\b", r"\bwarrant\b",
    r"\byou will be reported\b", r"\bwe will take action\b",
]

_IMPERSONATION_PATTERNS = [
    r"\bpaypal\b", r"\bmicrosoft\b", r"\bapple (inc\.?)?\b",
    r"\bamazon\b", r"\bnetflix\b", r"\bfacebook\b", r"\binstagram\b",
    r"\birs\b", r"\bhmrc\b", r"\byour bank\b", r"\bchase bank\b",
    r"\bbank of america\b", r"\bwells fargo\b", r"\bciti ?bank\b",
    r"\bdhl\b", r"\bfedex\b", r"\bups\b", r"\busps\b",
    r"\bworld health organization\b", r"\bwho\b",
    r"\bdear (valued |account |customer|user)",
]

_LOTTERY_PRIZE_PATTERNS = [
    r"\byou (have |'ve )?(won|been selected|are the winner)\b",
    r"\bcongratulations!? you\b", r"\byou are (a )?lucky\b",
    r"\bfree (gift|prize|reward|money|cash)\b",
    r"\bclaim your (prize|reward|winning)\b",
    r"\blottery (winner|ticket|jackpot)\b",
    r"\binheritan(ce|t)\b", r"\bnigerian prince\b",
    r"\bmillion (dollar|pound|euro)\b",
]

_SUSPICIOUS_URL_PATTERNS = [
    r"bit\.ly/", r"tinyurl\.com/", r"t\.co/", r"ow\.ly/",
    r"goo\.gl/", r"buff\.ly/", r"rebrand\.ly/", r"cutt\.ly/",
    r"is\.gd/", r"v\.gd/", r"cli\.re/",
]


def _count_pattern_hits(text: str, patterns: List[str]) -> int:
    """Count how many patterns match in the text."""
    return sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))


def _extract_urls(text: str) -> List[str]:
    """Extract URLs from text."""
    return re.findall(r'https?://[^\s<>"\')\]]+', text)


def _check_domain_mismatch(from_email: str, reply_to: str) -> bool:
    """Check if From domain and Reply-To domain differ."""
    if not from_email or not reply_to:
        return False
    try:
        from_domain = from_email.split("@")[-1].lower().strip(">")
        reply_domain = reply_to.split("@")[-1].lower().strip(">")
        return from_domain != reply_domain
    except Exception:
        return False


def _check_sender_name_mismatch(from_name: str, from_email: str) -> bool:
    """Check if display name contains a brand but email domain doesn't match."""
    if not from_name or not from_email:
        return False
    known_brands = [
        "paypal", "microsoft", "apple", "amazon", "netflix",
        "google", "facebook", "instagram", "bank", "chase",
        "wells fargo", "citi", "support", "security",
    ]
    name_lower  = from_name.lower()
    email_lower = from_email.lower()
    for brand in known_brands:
        if brand in name_lower and brand not in email_lower:
            return True
    return False


def _count_caps_ratio(text: str) -> float:
    """Return ratio of uppercase letters to total letters."""
    letters = [c for c in text if c.isalpha()]
    if len(letters) < 20:
        return 0.0
    caps = sum(1 for c in letters if c.isupper())
    return caps / len(letters)


def check_email(
    body:       str,
    subject:    str      = "",
    from_email: str      = "",
    from_name:  str      = "",
    reply_to:   str      = "",
    headers:    str      = "",
) -> Dict[str, Any]:
    """
    Run all rule-based checks on an email.

    Returns:
        {
            "score": 0-100,
            "triggered_rules": [...],
            "rule_count": int,
            "severity": "LOW|MEDIUM|HIGH|CRITICAL"
        }
    """
    full_text    = f"{subject}\n{body}"
    triggered:   List[Dict] = []
    total_weight = 0

    # ── Rule 1: Urgency language ─────────────────────────────────────────────
    hits = _count_pattern_hits(full_text, _URGENCY_PATTERNS)
    if hits > 0:
        weight = min(hits * 8, 25)
        total_weight += weight
        triggered.append({
            "rule_id":    "urgency_language",
            "name":       "Urgency Language",
            "severity":   "Medium" if hits < 3 else "High",
            "weight":     weight,
            "detail":     f"{hits} urgency pattern(s) detected (e.g., 'act now', 'account suspended')",
        })

    # ── Rule 2: Credential harvesting ───────────────────────────────────────
    hits = _count_pattern_hits(full_text, _CREDENTIAL_PATTERNS)
    if hits > 0:
        weight = min(hits * 12, 30)
        total_weight += weight
        triggered.append({
            "rule_id":    "credential_harvesting",
            "name":       "Credential Harvesting",
            "severity":   "High",
            "weight":     weight,
            "detail":     f"{hits} credential-request pattern(s) detected (e.g., 'verify your account', 'confirm password')",
        })

    # ── Rule 3: Financial fraud ──────────────────────────────────────────────
    hits = _count_pattern_hits(full_text, _FINANCIAL_PATTERNS)
    if hits > 0:
        weight = min(hits * 10, 25)
        total_weight += weight
        triggered.append({
            "rule_id":    "financial_fraud",
            "name":       "Financial Fraud Indicators",
            "severity":   "High",
            "weight":     weight,
            "detail":     f"{hits} financial fraud pattern(s) (e.g., 'wire transfer', 'bitcoin', 'gift card')",
        })

    # ── Rule 4: Threat language ──────────────────────────────────────────────
    hits = _count_pattern_hits(full_text, _THREAT_PATTERNS)
    if hits > 0:
        weight = min(hits * 8, 20)
        total_weight += weight
        triggered.append({
            "rule_id":    "threat_language",
            "name":       "Threat / Coercive Language",
            "severity":   "High",
            "weight":     weight,
            "detail":     f"{hits} threat pattern(s) detected (e.g., 'legal action', 'arrest', 'warrant')",
        })

    # ── Rule 5: Brand impersonation ──────────────────────────────────────────
    hits = _count_pattern_hits(full_text, _IMPERSONATION_PATTERNS)
    if hits > 0:
        weight = min(hits * 5, 20)
        total_weight += weight
        triggered.append({
            "rule_id":    "brand_impersonation",
            "name":       "Brand / Entity Impersonation",
            "severity":   "Medium",
            "weight":     weight,
            "detail":     f"{hits} brand reference(s) found — may indicate impersonation attempt",
        })

    # ── Rule 6: Lottery / prize scam ────────────────────────────────────────
    hits = _count_pattern_hits(full_text, _LOTTERY_PRIZE_PATTERNS)
    if hits > 0:
        weight = min(hits * 10, 25)
        total_weight += weight
        triggered.append({
            "rule_id":    "lottery_prize_scam",
            "name":       "Lottery / Prize Scam",
            "severity":   "High",
            "weight":     weight,
            "detail":     f"{hits} prize/lottery pattern(s) (e.g., 'you have won', 'claim your prize')",
        })

    # ── Rule 7: Shortened URLs ───────────────────────────────────────────────
    short_hits = _count_pattern_hits(full_text, _SUSPICIOUS_URL_PATTERNS)
    if short_hits > 0:
        weight = min(short_hits * 12, 20)
        total_weight += weight
        triggered.append({
            "rule_id":    "shortened_urls",
            "name":       "URL Shortener Used",
            "severity":   "Medium",
            "weight":     weight,
            "detail":     f"{short_hits} shortened URL(s) detected — can obscure malicious destinations",
        })

    # ── Rule 8: Multiple URLs ────────────────────────────────────────────────
    urls = _extract_urls(full_text)
    if len(urls) >= 5:
        weight = min((len(urls) - 4) * 3, 15)
        total_weight += weight
        triggered.append({
            "rule_id":    "excessive_urls",
            "name":       "Excessive URL Count",
            "severity":   "Low",
            "weight":     weight,
            "detail":     f"{len(urls)} URLs found — phishing emails often embed many redirect links",
        })

    # ── Rule 9: Sender name vs domain mismatch ───────────────────────────────
    if _check_sender_name_mismatch(from_name, from_email):
        weight = 20
        total_weight += weight
        triggered.append({
            "rule_id":    "sender_name_mismatch",
            "name":       "Sender Name / Domain Mismatch",
            "severity":   "High",
            "weight":     weight,
            "detail":     f"Display name '{from_name}' references a brand but sending domain '{from_email.split('@')[-1] if '@' in from_email else from_email}' does not match",
        })

    # ── Rule 10: From ↔ Reply-To domain mismatch ────────────────────────────
    if _check_domain_mismatch(from_email, reply_to):
        weight = 18
        total_weight += weight
        triggered.append({
            "rule_id":    "reply_to_mismatch",
            "name":       "From / Reply-To Domain Mismatch",
            "severity":   "High",
            "weight":     weight,
            "detail":     f"Reply-To domain differs from From domain — common in phishing to redirect replies",
        })

    # ── Rule 11: Excessive punctuation / CAPS ───────────────────────────────
    exclamation_count = full_text.count("!")
    if exclamation_count >= 5:
        weight = min(exclamation_count * 2, 10)
        total_weight += weight
        triggered.append({
            "rule_id":    "excessive_exclamation",
            "name":       "Excessive Exclamation Marks",
            "severity":   "Low",
            "weight":     weight,
            "detail":     f"{exclamation_count} exclamation marks — common in spam/phishing for false urgency",
        })

    caps_ratio = _count_caps_ratio(full_text)
    if caps_ratio > 0.35:
        weight = 8
        total_weight += weight
        triggered.append({
            "rule_id":    "excessive_caps",
            "name":       "Excessive UPPERCASE Text",
            "severity":   "Low",
            "weight":     weight,
            "detail":     f"{caps_ratio:.0%} uppercase letters — all-caps is often used to convey false urgency",
        })

    # ── Rule 12: Mismatched subject urgency vs body ──────────────────────────
    subj_urgent  = bool(re.search(r"\b(urgent|action required|verify|suspended|alert)\b", subject, re.IGNORECASE))
    body_benign  = len(full_text.split()) < 30
    if subj_urgent and body_benign:
        weight = 12
        total_weight += weight
        triggered.append({
            "rule_id":    "subject_body_mismatch",
            "name":       "Urgent Subject / Thin Body",
            "severity":   "Medium",
            "weight":     weight,
            "detail":     "Subject claims urgency but body has little content — typical of click-bait phishing",
        })

    # ── Rule 13: Generic greeting ────────────────────────────────────────────
    if re.search(r"^(dear (customer|user|account holder|valued customer|member|sir|madam))", body[:100], re.IGNORECASE):
        weight = 8
        total_weight += weight
        triggered.append({
            "rule_id":    "generic_greeting",
            "name":       "Generic Impersonal Greeting",
            "severity":   "Low",
            "weight":     weight,
            "detail":     "Email begins with generic greeting rather than recipient's name",
        })

    # ── Rule 14: Suspicious keyword combo ───────────────────────────────────
    has_click  = bool(re.search(r"\bclick (here|the link|below)\b", full_text, re.IGNORECASE))
    has_login  = bool(re.search(r"\b(login|sign in|log in)\b", full_text, re.IGNORECASE))
    has_verify = bool(re.search(r"\b(verify|confirm|validate)\b", full_text, re.IGNORECASE))
    combo_score = sum([has_click, has_login, has_verify])
    if combo_score >= 2:
        weight = combo_score * 7
        total_weight += weight
        triggered.append({
            "rule_id":    "click_login_verify_combo",
            "name":       "Click + Login + Verify Combo",
            "severity":   "Medium",
            "weight":     weight,
            "detail":     "Email contains combination of 'click here', 'login', and 'verify' — classic phishing pattern",
        })

    # ── Rule 15: Free email service in sender (for corporate context) ─────
    free_email_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com", "aol.com"]
    if from_email and any(f"@{d}" in from_email.lower() for d in free_email_domains):
        # Only flag if subject/body claims to be a corporate entity
        if re.search(r"\b(bank|paypal|microsoft|amazon|netflix|support team|it department|helpdesk)\b", full_text, re.IGNORECASE):
            weight = 15
            total_weight += weight
            triggered.append({
                "rule_id":    "free_email_corporate_claim",
                "name":       "Free Email + Corporate Claim",
                "severity":   "High",
                "weight":     weight,
                "detail":     f"Sender uses a free email service ({from_email}) but claims to be a corporate/official entity",
            })

    # ── Normalise to 0-100 ───────────────────────────────────────────────────
    # Max theoretical weight ≈ 243; normalise to 100
    score = min(int((total_weight / 243) * 100), 100)

    if score >= 70:
        severity = "CRITICAL"
    elif score >= 50:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "score":           score,
        "triggered_rules": triggered,
        "rule_count":      len(triggered),
        "severity":        severity,
        "total_weight":    total_weight,
    }
