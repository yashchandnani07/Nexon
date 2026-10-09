"""
sensitive_data_extractor.py
────────────────────────────────────────────────────────────────────────────
Module 3 — Sensitive Data Extraction

Scans email body and subject for:
  • Emails              → extracted_emails[]
  • Phone numbers       → extracted_phones[]
  • Account/card numbers→ extracted_account_numbers[]
  • Named entities (NER)→ extracted_names[]

Uses regex for structured patterns.
NER uses spaCy (en_core_web_sm) with automatic fallback to a regex-only
name-extraction heuristic when spaCy is not installed.
"""
from __future__ import annotations

import re
from typing import Dict, List

# ── Compiled regex patterns ───────────────────────────────────────────────────

# Email addresses
_RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# International phone numbers — covers E.164, US, UK, dotted, dashed formats
_RE_PHONE = re.compile(
    r"""
    (?:
        \+?1[\s\-.]?                     # optional country code +1
        (?:\(\d{3}\)|\d{3})[\s\-.]?      # area code
        \d{3}[\s\-.]?\d{4}               # local number
    |
        \+\d{1,3}[\s\-.]?\d{1,4}[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}  # international
    |
        0\d{9,10}                         # UK / EU style (0XXXXXXXXXX)
    )
    """,
    re.VERBOSE,
)

# Credit/debit card numbers (13–16 digits, optionally spaced/dashed)
_RE_CARD = re.compile(
    r"\b(?:\d[ \-]?){13,16}\b"
)

# Bank account / IBAN / routing patterns
_RE_ACCOUNT = re.compile(
    r"""
    (?:
        # IBAN — up to 34 chars
        [A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,16})
    |
        # US routing + account (9 + 8–17 digits, separated)
        \b\d{9}\b[\s\/\-]+\b\d{8,17}\b
    |
        # Generic account number — 8 to 18 consecutive digits not adjacent to
        # letters (avoids matching timestamps/IDs)
        (?<![A-Za-z\d])\d{8,18}(?![A-Za-z\d])
    )
    """,
    re.VERBOSE,
)

# Heuristic name pattern — "Firstname Lastname" capitalised words (fallback)
_RE_NAME = re.compile(
    r"\b([A-Z][a-z]{1,20})\s([A-Z][a-z]{1,20}(?:\s[A-Z][a-z]{1,20})?)\b"
)

# Common English words that look like names but aren't
_STOPWORDS = {
    "Dear", "Hello", "Subject", "Thank", "Sincerely", "Regards",
    "Please", "Click", "Verify", "Account", "Security", "Alert",
    "Notice", "Important", "Urgent", "Action", "Required", "Your",
    "This", "With", "From", "Send", "Contact", "Support", "Team",
    "Service", "Customer", "Banking", "Online", "Access", "Update",
    "Password", "Username", "Email", "Phone", "Number", "Date",
    "January", "February", "March", "April", "June", "July",
    "August", "September", "October", "November", "December",
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
    "Saturday", "Sunday", "United", "States", "America", "Kingdom",
}

# ── spaCy NER (lazy singleton) ────────────────────────────────────────────────

_nlp = None
_nlp_loaded = False
_nlp_error  = ""


def _load_spacy():
    global _nlp, _nlp_loaded, _nlp_error
    if _nlp_loaded:
        return _nlp is not None
    _nlp_loaded = True
    try:
        import spacy
        _nlp = spacy.load("en_core_web_sm")
        return True
    except ImportError:
        _nlp_error = "spacy not installed"
    except OSError:
        _nlp_error = "en_core_web_sm not found (run: python -m spacy download en_core_web_sm)"
    return False


def _extract_names_ner(text: str) -> List[str]:
    """Use spaCy NER to extract person names."""
    if not _load_spacy():
        return _extract_names_regex(text)
    try:
        doc   = _nlp(text[:2000])
        names = [
            ent.text.strip()
            for ent in doc.ents
            if ent.label_ == "PERSON" and len(ent.text.strip()) >= 3
        ]
        return _dedup(names)
    except Exception:
        return _extract_names_regex(text)


def _extract_names_regex(text: str) -> List[str]:
    """Fallback regex-based name extraction (capitalised bigrams/trigrams)."""
    matches = _RE_NAME.findall(text)
    names = []
    for parts in matches:
        name = " ".join(p for p in parts if p)
        words = name.split()
        if any(w in _STOPWORDS for w in words):
            continue
        names.append(name)
    return _dedup(names)


def _dedup(items: List[str]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for item in items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _luhn_valid(number: str) -> bool:
    """Basic Luhn check to filter out random digit strings as card numbers."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ── Public API ─────────────────────────────────────────────────────────────────

def extract_sensitive_data(subject: str = "", body: str = "") -> Dict:
    """
    Scan subject + body text for sensitive data.

    Returns:
        {
            "extracted_emails": [],
            "extracted_phones": [],
            "extracted_account_numbers": [],
            "extracted_names": [],
            "sensitive_data_found": bool
        }
    """
    combined = f"{subject}\n{body}"

    # ── Emails ────────────────────────────────────────────────────────────────
    emails = _dedup(_RE_EMAIL.findall(combined))

    # ── Phone numbers ─────────────────────────────────────────────────────────
    raw_phones = _RE_PHONE.findall(combined)
    phones     = _dedup([p.strip() for p in raw_phones if len(re.sub(r"\D", "", p)) >= 7])

    # ── Account / card numbers ────────────────────────────────────────────────
    account_numbers: List[str] = []

    # Cards (Luhn-validated)
    for m in _RE_CARD.finditer(combined):
        raw = m.group()
        digits_only = re.sub(r"\D", "", raw)
        if 13 <= len(digits_only) <= 16 and _luhn_valid(digits_only):
            account_numbers.append(raw.strip())

    # IBAN / routing / generic long account numbers
    for m in _RE_ACCOUNT.finditer(combined):
        val = m.group().strip()
        digits_only = re.sub(r"\D", "", val)
        # Skip anything already captured as a phone
        if val in phones:
            continue
        if len(digits_only) >= 8:
            account_numbers.append(val)

    account_numbers = _dedup(account_numbers)

    # ── Names ─────────────────────────────────────────────────────────────────
    names = _extract_names_ner(combined)

    found = bool(emails or phones or account_numbers or names)

    return {
        "extracted_emails":          emails,
        "extracted_phones":          phones,
        "extracted_account_numbers": account_numbers,
        "extracted_names":           names,
        "sensitive_data_found":      found,
    }
