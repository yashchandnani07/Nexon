"""
Homograph / IDN Attack Detector
================================
Detects Unicode confusable characters in domains and URLs.
Catches attacks like: аpple.com (Cyrillic а), аmazon.com, micrоsoft.com, linkеdin.com

Research basis: Unicode TR39 Confusable Detection (unicode.org/reports/tr39)
"""

import re
import unicodedata

# ── Confusable mapping: non-ASCII chars that look like ASCII ─────────────────
# Covers Cyrillic, Greek, and other common homoglyph substitutions
CONFUSABLE_MAP = {
    # Cyrillic → Latin
    '\u0430': 'a',   # Cyrillic а → a
    '\u0435': 'e',   # Cyrillic е → e
    '\u0456': 'i',   # Cyrillic і → i
    '\u043e': 'o',   # Cyrillic о → o
    '\u0440': 'p',   # Cyrillic р → p
    '\u0441': 'c',   # Cyrillic с → c
    '\u0443': 'y',   # Cyrillic у → y (looks like y)
    '\u0445': 'x',   # Cyrillic х → x
    '\u0455': 's',   # Cyrillic ѕ → s
    '\u0458': 'j',   # Cyrillic ј → j
    '\u04bb': 'h',   # Cyrillic һ → h
    '\u0432': 'b',   # Cyrillic в → b (close)
    '\u043d': 'h',   # Cyrillic н → h (sometimes used)
    '\u0442': 't',   # Cyrillic т → t (italic form)
    '\u043a': 'k',   # Cyrillic к → k
    '\u043c': 'm',   # Cyrillic м → m
    '\u0410': 'A',   # Cyrillic А → A
    '\u0412': 'B',   # Cyrillic В → B
    '\u0415': 'E',   # Cyrillic Е → E
    '\u041a': 'K',   # Cyrillic К → K
    '\u041c': 'M',   # Cyrillic М → M
    '\u041d': 'H',   # Cyrillic Н → H
    '\u041e': 'O',   # Cyrillic О → O
    '\u0420': 'P',   # Cyrillic Р → P
    '\u0421': 'C',   # Cyrillic С → C
    '\u0422': 'T',   # Cyrillic Т → T
    '\u0425': 'X',   # Cyrillic Х → X
    # Greek → Latin
    '\u03b1': 'a',   # Greek α → a
    '\u03b5': 'e',   # Greek ε → e (close)
    '\u03bf': 'o',   # Greek ο → o
    '\u03c1': 'p',   # Greek ρ → p
    '\u0391': 'A',   # Greek Α → A
    '\u0392': 'B',   # Greek Β → B
    '\u0395': 'E',   # Greek Ε → E
    '\u039f': 'O',   # Greek Ο → O
    # Special characters
    '\u0131': 'i',   # Turkish dotless ı → i
    '\u0268': 'i',   # Latin ɨ → i
    '\u0261': 'g',   # Latin ɡ → g
    '\u1d00': 'a',   # Small cap ᴀ → A
    '\u2010': '-',   # Hyphen ‐ → -
    '\u2011': '-',   # Non-breaking hyphen ‑ → -
    '\u2012': '-',   # Figure dash ‒ → -
    '\u2013': '-',   # En dash – → -
    '\uff0e': '.',   # Fullwidth . → .
    '\uff0f': '/',   # Fullwidth / → /
}

URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
DOMAIN_RE = re.compile(r'https?://([^/\s<>"\'?#]+)', re.IGNORECASE)


def _is_non_ascii_letter(ch: str) -> bool:
    """Check if a character is a letter but NOT basic ASCII."""
    return ch.isalpha() and ord(ch) > 127


def deconfuse(text: str) -> str:
    """Replace all confusable characters with their ASCII equivalents."""
    return ''.join(CONFUSABLE_MAP.get(ch, ch) for ch in text)


def detect_homoglyphs(text: str) -> dict:
    """
    Scan text for homoglyph/confusable characters.
    
    Returns:
        {
            "has_homoglyphs": bool,
            "homoglyph_count": int,
            "confusable_chars": [{"char": "а", "unicode": "U+0430", "looks_like": "a", "name": "CYRILLIC SMALL LETTER A"}],
            "affected_urls": [{"original": "https://www.аpple.com/...", "deconfused": "https://www.apple.com/..."}],
            "affected_domains": [{"original": "аpple.com", "deconfused": "apple.com"}],
            "risk_score": float  # 0.0 - 1.0
        }
    """
    found_chars = []
    seen = set()

    # Scan the entire text for confusable characters
    for ch in text:
        if ch in CONFUSABLE_MAP and ch not in seen:
            seen.add(ch)
            found_chars.append({
                "char": ch,
                "unicode": f"U+{ord(ch):04X}",
                "looks_like": CONFUSABLE_MAP[ch],
                "name": unicodedata.name(ch, "UNKNOWN"),
            })

    # Scan URLs specifically
    affected_urls = []
    affected_domains = []
    urls = URL_RE.findall(text)
    for url in urls:
        has_confusable = any(ch in CONFUSABLE_MAP for ch in url)
        if has_confusable:
            deconfused_url = deconfuse(url)
            affected_urls.append({
                "original": url,
                "deconfused": deconfused_url,
            })
            # Extract domain
            dm = DOMAIN_RE.search(url)
            if dm:
                orig_domain = dm.group(1)
                clean_domain = deconfuse(orig_domain)
                if orig_domain != clean_domain:
                    affected_domains.append({
                        "original": orig_domain,
                        "deconfused": clean_domain,
                    })

    # Also check for non-ASCII letters in domains that aren't in our map
    # (catches novel homoglyph attacks)
    for url in urls:
        dm = DOMAIN_RE.search(url)
        if dm:
            domain = dm.group(1)
            non_ascii = [ch for ch in domain if _is_non_ascii_letter(ch) and ch not in CONFUSABLE_MAP]
            for ch in non_ascii:
                if ch not in seen:
                    seen.add(ch)
                    found_chars.append({
                        "char": ch,
                        "unicode": f"U+{ord(ch):04X}",
                        "looks_like": "?",
                        "name": unicodedata.name(ch, "UNKNOWN"),
                    })

    count = len(found_chars)
    # Risk: any homoglyph in a URL is extremely suspicious
    risk = 0.0
    if affected_urls:
        risk = 0.95  # Almost certainly phishing
    elif count > 0:
        risk = min(0.3 + count * 0.15, 0.7)  # Suspicious but not in URL

    return {
        "has_homoglyphs": count > 0,
        "homoglyph_count": count,
        "confusable_chars": found_chars,
        "affected_urls": affected_urls,
        "affected_domains": affected_domains,
        "risk_score": round(risk, 2),
    }
