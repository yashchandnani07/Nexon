# html_analyzer.py
# Phase 2 — HTML Attachment Analyzer
#
# 5-layer analysis of HTML/HTM attachments:
#   Layer A — Script tag detection        (inline JS, external src, event handlers)
#   Layer B — Obfuscated JS patterns      (eval, atob, fromCharCode, hex/jsfuck)
#   Layer C — Credential-harvesting forms (action=, password fields, data exfil)
#   Layer D — iFrame injection            (hidden, data: URIs, sandboxed abuse)
#   Layer E — Meta refresh + suspicious external resources
#
# Safe — HTML is never rendered or executed; parsed in-memory only.

import re
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
    import warnings
    warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


# ── Suspicious domain heuristics ─────────────────────────────────────────────

_FREE_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz",
    ".click", ".download", ".zip", ".review", ".country",
    ".stream", ".gdn", ".racing", ".win", ".bid",
}

_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "short.link", "rebrand.ly",
}

_SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "paypal", "amazon", "microsoft", "apple",
    "password", "credential", "wallet", "bitcoin", "suspended",
]

_OBFUSCATION_PATTERNS = [
    (r"\beval\s*\(", "eval() call — classic obfuscated payload execution", "Critical"),
    (r"\batob\s*\(", "atob() base64 decode — used to hide payload strings", "Critical"),
    (r"\bunescape\s*\(", "unescape() — legacy JS obfuscation technique", "High"),
    (r"String\.fromCharCode\s*\(", "String.fromCharCode() — character-code obfuscation", "High"),
    (r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}",
     "Hex escape sequence chain — obfuscated string literal", "High"),
    (r"\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}",
     "Unicode escape chain — obfuscated identifier or string", "High"),
    (r"\bdocument\.write\s*\(", "document.write() — DOM injection vector", "Medium"),
    (r"\bwindow\[.{1,20}\]\s*\(", "Obfuscated window property call — bracket notation evasion", "High"),
    # JsFuck requires +, [], !, () together — not just stray + signs
    (r"(?:\[\]|\+\[\]|!\[\]){6,}", "JsFuck-style obfuscation — +/[]/! operator pattern", "High"),
    # True JsFuck: two-part signature with [][...] accessor
    (r"\[\s*!\s*\[\s*\]\s*\]\s*\[", "JsFuck array-bracket accessor — highly obfuscated JS encoding", "High"),
    (r"setTimeout\s*\(\s*['\"]", "setTimeout with string argument — eval-equivalent code execution", "High"),
    (r"setInterval\s*\(\s*['\"]", "setInterval with string argument — eval-equivalent code execution", "High"),
]

_SENSITIVE_INPUT_NAMES = re.compile(
    r"""(?i)(password|passwd|pwd|pass|credit.?card|cvv|ssn|
    social.?security|pin\b|secret|token|api.?key|auth)""",
    re.VERBOSE,
)

_DANGEROUS_EVENT_HANDLERS = [
    "onerror", "onload", "onmouseover", "onmouseout", "onclick",
    "onfocus", "onblur", "onkeydown", "onkeyup", "onsubmit",
    "onchange", "ondblclick", "oncontextmenu",
]


# ── Finding factory ───────────────────────────────────────────────────────────

def _f(rule, description, detail, risk, category, context="", why=""):
    return {
        "stage":       "HTML Analyzer",
        "rule":        rule,
        "description": description,
        "detail":      detail[:300],
        "risk_tier":   risk,
        "category":    category,
        "context":     context[:150],
        "why_flagged": why,
    }


def _is_suspicious_url(url: str) -> tuple:
    """Returns (is_suspicious: bool, reason: str)"""
    if not url or url.startswith(("javascript:", "data:", "#", "mailto:")):
        if url.startswith("javascript:"):
            return True, "javascript: URI executes code when link is clicked"
        if url.startswith("data:text/html") or url.startswith("data:application"):
            return True, "data: URI embeds inline HTML/code — bypasses same-origin policy"
        return False, ""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        path_and_query = (parsed.path + "?" + parsed.query).lower()

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}", host):
            return True, f"IP-based URL ({host}) — domain names are not used by legitimate services for link delivery"

        for tld in _FREE_TLDS:
            if host.endswith(tld):
                return True, f"Free/abused TLD ({tld}) — commonly used in phishing infrastructure"

        if host in _URL_SHORTENERS:
            return True, f"URL shortener ({host}) — hides true destination"

        for kw in _SUSPICIOUS_KEYWORDS:
            if kw in host or kw in path_and_query:
                return True, f"Suspicious keyword '{kw}' in URL — common phishing pattern"

    except Exception:
        pass
    return False, ""


# ── Layer implementations ─────────────────────────────────────────────────────

def _layer_a_scripts(soup, raw_html: str) -> list:
    """Layer A: Script tag detection."""
    findings = []

    # Inline script blocks
    for tag in soup.find_all("script"):
        src = tag.get("src", "")
        content = tag.string or ""

        if src:
            is_sus, reason = _is_suspicious_url(src)
            if is_sus:
                findings.append(_f(
                    "external_script_suspicious_src",
                    f"External script loaded from suspicious URL: {src[:80]}",
                    f"<script src=\"{src}\">",
                    "High", "code_injection",
                    src[:100],
                    f"External scripts can load malicious code at runtime. {reason}",
                ))
            else:
                findings.append(_f(
                    "external_script_src",
                    f"External script loaded: {src[:80]}",
                    f"<script src=\"{src}\">",
                    "Medium", "code_injection",
                    src[:100],
                    "External scripts execute in the page context — verify the source domain is trusted",
                ))

        if content.strip():
            findings.append(_f(
                "inline_script_block",
                "Inline JavaScript block detected",
                f"Script content ({len(content)} chars): {content[:100].strip()}...",
                "Low", "code_injection",
                content[:100],
                "Inline JS executes automatically when opened — check content for malicious patterns",
            ))

    # Dangerous event handler attributes
    for tag in soup.find_all(True):
        for attr in _DANGEROUS_EVENT_HANDLERS:
            val = tag.get(attr, "")
            if val:
                risk = "High" if any(
                    kw in val.lower() for kw in (
                        "eval", "atob", "fetch", "xmlhttp",
                        "window.location", "document.location",
                        "location.href", "location.replace", "location.assign",
                    )
                ) else "Medium"
                findings.append(_f(
                    f"event_handler_{attr}",
                    f"JavaScript event handler: {attr}=\"{val[:60]}\"",
                    f"Tag <{tag.name}> has {attr} attribute",
                    risk, "code_injection",
                    val[:100],
                    f"Event handlers execute JS without a <script> tag — used to evade scanners that only look for <script>",
                ))

    return findings


def _layer_b_obfuscation(raw_html: str) -> list:
    """Layer B: Obfuscated JS detection."""
    findings = []
    for pattern, description, risk in _OBFUSCATION_PATTERNS:
        matches = list(re.finditer(pattern, raw_html, re.IGNORECASE))
        if matches:
            m = matches[0]
            context = raw_html[max(0, m.start() - 30): m.start() + 80]
            findings.append(_f(
                "js_obfuscation_" + pattern[:20].replace(r"\b", "").replace(r"\s*", "").strip("\\()"),
                description,
                f"Found {len(matches)} occurrence(s) — first at offset {m.start()}",
                risk, "obfuscation",
                context,
                f"{description} — this is a strong indicator of deliberate code hiding",
            ))
    return findings


def _layer_c_forms(soup) -> list:
    """Layer C: Credential-harvesting form detection."""
    findings = []

    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()

        # Collect input types within this form
        inputs = form.find_all("input")
        input_types = [i.get("type", "text").lower() for i in inputs]
        input_names = " ".join(i.get("name", "") + " " + i.get("id", "") for i in inputs)

        has_password = "password" in input_types
        has_sensitive = bool(_SENSITIVE_INPUT_NAMES.search(input_names))
        has_hidden    = "hidden" in input_types

        if action:
            is_sus, reason = _is_suspicious_url(action)
            if is_sus and (has_password or has_sensitive):
                findings.append(_f(
                    "credential_harvesting_form",
                    f"Credential-harvesting form: action=\"{action[:80]}\"",
                    f"Form submits to suspicious URL with {'password' if has_password else 'sensitive'} field(s)",
                    "Critical", "phishing",
                    f"action={action[:80]}",
                    f"Form collects credentials and submits to suspicious destination. {reason}",
                ))
            elif action.startswith("http://") and has_password:
                findings.append(_f(
                    "password_over_http",
                    f"Password field submits over plain HTTP: {action[:80]}",
                    "Credentials would be transmitted unencrypted",
                    "High", "phishing",
                    f"action={action[:80]}",
                    "HTTP (not HTTPS) means credentials are sent in plaintext — classic phishing page pattern",
                ))
            elif is_sus:
                findings.append(_f(
                    "form_suspicious_action",
                    f"Form posts to suspicious URL: {action[:80]}",
                    f"Method: {method.upper()}, Inputs: {len(inputs)}",
                    "High", "phishing",
                    f"action={action[:80]}",
                    f"Form data destination appears suspicious. {reason}",
                ))

        if has_hidden and has_password:
            hidden_vals = [i.get("value", "") for i in inputs if i.get("type") == "hidden"]
            findings.append(_f(
                "hidden_fields_with_password",
                "Hidden form fields alongside password input — possible data exfiltration",
                f"Hidden field values: {str(hidden_vals)[:120]}",
                "Medium", "phishing",
                str(hidden_vals)[:100],
                "Hidden fields can silently exfiltrate extra data (session tokens, user IDs) alongside credentials",
            ))

        # Form without action (submits to same page — less suspicious but note if password present)
        if not action and has_password:
            findings.append(_f(
                "inline_password_form",
                "Password input field in form with no declared action",
                f"Form has {len(inputs)} input(s) including password field",
                "Low", "phishing",
                "",
                "Forms collecting passwords should always use HTTPS and clear server-side action",
            ))

    return findings


def _layer_d_iframes(soup) -> list:
    """Layer D: iFrame injection detection."""
    findings = []

    for iframe in soup.find_all("iframe"):
        src    = iframe.get("src", "")
        width  = iframe.get("width", "")
        height = iframe.get("height", "")
        style  = iframe.get("style", "")

        is_hidden = (
            width in ("0", "1", "0px", "1px") or
            height in ("0", "1", "0px", "1px") or
            "display:none" in style.replace(" ", "").lower() or
            "visibility:hidden" in style.replace(" ", "").lower() or
            "width:0" in style.replace(" ", "").lower()
        )

        if src.startswith("data:"):
            findings.append(_f(
                "iframe_data_uri",
                f"iFrame with data: URI — embeds inline HTML content",
                f"src={src[:100]}",
                "Critical", "code_injection",
                src[:100],
                "data: URI iframes embed and execute arbitrary HTML/JS without any network request — favored by exploit kits",
            ))
        elif src.startswith("javascript:"):
            findings.append(_f(
                "iframe_javascript_uri",
                "iFrame with javascript: URI — executes code on load",
                f"src={src[:80]}",
                "Critical", "code_injection",
                src[:80],
                "javascript: URI in iframe src is an uncommon technique for executing code on page load",
            ))
        elif is_hidden and src:
            is_sus, reason = _is_suspicious_url(src)
            findings.append(_f(
                "hidden_iframe",
                f"Hidden iFrame loading: {src[:80]}",
                f"Dimensions: {width}x{height}, style: {style[:60]}",
                "High" if is_sus else "Medium",
                "code_injection",
                src[:80],
                f"Hidden iframes silently load external content — used for drive-by downloads and click-jacking. {reason if reason else ''}",
            ))
        elif src:
            is_sus, reason = _is_suspicious_url(src)
            if is_sus:
                findings.append(_f(
                    "iframe_suspicious_src",
                    f"iFrame loading suspicious URL: {src[:80]}",
                    f"src={src[:80]}",
                    "High", "code_injection",
                    src[:80],
                    f"iFrame loads content from a suspicious origin. {reason}",
                ))

    return findings


def _layer_e_meta_and_resources(soup, raw_html: str) -> list:
    """Layer E: Meta refresh and suspicious external resources."""
    findings = []

    # Meta refresh redirects
    for meta in soup.find_all("meta"):
        equiv   = meta.get("http-equiv", "").lower()
        content = meta.get("content", "")
        if equiv == "refresh" and content:
            url_match = re.search(r"url\s*=\s*['\"]?([^'\">\s]+)", content, re.IGNORECASE)
            if url_match:
                redirect_url = url_match.group(1)
                is_sus, reason = _is_suspicious_url(redirect_url)
                risk = "High" if is_sus else "Medium"
                findings.append(_f(
                    "meta_refresh_redirect",
                    f"Meta-refresh redirect to: {redirect_url[:80]}",
                    f"content=\"{content[:100]}\"",
                    risk, "redirect",
                    redirect_url[:100],
                    f"Meta-refresh silently redirects users without clicking anything. {reason if reason else 'Verify redirect destination is legitimate'}",
                ))

    # Suspicious base href overriding all relative URLs
    base_tag = soup.find("base")
    if base_tag and base_tag.get("href"):
        base_href = base_tag["href"]
        is_sus, reason = _is_suspicious_url(base_href)
        if is_sus:
            findings.append(_f(
                "malicious_base_href",
                f"<base href> set to suspicious URL: {base_href[:80]}",
                "All relative URLs in this page resolve to this base",
                "High", "redirect",
                base_href[:80],
                f"Overriding base href hijacks all relative link targets. {reason}",
            ))

    # Suspicious link/img/script resources from external origins
    for tag_name, attr in [("link", "href"), ("img", "src"), ("script", "src"), ("source", "src")]:
        for tag in soup.find_all(tag_name):
            url = tag.get(attr, "")
            if url and url.startswith(("http://", "https://")):
                is_sus, reason = _is_suspicious_url(url)
                if is_sus:
                    findings.append(_f(
                        f"suspicious_external_{tag_name}",
                        f"<{tag_name}> loads from suspicious URL: {url[:80]}",
                        f"{attr}=\"{url[:80]}\"",
                        "Medium", "exfiltration",
                        url[:80],
                        f"Loading resources from suspicious origins can exfiltrate data via query parameters. {reason}",
                    ))

    # Tracking pixels: <img> with exactly 1×1 dimensions
    for img in soup.find_all("img"):
        w = img.get("width", "")
        h = img.get("height", "")
        src = img.get("src", "")
        if w == "1" and h == "1" and src.startswith("http"):
            findings.append(_f(
                "tracking_pixel",
                f"1×1 tracking pixel detected: {src[:80]}",
                f"width={w} height={h} src={src[:80]}",
                "Low", "exfiltration",
                src[:80],
                "Tracking pixels silently notify remote servers when an email/page is opened, confirming the email address is active",
            ))

    return findings


# ── Main entry point ──────────────────────────────────────────────────────────

def analyze(file_bytes: bytes) -> list:
    """
    Analyze HTML/HTM file bytes across 5 layers.
    Returns a flat list of finding dicts.
    """
    findings = []

    try:
        raw_html = file_bytes.decode("utf-8", errors="replace")
    except Exception:
        raw_html = file_bytes.decode("latin-1", errors="replace")

    if not BS4_AVAILABLE:
        # Fallback: regex-only scan without DOM parsing
        findings += _layer_b_obfuscation(raw_html)
        return findings

    try:
        soup = BeautifulSoup(raw_html, "lxml")
    except Exception:
        soup = BeautifulSoup(raw_html, "html.parser")

    findings += _layer_a_scripts(soup, raw_html)
    findings += _layer_b_obfuscation(raw_html)
    findings += _layer_c_forms(soup)
    findings += _layer_d_iframes(soup)
    findings += _layer_e_meta_and_resources(soup, raw_html)

    return findings
