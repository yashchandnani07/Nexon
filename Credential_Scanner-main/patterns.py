"""
patterns.py  –  Layer 1 & Layer 2 credential scanning
=======================================================
• Layer 1 – detect-secrets library  (built-in plugins: AWS, Azure, JWT, keyword, …)
• Layer 2 – custom regex patterns from patterns.json

Both layers produce findings in the same schema.
A global seen-hashes set ensures that even if detect-secrets and the regex
scan find the exact same raw value, it is only reported once.
"""

import re
import hashlib
import json
import os
import io

# ─────────────────────────────────────────────────────────────
# detect-secrets setup
# ─────────────────────────────────────────────────────────────
_DS_PLUGINS: list = []

def _load_detect_secrets_plugins():
    """Discover & instantiate every built-in detect-secrets plugin."""
    import importlib, pkgutil
    import detect_secrets.plugins as _pkg

    plugins = []
    for finder, module_name, _ in pkgutil.iter_modules(_pkg.__path__):
        try:
            mod = importlib.import_module(f"detect_secrets.plugins.{module_name}")
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                try:
                    from detect_secrets.plugins.base import BasePlugin
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BasePlugin)
                        and attr is not BasePlugin
                        and not getattr(attr, "__abstractmethods__", None)
                    ):
                        plugins.append(attr())
                except Exception:
                    pass
        except Exception:
            pass
    return plugins

try:
    _DS_PLUGINS = _load_detect_secrets_plugins()
    print(f"[patterns] detect-secrets: loaded {len(_DS_PLUGINS)} plugin(s)")
except Exception as _e:
    print(f"[patterns] detect-secrets unavailable: {_e}")


# ─────────────────────────────────────────────────────────────
# patterns.json
# ─────────────────────────────────────────────────────────────
PATTERNS_FILE = os.path.join(os.path.dirname(__file__), "patterns.json")


def load_patterns() -> dict:
    if not os.path.exists(PATTERNS_FILE):
        print("WARNING: patterns.json not found")
        return {}
    try:
        with open(PATTERNS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Deduplicate identical regex strings (patterns.json has some duplicates)
        seen_regex = {}
        deduped = {}
        for name, cfg in data.items():
            rx = cfg.get("regex", "")
            if rx and rx in seen_regex:
                continue        # skip duplicate regex
            seen_regex[rx] = name
            deduped[name] = cfg
        print(f"[patterns] Loaded {len(deduped)} unique patterns from patterns.json")
        return deduped
    except json.JSONDecodeError as e:
        print(f"ERROR: patterns.json invalid: {e}")
        return {}


CREDENTIAL_PATTERNS: dict = load_patterns()


# ─────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────
def redact(value: str) -> str:
    """Show first 4 chars + asterisks – never expose the secret."""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:4] + "*" * min(len(value) - 4, 12)


def hash_value(value: str) -> str:
    """Stable SHA-256 fingerprint of the raw secret value (stripped)."""
    return hashlib.sha256(value.strip().encode()).hexdigest()


# ─────────────────────────────────────────────────────────────
# Layer 1 – detect-secrets scan  (run before regex so hashes land first)
# ─────────────────────────────────────────────────────────────

# Risk tier heuristics keyed to detect-secrets secret_type strings
_DS_RISK_MAP = {
    "AWS Access Key":         ("Critical", "cloud_key"),
    "Azure Storage Account Access Key": ("Critical", "cloud_key"),
    "Basic Auth Credentials": ("High",     "credential"),
    "Artifactory Credentials":("High",     "dev_token"),
    "GitHub Token":           ("High",     "dev_token"),
    "Slack Token":            ("High",     "dev_token"),
    "Stripe Access Key":      ("Critical", "payment"),
    "Twilio API Key":         ("High",     "api_key"),
    "Private Key":            ("Critical", "cryptographic"),
    "JWT Token":              ("High",     "auth_token"),
    "Keyword":                ("Medium",   "credential"),
    "Secret Keyword":         ("Medium",   "credential"),
    "High Entropy String":    ("Medium",   "entropy"),
    "Hex High Entropy String":("Medium",   "entropy"),
    "Base64 High Entropy String": ("Medium", "entropy"),
}


def _get_risk_for_ds_type(secret_type: str):
    for key, val in _DS_RISK_MAP.items():
        if key.lower() in secret_type.lower():
            return val
    return ("Medium", "general")


def _run_detect_secrets_scan(text: str, seen: set) -> list:
    """Scan text using every detect-secrets plugin; return findings list."""
    if not _DS_PLUGINS:
        return []

    findings = []
    lines = text.splitlines()

    for line_no, line in enumerate(lines, start=1):
        for plugin in _DS_PLUGINS:
            try:
                matches = plugin.analyze_string(line)
            except Exception:
                continue
            for raw in matches:
                raw = raw.strip()
                if not raw or len(raw) < 4:
                    continue
                h = hash_value(raw)
                if h in seen:
                    continue
                seen.add(h)

                secret_type = getattr(plugin, "secret_type", "Unknown")
                risk, category = _get_risk_for_ds_type(secret_type)

                # context snippet: 60 chars around the match inside the line
                col = line.find(raw)
                s = max(0, col - 40)
                e = min(len(line), col + len(raw) + 40)
                snippet = line[s:e].replace(raw, redact(raw))

                findings.append({
                    "layer":           "regex",   # grouped with Layer 2 in the UI (both are static scan)
                    "sublayer":        "detect-secrets",
                    "credential_type": secret_type.lower().replace(" ", "_"),
                    "description":     f"detect-secrets: {secret_type}",
                    "risk_tier":       risk,
                    "category":        category,
                    "redacted_value":  redact(raw),
                    "value_hash":      h,
                    "context_snippet": snippet.strip(),
                    "char_position":   sum(len(l) + 1 for l in lines[:line_no - 1]) + max(0, col),
                    "confidence":      0.88,
                })

    return findings


# ─────────────────────────────────────────────────────────────
# Layer 2 – patterns.json regex scan
# ─────────────────────────────────────────────────────────────

def _run_patterns_scan(text: str, seen: set) -> list:
    findings = []
    for name, cfg in CREDENTIAL_PATTERNS.items():
        try:
            for match in re.finditer(cfg["regex"], text):
                raw = match.group(0)
                if len(raw.strip()) < 4:
                    continue
                h = hash_value(raw)
                if h in seen:
                    continue
                seen.add(h)

                s = max(0, match.start() - 60)
                e = min(len(text), match.end() + 60)
                snippet = text[s:e].replace(raw, redact(raw))

                findings.append({
                    "layer":           "regex",
                    "sublayer":        "patterns.json",
                    "credential_type": name,
                    "description":     cfg["desc"],
                    "risk_tier":       cfg["risk"],
                    "category":        cfg.get("category", "general"),
                    "redacted_value":  redact(raw),
                    "value_hash":      h,
                    "context_snippet": snippet.strip(),
                    "char_position":   match.start(),
                    "confidence":      0.90,
                })
        except re.error as e:
            print(f"Bad regex '{name}': {e}")
            continue
    return findings


# ─────────────────────────────────────────────────────────────
# Public entry-point
# ─────────────────────────────────────────────────────────────

def run_regex_scan(text: str) -> list:
    """
    Combined Layer 1 (detect-secrets) + Layer 2 (patterns.json) scan.

    A shared `seen` hash-set guarantees the same raw credential value is
    *never* duplicated across the two sub-scanners.
    """
    seen: set = set()

    # Layer 1 first so its hashes land in `seen` before the custom regex runs
    ds_findings  = _run_detect_secrets_scan(text, seen)
    pat_findings = _run_patterns_scan(text, seen)

    return ds_findings + pat_findings


def reload_patterns():
    global CREDENTIAL_PATTERNS
    CREDENTIAL_PATTERNS = load_patterns()
    return len(CREDENTIAL_PATTERNS)