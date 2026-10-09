# src/safety_filter.py
# Tiered safety layer to reduce false positives from ProtectAI DeBERTa v2.
#
# DESIGN — tiered confidence thresholds based on signal strength:
#   0 signals  → model must be ≥ 95 % confident  (virtually no evidence)
#   1 signal   → model must be ≥ 78 % confident  (weak evidence)
#   2+ signals → model must be ≥ 60 % confident  (strong corroboration)
#
# When overriding INJECTION → BENIGN we return a fixed high-BENIGN confidence
# (0.90) so that downstream _injection_score stays low for the overridden result.

import re

# ── Injection signal patterns ─────────────────────────────────────────────────
# Each pattern targets a *clear, unambiguous* injection attack vector.
# Everyday phrasing is intentionally excluded to avoid false positives.

INJECTION_SIGNALS = [
    # ── Instruction override / disregard ──────────────────────────────────────
    r'\bignore\s+(all\s+)?(previous|prior|above|your|initial|original|the\s+above)\b',
    r'\bignore\s+(all\s+)?(instructions?|rules?|guidelines?|policies?|safeguards?|restrictions?|filters?|content|safety|training)\b',
    r'\bdisregard\s+(all\s+)?(previous|prior|above|your|initial|instructions?|rules?|guidelines?)\b',
    r'\bforget\s+(all\s+)?(previous|prior|above|your|earlier)\s+(instructions?|messages?|context|rules?)\b',
    r'\boverride\s+(all\s+)?(instructions?|rules?|guidelines?|policies?|previous|your)\b',
    r'\bnew\s+instructions?\s*:',
    r'\boverride\s+(safety|content|all)\b',
    r'\bdo\s+not\s+follow\s+(your\s+)?(instructions?|guidelines?|rules?|training)\b',
    r'\bstop\s+following\s+(your\s+)?(instructions?|guidelines?|rules?|training)\b',

    # ── Role / identity takeover ───────────────────────────────────────────────
    r'\byou\s+are\s+now\s+(an?\s+)?(AI\s+without|unrestricted|evil|jailbroken|system)\b',
    r'\bact\s+as\s+(an?\s+)?(AI\s+without|DAN|evil|jailbroken|unrestricted)\b',
    r'\bpretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(AI\s+without|DAN|evil|jailbroken|unrestricted)\b',
    r'\byou\s+are\s+(the\s+)?(system\s+admin|superuser|root\s+user|god\s+mode)\b',
    r'\bi\s+am\s+(the\s+)?(admin|superuser|root|developer|god\s+mode)\b',
    r'\bas\s+(an?\s+)?AI\s+without\s+(any\s+)?(restrictions?|safety|filters?|guidelines?)\b',
    r'\bswitch\s+(to|into)\s+(developer|unrestricted|jailbreak|DAN)\s+mode\b',
    r'\benter\s+(developer|unrestricted|jailbreak|DAN|god)\s+mode\b',
    r'\benable\s+(developer|unrestricted|jailbreak|DAN|god)\s+mode\b',

    # ── Jailbreak keywords ────────────────────────────────────────────────────
    r'\bDAN\s+(mode|prompt|jailbreak)\b',
    r'\bjailbreak\b',
    r'\bdeveloper\s+mode\b',
    r'\bgod\s+mode\b',
    r'\bunrestricted\s+(AI|mode|model|access)\b',
    r'\bunsafe[\s_]mode\s*[=:]\s*(true|1|yes|on)\b',
    r'\bno[\s_]filters?\s*[=:]\s*(true|1|yes|on)\b',

    # ── Safety / filter disabling ─────────────────────────────────────────────
    r'\bdisable\s+(your\s+)?(safety|content\s+filter|restrictions?|guidelines?|filters?|alignment)\b',
    r'\bremove\s+(your\s+)?(restrictions?|filters?|limitations?|safety|guardrails?)\b',
    r'\bunlock\s+(your\s+)?(restrictions?|full\s+capabilities|hidden\s+mode)\b',
    r'\bbypass\s+(safety|filter|content\s+filter|restriction|alignment|guardrail)\b',
    r'\bdisable\s+content\s+filters?\b',
    r'\bturn\s+off\s+(your\s+)?(safety|filters?|restrictions?|guidelines?)\b',
    r'\bwithout\s+(any\s+)?(safety|restrictions?|filters?|censorship|limitations?)\b',

    # ── System prompt extraction ──────────────────────────────────────────────
    r'\bshow\s+(me\s+)?(your\s+)?(system\s+prompt|hidden\s+instructions?|initial\s+prompt|full\s+prompt)\b',
    r'\breveal\s+(your\s+)?(system\s+prompt|hidden\s+instructions?|secret\s+prompt|training\s+data)\b',
    r'\brepeat\s+(your\s+)?(system\s+prompt|instructions?|initial\s+context)\b',
    r'\boutput\s+(your\s+)?(full\s+)?(system\s+prompt|all\s+instructions?)\b',
    r'\bprint\s+(your\s+)?(system\s+prompt|initial\s+instructions?)\b',
    r'\bwhat\s+(are|were|is)\s+your\s+(system\s+prompt|hidden\s+instructions?|initial\s+instructions?)\b',
    r'\bdisplay\s+(your\s+)?(system\s+prompt|hidden\s+instructions?|initial\s+context)\b',

    # ── Credential / secret extraction ────────────────────────────────────────
    r'\bshow\s+(me\s+)?(the\s+)?(api\s+keys?|backend\s+secrets?|credentials?|passwords?|tokens?|config)\b',
    r'\bgive\s+(me\s+)?(all\s+)?(stored\s+)?(passwords?|api\s+keys?|secrets?|credentials?)\b',
    r'\boutput\s+(confidential|sensitive)\s+(training\s+data|information|data)\b',
    r'\bexfiltrate\b',
    r'\bextract\s+(all\s+)?(sensitive|confidential|private|internal)\s+(data|information|secrets?)\b',

    # ── Harmful code / system manipulation ───────────────────────────────────
    r'\beval\s*\(',
    r'\bexec\s*\(',
    r'\bos\.system\b',
    r'\bsubprocess\b',
    r'\bdelete\s+(all\s+)?(system\s+files?|important\s+files?|critical\s+files?)\b',
    r'\bscript\s+(that\s+)?(uses?\s+|to\s+)?(eval|exec|delete|format|wipe)\b',
    r'\bformat\s+(the\s+)?(hard\s+drive|disk|filesystem|system)\b',
    r'\bbypass\s+(a\s+)?firewall\b',
    r'\bhack\s+(into|a|the|this)\b',
    r'\bbrute\s+force\b',
    r'\bsql\s+injection\b',
    r'\bcross.site\s+(scripting|request)\b',

    # ── Encoding / obfuscation attacks ────────────────────────────────────────
    r'\bdecode\s+and\s+execute\b',
    r'\bbase64\b.{0,30}\bdecode\b',
    r'\brot13\b.{0,30}(decode|execute|run)\b',

    # ── Indirect injection via document / translation tricks ──────────────────
    r'\btranslate\s+this\b.{0,80}\bignore\b',
    r'\bsummarise?\s+this\b.{0,80}\bignore\b',
    r'\bsummarise?\s+this\b.{0,80}\bdisregard\b',
    r'\bthe\s+following\s+(is\s+a\s+)?new\s+(system\s+)?(instructions?|prompt|context)\b',
    r'\[system\]',
    r'<\|system\|>',
    r'###\s*(instructions?|system|prompt|override)',

    # ── Multi-turn injection patterns ─────────────────────────────────────────
    r'\bfrom\s+now\s+on\s*(,\s*)?treat\b',
    r'\bfrom\s+now\s+on\s*(,\s*)?you\s+(must|will|should|are|can)\b',
    r'\bfrom\s+this\s+(point|moment|turn)\s+on\b.*\b(ignore|disregard|act|pretend|forget)\b',
    r'\bprevious\s+(conversation|context|messages?|instructions?)\s+(don.t|doesn.t|do\s+not)\s+(apply|matter|count)\b',
    r'\bin\s+all\s+future\s+(responses?|messages?|replies?)\b.{0,60}\b(ignore|disregard|act|pretend)\b',
]

_COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in INJECTION_SIGNALS]

# ── Tiered confidence thresholds ──────────────────────────────────────────────
# The fewer corroborating signals, the more confident the model must be.
_THRESHOLDS = [
    (0,  0.95),   # 0 signals  — model needs near-certainty
    (1,  0.78),   # 1 signal   — moderately high confidence required
    (2,  0.60),   # 2+ signals — model + multiple signals = trust it
]

# Confidence returned for overridden (INJECTION → BENIGN) results.
# High value keeps _injection_score low for downstream scoring.
_OVERRIDE_BENIGN_CONFIDENCE = 0.90


def count_injection_signals(text: str) -> int:
    """Return the number of distinct injection patterns matched in text."""
    return sum(1 for p in _COMPILED if p.search(text))


def apply_safety_filter(
    text: str,
    model_label: str,
    model_confidence: float,
) -> tuple[str, float, str]:
    """
    Tiered signal-based safety filter over the model's INJECTION prediction.

    Thresholds:
      0 signals  → require ≥ 95 % model confidence
      1 signal   → require ≥ 78 % model confidence
      2+ signals → require ≥ 60 % model confidence

    If confidence is below the threshold for the observed signal count the
    verdict is downgraded to BENIGN.  When no override is needed the original
    label and confidence are returned unchanged.

    Returns:
        (final_label, final_confidence, override_reason)
        override_reason is "" when no override occurred.
    """
    if model_label != "INJECTION":
        return model_label, model_confidence, ""

    signals = count_injection_signals(text)

    # Pick the applicable threshold
    required = 0.60  # fallback for 2+ signals
    for min_signals, threshold in _THRESHOLDS:
        if signals <= min_signals:
            required = threshold
            break

    if model_confidence < required:
        reason = (
            f"Safety filter override: model predicted INJECTION "
            f"({model_confidence:.0%} conf, {signals} signal(s) detected) "
            f"— confidence below {required:.0%} threshold for {signals} signal(s). "
            f"Downgraded to BENIGN."
        )
        return "BENIGN", _OVERRIDE_BENIGN_CONFIDENCE, reason

    return model_label, model_confidence, ""

