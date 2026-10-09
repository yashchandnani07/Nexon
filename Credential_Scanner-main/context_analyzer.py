import re

URGENCY = [
    "verify your account", "suspended", "unusual activity",
    "click here immediately", "act now", "account will be closed",
    "confirm your details", "unauthorized access", "security alert",
    "otp expires", "update your payment", "validate your","will be blocked", "transaction initiated",
"if this was not you", "verify immediately",
"account will be suspended", "click here",
"re-verification required", "action required"
]

INTERNAL_EXPOSURE = [
    "attached please find", "please use the following",
    "credentials are", "login details", "access details below",
    "here are the details", "please keep confidential",
    "as discussed", "use the following credentials",
]

IMPERSONATION = [
    "Example Bank bank", "Example Bank security", "Example Bank team",
    "dear valued customer", "your Example Bank account",
    "Example Bank fraud", "Example Bank helpdesk","fraud prevention team", "security department",
"Example Bank alerts", "Example Bank-secure",
"bank security", "fraud team"
]

def deduplicate(findings: list) -> list:
    """
    Cross-layer deduplication with confidence boosting.

    Strategy (two passes):
    1. Primary key  – SHA-256 value_hash: exact same raw secret from ANY
       layer/sublayer (regex, detect-secrets, NER-BERT, NER-NLTK, LLM)
       is merged into a single finding with every contributing layer listed
       in `detected_by`.
    2. Fuzzy pass   – findings whose redacted_value prefix OR context
       snippet overlap are also merged when they share the same credential
       type family, ensuring near-duplicates don't slip through.

    The final merged finding:
      • Uses the highest-confidence source as the base.
      • Receives a confidence *boost* from each additional corroborating layer.
      • Upgrades risk_tier to the highest tier seen across the group.
      • Lists all contributing layers in `detected_by`.
    """
    # ── Pass 1 : group by exact value_hash ──────────────────────────────────
    groups: dict = {}
    for f in findings:
        h = f["value_hash"]
        if h not in groups:
            groups[h] = []
        groups[h].append(f)

    # ── Pass 2 : fuzzy merge across different hashes ─────────────────────────
    processed = list(groups.values())
    merged    = []
    used      = set()

    for i, group_a in enumerate(processed):
        if i in used:
            continue
        base_group = list(group_a)

        for j, group_b in enumerate(processed):
            if i == j or j in used:
                continue

            a = group_a[0]
            b = group_b[0]

            a_evidence = a.get("context_snippet", "").lower()
            b_evidence = b.get("context_snippet", "").lower()
            a_redacted = a.get("redacted_value", "")[:4].lower()
            b_redacted = b.get("redacted_value", "")[:4].lower()

            same_type = (
                a.get("credential_type", "") == b.get("credential_type", "")
                or (a_redacted and b_redacted and a_redacted == b_redacted)
                or (a_redacted and a_redacted in b_evidence)
                or (b_redacted and b_redacted in a_evidence)
            )

            # Only merge cross-layer hits (same layer duplicates are kept separate)
            if same_type and a.get("layer") != b.get("layer"):
                base_group.extend(group_b)
                used.add(j)

        used.add(i)
        merged.append(base_group)

    # ── Combine each merged group into a single finding ──────────────────────
    combined = []
    tier_order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

    for group in merged:
        if len(group) == 1:
            f = group[0].copy()
            f["detected_by"] = [f["layer"]]
            f["sublayers"]   = [f.get("sublayer", f["layer"])]
            f["layer_count"] = 1
            combined.append(f)
        else:
            # Pick the highest-confidence finding as base
            base = max(group, key=lambda x: x["confidence"]).copy()

            layers_found   = list(dict.fromkeys(f["layer"]    for f in group))
            sublayers_found = list(dict.fromkeys(f.get("sublayer", f["layer"]) for f in group))

            base["detected_by"] = layers_found
            base["sublayers"]   = sublayers_found
            base["layer_count"] = len(layers_found)

            # Confidence boost for each additional corroborating layer
            boost = sum(
                f["confidence"] * 0.30
                for f in group if f["layer"] != base["layer"]
            )
            base["confidence"] = min(base["confidence"] + boost, 0.99)

            # Always take the highest risk tier
            base["risk_tier"] = max(
                group,
                key=lambda x: tier_order.get(x["risk_tier"], 0),
            )["risk_tier"]

            combined.append(base)

    return combined


def analyze_context(text: str, findings: list) -> dict:
    low = text.lower()

    urgency       = any(p in low for p in URGENCY)
    internal      = any(p in low for p in INTERNAL_EXPOSURE)
    impersonation = any(p in low for p in IMPERSONATION)
    categories    = set(f.get("category", "") for f in findings)
    multi_cred    = len(categories) >= 2
    has_critical  = any(f["risk_tier"] == "Critical" for f in findings)
    has_attachment = bool(re.search(
        r"(?i)(attached|attachment|find attached|see attached)", text))
    multi_layer_confirmed = sum(
        1 for f in findings if f.get("layer_count", 1) > 1
    )

    multiplier = 1.0
    if urgency:        multiplier += 0.25
    if impersonation:  multiplier += 0.30
    if internal:       multiplier += 0.20
    if multi_cred:     multiplier += 0.20
    if has_critical and (urgency or impersonation):
        multiplier += 0.30
    if multi_layer_confirmed >= 2:
        multiplier += 0.15

    return {
        "has_urgency_language":          urgency,
        "has_internal_exposure_signals": internal,
        "has_impersonation_signals":     impersonation,
        "has_multiple_credential_types": multi_cred,
        "has_attachment_reference":      has_attachment,
        "credential_categories":         list(categories),
        "multi_layer_confirmed_count":   multi_layer_confirmed,
        "context_multiplier":            round(multiplier, 2),
    }