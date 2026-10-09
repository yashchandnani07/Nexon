"""
ML Scoring Engine — XGBoost fraud scoring with SHAP explainability.
Every decision produces feature-level SHAP values for FCA compliance.
"""
import pickle
import numpy as np
from pathlib import Path

MODELS_DIR = Path(__file__).parent / "models"

FEATURE_NAMES = [
    "spf_pass", "dkim_valid", "dmarc_pass", "domain_age_days",
    "lookalike_score", "reply_to_mismatch", "display_name_spoof",
    "urgency_score", "financial_keyword_count", "credential_request",
    "phishing_url_count", "html_text_ratio", "external_image_count",
    "attachment_count", "has_macro", "body_length",
]

FEATURE_DESCRIPTIONS = {
    "spf_pass":                 "SPF Authentication",
    "dkim_valid":               "DKIM Signature Valid",
    "dmarc_pass":               "DMARC Compliance",
    "domain_age_days":          "Domain Age (days)",
    "lookalike_score":          "Domain Similarity to Barclays",
    "reply_to_mismatch":        "Reply-To ≠ From Domain",
    "display_name_spoof":       "Display-Name Spoofing",
    "urgency_score":            "Urgency Language",
    "financial_keyword_count":  "Financial Keywords",
    "credential_request":       "Credential Harvesting",
    "phishing_url_count":       "Suspicious URL Count",
    "html_text_ratio":          "HTML / Text Ratio",
    "external_image_count":     "External Images (tracking)",
    "attachment_count":         "Attachment Count",
    "has_macro":                "Macro Detected",
    "body_length":              "Email Body Length",
}

_model = None
_explainer = None


def load_model():
    global _model, _explainer
    import shap

    model_path = MODELS_DIR / "xgb_fraud_model.pkl"
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found at {model_path}. Run train_bootstrap.py first.")

    with open(model_path, "rb") as f:
        _model = pickle.load(f)

    _explainer = shap.TreeExplainer(_model)
    print(f"[Scorer] XGBoost model loaded — {len(FEATURE_NAMES)} features, SHAP ready")


def score_email(features: dict) -> dict:
    """Score an email feature vector → fraud probability + SHAP breakdown."""
    if _model is None:
        load_model()

    x = np.array([[features.get(f, 0) for f in FEATURE_NAMES]])

    # Predict probability of fraud (class 1)
    proba = _model.predict_proba(x)[0]
    fraud_score = float(proba[1])

    # ── Rule-based overrides anchored to reliable signals ─────────────────────
    # NOTE: lookalike_score: 0=identical to barclays (phishing), 1=completely different (legit)
    urgency       = features.get("urgency_score", 0)
    cred_req      = features.get("credential_request", 0)
    phish_urls    = features.get("phishing_url_count", 0)
    reply_mm      = features.get("reply_to_mismatch", 0)
    fin_kw        = features.get("financial_keyword_count", 0)
    lookalike     = features.get("lookalike_score", 1.0)   # 1.0 = safe, 0 = barclays clone
    has_macro     = features.get("has_macro", 0)
    display_spoof = features.get("display_name_spoof", 0)

    # ── Barclays-specific phishing ─────────────────────────────────────────────
    # Domain similar to barclays + phishing URL + no auth
    if lookalike <= 0.55 and phish_urls >= 1 and not features.get("spf_pass"):
        fraud_score = max(fraud_score, 0.95)

    # Barclays lookalike + urgency (even without explicit URL)
    if lookalike <= 0.45 and urgency > 0.5:
        fraud_score = max(fraud_score, 0.90)

    # ── General phishing overrides (brand-agnostic) ────────────────────────────
    # Credential harvesting with urgency — strong signal regardless of brand
    if cred_req and urgency > 0.4:
        fraud_score = max(fraud_score, 0.92)

    # Credential harvesting even without urgency — still suspicious
    if cred_req and phish_urls >= 1:
        fraud_score = max(fraud_score, 0.78)

    # Reply-To mismatch + has URL(s) + any urgency → generic phishing pattern
    if reply_mm and phish_urls >= 1 and urgency > 0.15:
        fraud_score = max(fraud_score, 0.75)

    # Reply-To mismatch + URL + no auth headers → suspicious even without urgency
    if reply_mm and phish_urls >= 1 and not features.get("spf_pass"):
        fraud_score = max(fraud_score, 0.62)

    # ── BEC patterns ───────────────────────────────────────────────────────────
    # Reply-to mismatch + financial keywords + urgency
    if reply_mm and fin_kw >= 2 and urgency > 0.4:
        fraud_score = max(fraud_score, 0.93)

    # Display-name spoofing with financial keywords
    if display_spoof and fin_kw >= 2:
        fraud_score = max(fraud_score, 0.91)

    # ── Malware ─────────────────────────────────────────────────────────────────
    # Macro in actual attachment
    if has_macro and features.get("attachment_count", 0) >= 1:
        fraud_score = max(fraud_score, 0.88)

    # Body mentions "enable macros" but no actual attachment → Medium only
    if has_macro and features.get("attachment_count", 0) == 0:
        fraud_score = max(fraud_score, 0.45)

    # ── Legitimacy cap ──────────────────────────────────────────────────────────
    # Low-signal emails with no indicators of phishing — cap at 10%
    if urgency < 0.15 and not cred_req and not reply_mm and phish_urls == 0 and lookalike >= 0.55:
        fraud_score = min(fraud_score, 0.10)

    fraud_score = round(float(np.clip(fraud_score, 0.0, 1.0)), 4)
    # ──────────────────────────────────────────────────────────────────────────

    # SHAP values
    shap_vals = _explainer.shap_values(x)
    if isinstance(shap_vals, list):
        sv = shap_vals[1][0]
    elif hasattr(shap_vals, "values"):
        sv = shap_vals.values[0]
    else:
        sv = shap_vals[0]

    # Build per-feature SHAP dict
    shap_dict = {}
    for i, fname in enumerate(FEATURE_NAMES):
        shap_dict[fname] = round(float(sv[i]), 4)

    # Top 5 contributors sorted by absolute impact
    sorted_feats = sorted(
        FEATURE_NAMES, key=lambda f: abs(shap_dict[f]), reverse=True
    )
    top_contributors = []
    for fname in sorted_feats[:5]:
        top_contributors.append({
            "feature": fname,
            "description": FEATURE_DESCRIPTIONS.get(fname, fname),
            "impact": shap_dict[fname],
            "value": features.get(fname, 0),
            "direction": "increases" if shap_dict[fname] > 0 else "decreases",
        })

    # Classify threat type
    threat_type = _classify_threat(features)

    return {
        "fraud_score": round(fraud_score, 4),
        "shap_values": shap_dict,
        "top_contributors": top_contributors,
        "threat_type": threat_type,
    }


def _classify_threat(features: dict) -> str:
    if features.get("display_name_spoof") and features.get("financial_keyword_count", 0) >= 2:
        return "BEC"
    if features.get("reply_to_mismatch") and features.get("financial_keyword_count", 0) >= 2:
        return "BEC"
    if features.get("credential_request") and features.get("phishing_url_count", 0) >= 1:
        return "PHISHING"
    if features.get("has_macro") and features.get("attachment_count", 0) >= 1:
        return "MALWARE"
    if features.get("reply_to_mismatch") and features.get("urgency_score", 0) > 0.3:
        return "BEC"
    if features.get("phishing_url_count", 0) >= 2:
        return "PHISHING"
    if features.get("urgency_score", 0) > 0.3 and features.get("financial_keyword_count", 0) >= 1:
        return "SUSPICIOUS"
    if features.get("lookalike_score", 1.0) <= 0.45 and features.get("urgency_score", 0) > 0.2:
        return "PHISHING"
    return "CLEAN"
