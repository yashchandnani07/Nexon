"""
Bootstrap model trainer — generates synthetic email data and trains XGBoost.
Run at Docker build time: python train_bootstrap.py
Produces: models/xgb_fraud_model.pkl
"""
import numpy as np
import pickle
from pathlib import Path

FEATURE_NAMES = [
    "spf_pass", "dkim_valid", "dmarc_pass", "domain_age_days",
    "lookalike_score", "reply_to_mismatch", "display_name_spoof",
    "urgency_score", "financial_keyword_count", "credential_request",
    "phishing_url_count", "html_text_ratio", "external_image_count",
    "attachment_count", "has_macro", "body_length",
]


def _legit(n):
    """Legitimate corporate email feature vectors."""
    d = np.zeros((n, 16))
    d[:, 0] = np.random.choice([0, 1], n, p=[0.10, 0.90])    # spf_pass
    d[:, 1] = np.random.choice([0, 1], n, p=[0.15, 0.85])    # dkim_valid
    d[:, 2] = np.random.choice([0, 1], n, p=[0.20, 0.80])    # dmarc_pass
    d[:, 3] = np.random.exponential(1000, n).clip(30, 10000)  # domain_age (old domains)
    # lookalike: 0=identical to barclays, 1=completely different; legit domains are FAR from barclays (high ratio)
    d[:, 4] = np.random.uniform(0.55, 1.00, n)                # far from barclays = legit
    d[:, 5] = np.random.choice([0, 1], n, p=[0.95, 0.05])    # reply_to_mismatch
    d[:, 6] = 0                                                 # display_name_spoof
    d[:, 7] = np.random.beta(1, 8, n)                          # urgency_score (low)
    d[:, 8] = np.random.poisson(0.3, n).clip(0, 3)            # financial_keywords
    d[:, 9] = 0                                                 # credential_request
    d[:, 10] = np.random.poisson(0.5, n).clip(0, 2)           # phishing_url_count (few)
    d[:, 11] = np.random.exponential(1.0, n).clip(0, 8)       # html_text_ratio
    d[:, 12] = np.random.poisson(0.3, n).clip(0, 3)           # external_images
    d[:, 13] = np.random.poisson(0.4, n).clip(0, 3)           # attachment_count
    d[:, 14] = 0                                                # has_macro
    d[:, 15] = np.random.exponential(500, n).clip(50, 5000)   # body_length
    return d


def _phishing(n):
    """Phishing / credential-harvesting email feature vectors."""
    d = np.zeros((n, 16))
    d[:, 0] = np.random.choice([0, 1], n, p=[0.70, 0.30])    # spf fails
    d[:, 1] = np.random.choice([0, 1], n, p=[0.75, 0.25])
    d[:, 2] = np.random.choice([0, 1], n, p=[0.80, 0.20])
    d[:, 3] = np.random.exponential(30, n).clip(1, 180)       # young domains
    # lookalike: low ratio = SIMILAR to barclays = phishing impersonation
    d[:, 4] = np.random.uniform(0.10, 0.55, n)                # close to barclays = phishing
    d[:, 5] = np.random.choice([0, 1], n, p=[0.40, 0.60])
    d[:, 6] = np.random.choice([0, 1], n, p=[0.50, 0.50])
    d[:, 7] = np.random.beta(5, 2, n)                          # high urgency
    d[:, 8] = np.random.poisson(1.5, n).clip(0, 8)
    d[:, 9] = np.random.choice([0, 1], n, p=[0.25, 0.75])    # credential request common
    d[:, 10] = np.random.poisson(3, n).clip(1, 10)            # many phishing URLs
    d[:, 11] = np.random.exponential(5, n).clip(1, 50)
    d[:, 12] = np.random.poisson(2, n).clip(0, 8)
    d[:, 13] = np.random.poisson(0.2, n).clip(0, 2)
    d[:, 14] = 0
    d[:, 15] = np.random.exponential(300, n).clip(50, 2000)
    return d


def _bec(n):
    """Business Email Compromise — impersonation + wire fraud."""
    d = np.zeros((n, 16))
    d[:, 0] = np.random.choice([0, 1], n, p=[0.30, 0.70])    # often passes SPF
    d[:, 1] = np.random.choice([0, 1], n, p=[0.40, 0.60])
    d[:, 2] = np.random.choice([0, 1], n, p=[0.50, 0.50])
    d[:, 3] = np.random.exponential(200, n).clip(10, 2000)
    # BEC uses lookalike domains (impersonating barclays CEO domain)
    d[:, 4] = np.random.uniform(0.15, 0.50, n)                # low ratio = impersonates barclays
    d[:, 5] = np.random.choice([0, 1], n, p=[0.15, 0.85])    # reply-to mismatch key signal
    d[:, 6] = np.random.choice([0, 1], n, p=[0.25, 0.75])    # display-name spoof key signal
    d[:, 7] = np.random.beta(4, 2, n)                          # high urgency
    d[:, 8] = np.random.poisson(4, n).clip(1, 15)             # lots of financial keywords
    d[:, 9] = np.random.choice([0, 1], n, p=[0.70, 0.30])
    d[:, 10] = np.random.poisson(0.4, n).clip(0, 3)           # few URLs (text-based BEC)
    d[:, 11] = np.random.exponential(1.2, n).clip(0, 8)
    d[:, 12] = np.random.poisson(0.2, n).clip(0, 2)
    d[:, 13] = np.random.poisson(0.5, n).clip(0, 2)
    d[:, 14] = 0
    d[:, 15] = np.random.exponential(400, n).clip(100, 3000)
    return d


def _malware(n):
    """Malware delivery via weaponised attachments."""
    d = np.zeros((n, 16))
    d[:, 0] = np.random.choice([0, 1], n, p=[0.60, 0.40])
    d[:, 1] = np.random.choice([0, 1], n, p=[0.65, 0.35])
    d[:, 2] = np.random.choice([0, 1], n, p=[0.70, 0.30])
    d[:, 3] = np.random.exponential(60, n).clip(1, 500)
    d[:, 4] = np.random.uniform(0.30, 0.70, n)                # moderate lookalike
    d[:, 5] = np.random.choice([0, 1], n, p=[0.55, 0.45])
    d[:, 6] = np.random.choice([0, 1], n, p=[0.60, 0.40])
    d[:, 7] = np.random.beta(3, 2, n)
    d[:, 8] = np.random.poisson(1.5, n).clip(0, 6)
    d[:, 9] = np.random.choice([0, 1], n, p=[0.65, 0.35])
    d[:, 10] = np.random.poisson(1, n).clip(0, 5)
    d[:, 11] = np.random.exponential(3, n).clip(0, 20)
    d[:, 12] = np.random.poisson(0.8, n).clip(0, 4)
    d[:, 13] = np.random.poisson(1.5, n).clip(1, 5)           # attachments key signal
    d[:, 14] = np.random.choice([0, 1], n, p=[0.25, 0.75])   # macros key signal
    d[:, 15] = np.random.exponential(200, n).clip(50, 1500)
    return d


def main():
    from xgboost import XGBClassifier
    from sklearn.metrics import classification_report

    np.random.seed(42)

    # Class distribution: ~60% legit, ~20% phishing, ~15% BEC, ~5% malware
    X = np.vstack([_legit(6000), _phishing(2000), _bec(1500), _malware(500)])
    y = np.concatenate([np.zeros(6000), np.ones(2000), np.ones(1500), np.ones(500)])

    idx = np.random.permutation(len(X))
    X, y = X[idx], y[idx]

    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=6000 / 4000,
        eval_metric="logloss",
        use_label_encoder=False,
        random_state=42,
    )
    model.fit(X, y)

    y_pred = model.predict(X)
    print(classification_report(y, y_pred, target_names=["Legitimate", "Fraud"]))

    out = Path(__file__).parent / "models"
    out.mkdir(exist_ok=True)

    with open(out / "xgb_fraud_model.pkl", "wb") as f:
        pickle.dump(model, f)

    print(f"[Train] Model saved → {out / 'xgb_fraud_model.pkl'}")
    print(f"[Train] Features ({len(FEATURE_NAMES)}): {FEATURE_NAMES}")


if __name__ == "__main__":
    main()
