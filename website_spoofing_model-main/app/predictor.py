"""
predictor.py – Standalone inference module for URL phishing detection.
Usage:
    from app.predictor import Predictor
    p = Predictor()
    result = p.predict("http://suspicious-link.com")
"""
from __future__ import annotations

import warnings
warnings.filterwarnings("ignore")

import joblib
from pathlib import Path
from typing import TypedDict

from app.config import settings
from app.feature_extractor import extractor
from app.logger import logger

class PredictionResult(TypedDict):
    url: str
    label: str  # "legitimate", "suspicious", or "phishing"
    probability: float
    is_phishing: bool
    risk_factors: list[str]
    safe_factors: list[str]
    summary_report: str

class Predictor:
    """
    Loads the trained XGBoost model and provides a simple prediction interface.
    """
    # Common trusted domains to prevent false positives
    TRUSTED_DOMAINS = {
        "google.com", "google.co.uk", "barclays.co.uk", "barclays.com",
        "microsoft.com", "apple.com", "facebook.com", "amazon.com",
        "netflix.com", "paypal.com", "ebay.com", "github.com",
        "linkedin.com", "twitter.com", "instagram.com", "bing.com"
    }

    # Common trusted domains to prevent false positives
    TRUSTED_DOMAINS = {
        "google.com", "google.co.uk", "youtube.com", "wikipedia.org",
        "microsoft.com", "apple.com", "facebook.com", "amazon.com",
        "netflix.com", "paypal.com", "ebay.com", "github.com",
        "linkedin.com", "twitter.com", "instagram.com", "bing.com",
        "barclays.co.uk", "barclays.com", "barclays.net", "live.com",
        "outlook.com", "gmail.com", "yahoo.com"
    }

    def __init__(self, model_path: Path | None = None) -> None:
        self.model_path = model_path or settings.model_path
        self.scaler_path = settings.scaler_path
        self.le_path = settings.label_encoder_path
        
        self.mock_mode = False
        if not self.model_path.exists():
            logger.warning(f"Model not found at {self.model_path}. Running in MOCK heuristics mode.")
            self.mock_mode = True
        else:
            logger.info(f"Loading model artefacts from {self.model_path.parent}")
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            self.le = joblib.load(self.le_path)

    def is_trusted(self, url: str) -> bool:
        """Check if the URL belongs to a trusted domain."""
        import tldextract
        try:
            ext = tldextract.extract(url)
            domain = f"{ext.domain}.{ext.suffix}".lower()
            return domain in self.TRUSTED_DOMAINS
        except Exception:
            return False

    def predict(self, url: str) -> PredictionResult:
        """
        Analyse a single URL and return the classification results with explanation.
        """
        # 0. Check allowlist first
        if self.is_trusted(url):
            return {
                "url": url,
                "label": "legitimate",
                "probability": 0.01,
                "is_phishing": False,
                "risk_factors": [],
                "safe_factors": ["Verified Trusted Enterprise Domain"],
                "summary_report": f"This URL belongs to a verified trusted domain ({url}). PhishGuard identifies this as highly safe."
            }

        # 1. Extract features
        features = extractor.extract(url)
        feat_list = features.to_list()
        X = [feat_list]
        
        if self.mock_mode:
            # Simulated Probability generated via basic heuristics
            phish_prob = 0.15 # Base Risk
            if features.suspicious_keywords > 0: phish_prob += 0.2
            if features.brand_mimicry == 1: phish_prob += 0.3
            if features.is_shortened == 1: phish_prob += 0.15
            if features.tld_suspicious == 1: phish_prob += 0.25
            if features.has_ip == 1: phish_prob += 0.3
            phish_prob = min(phish_prob, 0.98)
            X_scaled = X # Not actually scaled
            predicted_label = "phishing" if phish_prob >= settings.suspicious_threshold / 100 else "legitimate"
        else:
            # 2. Scale features
            X_scaled = self.scaler.transform(X)
            
            # 3. Predict probability and class using the trained model + label encoder
            proba = self.model.predict_proba(X_scaled)[0]
            y_pred_encoded = self.model.predict(X_scaled)[0]
            # Use label encoder to decode predicted class to human-readable label
            import typing
            label_classes = typing.cast(typing.List[str], list(self.le.classes_))
            predicted_label = str(self.le.inverse_transform([y_pred_encoded])[0])
            phish_idx = label_classes.index("phishing") if "phishing" in label_classes else -1
            phish_prob = float(proba[phish_idx]) if phish_idx >= 0 else float(proba[-1])
        
        # 3. Explainability: Identify high-risk signals
        from app.feature_extractor import URLFeatures
        feat_names = URLFeatures.feature_names()
        risk_factors = []
        for i, val in enumerate(X_scaled[0]):
            if val > 1.5 or (self.mock_mode and val > 0):  # High contribution to the phishing score
                feature_raw = feat_names[i]
                # Map technical features to professional explanations
                narratives = {
                    "prefix_suffix": "Uses suspicious hyphenated branding",
                    "num_subdomains": "Contains an abnormally high number of subdomains",
                    "digit_ratio": "Features dense clusters of digits",
                    "entropy": "URL structure is highly randomized",
                    "url_length": "URL is excessively long",
                    "num_phishing_path_patterns": "Uses suspicious folder paths",
                    "tld_rarity": "Domain is hosted on a high-risk TLD",
                    "brand_mimicry": "Attempts to mimic a well-known brand identity",
                    "is_shortened": "Uses a link-shortening service",
                }
                explanation = narratives.get(feature_raw, feature_raw.replace("_", " ").title())
                risk_factors.append(explanation)

        # Manual hints for borderline cases
        if features.num_phishing_path_patterns > 0:
            risk_factors.append("Detected common phishing kit structures")
        if features.brand_mimicry == 1:
            risk_factors.append("Detected brand name mimicry")
        if features.is_shortened == 1:
            risk_factors.append("URL uses a shortening service")

        # --- AI HEURISTIC GUARD ---
        # If AI score is high but no blatant phishing heuristics triggered:
        # Flag as false positive and Force to safe zone.
        if phish_prob > 0.60:
            blatant_risks = features.brand_mimicry == 1 or features.suspicious_keywords > 0 or features.tld_suspicious == 1
            if not blatant_risks and len(risk_factors) < 2:
                logger.warning(f"AI Override triggered for {url}. AI predicted {phish_prob:.2f} but no heuristics found.")
                phish_prob = min(phish_prob, 0.45) # Force to safe territory

        # Deduplicate 
        unique_risks: list[str] = sorted(list(set(risk_factors)))
        
        # 4. Determine Safe Factors
        safe_factors = []
        if features.has_https == 1:
            safe_factors.append("Uses Secure HTTPS Encryption")
        if features.has_ip == 0:
            safe_factors.append("Uses Official Domain")
        if features.suspicious_keywords == 0:
            safe_factors.append("No suspicious keywords detected")
        if features.brand_mimicry == 0:
            safe_factors.append("No brand typosquatting detected")

        safe_factors = sorted(list(set(safe_factors)))

        # 5. Determine label using the label encoder decoded prediction (real model) as primary signal,
        #    with probability-based "suspicious" band as a refinement.
        if not self.mock_mode:
            # Use the label encoder decoded prediction as the base label
            if predicted_label == "phishing":
                if phish_prob < settings.safe_threshold / 100:
                    # Heuristic guard overrode the probability — downgrade to suspicious
                    label_display = "suspicious"
                    status_text = "SUSPICIOUS"
                else:
                    label_display = "phishing"
                    status_text = "DANGEROUS (Phishing Attempt)"
            else:
                # Model predicted legitimate; use probability to check for suspicious band
                if phish_prob >= settings.suspicious_threshold / 100:
                    label_display = "phishing"
                    status_text = "DANGEROUS (Phishing Attempt)"
                elif phish_prob >= settings.safe_threshold / 100:
                    label_display = "suspicious"
                    status_text = "SUSPICIOUS"
                else:
                    label_display = "legitimate"
                    status_text = "SAFE (Legitimate)"
        else:
            # Mock mode: rely solely on probability thresholds
            if phish_prob < settings.safe_threshold / 100:
                status_text = "SAFE (Legitimate)"
                label_display = "legitimate"
            elif phish_prob < settings.suspicious_threshold / 100:
                status_text = "SUSPICIOUS"
                label_display = "suspicious"
            else:
                status_text = "DANGEROUS (Phishing Attempt)"
                label_display = "phishing"

        report_lines = [
            f"The PhishGuard engine analyzed {len(feat_names)} signatures across this URL. "
            f"Classification Result: {status_text}. (Confidence Level: {phish_prob * 100:.1f}%)"
        ]
        
        if unique_risks:
            report_lines.append(f"Security Alert Summary: Found patterns indicating {', '.join(unique_risks[:3])}.")
        else:
            report_lines.append("No immediate structural or lexical risk patterns were detected.")
            
        if safe_factors:
            report_lines.append(f"Safe Signatures Detected: {', '.join(safe_factors[:3])}.")
            
        summary_report = " ".join(report_lines)

        return {
            "url": url,
            "label": label_display,
            "probability": float(phish_prob),
            "is_phishing": label_display == "phishing",
            "risk_factors": unique_risks[:3],
            "safe_factors": safe_factors[:3],
            "summary_report": summary_report
        }

if __name__ == "__main__":
    import sys
    url_to_test = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    predictor = Predictor()
    res = predictor.predict(url_to_test)
    print(f"\nAnalysis for: {res['url']}")
    print(f"Result: {res['label'].upper()}")
    print(f"Phishing Probability: {res['probability'] * 100:.2f}%\n")
    print(res["summary_report"])

if __name__ == "__main__":
    import sys
    url_to_test = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    
    predictor = Predictor()
    res = predictor.predict(url_to_test)
    print(f"\nAnalysis for: {res['url']}")
    print(f"Result: {res['label'].upper()}")
    print(f"Phishing Probability: {res['probability'] * 100:.2f}%\n")
    
    print("--- Detailed Summary ---")
    import textwrap
    for line in textwrap.wrap(res["summary_report"], width=80):
        print(line)
    
    print("\n--- Feature Breakdown ---")
    if res["risk_factors"]:
        print(f"Key Risk Factors: {', '.join(res['risk_factors'])}")
    if res["safe_factors"]:
        print(f"Key Safe Factors: {', '.join(res['safe_factors'])}")
    print("=========================")
