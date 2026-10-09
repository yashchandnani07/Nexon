import os
import joblib
import pandas as pd


MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "models",
    "malware_model.pkl"
)


# Load model safely
model = None
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)


def score(scan_result):

    # If model not available
    if model is None:
        return {
            "applicable": False,
            "score": 50.0,
            "label": "Model unavailable"
        }

    findings = scan_result.get("stage_2_findings", [])
    file_type = scan_result.get("stage_1_file_type", {})
    hash_result = scan_result.get("stage_3_hash", {})

    # Risk counts
    critical = sum(1 for f in findings if f.get("risk_tier") == "Critical")
    high = sum(1 for f in findings if f.get("risk_tier") == "High")
    medium = sum(1 for f in findings if f.get("risk_tier") == "Medium")
    low = sum(1 for f in findings if f.get("risk_tier") == "Low")

    pattern_count = len(findings)

    hash_match = 1 if hash_result.get("known_malware") else 0
    extension_mismatch = 1 if file_type.get("extension_mismatch") else 0

    file_size = file_type.get("file_size_kb", 0)

    # Behavior indicators
    macro_detected = int(
        any("macro" in f.get("description", "").lower() for f in findings)
    )

    pdf_js_detected = int(
        any("javascript" in f.get("description", "").lower() for f in findings)
    )

    embedded_file_detected = int(
        any("embedded" in f.get("description", "").lower() for f in findings)
    )

    packer_detected = int(
        any("packer" in f.get("description", "").lower() for f in findings)
    )

    suspicious_imports = int(
        any("import" in f.get("description", "").lower() for f in findings)
    )

    yara_match_count = pattern_count

    # EXACT same order as training_dataset.csv
    features = [
        critical,
        high,
        medium,
        low,
        pattern_count,
        hash_match,
        extension_mismatch,
        file_size,
        macro_detected,
        pdf_js_detected,
        embedded_file_detected,
        packer_detected,
        suspicious_imports,
        yara_match_count
    ]

    # Convert to dataframe using trained feature names
    features_df = pd.DataFrame([features], columns=model.feature_name_)

    probability = model.predict_proba(features_df)[0][1]

    score_percent =float(round(probability * 100, 2))

    if score_percent >= 80:
        label = "Malicious"
    elif score_percent >= 50:
        label = "Suspicious"
    else:
        label = "Benign"

    return {
        "applicable": True,
        "score": score_percent,
        "label": label
    }