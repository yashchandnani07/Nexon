import csv
import os

DATASET = "training_dataset.csv"

HEADERS = [
    "critical",
    "high",
    "medium",
    "low",
    "pattern_count",
    "hash_match",
    "extension_mismatch",
    "file_size",
    "macro_detected",
    "pdf_js",
    "embedded_file",
    "packer_detected",
    "suspicious_imports",
    "yara_matches",
    "label"
]


def save_sample(features):

    file_exists = os.path.exists(DATASET)

    with open(DATASET, "a", newline="") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow(HEADERS)

        writer.writerow(features)