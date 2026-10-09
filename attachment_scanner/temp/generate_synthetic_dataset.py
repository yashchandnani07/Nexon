import random
import pandas as pd

OUTPUT_FILE = "training_dataset.csv"
NUM_SAMPLES = 10000


def generate_sample(label):
    """
    label = 1 → malware
    label = 0 → benign
    """

    if label == 1:
        return [
            random.randint(0, 5),   # critical
            random.randint(1, 6),   # high
            random.randint(2, 8),   # medium
            random.randint(0, 4),   # low
            random.randint(5, 20),  # pattern_count
            random.choice([0, 1]),  # hash_match
            random.choice([0, 1]),  # extension_mismatch
            random.uniform(50, 5000),  # file_size
            random.choice([0, 1]),  # macro_detected
            random.choice([0, 1]),  # pdf_js
            random.choice([0, 1]),  # embedded_file
            random.choice([0, 1]),  # packer_detected
            random.choice([0, 1]),  # suspicious_imports
            random.randint(5, 20),  # yara_matches
            1                      # label
        ]

    else:
        return [
            random.randint(0, 1),
            random.randint(0, 2),
            random.randint(0, 3),
            random.randint(1, 6),
            random.randint(0, 4),
            0,
            random.choice([0, 1]),
            random.uniform(10, 3000),
            0,
            0,
            0,
            0,
            0,
            random.randint(0, 4),
            0
        ]


data = []

for _ in range(NUM_SAMPLES // 2):
    data.append(generate_sample(1))

for _ in range(NUM_SAMPLES // 2):
    data.append(generate_sample(0))


columns = [
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


df = pd.DataFrame(data, columns=columns)
df = df.sample(frac=1).reset_index(drop=True)

df.to_csv(OUTPUT_FILE, index=False)

print(f"Dataset generated: {OUTPUT_FILE} with {len(df)} samples")