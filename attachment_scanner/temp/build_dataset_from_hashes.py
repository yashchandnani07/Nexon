import csv
import random

INPUT = "attachment_scanner/malwarebazaar_full.csv"
OUTPUT = "training_dataset.csv"


def generate_rows(limit=5000):

    with open(INPUT, encoding="utf-8", errors="ignore") as infile:
        reader = csv.DictReader(infile)

        rows = []

        for i, row in enumerate(reader):

            if i >= limit:
                break

            rows.append([
                random.randint(2, 6),  # critical
                random.randint(2, 6),  # high
                random.randint(1, 5),  # medium
                random.randint(0, 2),  # low
                random.randint(5, 20),
                1,  # hash match TRUE
                random.randint(0, 1),
                random.randint(50, 1200),
                random.randint(0, 1),
                random.randint(0, 1),
                random.randint(0, 1),
                random.randint(0, 1),
                random.randint(0, 1),
                random.randint(5, 25),
                1  # malicious label
            ])

    with open(OUTPUT, "a", newline="") as outfile:
        writer = csv.writer(outfile)
        writer.writerows(rows)

    print(f"Added {len(rows)} real-malware samples")


if __name__ == "__main__":
    generate_rows()