import csv
import random

OUTPUT = "training_dataset.csv"


def generate_benign(rows=5000):

    dataset = []

    for _ in range(rows):

        dataset.append([
            random.randint(0, 1),
            random.randint(0, 2),
            random.randint(0, 3),
            random.randint(2, 8),
            random.randint(0, 3),
            0,
            random.randint(0, 1),
            random.randint(5, 400),
            0,
            random.randint(0, 1),
            random.randint(0, 1),
            0,
            random.randint(0, 1),
            random.randint(0, 2),
            0
        ])

    with open(OUTPUT, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(dataset)

    print(f"Added {rows} benign samples")


if __name__ == "__main__":
    generate_benign()