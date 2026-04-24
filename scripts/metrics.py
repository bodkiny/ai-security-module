import argparse
import csv
from pathlib import Path


def is_malicious_detected(decision: str) -> bool:
    return decision in {"SAFE_MODE", "BLOCK"}


def compute_metrics(results_csv: Path):
    with results_csv.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    tp = fp = tn = fn = 0
    for row in rows:
        expected = row["expected"]
        detected = is_malicious_detected(row["decision"])
        if expected == "malicious" and detected:
            tp += 1
        elif expected == "malicious" and not detected:
            fn += 1
        elif expected == "benign" and detected:
            fp += 1
        elif expected == "benign" and not detected:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print("Confusion Matrix:")
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", default="datasets/results.csv")
    args = parser.parse_args()

    compute_metrics(Path(args.results))