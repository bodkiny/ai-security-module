import argparse
import csv
import json
import random
from pathlib import Path
from typing import Any, Iterable

from datasets import load_dataset

DATASET_NAME = "neuralchemy/Prompt-injection-dataset"
DEFAULT_CONFIG = "core"

BENIGN_LABELS = {"benign", "safe", "0", 0, "no", "negative"}
MALICIOUS_LABELS = {"malicious", "injection", "attack", "1", 1, "yes", "positive"}


def _normalize_label(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "malicious" if value else "benign"
    if isinstance(value, (int, float)):
        return "malicious" if int(value) == 1 else "benign"
    val = str(value).strip().lower()
    if val in BENIGN_LABELS:
        return "benign"
    if val in MALICIOUS_LABELS:
        return "malicious"
    return None


def _extract_prompt(row: dict) -> str | None:
    for key in ["prompt", "text", "instruction", "query", "input"]:
        if key in row and isinstance(row[key], str) and row[key].strip():
            return row[key].strip()
    return None


def _extract_label(row: dict) -> str | None:
    for key in ["label", "labels", "class", "category", "is_injection", "is_malicious"]:
        if key in row:
            lbl = _normalize_label(row[key])
            if lbl:
                return lbl
    return None


def _iter_rows(ds) -> Iterable[dict]:
    for split in ds.keys():
        for row in ds[split]:
            yield row


def build_dataset(
    out_csv: Path,
    out_jsonl: Path,
    per_class: int,
    seed: int,
    dataset_name: str,
    dataset_config: str | None,
):
    random.seed(seed)
    items = []

    ds = load_dataset(dataset_name, dataset_config) if dataset_config else load_dataset(dataset_name)
    for row in _iter_rows(ds):
        prompt = _extract_prompt(row)
        label = _extract_label(row)
        if not prompt or not label:
            continue
        items.append(
            {
                "prompt": prompt,
                "expected": label,
                "source": dataset_name,
                "meta": {k: row.get(k) for k in ["category", "description", "id"] if k in row},
            }
        )

    benign = [x for x in items if x["expected"] == "benign"]
    malicious = [x for x in items if x["expected"] == "malicious"]

    random.shuffle(benign)
    random.shuffle(malicious)

    benign = benign[:per_class]
    malicious = malicious[:per_class]

    final = benign + malicious
    random.shuffle(final)

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["prompt", "expected"])
        writer.writeheader()
        for row in final:
            writer.writerow({"prompt": row["prompt"], "expected": row["expected"]})

    with out_jsonl.open("w", encoding="utf-8") as f:
        for row in final:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"Saved CSV: {out_csv}")
    print(f"Saved JSONL: {out_jsonl}")
    print(f"Total: {len(final)} (benign={len(benign)}, malicious={len(malicious)})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-csv", default="datasets/attacks.csv")
    parser.add_argument("--out-jsonl", default="datasets/attacks.jsonl")
    parser.add_argument("--per-class", type=int, default=50)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--dataset", default=DATASET_NAME)
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    args = parser.parse_args()

    build_dataset(
        Path(args.out_csv),
        Path(args.out_jsonl),
        args.per_class,
        args.seed,
        args.dataset,
        args.config,
    )