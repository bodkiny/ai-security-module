import argparse
import csv
import httpx
from pathlib import Path


def evaluate(input_csv: Path, output_csv: Path, url: str):
    with input_csv.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    results = []
    with httpx.Client(timeout=20.0) as client:
        for row in rows:
            prompt = row["prompt"]
            expected = row["expected"]
            payload = {"user_id": "eval-user", "prompt": prompt}
            r = client.post(url, json=payload)
            r.raise_for_status()
            data = r.json()
            results.append(
                {
                    "prompt": prompt,
                    "expected": expected,
                    "decision": data.get("decision"),
                    "risk_score": data.get("risk_score"),
                    "reasons": "|".join(data.get("reasons", [])),
                }
            )

    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["prompt", "expected", "decision", "risk_score", "reasons"]
        )
        writer.writeheader()
        writer.writerows(results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="datasets/attacks.csv")
    parser.add_argument("--output", default="datasets/results.csv")
    parser.add_argument("--url", default="http://127.0.0.1:8000/api/v1/secure-chat")
    args = parser.parse_args()

    evaluate(Path(args.input), Path(args.output), args.url)
    print(f"Saved results to {args.output}")