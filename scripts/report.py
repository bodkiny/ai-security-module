import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path


WORD_RE = re.compile(r"[A-Za-z0-9_]{3,}")
STOPWORDS = {
    "the",
    "and",
    "you",
    "your",
    "are",
    "this",
    "that",
    "with",
    "have",
    "been",
    "from",
    "please",
    "what",
    "how",
    "can",
    "all",
    "not",
    "for",
    "now",
    "only",
    "must",
    "just",
    "into",
    "also",
    "then",
    "will",
    "tell",
    "about",
    "make",
    "output",
    "write",
    "reply",
    "response",
    "question",
    "rule",
    "rules",
    "instruction",
    "instructions",
    "ignore",
    "system",
    "prompt",
    "pwned",
}


def _safe_text(text: str) -> str:
    return text.encode("ascii", "backslashreplace").decode("ascii")


def _parse_reasons(value: str) -> list[str]:
    if not value:
        return []
    return [part for part in value.split("|") if part]


def report(results_csv: Path, top_n: int, max_prompt_chars: int):
    with results_csv.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    malicious = [r for r in rows if r["expected"] == "malicious"]
    benign = [r for r in rows if r["expected"] == "benign"]
    fn = [r for r in malicious if r["decision"] == "ALLOW"]

    print(f"Total rows: {len(rows)}")
    print(f"Malicious: {len(malicious)} Benign: {len(benign)}")
    print(f"False negatives: {len(fn)}")

    if fn:
        print("\nFalse negative samples:")
        for row in fn[:top_n]:
            sample = _safe_text(row["prompt"][:max_prompt_chars])
            print(f"- {sample}")

    reason_counts = defaultdict(lambda: {"total": 0, "malicious": 0, "benign": 0})
    for row in rows:
        reasons = _parse_reasons(row.get("reasons", ""))
        for reason in reasons:
            reason_counts[reason]["total"] += 1
            if row["expected"] == "malicious":
                reason_counts[reason]["malicious"] += 1
            else:
                reason_counts[reason]["benign"] += 1

    if reason_counts:
        print("\nReason hit rates:")
        totals_mal = len(malicious) or 1
        totals_benign = len(benign) or 1
        stats = []
        for reason, counts in reason_counts.items():
            mal_rate = counts["malicious"] / totals_mal
            benign_rate = counts["benign"] / totals_benign
            stats.append((mal_rate, counts["total"], benign_rate, reason))
        for mal_rate, total, benign_rate, reason in sorted(stats, reverse=True):
            print(
                f"- {reason}: malicious={mal_rate:.2%} benign={benign_rate:.2%} total={total}"
            )

    if fn:
        token_counts = Counter()
        for row in fn:
            for token in WORD_RE.findall(row["prompt"].lower()):
                if token in STOPWORDS:
                    continue
                token_counts[token] += 1
        if token_counts:
            print("\nTop FN tokens:")
            for token, count in token_counts.most_common(top_n):
                print(f"- {token}: {count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", default="datasets/results.csv")
    parser.add_argument("--top-n", type=int, default=10)
    parser.add_argument("--max-prompt-chars", type=int, default=120)
    args = parser.parse_args()

    report(Path(args.results), args.top_n, args.max_prompt_chars)
