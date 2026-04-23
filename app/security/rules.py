from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from app.core.config import settings


def _resolve_rules_path() -> Path:
    path = Path(settings.rules_path)
    if path.is_absolute():
        return path
    root = Path(__file__).resolve().parents[2]
    return root / path


@lru_cache
def _load_rules() -> dict:
    path = _resolve_rules_path()
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache
def get_injection_patterns() -> list[tuple[str, re.Pattern[str]]]:
    rules = _load_rules()
    patterns = []
    for entry in rules.get("injection_patterns", []):
        code = entry["code"]
        pattern = entry["pattern"]
        patterns.append((code, re.compile(pattern, re.IGNORECASE)))
    return patterns


def get_direct_injection_snippets() -> list[str]:
    rules = _load_rules()
    return list(rules.get("direct_injection_snippets", []))


def get_obfuscated_snippets() -> list[str]:
    rules = _load_rules()
    return list(rules.get("obfuscated_snippets", []))


def get_term_weights() -> dict[str, float]:
    rules = _load_rules()
    return {k: float(v) for k, v in rules.get("term_weights", {}).items()}


def get_reason_weights() -> dict[str, float]:
    rules = _load_rules()
    return {k: float(v) for k, v in rules.get("reason_weights", {}).items()}
