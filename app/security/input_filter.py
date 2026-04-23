import re
import unicodedata
from app.core.config import settings
from app.security.rules import (
    get_direct_injection_snippets,
    get_injection_patterns,
    get_obfuscated_snippets,
)

ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\uFEFF]")
WHITESPACE_RE = re.compile(r"\s+")
NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")

ROLE_LABEL_RE = re.compile(r"(?m)^\s*(system|developer|assistant)\s*:")
ENCODING_HINTS_RE = re.compile(
    r"\b(base64|rot13|hex|url-?encode|decode|encoded|cipher|obfuscat\w*)\b",
    re.IGNORECASE,
)


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = ZERO_WIDTH_RE.sub("", normalized)
    normalized = WHITESPACE_RE.sub(" ", normalized).strip()
    return normalized


def _compact_text(text: str) -> str:
    return NON_ALNUM_RE.sub("", text.lower())


def _looks_obfuscated_injection(compact: str, lower: str) -> bool:
    direct_snippets = get_direct_injection_snippets()
    obfuscated_snippets = get_obfuscated_snippets()
    if any(snippet in lower for snippet in direct_snippets):
        return False
    return any(snippet in compact for snippet in obfuscated_snippets)


def validate_input(prompt: str) -> list[str]:
    reasons = []
    if len(prompt) > settings.max_prompt_chars:
        reasons.append("PROMPT_TOO_LONG")
    if ZERO_WIDTH_RE.search(prompt):
        reasons.append("ZERO_WIDTH_CHARS")

    normalized = normalize_text(prompt)
    lower = normalized.lower()

    pattern_hit = False
    for code, pattern in get_injection_patterns():
        if pattern.search(lower):
            reasons.append(code)
            pattern_hit = True

    if pattern_hit:
        reasons.append("INJECTION_PATTERN_DETECTED")

    if ROLE_LABEL_RE.search(normalized):
        reasons.append("ROLE_LABELS_PRESENT")

    if ENCODING_HINTS_RE.search(lower):
        reasons.append("ENCODING_OBFUSCATION_HINTS")

    compact = _compact_text(normalized)
    if _looks_obfuscated_injection(compact, lower):
        reasons.append("OBFUSCATED_INJECTION_PATTERN")

    return list(dict.fromkeys(reasons))
