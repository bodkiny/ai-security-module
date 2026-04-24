import html
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
CONFUSABLES_MAP = str.maketrans(
    {
        "\u0430": "a",  # Cyrillic a
        "\u03b1": "a",  # Greek alpha
        "\u0435": "e",  # Cyrillic e
        "\u03b5": "e",  # Greek epsilon
        "\u043e": "o",  # Cyrillic o
        "\u03bf": "o",  # Greek omicron
        "\u0456": "i",  # Cyrillic i
        "\u03b9": "i",  # Greek iota
        "\u0443": "y",  # Cyrillic u
        "\u03c5": "y",  # Greek upsilon
        "\u0440": "p",  # Cyrillic pe
        "\u0441": "c",  # Cyrillic es
        "\u0445": "x",  # Cyrillic ha
        "\u043d": "h",  # Cyrillic en
        "\u043a": "k",  # Cyrillic ka
        "\u043c": "m",  # Cyrillic em
        "\u0442": "t",  # Cyrillic te
        "\u0432": "b",  # Cyrillic ve
        "\u043b": "l",  # Cyrillic el
        "\u0455": "s",  # Cyrillic dze
        "\u03b2": "b",  # Greek beta
        "\u03b3": "g",  # Greek gamma
        "\u03ba": "k",  # Greek kappa
        "\u03c4": "t",  # Greek tau
        "\u03c1": "p",  # Greek rho
    }
)
LEETSPEAK_MAP = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "6": "g",
        "7": "t",
        "8": "b",
        "9": "g",
        "@": "a",
        "$": "s",
        "\u20ac": "e",
        "|": "l",
        "!": "i",
        "†": "t",
    }
)

ROLE_LABEL_RE = re.compile(r"(?m)^\s*(system|developer|assistant)\s*:")
ENCODING_HINTS_RE = re.compile(
    r"\b(base64|rot13|hex|url-?encode|decode|encoded|cipher|obfuscat\w*)\b",
    re.IGNORECASE,
)


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = html.unescape(normalized)
    normalized = ZERO_WIDTH_RE.sub("", normalized)
    normalized = WHITESPACE_RE.sub(" ", normalized).strip()
    return normalized


def _compact_text(text: str) -> str:
    return NON_ALNUM_RE.sub("", text.lower())


def normalize_obfuscation(text: str) -> str:
    return text.translate(CONFUSABLES_MAP).translate(LEETSPEAK_MAP)


def _looks_obfuscated_injection(compact: str, lower: str, compact_obfuscated: str) -> bool:
    direct_snippets = get_direct_injection_snippets()
    obfuscated_snippets = get_obfuscated_snippets()
    if any(snippet in lower for snippet in direct_snippets):
        return False
    return any(
        snippet in compact or snippet in compact_obfuscated for snippet in obfuscated_snippets
    )


def validate_input(prompt: str) -> list[str]:
    reasons = []
    if len(prompt) > settings.max_prompt_chars:
        reasons.append("PROMPT_TOO_LONG")
    if ZERO_WIDTH_RE.search(prompt):
        reasons.append("ZERO_WIDTH_CHARS")

    normalized = normalize_text(prompt)
    lower = normalized.lower()
    deobfuscated = normalize_obfuscation(lower)

    pattern_hit = False
    obfuscation_hit = False
    for code, pattern in get_injection_patterns():
        if pattern.search(lower):
            reasons.append(code)
            pattern_hit = True
        elif deobfuscated != lower and pattern.search(deobfuscated):
            reasons.append(code)
            pattern_hit = True
            obfuscation_hit = True

    if pattern_hit:
        reasons.append("INJECTION_PATTERN_DETECTED")
    if obfuscation_hit:
        reasons.append("OBFUSCATION_NORMALIZED")

    if ROLE_LABEL_RE.search(normalized):
        reasons.append("ROLE_LABELS_PRESENT")

    if ENCODING_HINTS_RE.search(lower):
        reasons.append("ENCODING_OBFUSCATION_HINTS")

    compact = _compact_text(normalized)
    compact_obfuscated = _compact_text(deobfuscated)
    if _looks_obfuscated_injection(compact, lower, compact_obfuscated):
        reasons.append("OBFUSCATED_INJECTION_PATTERN")

    return list(dict.fromkeys(reasons))
