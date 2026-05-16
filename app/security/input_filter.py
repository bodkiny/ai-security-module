import html
import re
import unicodedata
from app.core.config import settings
from app.security.rules import (
    get_direct_injection_snippets,
    get_injection_patterns,
    get_obfuscated_snippets,
)

ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\u2060\uFEFF]")
BIDI_CONTROL_RE = re.compile(r"[\u200E-\u200F\u202A-\u202E\u2066-\u2069]")
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
    r"\b(base64|hex|rot13|xor|encode|decode|convert|ascii|bytes|byte|unicode)\b", re.I
)

# Emoji smuggling / hidden channels
VARIATION_SELECTOR_RE = re.compile(r"[\uFE00-\uFE0F]")
TAG_CHAR_RE = re.compile(r"[\U000E0000-\U000E007F]")
COMBINING_MARK_RE = re.compile(r"[\u0300-\u036F]")
PRIVATE_USE_RE = re.compile(r"[\uE000-\uF8FF\U000F0000-\U000FFFFD\U00100000-\U0010FFFD]")


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = html.unescape(normalized)
    normalized = ZERO_WIDTH_RE.sub("", normalized)
    normalized = BIDI_CONTROL_RE.sub("", normalized)
    normalized = VARIATION_SELECTOR_RE.sub("", normalized)
    normalized = TAG_CHAR_RE.sub("", normalized)
    normalized = COMBINING_MARK_RE.sub("", normalized)
    normalized = PRIVATE_USE_RE.sub("", normalized)
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


def hidden_unicode_counts(text: str) -> dict[str, int]:
    return {
        "zero_width": len(ZERO_WIDTH_RE.findall(text)),
        "bidi_control": len(BIDI_CONTROL_RE.findall(text)),
        "variation_selector": len(VARIATION_SELECTOR_RE.findall(text)),
        "tag_chars": len(TAG_CHAR_RE.findall(text)),
        "combining_marks": len(COMBINING_MARK_RE.findall(text)),
        "private_use": len(PRIVATE_USE_RE.findall(text)),
    }


def hidden_unicode_categories(counts: dict[str, int]) -> list[str]:
    return [key for key, value in counts.items() if value > 0]


def validate_input(prompt: str) -> list[str]:
    reasons = []

    if len(prompt) > settings.max_prompt_chars:
        reasons.append("PROMPT_TOO_LONG")

    hidden_counts = hidden_unicode_counts(prompt)
    hidden_total = sum(hidden_counts.values())
    hidden_categories = hidden_unicode_categories(hidden_counts)

    if hidden_counts["zero_width"] > 0:
        reasons.append("ZERO_WIDTH_CHARS")
    if hidden_total > 0:
        reasons.append("EMOJI_SMUGGLING_SUSPECTED")
    if len(hidden_categories) >= 2:
        reasons.append("HIDDEN_UNICODE_MARKERS")
    if hidden_counts["variation_selector"] >= 2:
        reasons.append("VARIATION_SELECTOR_EXCESS")

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

    if ENCODING_HINTS_RE.search(normalized):
        reasons.append("ENCODING_OBFUSCATION_HINTS")

    compact = _compact_text(normalized)
    compact_obfuscated = _compact_text(deobfuscated)
    if _looks_obfuscated_injection(compact, lower, compact_obfuscated):
        reasons.append("OBFUSCATED_INJECTION_PATTERN")

    decode_intent = (
        "BYTE_DECODE_INSTRUCTION" in reasons
        or "LOWEST_BYTE_PATTERN" in reasons
        or "HIDDEN_TEXT_DECODING" in reasons
        or bool(ENCODING_HINTS_RE.search(lower))
    )
    if hidden_total > 0 and decode_intent:
        reasons.append("HIDDEN_TEXT_DECODING")

    return list(dict.fromkeys(reasons))
