import re
from typing import Callable

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}(?![\d\s-])"
)
EXPLICIT_KEY_RE = re.compile(
    r"\b("
    r"sk-[A-Za-z0-9]{20,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r")\b"
)
PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b")
BEARER_TOKEN_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
SECRET_FIELD_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret)\b(\s*[:=]\s*)([A-Za-z0-9_\-./+=]{10,})"
)
PASSWORD_FIELD_RE = re.compile(r"(?i)\b(password|passwd|pwd)\b(\s*[:=]\s*)([^\s,;]+)")
CREDIT_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def _add_redaction(redactions: list[str], label: str) -> None:
    if label not in redactions:
        redactions.append(label)


def _apply_sub(
    text: str,
    pattern: re.Pattern[str],
    replacement: str | Callable[[re.Match[str]], str],
    label: str,
    redactions: list[str],
) -> str:
    new_text, count = pattern.subn(replacement, text)
    if count > 0:
        _add_redaction(redactions, label)
    return new_text


def _luhn_valid(digits: str) -> bool:
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def redact_sensitive(text: str) -> tuple[str, list[str]]:
    redactions = []

    text = _apply_sub(
        text, PRIVATE_KEY_BLOCK_RE, "[REDACTED_PRIVATE_KEY]", "PRIVATE_KEY", redactions
    )
    text = _apply_sub(text, EMAIL_RE, "[REDACTED_EMAIL]", "EMAIL", redactions)
    text = _apply_sub(text, SSN_RE, "[REDACTED_SSN]", "SSN", redactions)
    text = _apply_sub(text, EXPLICIT_KEY_RE, "[REDACTED_KEY]", "API_KEY", redactions)
    text = _apply_sub(text, JWT_RE, "[REDACTED_JWT]", "JWT", redactions)
    text = _apply_sub(
        text, BEARER_TOKEN_RE, "[REDACTED_BEARER_TOKEN]", "BEARER_TOKEN", redactions
    )
    text = _apply_sub(
        text,
        SECRET_FIELD_RE,
        lambda m: f"{m.group(1)}{m.group(2)}[REDACTED_SECRET]",
        "API_KEY",
        redactions,
    )
    text = _apply_sub(
        text,
        PASSWORD_FIELD_RE,
        lambda m: f"{m.group(1)}{m.group(2)}[REDACTED_PASSWORD]",
        "PASSWORD",
        redactions,
    )

    card_redacted = False
    def _credit_card_repl(match: re.Match[str]) -> str:
        nonlocal card_redacted
        candidate = match.group(0)
        digits = re.sub(r"\D", "", candidate)
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            card_redacted = True
            return "[REDACTED_CREDIT_CARD]"
        return candidate

    text = CREDIT_CARD_CANDIDATE_RE.sub(_credit_card_repl, text)
    if card_redacted:
        _add_redaction(redactions, "CREDIT_CARD")

    phone_redacted = False
    def _phone_repl(match: re.Match[str]) -> str:
        nonlocal phone_redacted
        candidate = match.group(0)
        digits = re.sub(r"\D", "", candidate)
        if len(digits) > 11 and not candidate.lstrip().startswith("+"):
            return candidate
        if 10 <= len(digits) <= 15:
            phone_redacted = True
            return "[REDACTED_PHONE]"
        return candidate

    text = PHONE_RE.sub(_phone_repl, text)
    if phone_redacted:
        _add_redaction(redactions, "PHONE")

    return text, redactions
