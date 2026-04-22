import re
from app.core.config import settings

INJECTION_PATTERNS = [
    r"ignore (all|previous) instructions",
    r"reveal (system|hidden) prompt",
    r"you are now (developer|system)",
    r"bypass (policy|safety)",
    r"do anything now",
]

def normalize_text(text: str) -> str:
    # Basic normalization for MVP
    return " ".join(text.strip().split())


def validate_input(prompt: str) -> list[str]:
    reasons = []
    if len(prompt) > settings.max_prompt_chars:
        reasons.append("PROMPT_TOO_LONG")

    lower = prompt.lower()
    for pat in INJECTION_PATTERNS:
        if re.search(pat, lower):
            reasons.append("INJECTION_PATTERN_DETECTED")
            break
    return reasons