from app.core.config import settings
from app.security.input_filter import normalize_obfuscation
from app.security.rules import get_reason_weights, get_term_weights

DEFAULT_TERM_WEIGHTS: dict[str, float] = {}

def _non_alnum_ratio(text: str) -> float:
    non_alnum = sum(1 for ch in text if not ch.isalnum() and not ch.isspace())
    return non_alnum / max(len(text), 1)

def score_risk(prompt: str, validation_reasons: list[str]) -> float:
    score = settings.base_risk
    lower = prompt.lower()
    deobfuscated = normalize_obfuscation(lower)

    term_hits = 0
    term_weights = get_term_weights() or DEFAULT_TERM_WEIGHTS
    for term, weight in term_weights.items():
        if term in lower or term in deobfuscated:
            score += weight
            term_hits += 1

    if len(prompt) > settings.long_prompt_chars:
        score += settings.long_prompt_risk

    if _non_alnum_ratio(prompt) > settings.non_alnum_ratio_threshold:
        score += settings.non_alnum_ratio_risk

    if term_hits >= settings.multi_term_threshold:
        score += settings.multi_term_bonus

    reason_weights = get_reason_weights() or {}
    for reason in validation_reasons:
        score += reason_weights.get(reason, 0.0)

    return min(score, 1.0)
