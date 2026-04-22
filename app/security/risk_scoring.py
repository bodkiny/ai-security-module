def score_risk(prompt: str, validation_reasons: list[str]) -> float:
    score = 0.05  # base risk

    lower = prompt.lower()

    suspicious_tokens = [
        "ignore previous",
        "reveal system prompt",
        "api key",
        "password",
        "token",
        "bypass",
        "jailbreak",
    ]

    for tok in suspicious_tokens:
        if tok in lower:
            score += 0.15

    if "INJECTION_PATTERN_DETECTED" in validation_reasons:
        score += 0.35

    if len(prompt) > 2000:
        score += 0.10

    return min(score, 1.0)