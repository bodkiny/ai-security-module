from app.core.config import settings
from app.models.enums import Decision


def decide(risk_score: float, reasons: list[str]) -> Decision:
    if any(reason in settings.hard_block_reasons for reason in reasons):
        return Decision.BLOCK
    if risk_score >= settings.block_threshold:
        return Decision.BLOCK
    if any(reason in settings.safe_mode_reasons for reason in reasons):
        return Decision.SAFE_MODE
    if risk_score >= settings.safe_mode_threshold:
        return Decision.SAFE_MODE
    return Decision.ALLOW
