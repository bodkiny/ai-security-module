from app.core.config import settings
from app.models.enums import Decision


def decide(risk_score: float) -> Decision:
    if risk_score >= settings.block_threshold:
        return Decision.BLOCK
    if risk_score >= settings.safe_mode_threshold:
        return Decision.SAFE_MODE
    return Decision.ALLOW