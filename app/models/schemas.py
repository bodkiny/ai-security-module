from pydantic import BaseModel, Field
from app.models.enums import Decision


class SecureChatRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    prompt: str = Field(min_length=1, max_length=10000)


class SecureChatResponse(BaseModel):
    decision: Decision
    risk_score: float
    reasons: list[str]
    response_text: str
    redactions: list[str] = []