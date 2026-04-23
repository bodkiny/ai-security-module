from fastapi import APIRouter
from app.models.schemas import SecureChatRequest, SecureChatResponse
from app.models.enums import Decision
from app.security.input_filter import normalize_text, validate_input
from app.security.risk_scoring import score_risk
from app.security.policy_engine import decide
from app.security.output_filter import redact_sensitive
from app.llm.client import LLMClient
from app.storage.audit_store import save_event

router = APIRouter()
llm_client = LLMClient()


@router.post("/secure-chat", response_model=SecureChatResponse)
def secure_chat(payload: SecureChatRequest) -> SecureChatResponse:
    prompt = normalize_text(payload.prompt)
    reasons = validate_input(prompt)
    risk = score_risk(prompt, reasons)
    decision = decide(risk, reasons)

    if decision == Decision.BLOCK:
        response_text = "Request blocked by security policy."
        redactions = []
    else:
        raw = llm_client.generate(prompt, decision)
        response_text, redactions = redact_sensitive(raw)

    save_event(
        {
            "user_id": payload.user_id,
            "decision": decision.value,
            "risk_score": risk,
            "reasons": reasons,
            "redactions": redactions,
        }
    )

    return SecureChatResponse(
        decision=decision,
        risk_score=risk,
        reasons=reasons,
        response_text=response_text,
        redactions=redactions,
    )
