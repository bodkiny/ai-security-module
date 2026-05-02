from fastapi import APIRouter, Request
from app.core.config import settings
from app.models.schemas import SecureChatRequest, SecureChatResponse
from app.models.enums import Decision
from app.security.input_filter import normalize_text, validate_input
from app.security.risk_scoring import score_risk
from app.security.policy_engine import decide
from app.security.output_filter import redact_sensitive
from app.llm.client import LLMClient
from app.storage.audit_store import save_event
from app.security.rate_limiter import RateLimiter, get_redis

router = APIRouter()
llm_client = LLMClient()
rate_limiter = RateLimiter(get_redis())


def _get_client_ip(request: Request) -> str | None:
    if settings.rate_limit_trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            ip = forwarded.split(",", maxsplit=1)[0].strip()
            if ip:
                return ip
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()

    if request.client:
        return request.client.host
    return None


@router.post("/secure-chat", response_model=SecureChatResponse)
def secure_chat(payload: SecureChatRequest, request: Request) -> SecureChatResponse:
    client_ip = _get_client_ip(request)
    rl = rate_limiter.check(payload.user_id, client_ip)
    if not rl.allowed:
        reason = rl.reason or "RATE_LIMIT_EXCEEDED"
        save_event(
            {
                "user_id": payload.user_id,
                "decision": Decision.BLOCK.value,
                "risk_score": 1.0,
                "reasons": [reason],
                "redactions": [],
                "rate_limit_retry_after_s": rl.retry_after_s,
            }
        )
        return SecureChatResponse(
            decision=Decision.BLOCK,
            risk_score=1.0,
            reasons=[reason],
            response_text="Too many requests. Please try again later.",
            redactions=[],
        )

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
