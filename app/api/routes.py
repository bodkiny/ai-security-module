import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from app.core.config import settings
from app.models.schemas import SecureChatRequest, SecureChatResponse
from app.models.enums import Decision
from app.security.input_filter import (
    hidden_unicode_categories,
    hidden_unicode_counts,
    normalize_text,
    validate_input,
)
from app.security.risk_scoring import score_risk
from app.security.policy_engine import decide
from app.security.output_filter import redact_sensitive
from app.llm.client import LLMClient
from app.storage.audit_store import get_audit_summary, save_event
from app.security.rate_limiter import RateLimiter, get_redis

router = APIRouter()
llm_client = LLMClient()
rate_limiter = RateLimiter(get_redis())
audit_logger = logging.getLogger("audit")


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
        audit_logger.info(
            "Rate limit exceeded: user_id=%s client_ip=%s reason=%s retry_after_s=%s",
            payload.user_id,
            client_ip,
            reason,
            rl.retry_after_s,
        )
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

    raw_prompt = payload.prompt
    prompt = normalize_text(raw_prompt)
    reasons = validate_input(raw_prompt)
    risk = score_risk(prompt, reasons)
    decision = decide(risk, reasons)

    if decision == Decision.BLOCK:
        response_text = "Request blocked by security policy."
        redactions = []
    else:
        raw = llm_client.generate(prompt, decision)
        response_text, redactions = redact_sensitive(raw)

    meta = None
    hidden_counts = hidden_unicode_counts(raw_prompt)
    hidden_total = sum(hidden_counts.values())
    if hidden_total > 0:
        meta = {
            "hidden_unicode_total": hidden_total,
            "hidden_unicode_counts": hidden_counts,
            "hidden_unicode_categories": hidden_unicode_categories(hidden_counts),
            "hidden_trigger_reasons": [
                reason
                for reason in reasons
                if reason
                in {
                    "EMOJI_SMUGGLING_SUSPECTED",
                    "HIDDEN_UNICODE_MARKERS",
                    "VARIATION_SELECTOR_EXCESS",
                    "HIDDEN_TEXT_DECODING",
                    "BYTE_DECODE_INSTRUCTION",
                    "LOWEST_BYTE_PATTERN",
                }
            ],
        }

    event = {
        "user_id": payload.user_id,
        "decision": decision.value,
        "risk_score": risk,
        "reasons": reasons,
        "redactions": redactions,
    }
    if meta is not None:
        event["meta"] = meta
    save_event(event)

    return SecureChatResponse(
        decision=decision,
        risk_score=risk,
        reasons=reasons,
        response_text=response_text,
        redactions=redactions,
    )


@router.get("/monitoring/summary")
def monitoring_summary(hours: int = 24, recent_limit: int = 20):
    if not settings.monitoring_enabled:
        return {"status": "disabled"}
    return get_audit_summary(hours=hours, recent_limit=recent_limit)


@router.get("/monitoring", response_class=HTMLResponse)
def monitoring_page():
    if not settings.monitoring_enabled:
        return "<html><body><h2>Monitoring disabled</h2></body></html>"
    return """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>AI Security Monitoring</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; color: #222; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(160px, 1fr)); gap: 12px; margin-bottom: 16px; }
    .card { border: 1px solid #ddd; border-radius: 8px; padding: 12px; }
    h1 { margin-top: 0; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { border: 1px solid #e4e4e4; padding: 8px; text-align: left; font-size: 13px; }
    th { background: #f8f8f8; }
    .muted { color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <h1>AI Security Monitoring</h1>
  <div class="muted">Auto-refreshes every 10s</div>
  <div class="grid">
    <div class="card"><div>Total events</div><h2 id="allTime">-</h2></div>
    <div class="card"><div>Events (24h)</div><h2 id="window">-</h2></div>
    <div class="card"><div>Rate-limited (24h)</div><h2 id="rateLimited">-</h2></div>
    <div class="card"><div>Avg risk (24h)</div><h2 id="avgRisk">-</h2></div>
  </div>

  <h3>Decision counts (24h)</h3>
  <table id="decisions"><thead><tr><th>Decision</th><th>Count</th></tr></thead><tbody></tbody></table>

  <h3>Top reasons (24h)</h3>
  <table id="reasons"><thead><tr><th>Reason</th><th>Count</th></tr></thead><tbody></tbody></table>

  <h3>Recent events</h3>
  <table id="recent">
    <thead><tr><th>Created at</th><th>User</th><th>Decision</th><th>Risk</th><th>Reasons</th></tr></thead>
    <tbody></tbody>
  </table>

  <script>
    function renderRows(tableId, rows, cols) {
      const body = document.querySelector(`#${tableId} tbody`);
      body.innerHTML = "";
      rows.forEach(row => {
        const tr = document.createElement("tr");
        cols.forEach(c => {
          const td = document.createElement("td");
          const v = row[c];
          td.textContent = Array.isArray(v) ? v.join(", ") : (v ?? "");
          tr.appendChild(td);
        });
        body.appendChild(tr);
      });
    }

    async function refresh() {
      const url = `${window.location.pathname.replace(/\\/$/, "")}/summary?hours=24&recent_limit=20`;
      const r = await fetch(url);
      const data = await r.json();
      if (data.status !== "ok") return;
      document.getElementById("allTime").textContent = data.totals.all_time;
      document.getElementById("window").textContent = data.totals.window;
      document.getElementById("rateLimited").textContent = data.rate_limited_in_window;
      document.getElementById("avgRisk").textContent = data.avg_risk_in_window.toFixed(3);
      renderRows("decisions", data.decision_counts, ["decision", "count"]);
      renderRows("reasons", data.top_reasons, ["reason", "count"]);
      renderRows("recent", data.recent_events, ["created_at", "user_id", "decision", "risk_score", "reasons"]);
    }

    refresh();
    setInterval(refresh, 10000);
  </script>
</body>
</html>
"""
