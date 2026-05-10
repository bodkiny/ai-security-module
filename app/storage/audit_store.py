from __future__ import annotations

import logging
from time import sleep
from typing import Any
from uuid import uuid4

from psycopg import Error as PsycopgError
from psycopg.conninfo import make_conninfo
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool, PoolTimeout

from app.core.config import settings

logger = logging.getLogger("audit")
pool: ConnectionPool | None = None


CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    risk_score DOUBLE PRECISION NOT NULL,
    reasons JSONB NOT NULL,
    redactions JSONB NOT NULL,
    rate_limit_retry_after_s INTEGER,
    meta JSONB
);
"""

INSERT_SQL = """
INSERT INTO audit_events (
    id, user_id, decision, risk_score, reasons, redactions, rate_limit_retry_after_s, meta
) VALUES (
    %(id)s, %(user_id)s, %(decision)s, %(risk_score)s, %(reasons)s, %(redactions)s, %(rate_limit_retry_after_s)s, %(meta)s
);
"""


def _conninfo() -> str:
    return make_conninfo(
        settings.postgres_dsn, connect_timeout=settings.postgres_connect_timeout_s
    )


def _get_pool() -> ConnectionPool:
    global pool
    if pool is None:
        pool = ConnectionPool(
            conninfo=_conninfo(),
            min_size=settings.audit_store_pool_min_size,
            max_size=settings.audit_store_pool_max_size,
            timeout=settings.audit_store_pool_timeout_s,
            open=True,
            kwargs={"autocommit": False},
        )
    return pool


def init_audit_store() -> None:
    if not settings.audit_store_enabled:
        return

    last_error: Exception | None = None
    for attempt in range(settings.audit_store_init_retries + 1):
        try:
            with _get_pool().connection() as conn:
                conn.execute(CREATE_TABLE_SQL)
                conn.commit()
            logger.info("Audit store initialized")
            return
        except (PsycopgError, PoolTimeout, OSError) as exc:
            last_error = exc
            if attempt < settings.audit_store_init_retries:
                sleep(settings.audit_store_init_retry_delay_s)
                continue
            if settings.audit_store_fail_open:
                logger.warning("Audit store init failed (fail-open): %s", exc)
                return
            raise

    if last_error and not settings.audit_store_fail_open:
        raise last_error


def save_event(payload: dict[str, Any]) -> None:
    if not settings.audit_store_enabled:
        return
    try:
        with _get_pool().connection() as conn:
            conn.execute(
                INSERT_SQL,
                {
                    "id": str(uuid4()),
                    "user_id": payload.get("user_id"),
                    "decision": payload.get("decision"),
                    "risk_score": payload.get("risk_score"),
                    "reasons": Jsonb(payload.get("reasons", [])),
                    "redactions": Jsonb(payload.get("redactions", [])),
                    "rate_limit_retry_after_s": payload.get("rate_limit_retry_after_s"),
                    "meta": Jsonb(payload.get("meta") or {}),
                },
            )
            conn.commit()
    except (PsycopgError, PoolTimeout, OSError) as exc:
        logger.warning("Audit store write failed: %s", exc)
        if not settings.audit_store_fail_open:
            raise


def get_audit_summary(hours: int = 24, recent_limit: int = 20) -> dict[str, Any]:
    if not settings.audit_store_enabled:
        return {
            "status": "disabled",
            "hours": hours,
            "totals": {"all_time": 0, "window": 0},
            "decision_counts": [],
            "top_reasons": [],
            "rate_limited_in_window": 0,
            "avg_risk_in_window": 0.0,
            "recent_events": [],
        }

    window_sql = "created_at >= now() - make_interval(hours => %(hours)s)"
    summary: dict[str, Any] = {"status": "ok", "hours": hours}

    try:
        with _get_pool().connection() as conn:
            all_time = conn.execute("SELECT COUNT(*) FROM audit_events;").fetchone()[0]
            in_window = conn.execute(
                f"SELECT COUNT(*) FROM audit_events WHERE {window_sql};",
                {"hours": hours},
            ).fetchone()[0]
            summary["totals"] = {"all_time": all_time, "window": in_window}

            decision_rows = conn.execute(
                f"""
                SELECT decision, COUNT(*)
                FROM audit_events
                WHERE {window_sql}
                GROUP BY decision
                ORDER BY COUNT(*) DESC;
                """,
                {"hours": hours},
            ).fetchall()
            summary["decision_counts"] = [
                {"decision": row[0], "count": row[1]} for row in decision_rows
            ]

            reasons_rows = conn.execute(
                f"""
                SELECT reason.value AS reason, COUNT(*)
                FROM audit_events
                CROSS JOIN LATERAL jsonb_array_elements_text(reasons) AS reason(value)
                WHERE {window_sql}
                GROUP BY reason.value
                ORDER BY COUNT(*) DESC
                LIMIT %(recent_limit)s;
                """,
                {"hours": hours, "recent_limit": recent_limit},
            ).fetchall()
            summary["top_reasons"] = [
                {"reason": row[0], "count": row[1]} for row in reasons_rows
            ]

            rate_limited = conn.execute(
                f"""
                SELECT COUNT(*)
                FROM audit_events
                WHERE {window_sql}
                AND reasons @> '["RATE_LIMIT_EXCEEDED"]'::jsonb;
                """,
                {"hours": hours},
            ).fetchone()[0]
            summary["rate_limited_in_window"] = rate_limited

            avg_risk = conn.execute(
                f"""
                SELECT COALESCE(AVG(risk_score), 0.0)
                FROM audit_events
                WHERE {window_sql};
                """,
                {"hours": hours},
            ).fetchone()[0]
            summary["avg_risk_in_window"] = float(avg_risk)

            recent_rows = conn.execute(
                """
                SELECT created_at, user_id, decision, risk_score, reasons
                FROM audit_events
                ORDER BY created_at DESC
                LIMIT %(recent_limit)s;
                """,
                {"recent_limit": recent_limit},
            ).fetchall()
            summary["recent_events"] = [
                {
                    "created_at": row[0].isoformat(),
                    "user_id": row[1],
                    "decision": row[2],
                    "risk_score": float(row[3]),
                    "reasons": row[4],
                }
                for row in recent_rows
            ]
    except (PsycopgError, PoolTimeout, OSError) as exc:
        logger.warning("Audit summary read failed: %s", exc)
        return {"status": "unavailable", "error": str(exc), "hours": hours}

    return summary


def close_audit_store() -> None:
    global pool
    if pool is not None:
        pool.close()
        pool = None
