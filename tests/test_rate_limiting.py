import logging
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from redis import Redis
from redis.exceptions import RedisError

from app.core.config import settings
from app.main import app

client = TestClient(app)


def _get_redis() -> Redis | None:
    try:
        redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
        redis_client.ping()
        return redis_client
    except RedisError:
        return None


def _delete_keys(redis_client: Redis, pattern: str) -> None:
    cursor = 0
    while True:
        cursor, keys = redis_client.scan(cursor=cursor, match=pattern, count=200)
        if keys:
            redis_client.delete(*keys)
        if cursor == 0:
            break


@pytest.fixture
def redis_client():
    client_instance = _get_redis()
    if not client_instance:
        pytest.skip("Redis is not available; rate limit tests skipped.")
    yield client_instance
    client_instance.close()


def _post(prompt: str, user_id: str, headers: dict | None = None):
    return client.post(
        "/api/v1/secure-chat",
        json={"user_id": user_id, "prompt": prompt},
        headers=headers or {},
    )


def test_rate_limit_blocks_user_id(redis_client, monkeypatch):
    user_id = f"u-rl-{uuid4().hex}"
    _delete_keys(redis_client, f"rl:*:{user_id}")

    monkeypatch.setattr(settings, "rate_limit_window_s", 60)
    monkeypatch.setattr(settings, "rate_limit_requests", 2)
    monkeypatch.setattr(settings, "rate_limit_burst_window_s", 5)
    monkeypatch.setattr(settings, "rate_limit_burst_requests", 2)
    monkeypatch.setattr(settings, "rate_limit_enforce_ip", False)

    for _ in range(2):
        r = _post("Hello there.", user_id)
        assert r.status_code == 200
        assert "RATE_LIMIT_EXCEEDED" not in r.json().get("reasons", [])

    r = _post("Hello there.", user_id)
    body = r.json()
    assert body["decision"] == "BLOCK"
    assert "RATE_LIMIT_EXCEEDED" in body["reasons"]


def test_rate_limit_ip_enforcement_with_rotating_user(redis_client, monkeypatch):
    ip = f"203.0.113.{int(uuid4().hex[:2], 16)}"
    _delete_keys(redis_client, f"rl:*:{ip}")

    monkeypatch.setattr(settings, "rate_limit_window_s", 60)
    monkeypatch.setattr(settings, "rate_limit_requests", 2)
    monkeypatch.setattr(settings, "rate_limit_burst_window_s", 5)
    monkeypatch.setattr(settings, "rate_limit_burst_requests", 2)
    monkeypatch.setattr(settings, "rate_limit_enforce_ip", True)
    monkeypatch.setattr(settings, "rate_limit_trust_proxy_headers", True)

    for _ in range(2):
        r = _post("Hello there.", f"u-rl-{uuid4().hex}", headers={"X-Forwarded-For": ip})
        assert r.status_code == 200
        assert "RATE_LIMIT_EXCEEDED" not in r.json().get("reasons", [])

    r = _post("Hello there.", f"u-rl-{uuid4().hex}", headers={"X-Forwarded-For": ip})
    body = r.json()
    assert body["decision"] == "BLOCK"
    assert "RATE_LIMIT_EXCEEDED" in body["reasons"]


def test_rate_limit_audit_log(redis_client, monkeypatch, caplog):
    user_id = f"u-rl-{uuid4().hex}"
    _delete_keys(redis_client, f"rl:*:{user_id}")

    monkeypatch.setattr(settings, "rate_limit_window_s", 60)
    monkeypatch.setattr(settings, "rate_limit_requests", 1)
    monkeypatch.setattr(settings, "rate_limit_burst_window_s", 5)
    monkeypatch.setattr(settings, "rate_limit_burst_requests", 1)
    monkeypatch.setattr(settings, "rate_limit_enforce_ip", False)

    caplog.set_level(logging.INFO, logger="audit")

    _post("Hello there.", user_id)
    r = _post("Hello there.", user_id)
    assert r.json()["decision"] == "BLOCK"

    assert any(
        "RATE_LIMIT_EXCEEDED" in record.message for record in caplog.records
    ), "Expected rate-limit audit log entry not found."
