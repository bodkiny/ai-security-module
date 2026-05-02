from __future__ import annotations

from dataclasses import dataclass
from time import time
from uuid import uuid4

from redis import Redis
from redis.exceptions import RedisError

from app.core.config import settings


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after_s: int | None
    reason: str | None


class RateLimiter:
    def __init__(self, redis: Redis):
        self.redis = redis

    def check(self, user_id: str, ip: str | None) -> RateLimitResult:
        try:
            return self._check_limits(user_id, ip)
        except RedisError:
            if settings.rate_limit_fail_open:
                return RateLimitResult(
                    allowed=True, retry_after_s=None, reason="RATE_LIMIT_UNAVAILABLE"
                )
            return RateLimitResult(
                allowed=False, retry_after_s=None, reason="RATE_LIMIT_UNAVAILABLE"
            )

    def _check_limits(self, user_id: str, ip: str | None) -> RateLimitResult:
        now = time()

        if user_id:
            window = self._hit(
                f"rl:window:{user_id}",
                settings.rate_limit_window_s,
                settings.rate_limit_requests,
                now,
            )
            if not window.allowed:
                return window

            burst = self._hit(
                f"rl:burst:{user_id}",
                settings.rate_limit_burst_window_s,
                settings.rate_limit_burst_requests,
                now,
            )
            if not burst.allowed:
                return burst

        enforce_ip = settings.rate_limit_enforce_ip or not user_id
        if enforce_ip and ip:
            ip_window = self._hit(
                f"rl:window_ip:{ip}",
                settings.rate_limit_window_s,
                settings.rate_limit_requests,
                now,
            )
            if not ip_window.allowed:
                return ip_window

            ip_burst = self._hit(
                f"rl:burst_ip:{ip}",
                settings.rate_limit_burst_window_s,
                settings.rate_limit_burst_requests,
                now,
            )
            if not ip_burst.allowed:
                return ip_burst

        return RateLimitResult(allowed=True, retry_after_s=None, reason=None)

    def _hit(
        self, key: str, window_s: int, limit: int, now: float
    ) -> RateLimitResult:
        pipe = self.redis.pipeline()
        member = f"{now}:{uuid4().hex}"
        pipe.zadd(key, {member: now})
        pipe.zremrangebyscore(key, 0, now - window_s)
        pipe.zcard(key)
        pipe.expire(key, window_s)
        _, _, count, _ = pipe.execute()

        if count > limit:
            oldest = self.redis.zrange(key, 0, 0, withscores=True)
            retry_after = 1
            if oldest:
                retry_after = max(1, int(window_s - (now - oldest[0][1])))
            return RateLimitResult(
                allowed=False, retry_after_s=retry_after, reason="RATE_LIMIT_EXCEEDED"
            )

        return RateLimitResult(allowed=True, retry_after_s=None, reason=None)


def get_redis() -> Redis:
    return Redis.from_url(settings.redis_url, decode_responses=True)
