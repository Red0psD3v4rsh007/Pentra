"""Per-tenant rate limiting middleware using Redis.

Enforces a sliding-window rate limit per tenant, based on the
``request.state.tenant_id`` populated by the auth middleware.

Rate limits are configurable per tier (W-17 from MOD-01.5):
  - Free:       60 req/min
  - Pro:        300 req/min
  - Enterprise: 1000 req/min

Unauthenticated requests use a per-IP fallback limit.
"""

from __future__ import annotations

import logging
import time

import redis.asyncio as aioredis
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from pentra_common.config.settings import get_settings

logger = logging.getLogger(__name__)

# Tier-based limits (requests per minute)
_TIER_LIMITS: dict[str, int] = {
    "free": 60,
    "pro": 300,
    "enterprise": 1000,
}
_UNAUTHENTICATED_LIMIT = 30  # per-IP fallback
_WINDOW_SECONDS = 60
_LOCAL_DEV_HOSTS = {"127.0.0.1", "::1", "localhost"}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter backed by Redis INCR + EXPIRE."""

    def __init__(self, app, **kwargs):
        super().__init__(app, **kwargs)
        settings = get_settings()
        self._redis: aioredis.Redis | None = None
        self._redis_url = settings.redis_url
        self._app_env = settings.app_env
        self._allow_local_dev_bypass = settings.allow_local_dev_rate_limit_bypass

    async def _get_redis(self) -> aioredis.Redis:
        """Lazy-initialise the Redis connection."""
        if self._redis is None:
            self._redis = aioredis.from_url(
                self._redis_url, decode_responses=True
            )
        return self._redis

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip rate limiting for health probes
        if request.url.path in ("/health", "/ready"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        origin = request.headers.get("origin", "")
        if self._is_local_dev_request(client_ip=client_ip, origin=origin):
            return await call_next(request)

        # Determine rate limit key and threshold
        user = getattr(request.state, "user", None)
        if user is not None:
            key = f"pentra:ratelimit:tenant:{user.tenant_id}"
            tier = getattr(user, "tier", "free")
            limit = _TIER_LIMITS.get(tier, _UNAUTHENTICATED_LIMIT)
        else:
            key = f"pentra:ratelimit:ip:{client_ip}"
            limit = _UNAUTHENTICATED_LIMIT

        # Check rate limit
        try:
            r = await self._get_redis()
            current = await r.incr(key)
            if current == 1:
                # First request in window — set expiry
                await r.expire(key, _WINDOW_SECONDS)

            ttl = await r.ttl(key)
        except Exception:
            # Redis unavailable — fail open (allow request)
            logger.warning("Rate limiter Redis unavailable — failing open")
            return await call_next(request)

        # Set rate limit headers on all responses
        response: Response
        if current > limit:
            logger.warning(
                "Rate limit exceeded: key=%s current=%d limit=%d",
                key, current, limit,
            )
            response = JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": ttl,
                },
            )
        else:
            response = await call_next(request)

        # Standard rate limit headers (RFC 6585 / draft-ietf-httpapi-ratelimit-headers)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - current))
        response.headers["X-RateLimit-Reset"] = str(ttl if ttl > 0 else _WINDOW_SECONDS)

        return response

    def _is_local_dev_request(self, *, client_ip: str, origin: str) -> bool:
        if self._app_env != "development" or not self._allow_local_dev_bypass:
            return False

        if client_ip in _LOCAL_DEV_HOSTS:
            return True

        return origin.startswith("http://localhost:") or origin.startswith(
            "http://127.0.0.1:"
        )
