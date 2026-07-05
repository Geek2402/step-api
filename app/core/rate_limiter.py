from fastapi import HTTPException, Request, status

from app.core.redis_client import redis_client


def get_client_ip(request: Request) -> str:
    """Retrieves the client's real IP even behind a reverse proxy
    (Nginx, Coolify, Dokku...). X-Forwarded-For may contain a list
    IP1, IP2, ... — the first one is the originating client's."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimiter:
    """Generic fixed-window limiter backed by a Redis counter.

    Usage:
        limiter = RateLimiter("login_email", max_attempts=5, window_seconds=900)
        await limiter.check(identifier)          # raises 429 if exceeded
        await limiter.register_failure(identifier)  # call on failure
        await limiter.reset(identifier)              # call on success
    """

    def __init__(self, key_prefix: str, max_attempts: int, window_seconds: int):
        self.key_prefix = key_prefix
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds

    def _key(self, identifier: str) -> str:
        return f"ratelimit:{self.key_prefix}:{identifier}"

    async def check(self, identifier: str) -> None:
        key = self._key(identifier)
        current = await redis_client.get(key)
        current = int(current) if current else 0

        if current >= self.max_attempts:
            ttl = await redis_client.ttl(key)
            retry_after = ttl if ttl and ttl > 0 else self.window_seconds
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many attempts. Please try again in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)},
            )

    async def register_failure(self, identifier: str) -> None:
        key = self._key(identifier)
        new_count = await redis_client.incr(key)
        if new_count == 1:
            await redis_client.expire(key, self.window_seconds)

    async def reset(self, identifier: str) -> None:
        await redis_client.delete(self._key(identifier))
