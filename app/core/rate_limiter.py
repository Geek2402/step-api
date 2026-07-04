from fastapi import HTTPException, Request, status

from app.core.redis_client import redis_client


def get_client_ip(request: Request) -> str:
    """Récupère l'IP réelle du client même derrière un reverse proxy
    (Nginx, Coolify, Dokku...). X-Forwarded-For peut contenir une liste
    IP1, IP2, ... — la première est celle du client d'origine."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimiter:
    """Limiteur générique à fenêtre fixe, basé sur un compteur Redis.

    Usage :
        limiter = RateLimiter("login_email", max_attempts=5, window_seconds=900)
        await limiter.check(identifier)          # lève 429 si dépassé
        await limiter.register_failure(identifier)  # à appeler sur échec
        await limiter.reset(identifier)              # à appeler sur succès
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
                detail=f"Trop de tentatives. Réessayez dans {retry_after} secondes.",
                headers={"Retry-After": str(retry_after)},
            )

    async def register_failure(self, identifier: str) -> None:
        key = self._key(identifier)
        new_count = await redis_client.incr(key)
        if new_count == 1:
            await redis_client.expire(key, self.window_seconds)

    async def reset(self, identifier: str) -> None:
        await redis_client.delete(self._key(identifier))
