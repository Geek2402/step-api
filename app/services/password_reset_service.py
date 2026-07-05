import secrets
from urllib.parse import quote

from app.core.redis_client import redis_client

RESET_TOKEN_TTL_SECONDS = 15 * 60


def _key(actor_type: str, identifier: str) -> str:
    return f"pwd_reset:{actor_type}:{identifier}"


async def create_reset_token(actor_type: str, identifier: str) -> str:
    """Generates a single-use reset token and stores it in Redis (15 min TTL)."""
    token = secrets.token_urlsafe(32)
    await redis_client.set(_key(actor_type, identifier), token, ex=RESET_TOKEN_TTL_SECONDS)
    return token


async def verify_reset_token(actor_type: str, identifier: str, token: str) -> bool:
    stored = await redis_client.get(_key(actor_type, identifier))
    return stored is not None and stored == token


async def delete_reset_token(actor_type: str, identifier: str) -> None:
    await redis_client.delete(_key(actor_type, identifier))


def build_reset_link(base_url: str, email: str, token: str) -> str:
    return f"{base_url}?email={quote(email)}&token={token}"
