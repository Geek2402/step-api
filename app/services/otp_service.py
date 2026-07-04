from app.core.config import settings
from app.core.email_client import send_otp_email
from app.core.exceptions import EmailDeliveryError
from app.core.redis_client import redis_client
from app.core.security import generate_otp_code, hash_otp


def _otp_key(actor_type: str, actor_id: str, purpose: str) -> str:
    return f"otp:{actor_type}:{actor_id}:{purpose}"


def _attempts_key(actor_type: str, actor_id: str, purpose: str) -> str:
    return f"otp_attempts:{actor_type}:{actor_id}:{purpose}"


async def issue_otp(actor_type: str, actor_id: str, email: str, purpose: str = "login_mfa") -> None:
    code = generate_otp_code()
    key = _otp_key(actor_type, actor_id, purpose)
    await redis_client.set(key, hash_otp(code), ex=settings.OTP_TTL_SECONDS)
    await redis_client.delete(_attempts_key(actor_type, actor_id, purpose))

    try:
        await send_otp_email(email, code, purpose)
    except Exception as exc:
        # L'OTP est déjà en Redis (TTL le nettoiera de toute façon) ; on informe
        # proprement l'appelant plutôt que de laisser fuiter une exception SMTP brute.
        raise EmailDeliveryError() from exc


async def verify_otp(actor_type: str, actor_id: str, code: str, purpose: str = "login_mfa") -> bool:
    key = _otp_key(actor_type, actor_id, purpose)
    attempts_key = _attempts_key(actor_type, actor_id, purpose)

    stored_hash = await redis_client.get(key)
    if stored_hash is None:
        return False

    attempts = int(await redis_client.get(attempts_key) or 0)
    if attempts >= settings.OTP_MAX_ATTEMPTS:
        await redis_client.delete(key, attempts_key)
        return False

    if hash_otp(code) != stored_hash:
        await redis_client.incr(attempts_key)
        await redis_client.expire(attempts_key, settings.OTP_TTL_SECONDS)
        return False

    await redis_client.delete(key, attempts_key)
    return True
