import hashlib


async def resolve_otp(redis, actor_type: str, actor_id: str, purpose: str = "login_mfa") -> str:
    """Reads otp:{actor_type}:{actor_id}:{purpose} (SHA-256 hash, set by app.services.otp_service)
    from Redis and recovers the plaintext 6-digit code by brute force over the 10**6 space.

    This is purely an offline comparison against a hash already sitting in the same Redis
    instance the script has direct, authorized access to (via REDIS_URL from .env) — it never
    calls /verify-otp during the search, so it does not consume any of the API's own
    OTP_MAX_ATTEMPTS budget."""
    key = f"otp:{actor_type}:{actor_id}:{purpose}"
    stored_hash = await redis.get(key)
    if stored_hash is None:
        raise RuntimeError(f"No OTP pending for {key} — was /login called first?")

    for n in range(1_000_000):
        code = f"{n:06d}"
        if hashlib.sha256(code.encode()).hexdigest() == stored_hash:
            return code
    raise RuntimeError(f"Could not recover OTP for {key} within the 10**6 search space")


async def resolve_reset_token(redis, actor_type: str, identifier: str) -> str:
    """pwd_reset:{actor_type}:{identifier} is stored in PLAINTEXT by
    app.services.password_reset_service — just read it back, no brute force needed."""
    key = f"pwd_reset:{actor_type}:{identifier}"
    token = await redis.get(key)
    if token is None:
        raise RuntimeError(f"No pending reset token for {key} — was /forgot-password called first?")
    return token
