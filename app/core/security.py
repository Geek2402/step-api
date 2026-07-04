import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import bcrypt

from app.core.config import settings


# ---------- Mots de passe ----------
def hash_password(password: str) -> str:
    """Retourne le hash bcrypt d'un mot de passe."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifie qu'un mot de passe correspond à son hash."""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


# ---------- Tokens d'application (secrets aléatoires Python) ----------
def generate_app_token() -> tuple[str, str, str]:
    """Retourne (token_clair, prefix_affichable, token_hash_a_stocker)."""
    raw = secrets.token_urlsafe(settings.APP_TOKEN_BYTES)
    token = f"{settings.APP_TOKEN_PREFIX}{raw}"
    prefix = token[: len(settings.APP_TOKEN_PREFIX) + 8]
    return token, prefix, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---------- OTP ----------
def generate_otp_code() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(settings.OTP_LENGTH))


def hash_otp(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


# ---------- JWT ----------
def _create_jwt(secret: str, subject: str, extra_claims: dict, ttl_minutes: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=ttl_minutes),
        "jti": str(uuid.uuid4()),
        **extra_claims,
    }
    return jwt.encode(payload, secret, algorithm=settings.JWT_ALGORITHM)


def create_user_token(user_id: str, is_admin: bool) -> str:
    return _create_jwt(
        settings.JWT_SECRET_USERS,
        subject=user_id,
        extra_claims={"is_admin": is_admin, "type": "user"},
        ttl_minutes=settings.ACCESS_TOKEN_TTL_MINUTES,
    )


def create_end_user_token(end_user_id: str, app_id: str, email: str) -> str:
    return _create_jwt(
        settings.JWT_SECRET_END_USERS,
        subject=end_user_id,
        extra_claims={"app_id": app_id, "email": email, "type": "end_user"},
        ttl_minutes=settings.ACCESS_TOKEN_TTL_MINUTES,
    )


def decode_token(token: str, secret: str) -> dict:
    return jwt.decode(token, secret, algorithms=[settings.JWT_ALGORITHM])
