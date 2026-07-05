from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import (
    blacklist_token,
    decode_and_check_blacklist,
    extract_bearer_token,
)
from app.core.config import settings
from app.core.email_client import send_reset_password_email
from app.core.exceptions import EmailDeliveryError
from app.core.rate_limiter import RateLimiter, get_client_ip
from app.core.security import create_user_token, hash_password, verify_password
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    ResetPasswordRequest,
    VerifyOtpRequest,
)
from app.schemas.token import UserTokenResponse
from app.services.audit_service import log_event
from app.services.otp_service import issue_otp, verify_otp
from app.services.password_reset_service import (
    RESET_TOKEN_TTL_SECONDS,
    build_reset_link,
    create_reset_token,
    delete_reset_token,
    verify_reset_token,
)

router = APIRouter(prefix="/users/auth", tags=["user-auth"])

login_ip_limiter = RateLimiter("login_ip_user", max_attempts=20, window_seconds=900)
login_email_limiter = RateLimiter("login_email_user", max_attempts=5, window_seconds=900)


@router.post("/login", response_model=MessageResponse)
async def login(payload: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = get_client_ip(request)
    email_key = payload.email.lower()

    await login_ip_limiter.check(client_ip)
    await login_email_limiter.check(email_key)

    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.password_hash):
        await login_ip_limiter.register_failure(client_ip)
        await login_email_limiter.register_failure(email_key)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Email ou mot de passe incorrect")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte désactivé")

    await login_ip_limiter.reset(client_ip)
    await login_email_limiter.reset(email_key)

    await issue_otp("user", str(user.id), user.email, purpose="login_mfa")
    await log_event(db, "user", "otp_requested", actor_id=user.id)
    return MessageResponse(message="Code de vérification envoyé par email")


@router.post("/verify-otp", response_model=UserTokenResponse)
async def verify_otp_route(payload: VerifyOtpRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Email ou code invalide")

    ok = await verify_otp("user", str(user.id), payload.code, purpose="login_mfa")
    if not ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Code invalide ou expiré")

    if not user.is_verified:
        user.is_verified = True
        await db.commit()
        await db.refresh(user)

    token = create_user_token(str(user.id), user.is_admin)
    await log_event(db, "user", "login_success", actor_id=user.id)
    return UserTokenResponse(access_token=token, user=user)


@router.post("/logout", response_model=MessageResponse)
async def logout(authorization: str | None = Header(default=None)):
    token = extract_bearer_token(authorization)
    payload = await decode_and_check_blacklist(token, settings.JWT_SECRET_USERS)
    await blacklist_token(payload)
    return MessageResponse(message="Déconnecté")


@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(payload: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if user and user.is_active:
        token = await create_reset_token("user", user.email)
        reset_value = (
            build_reset_link(settings.FRONTEND_URL, user.email, token)
            if settings.FRONTEND_URL
            else token
        )
        try:
            await send_reset_password_email(user.email, reset_value, RESET_TOKEN_TTL_SECONDS // 60)
        except Exception as exc:
            raise EmailDeliveryError() from exc
        await log_event(db, "user", "password_reset_requested", actor_id=user.id)

    return MessageResponse(message="Si cet email existe, un lien de réinitialisation a été envoyé")


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(payload: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not await verify_reset_token("user", user.email, payload.token):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Lien de réinitialisation invalide ou expiré")

    user.password_hash = hash_password(payload.new_password)
    await db.commit()
    await delete_reset_token("user", user.email)
    await log_event(db, "user", "password_reset_completed", actor_id=user.id)
    return MessageResponse(message="Mot de passe mis à jour avec succès")

