import uuid

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
from app.models.enums import ActorType, AuditEventType
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

    try:
        await login_ip_limiter.check(client_ip)
        await login_email_limiter.check(email_key)
    except HTTPException:
        await log_event(
            db, ActorType.USER, AuditEventType.RATE_LIMIT_TRIGGERED,
            metadata={"email": payload.email, "ip": client_ip},
        )
        raise

    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.password_hash):
        await login_ip_limiter.register_failure(client_ip)
        await login_email_limiter.register_failure(email_key)
        await log_event(
            db, ActorType.USER, AuditEventType.USER_LOGIN_FAILED,
            actor_id=user.id if user else None,
            metadata={"email": payload.email, "reason": "invalid_credentials"},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    if not user.is_active:
        await log_event(
            db, ActorType.USER, AuditEventType.USER_LOGIN_FAILED, actor_id=user.id,
            metadata={"email": payload.email, "reason": "inactive_account"},
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account disabled")

    await login_ip_limiter.reset(client_ip)
    await login_email_limiter.reset(email_key)

    await issue_otp("user", str(user.id), user.email, purpose="login_mfa")
    await log_event(db, ActorType.USER, AuditEventType.USER_OTP_REQUESTED, actor_id=user.id)
    return MessageResponse(message="Verification code sent by email")


@router.post("/verify-otp", response_model=UserTokenResponse)
async def verify_otp_route(payload: VerifyOtpRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user:
        await log_event(
            db, ActorType.USER, AuditEventType.USER_OTP_VERIFY_FAILED,
            metadata={"email": payload.email, "reason": "unknown_email"},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or code")

    ok = await verify_otp("user", str(user.id), payload.code, purpose="login_mfa")
    if not ok:
        await log_event(db, ActorType.USER, AuditEventType.USER_OTP_VERIFY_FAILED, actor_id=user.id)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired code")

    if not user.is_verified:
        user.is_verified = True
        await db.commit()
        await db.refresh(user)

    token = create_user_token(str(user.id), user.is_admin)
    await log_event(db, ActorType.USER, AuditEventType.USER_LOGIN_SUCCESS, actor_id=user.id)
    return UserTokenResponse(access_token=token, user=user)


@router.post("/logout", response_model=MessageResponse)
async def logout(authorization: str | None = Header(default=None), db: AsyncSession = Depends(get_db)):
    token = extract_bearer_token(authorization)
    payload = await decode_and_check_blacklist(token, settings.JWT_SECRET_USERS)
    await blacklist_token(payload)
    await log_event(db, ActorType.USER, AuditEventType.USER_LOGOUT, actor_id=uuid.UUID(payload["sub"]))
    return MessageResponse(message="Logged out")


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
        await log_event(db, ActorType.USER, AuditEventType.USER_PASSWORD_RESET_REQUESTED, actor_id=user.id)

    return MessageResponse(message="If this email exists, a reset link has been sent")


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(payload: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not await verify_reset_token("user", user.email, payload.token):
        await log_event(
            db, ActorType.USER, AuditEventType.USER_PASSWORD_RESET_FAILED,
            actor_id=user.id if user else None,
            metadata={"email": payload.email},
        )
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired reset link")

    user.password_hash = hash_password(payload.new_password)
    await db.commit()
    await delete_reset_token("user", user.email)
    await log_event(db, ActorType.USER, AuditEventType.USER_PASSWORD_RESET_COMPLETED, actor_id=user.id)
    return MessageResponse(message="Password updated successfully")
