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


@router.post("/login", response_model=MessageResponse, summary="Log in with email and password")
async def login(payload: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Starts the login flow for a User (dev/admin account) by verifying email + password.

    On success, no token is issued yet: a one-time verification code (OTP) is emailed to the
    account and must be confirmed via `POST /verify-otp` to obtain a JWT.

    Rate-limited to prevent brute-forcing: 5 failed attempts / 15 min per email, and 20 failed
    attempts / 15 min per source IP (across all emails). Exceeding either returns 429 with a
    `Retry-After` header and logs a `RATE_LIMIT_TRIGGERED` audit event. A disabled account does
    not count against the rate limit.

    Errors:
    - 401 if the email/password combination is incorrect.
    - 403 if the account exists but has been deactivated.
    - 429 if a rate limit has been exceeded.
    """
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


@router.post("/verify-otp", response_model=UserTokenResponse, summary="Verify the login OTP and obtain a JWT")
async def verify_otp_route(payload: VerifyOtpRequest, db: AsyncSession = Depends(get_db)):
    """Completes the login flow: exchanges the emailed one-time code for a User JWT.

    The code must match the one issued by `POST /login` for this email (case-sensitive,
    single-use, expires after `OTP_TTL_SECONDS`). Too many wrong attempts invalidates the
    code and forces a fresh login. On first successful verification the account is marked
    verified. The returned JWT (`JWT_SECRET_USERS`) embeds the admin flag and expires after
    30 minutes by default; there is no refresh token — repeat the full login flow when it expires.

    Errors: 401 if the email is unknown or the code is invalid/expired/wrong.
    """
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


@router.post("/logout", response_model=MessageResponse, summary="Log out and revoke the current JWT")
async def logout(authorization: str | None = Header(default=None), db: AsyncSession = Depends(get_db)):
    """Invalidates the JWT passed in the `Authorization: Bearer <token>` header.

    The token's `jti` is added to a Redis blacklist until its natural expiry, so it can never
    be reused even though JWTs are otherwise stateless. Since there is no refresh token, logging
    back in requires the full email/password + OTP flow again.

    Errors: 401 if the header is missing/malformed, the token is invalid/expired, or it has
    already been revoked.
    """
    token = extract_bearer_token(authorization)
    payload = await decode_and_check_blacklist(token, settings.JWT_SECRET_USERS)
    await blacklist_token(payload)
    await log_event(db, ActorType.USER, AuditEventType.USER_LOGOUT, actor_id=uuid.UUID(payload["sub"]))
    return MessageResponse(message="Logged out")


@router.post("/forgot-password", response_model=MessageResponse, summary="Request a password reset link by email")
async def forgot_password(payload: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    """Sends a password reset link to the given email, if a matching active account exists.

    Always returns the same generic success message regardless of whether the email exists,
    is unverified, or is disabled — this is intentional to prevent account enumeration. The
    reset link/token is only actually generated and emailed when the account exists and is
    active, and is valid for a limited time (see `RESET_TOKEN_TTL_SECONDS`).

    Errors: 503 if the email fails to send (account state is otherwise never leaked via errors).
    """
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


@router.post("/reset-password", response_model=MessageResponse, summary="Reset the password using a reset token")
async def reset_password(payload: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    """Sets a new password using the token obtained from `POST /forgot-password`.

    The reset token is single-use: it is deleted as soon as it is successfully consumed, so
    the same link cannot be replayed. Does not require being logged in.

    Errors: 400 if the email is unknown or the token is invalid/expired/already used.
    """
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
