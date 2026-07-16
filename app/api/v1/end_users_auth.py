import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import (
    blacklist_token,
    decode_and_check_blacklist,
    extract_bearer_token,
    get_current_app,
)
from app.core.email_client import send_reset_password_email
from app.core.exceptions import EmailDeliveryError
from app.core.rate_limiter import RateLimiter, get_client_ip
from app.core.security import create_end_user_token, hash_password, verify_password
from app.db.session import get_db
from app.models.app import App
from app.models.end_user import EndUser
from app.models.enums import ActorType, AuditEventType
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    ResetPasswordRequest,
    VerifyOtpRequest,
)
from app.schemas.token import EndUserTokenResponse
from app.services.audit_service import log_event
from app.services.otp_service import issue_otp, verify_otp
from app.services.password_reset_service import (
    RESET_TOKEN_TTL_SECONDS,
    build_reset_link,
    create_reset_token,
    delete_reset_token,
    verify_reset_token,
)

router = APIRouter(prefix="/end-users/auth", tags=["end-user-auth"])

login_ip_limiter = RateLimiter("login_ip_enduser", max_attempts=20, window_seconds=900)
login_email_limiter = RateLimiter("login_email_enduser", max_attempts=5, window_seconds=900)


@router.post("/login", response_model=MessageResponse, summary="Log in an EndUser with email and password")
async def login(
    payload: LoginRequest,
    request: Request,
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
):
    """Starts the login flow for an EndUser of the calling App, by verifying email + password.

    Requires the `X-App-Token` header identifying the App; the email is looked up scoped to
    that App only (the same email can belong to a different EndUser in another App). On
    success, no token is issued yet: a one-time verification code (OTP) is emailed to the
    EndUser and must be confirmed via `POST /verify-otp` to obtain a JWT.

    Rate-limited per App to prevent brute-forcing: 5 failed attempts / 15 min per email, and
    20 failed attempts / 15 min per source IP (both scoped to this App, so activity on one
    App never affects another). Exceeding either returns 429 with a `Retry-After` header and
    logs a `RATE_LIMIT_TRIGGERED` audit event. A disabled account does not count against the
    rate limit.

    Errors:
    - 401 if the `X-App-Token` header is missing/invalid, or the email/password combination
      is incorrect.
    - 403 if the account exists but has been deactivated.
    - 429 if a rate limit has been exceeded.
    """
    client_ip = get_client_ip(request)
    # Composite key app_id + email: the same email can exist across
    # several apps, their counters must not be mixed.
    email_key = f"{app.id}:{payload.email.lower()}"
    ip_key = f"{app.id}:{client_ip}"

    try:
        await login_ip_limiter.check(ip_key)
        await login_email_limiter.check(email_key)
    except HTTPException:
        await log_event(
            db, ActorType.END_USER, AuditEventType.RATE_LIMIT_TRIGGERED, app_id=app.id,
            metadata={"email": payload.email, "ip": client_ip},
        )
        raise

    result = await db.execute(
        select(EndUser).where(EndUser.app_id == app.id, EndUser.email == payload.email)
    )
    end_user = result.scalar_one_or_none()

    if not end_user or not verify_password(payload.password, end_user.password_hash):
        await login_ip_limiter.register_failure(ip_key)
        await login_email_limiter.register_failure(email_key)
        await log_event(
            db, ActorType.END_USER, AuditEventType.END_USER_LOGIN_FAILED,
            actor_id=end_user.id if end_user else None, app_id=app.id,
            metadata={"email": payload.email, "reason": "invalid_credentials"},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    if not end_user.is_active:
        await log_event(
            db, ActorType.END_USER, AuditEventType.END_USER_LOGIN_FAILED, actor_id=end_user.id, app_id=app.id,
            metadata={"email": payload.email, "reason": "inactive_account"},
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account disabled")

    await login_ip_limiter.reset(ip_key)
    await login_email_limiter.reset(email_key)

    await issue_otp("end_user", str(end_user.id), end_user.email, purpose="login_mfa")
    await log_event(db, ActorType.END_USER, AuditEventType.END_USER_OTP_REQUESTED, actor_id=end_user.id, app_id=app.id)
    return MessageResponse(message="Verification code sent by email")


@router.post(
    "/verify-otp", response_model=EndUserTokenResponse, summary="Verify the login OTP and obtain a JWT"
)
async def verify_otp_route(
    payload: VerifyOtpRequest,
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
):
    """Completes the login flow: exchanges the emailed one-time code for an EndUser JWT.

    Requires the `X-App-Token` header. The code must match the one issued by `POST /login`
    for this email within this App (single-use, expires after `OTP_TTL_SECONDS`). Too many
    wrong attempts invalidates the code and forces a fresh login. On first successful
    verification the account is marked verified. The returned JWT is bound to this specific
    App (it will be rejected by any other App's routes) and expires after 30 minutes by
    default; there is no refresh token — repeat the full login flow when it expires.

    Errors: 401 if the `X-App-Token` header is missing/invalid, the email is unknown, or the
    code is invalid/expired/wrong.
    """
    result = await db.execute(
        select(EndUser).where(EndUser.app_id == app.id, EndUser.email == payload.email)
    )
    end_user = result.scalar_one_or_none()
    if not end_user:
        await log_event(
            db, ActorType.END_USER, AuditEventType.END_USER_OTP_VERIFY_FAILED, app_id=app.id,
            metadata={"email": payload.email, "reason": "unknown_email"},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or code")

    ok = await verify_otp("end_user", str(end_user.id), payload.code, purpose="login_mfa")
    if not ok:
        await log_event(
            db, ActorType.END_USER, AuditEventType.END_USER_OTP_VERIFY_FAILED, actor_id=end_user.id, app_id=app.id,
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired code")

    if not end_user.is_verified:
        end_user.is_verified = True
        await db.commit()
        await db.refresh(end_user)

    token = create_end_user_token(str(end_user.id), str(app.id), end_user.email)
    await log_event(db, ActorType.END_USER, AuditEventType.END_USER_LOGIN_SUCCESS, actor_id=end_user.id, app_id=app.id)
    return EndUserTokenResponse(access_token=token, email=end_user.email, end_user=end_user)


@router.post("/logout", response_model=MessageResponse, summary="Log out and revoke the current JWT")
async def logout(
    authorization: str | None = Header(default=None),
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
):
    """Invalidates the EndUser JWT passed in the `Authorization: Bearer <token>` header.

    Requires the `X-App-Token` header. The token's `jti` is added to a Redis blacklist until
    its natural expiry, so it can never be reused even though JWTs are otherwise stateless.
    Since there is no refresh token, logging back in requires the full email/password + OTP
    flow again.

    Errors: 401 if the `X-App-Token` header or the `Authorization` header is
    missing/malformed, the token is invalid/expired, or it has already been revoked.
    """
    token = extract_bearer_token(authorization)
    payload = await decode_and_check_blacklist(token, settings.JWT_SECRET_END_USERS)
    await blacklist_token(payload)
    await log_event(
        db, ActorType.END_USER, AuditEventType.END_USER_LOGOUT, actor_id=uuid.UUID(payload["sub"]), app_id=app.id,
    )
    return MessageResponse(message="Logged out")


@router.post(
    "/forgot-password", response_model=MessageResponse, summary="Request a password reset link by email"
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
):
    """Sends a password reset link to the given email, if a matching active EndUser exists
    for this App.

    Requires the `X-App-Token` header. Always returns the same generic success message
    regardless of whether the email exists, is unverified, or is disabled — this is
    intentional to prevent account enumeration. The reset link/token is only actually
    generated and emailed when the account exists and is active, and is valid for a limited
    time (see `RESET_TOKEN_TTL_SECONDS`). If the App has a `frontend_url` configured, the
    link points there; otherwise the raw token is returned for the App's backend to embed
    itself.

    Errors: 401 if the `X-App-Token` header is missing/invalid; 503 if the email fails to
    send (account state is otherwise never leaked via errors).
    """
    result = await db.execute(
        select(EndUser).where(EndUser.app_id == app.id, EndUser.email == payload.email)
    )
    end_user = result.scalar_one_or_none()

    if end_user and end_user.is_active:
        identifier = f"{app.id}:{end_user.email}"
        token = await create_reset_token("end_user", identifier)
        reset_value = (
            build_reset_link(app.frontend_url, end_user.email, token)
            if app.frontend_url
            else token
        )
        try:
            await send_reset_password_email(end_user.email, reset_value, RESET_TOKEN_TTL_SECONDS // 60)
        except Exception as exc:
            raise EmailDeliveryError() from exc
        await log_event(
            db, ActorType.END_USER, AuditEventType.END_USER_PASSWORD_RESET_REQUESTED,
            actor_id=end_user.id, app_id=app.id,
        )

    return MessageResponse(message="If this email exists, a reset link has been sent")


@router.post(
    "/reset-password", response_model=MessageResponse, summary="Reset the password using a reset token"
)
async def reset_password(
    payload: ResetPasswordRequest,
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
):
    """Sets a new password for an EndUser using the token obtained from `POST /forgot-password`.

    Requires the `X-App-Token` header; does not require being logged in. The reset token is
    single-use: it is deleted as soon as it is successfully consumed, so the same link cannot
    be replayed.

    Errors: 401 if the `X-App-Token` header is missing/invalid; 400 if the email is unknown
    (for this App) or the token is invalid/expired/already used.
    """
    result = await db.execute(
        select(EndUser).where(EndUser.app_id == app.id, EndUser.email == payload.email)
    )
    end_user = result.scalar_one_or_none()
    identifier = f"{app.id}:{payload.email}"

    if not end_user or not await verify_reset_token("end_user", identifier, payload.token):
        await log_event(
            db, ActorType.END_USER, AuditEventType.END_USER_PASSWORD_RESET_FAILED,
            actor_id=end_user.id if end_user else None, app_id=app.id,
            metadata={"email": payload.email},
        )
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired reset link")

    end_user.password_hash = hash_password(payload.new_password)
    await db.commit()
    await delete_reset_token("end_user", identifier)
    await log_event(
        db, ActorType.END_USER, AuditEventType.END_USER_PASSWORD_RESET_COMPLETED,
        actor_id=end_user.id, app_id=app.id,
    )
    return MessageResponse(message="Password updated successfully")
