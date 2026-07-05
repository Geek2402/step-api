from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import (
    blacklist_token,
    decode_and_check_blacklist,
    extract_bearer_token,
    get_current_app,
    get_current_end_user,
)
from app.core.email_client import send_reset_password_email
from app.core.exceptions import EmailDeliveryError
from app.core.rate_limiter import RateLimiter, get_client_ip
from app.core.security import create_end_user_token, hash_password, verify_password
from app.db.session import get_db
from app.models.app import App
from app.models.end_user import EndUser
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    ResetPasswordRequest,
    VerifyOtpRequest,
)
from app.schemas.end_user import EndUserCreate, EndUserRead
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


@router.post("/register", response_model=EndUserRead, status_code=status.HTTP_201_CREATED)
async def register(
    payload: EndUserCreate,
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
):
    existing = await db.execute(
        select(EndUser).where(EndUser.app_id == app.id, EndUser.email == payload.email)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Un utilisateur existe déjà avec cet email pour cette application"
        )

    end_user = EndUser(
        app_id=app.id,
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=payload.email,
        password_hash=hash_password(payload.password),
    )
    db.add(end_user)
    await db.commit()
    await db.refresh(end_user)
    await log_event(db, "end_user", "end_user_registered", actor_id=end_user.id, app_id=app.id)
    return end_user


@router.post("/login", response_model=MessageResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
):
    client_ip = get_client_ip(request)
    # Clé composite app_id + email : un même email peut exister sur
    # plusieurs apps, il ne faut pas mélanger leurs compteurs.
    email_key = f"{app.id}:{payload.email.lower()}"
    ip_key = f"{app.id}:{client_ip}"

    await login_ip_limiter.check(ip_key)
    await login_email_limiter.check(email_key)

    result = await db.execute(
        select(EndUser).where(EndUser.app_id == app.id, EndUser.email == payload.email)
    )
    end_user = result.scalar_one_or_none()

    if not end_user or not verify_password(payload.password, end_user.password_hash):
        await login_ip_limiter.register_failure(ip_key)
        await login_email_limiter.register_failure(email_key)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Email ou mot de passe incorrect")
    if not end_user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte désactivé")

    await login_ip_limiter.reset(ip_key)
    await login_email_limiter.reset(email_key)

    await issue_otp("end_user", str(end_user.id), end_user.email, purpose="login_mfa")
    await log_event(db, "end_user", "otp_requested", actor_id=end_user.id, app_id=app.id)
    return MessageResponse(message="Code de vérification envoyé par email")


@router.post("/verify-otp", response_model=EndUserTokenResponse)
async def verify_otp_route(
    payload: VerifyOtpRequest,
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(EndUser).where(EndUser.app_id == app.id, EndUser.email == payload.email)
    )
    end_user = result.scalar_one_or_none()
    if not end_user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Email ou code invalide")

    ok = await verify_otp("end_user", str(end_user.id), payload.code, purpose="login_mfa")
    if not ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Code invalide ou expiré")

    if not end_user.is_verified:
        end_user.is_verified = True
        await db.commit()
        await db.refresh(end_user)

    token = create_end_user_token(str(end_user.id), str(app.id), end_user.email)
    await log_event(db, "end_user", "login_success", actor_id=end_user.id, app_id=app.id)
    return EndUserTokenResponse(access_token=token, email=end_user.email, end_user=end_user)


@router.post("/logout", response_model=MessageResponse)
async def logout(
    authorization: str | None = Header(default=None),
    app: App = Depends(get_current_app),
):
    token = extract_bearer_token(authorization)
    payload = await decode_and_check_blacklist(token, settings.JWT_SECRET_END_USERS)
    await blacklist_token(payload)
    return MessageResponse(message="Déconnecté")


@router.get("/me", response_model=EndUserRead)
async def me(end_user: EndUser = Depends(get_current_end_user)):
    return end_user


@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(
    payload: ForgotPasswordRequest,
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
):
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
        await log_event(db, "end_user", "password_reset_requested", actor_id=end_user.id, app_id=app.id)

    return MessageResponse(message="Si cet email existe, un lien de réinitialisation a été envoyé")


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
    payload: ResetPasswordRequest,
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(EndUser).where(EndUser.app_id == app.id, EndUser.email == payload.email)
    )
    end_user = result.scalar_one_or_none()
    identifier = f"{app.id}:{payload.email}"

    if not end_user or not await verify_reset_token("end_user", identifier, payload.token):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Lien de réinitialisation invalide ou expiré")

    end_user.password_hash = hash_password(payload.new_password)
    await db.commit()
    await delete_reset_token("end_user", identifier)
    await log_event(db, "end_user", "password_reset_completed", actor_id=end_user.id, app_id=app.id)
    return MessageResponse(message="Mot de passe mis à jour avec succès")
