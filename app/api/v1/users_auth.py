from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import (
    blacklist_token,
    decode_and_check_blacklist,
    extract_bearer_token,
    get_current_user,
)
from app.core.config import settings
from app.core.rate_limiter import RateLimiter, get_client_ip
from app.core.security import create_user_token, hash_password, verify_password
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, MessageResponse, VerifyOtpRequest
from app.schemas.token import UserTokenResponse
from app.schemas.user import UserCreate, UserRead
from app.services.audit_service import log_event
from app.services.otp_service import issue_otp, verify_otp

router = APIRouter(prefix="/users/auth", tags=["user-auth"])

login_ip_limiter = RateLimiter("login_ip_user", max_attempts=20, window_seconds=900)
login_email_limiter = RateLimiter("login_email_user", max_attempts=5, window_seconds=900)


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Un compte existe déjà avec cet email")

    user = User(
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=payload.email,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    await log_event(db, "user", "user_registered", actor_id=user.id)
    return user


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


@router.get("/me", response_model=UserRead)
async def me(user: User = Depends(get_current_user)):
    return user
