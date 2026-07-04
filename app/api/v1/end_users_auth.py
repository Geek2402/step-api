from fastapi import APIRouter, Depends, Header, HTTPException, status
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
from app.core.security import create_end_user_token, hash_password, verify_password
from app.db.session import get_db
from app.models.app import App
from app.models.end_user import EndUser
from app.schemas.auth import LoginRequest, MessageResponse, VerifyOtpRequest
from app.schemas.end_user import EndUserCreate, EndUserRead
from app.schemas.token import EndUserTokenResponse
from app.services.audit_service import log_event
from app.services.otp_service import issue_otp, verify_otp

router = APIRouter(prefix="/end-users/auth", tags=["end-user-auth"])


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
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(EndUser).where(EndUser.app_id == app.id, EndUser.email == payload.email)
    )
    end_user = result.scalar_one_or_none()

    if not end_user or not verify_password(payload.password, end_user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Email ou mot de passe incorrect")
    if not end_user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte désactivé")

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
