import time
import uuid

import jwt
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.redis_client import redis_client
from app.core.security import decode_token, hash_token
from app.db.session import get_db
from app.models.app import App
from app.models.end_user import EndUser
from app.models.enums import ActorType, AuditEventType
from app.models.user import User
from app.services.audit_service import log_event


def extract_bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Header Authorization manquant ou invalide")
    return authorization.split(" ", 1)[1]


async def decode_and_check_blacklist(token: str, secret: str) -> dict:
    try:
        payload = decode_token(token, secret)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token invalide ou expiré")

    if await redis_client.get(f"blacklist:{payload['jti']}"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token révoqué")

    return payload


async def blacklist_token(payload: dict) -> None:
    ttl = max(int(payload["exp"] - time.time()), 0)
    await redis_client.set(f"blacklist:{payload['jti']}", "1", ex=ttl)


# ---------- User (dev / admin) ----------
async def get_current_user(
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> User:
    token = extract_bearer_token(authorization)
    payload = await decode_and_check_blacklist(token, settings.JWT_SECRET_USERS)

    user = await db.get(User, uuid.UUID(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Utilisateur introuvable ou désactivé")
    return user


async def require_admin(
    user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
) -> User:
    if not user.is_admin:
        await log_event(
            db, ActorType.USER, AuditEventType.ACCESS_DENIED, actor_id=user.id,
            metadata={"reason": "not_admin"},
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Accès réservé aux administrateurs")
    return user


# ---------- App (token statique en header) ----------
async def get_current_app(
    x_app_token: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> App:
    if not x_app_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Header X-App-Token manquant")

    result = await db.execute(select(App).where(App.token_hash == hash_token(x_app_token)))
    app = result.scalar_one_or_none()
    if not app or not app.is_active:
        if app:
            await log_event(
                db, ActorType.APP, AuditEventType.APP_TOKEN_INVALID, app_id=app.id,
                metadata={"reason": "inactive"},
            )
        else:
            # Aucune app trouvée pour ce token : on ne logue que le préfixe pour tracer
            # un éventuel scan/bruteforce de tokens sans jamais persister le secret complet.
            await log_event(
                db, ActorType.APP, AuditEventType.APP_TOKEN_INVALID,
                metadata={"reason": "unknown_token", "token_prefix": x_app_token[:12]},
            )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token d'application invalide")
    return app


# ---------- EndUser (JWT + X-App-Token obligatoires) ----------
async def get_current_end_user(
    authorization: str | None = Header(default=None),
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
) -> EndUser:
    token = extract_bearer_token(authorization)
    payload = await decode_and_check_blacklist(token, settings.JWT_SECRET_END_USERS)

    if payload.get("app_id") != str(app.id):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Ce token n'appartient pas à cette application")

    end_user = await db.get(EndUser, uuid.UUID(payload["sub"]))
    if not end_user or not end_user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Utilisateur introuvable ou désactivé")
    return end_user


# ---------- Permissions croisées App <-> User ----------
async def require_app_owner_or_admin(
    app: App = Depends(get_current_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> App:
    """X-App-Token + JWT User obligatoires. Réservé au créateur de l'App ou à un admin."""
    if not user.is_admin and user.id != app.owner_id:
        await log_event(
            db, ActorType.USER, AuditEventType.ACCESS_DENIED, actor_id=user.id, app_id=app.id,
            metadata={"reason": "not_owner"},
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Accès réservé au créateur de l'application ou à un administrateur"
        )
    return app


async def get_owned_app(
    app_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> App:
    """Récupère une App par id, réservée à son créateur ou à un admin (404 sinon, pour ne
    pas révéler l'existence d'une App appartenant à quelqu'un d'autre)."""
    app = await db.get(App, app_id)
    if not app:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Application introuvable")
    if not user.is_admin and app.owner_id != user.id:
        await log_event(
            db, ActorType.USER, AuditEventType.ACCESS_DENIED, actor_id=user.id, app_id=app.id,
            metadata={"reason": "not_owner"},
        )
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Application introuvable")
    return app


async def authorize_end_user_access(
    end_user: EndUser,
    app: App,
    authorization: str | None,
    db: AsyncSession,
) -> tuple[ActorType, uuid.UUID]:
    """Autorise soit l'EndUser concerné (son propre JWT), soit le créateur de l'App ou un
    admin (JWT User). À appeler manuellement dans les routes qui combinent X-App-Token avec
    l'un ou l'autre type de JWT selon l'appelant. Retourne (type, id) de l'acteur autorisé,
    pour que l'appelant puisse tracer le bon acteur dans l'audit."""
    token = extract_bearer_token(authorization)

    try:
        payload = await decode_and_check_blacklist(token, settings.JWT_SECRET_END_USERS)
        if payload.get("app_id") == str(app.id) and payload.get("sub") == str(end_user.id):
            return ActorType.END_USER, end_user.id
    except HTTPException:
        pass

    payload = await decode_and_check_blacklist(token, settings.JWT_SECRET_USERS)
    user = await db.get(User, uuid.UUID(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Utilisateur introuvable ou désactivé")
    if not user.is_admin and user.id != app.owner_id:
        await log_event(
            db, ActorType.USER, AuditEventType.ACCESS_DENIED, actor_id=user.id, app_id=app.id,
            metadata={"reason": "not_owner", "target_end_user_id": str(end_user.id)},
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Accès non autorisé à cet utilisateur")
    return ActorType.USER, user.id
