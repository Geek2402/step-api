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
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing or invalid Authorization header")
    return authorization.split(" ", 1)[1]


async def decode_and_check_blacklist(token: str, secret: str) -> dict:
    try:
        payload = decode_token(token, secret)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")

    if await redis_client.get(f"blacklist:{payload['jti']}"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token revoked")

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
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or disabled")
    return user


async def require_admin(
    user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
) -> User:
    if not user.is_admin:
        await log_event(
            db, ActorType.USER, AuditEventType.ACCESS_DENIED, actor_id=user.id,
            metadata={"reason": "not_admin"},
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Access restricted to administrators")
    return user


# ---------- App (static token in header) ----------
async def get_current_app(
    x_app_token: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> App:
    if not x_app_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing X-App-Token header")

    result = await db.execute(select(App).where(App.token_hash == hash_token(x_app_token)))
    app = result.scalar_one_or_none()
    if not app or not app.is_active:
        if app:
            await log_event(
                db, ActorType.APP, AuditEventType.APP_TOKEN_INVALID, app_id=app.id,
                metadata={"reason": "inactive"},
            )
        else:
            # No app found for this token: only log the prefix to trace a
            # potential token scan/bruteforce without ever persisting the full secret.
            await log_event(
                db, ActorType.APP, AuditEventType.APP_TOKEN_INVALID,
                metadata={"reason": "unknown_token", "token_prefix": x_app_token[:12]},
            )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid app token")
    return app


# ---------- EndUser (JWT + X-App-Token required) ----------
async def get_current_end_user(
    authorization: str | None = Header(default=None),
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
) -> EndUser:
    token = extract_bearer_token(authorization)
    payload = await decode_and_check_blacklist(token, settings.JWT_SECRET_END_USERS)

    if payload.get("app_id") != str(app.id):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "This token does not belong to this app")

    end_user = await db.get(EndUser, uuid.UUID(payload["sub"]))
    if not end_user or not end_user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or disabled")
    return end_user


# ---------- Cross App <-> User permissions ----------
async def require_app_owner_or_admin(
    app: App = Depends(get_current_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> App:
    """X-App-Token + User JWT required. Restricted to the App's creator or an admin."""
    if not user.is_admin and user.id != app.owner_id:
        await log_event(
            db, ActorType.USER, AuditEventType.ACCESS_DENIED, actor_id=user.id, app_id=app.id,
            metadata={"reason": "not_owner"},
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Access restricted to the app's creator or an administrator"
        )
    return app


async def get_owned_app(
    app_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> App:
    """Fetches an App by id, restricted to its creator or an admin (404 otherwise, so as
    not to reveal the existence of an App owned by someone else)."""
    app = await db.get(App, app_id)
    if not app:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "App not found")
    if not user.is_admin and app.owner_id != user.id:
        await log_event(
            db, ActorType.USER, AuditEventType.ACCESS_DENIED, actor_id=user.id, app_id=app.id,
            metadata={"reason": "not_owner"},
        )
        raise HTTPException(status.HTTP_404_NOT_FOUND, "App not found")
    return app


async def authorize_end_user_access(
    end_user: EndUser,
    app: App,
    authorization: str | None,
    db: AsyncSession,
) -> tuple[ActorType, uuid.UUID]:
    """Authorizes either the EndUser concerned (their own JWT), or the App's creator or an
    admin (User JWT). To be called manually in routes that combine X-App-Token with
    either type of JWT depending on the caller. Returns (type, id) of the authorized actor,
    so the caller can log the correct actor in the audit trail."""
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
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or disabled")
    if not user.is_admin and user.id != app.owner_id:
        await log_event(
            db, ActorType.USER, AuditEventType.ACCESS_DENIED, actor_id=user.id, app_id=app.id,
            metadata={"reason": "not_owner", "target_end_user_id": str(end_user.id)},
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Access to this user is not authorized")
    return ActorType.USER, user.id
