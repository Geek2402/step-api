import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import (
    authorize_end_user_access,
    get_current_app,
    get_current_end_user,
    get_current_user,
    require_app_owner_or_admin,
)
from app.core.security import hash_password
from app.db.session import get_db
from app.models.app import App
from app.models.end_user import EndUser
from app.models.enums import ActorType, AuditEventType
from app.models.user import User
from app.schemas.end_user import EndUserCreate, EndUserRead, EndUserUpdate
from app.schemas.pagination import DEFAULT_LIMIT, MAX_LIMIT, Page
from app.services.audit_service import log_event

# Tag distinct de "end-user-auth" pour que Swagger regroupe séparément le CRUD
# et le flow d'auth, tout en gardant les deux visibles dans la doc publique /docs
# (voir la liste PUBLIC_TAGS dans main.py).
router = APIRouter(prefix="/end-users", tags=["end-users"])


async def _get_owned_end_user(end_user_id: uuid.UUID, app: App, db: AsyncSession) -> EndUser:
    end_user = await db.get(EndUser, end_user_id)
    if not end_user or end_user.app_id != app.id:
        if end_user:
            await log_event(
                db, ActorType.APP, AuditEventType.ACCESS_DENIED, app_id=app.id,
                metadata={"reason": "not_owner", "target_end_user_id": str(end_user_id)},
            )
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur introuvable")
    return end_user


@router.post("", response_model=EndUserRead, status_code=status.HTTP_201_CREATED)
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
    await log_event(db, ActorType.END_USER, AuditEventType.END_USER_REGISTERED, actor_id=end_user.id, app_id=app.id)
    return end_user


@router.get("/me", response_model=EndUserRead)
async def me(end_user: EndUser = Depends(get_current_end_user), db: AsyncSession = Depends(get_db)):
    await log_event(
        db, ActorType.END_USER, AuditEventType.END_USER_READ, actor_id=end_user.id, app_id=end_user.app_id,
        metadata={"target_end_user_id": str(end_user.id), "self": True},
    )
    return end_user


@router.get("", response_model=Page[EndUserRead])
async def list_end_users(
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    app: App = Depends(require_app_owner_or_admin),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    total = (
        await db.execute(select(func.count()).select_from(EndUser).where(EndUser.app_id == app.id))
    ).scalar_one()
    result = await db.execute(
        select(EndUser).where(EndUser.app_id == app.id).order_by(EndUser.created_at).limit(limit).offset(offset)
    )
    await log_event(db, ActorType.USER, AuditEventType.END_USER_LIST, actor_id=user.id, app_id=app.id)
    return Page(items=result.scalars().all(), total=total, limit=limit, offset=offset)


@router.get("/{end_user_id}", response_model=EndUserRead)
async def get_end_user(
    end_user_id: uuid.UUID,
    app: App = Depends(get_current_app),
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
):
    end_user = await _get_owned_end_user(end_user_id, app, db)
    actor_type, actor_id = await authorize_end_user_access(end_user, app, authorization, db)
    await log_event(
        db, actor_type, AuditEventType.END_USER_READ, actor_id=actor_id, app_id=app.id,
        metadata={"target_end_user_id": str(end_user.id), "self": actor_id == end_user.id},
    )
    return end_user


@router.patch("/{end_user_id}", response_model=EndUserRead)
async def update_end_user(
    end_user_id: uuid.UUID,
    payload: EndUserUpdate,
    app: App = Depends(get_current_app),
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
):
    end_user = await _get_owned_end_user(end_user_id, app, db)
    actor_type, actor_id = await authorize_end_user_access(end_user, app, authorization, db)

    if payload.email is not None and payload.email != end_user.email:
        existing = await db.execute(
            select(EndUser).where(EndUser.app_id == app.id, EndUser.email == payload.email)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status.HTTP_409_CONFLICT, "Un utilisateur existe déjà avec cet email pour cette application"
            )
        end_user.email = payload.email
    if payload.first_name is not None:
        end_user.first_name = payload.first_name
    if payload.last_name is not None:
        end_user.last_name = payload.last_name
    if payload.password is not None:
        end_user.password_hash = hash_password(payload.password)

    await db.commit()
    await db.refresh(end_user)
    await log_event(
        db, actor_type, AuditEventType.END_USER_UPDATED, actor_id=actor_id, app_id=app.id,
        metadata={"target_end_user_id": str(end_user.id)},
    )
    return end_user


@router.delete("/{end_user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_end_user(
    end_user_id: uuid.UUID,
    app: App = Depends(get_current_app),
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
):
    end_user = await _get_owned_end_user(end_user_id, app, db)
    actor_type, actor_id = await authorize_end_user_access(end_user, app, authorization, db)
    end_user_id_for_log = end_user.id
    await db.delete(end_user)
    await db.commit()
    await log_event(
        db, actor_type, AuditEventType.END_USER_DELETED, actor_id=actor_id, app_id=app.id,
        metadata={"target_end_user_id": str(end_user_id_for_log)},
    )


@router.post("/{end_user_id}/activate", response_model=EndUserRead)
async def activate_end_user(
    end_user_id: uuid.UUID,
    app: App = Depends(require_app_owner_or_admin),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    end_user = await _get_owned_end_user(end_user_id, app, db)
    end_user.is_active = True
    await db.commit()
    await db.refresh(end_user)
    await log_event(
        db, ActorType.USER, AuditEventType.END_USER_ACTIVATED, actor_id=user.id, app_id=app.id,
        metadata={"target_end_user_id": str(end_user.id)},
    )
    return end_user


@router.post("/{end_user_id}/deactivate", response_model=EndUserRead)
async def deactivate_end_user(
    end_user_id: uuid.UUID,
    app: App = Depends(require_app_owner_or_admin),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    end_user = await _get_owned_end_user(end_user_id, app, db)
    end_user.is_active = False
    await db.commit()
    await db.refresh(end_user)
    await log_event(
        db, ActorType.USER, AuditEventType.END_USER_DEACTIVATED, actor_id=user.id, app_id=app.id,
        metadata={"target_end_user_id": str(end_user.id)},
    )
    return end_user
