import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user
from app.core.security import generate_app_token
from app.db.session import get_db
from app.models.app import App
from app.models.user import User
from app.schemas.app import AppCreate, AppCreated, AppRead
from app.services.audit_service import log_event

router = APIRouter(prefix="/apps", tags=["apps"])


def _to_created(app: App, token: str) -> AppCreated:
    return AppCreated(
        id=app.id,
        name=app.name,
        token_prefix=app.token_prefix,
        is_active=app.is_active,
        created_at=app.created_at,
        token=token,
    )


@router.post("", response_model=AppCreated, status_code=status.HTTP_201_CREATED)
async def create_app(
    payload: AppCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    token, prefix, token_hash = generate_app_token()
    app = App(owner_id=user.id, name=payload.name, token_hash=token_hash, token_prefix=prefix)
    db.add(app)
    await db.commit()
    await db.refresh(app)
    await log_event(db, "user", "app_created", actor_id=user.id, app_id=app.id)
    return _to_created(app, token)


@router.get("", response_model=list[AppRead])
async def list_apps(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    query = select(App) if user.is_admin else select(App).where(App.owner_id == user.id)
    result = await db.execute(query)
    return result.scalars().all()


async def _get_owned_app(app_id: uuid.UUID, user: User, db: AsyncSession) -> App:
    app = await db.get(App, app_id)
    if not app or (not user.is_admin and app.owner_id != user.id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Application introuvable")
    return app


@router.get("/{app_id}", response_model=AppRead)
async def get_app(app_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await _get_owned_app(app_id, user, db)


@router.post("/{app_id}/rotate-token", response_model=AppCreated)
async def rotate_token(
    app_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    app = await _get_owned_app(app_id, user, db)

    token, prefix, token_hash = generate_app_token()
    app.token_hash = token_hash
    app.token_prefix = prefix
    await db.commit()
    await db.refresh(app)
    await log_event(db, "user", "app_token_rotated", actor_id=user.id, app_id=app.id)
    return _to_created(app, token)


@router.delete("/{app_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_app(
    app_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    app = await _get_owned_app(app_id, user, db)
    app.is_active = False
    await db.commit()
    await log_event(db, "user", "app_deactivated", actor_id=user.id, app_id=app.id)
