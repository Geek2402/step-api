import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user
from app.core.security import generate_app_token
from app.db.session import get_db
from app.models.app import App
from app.models.user import User
from app.schemas.app import AppCreate, AppCreated, AppRead, AppUpdate
from app.services.audit_service import log_event

router = APIRouter(prefix="/apps", tags=["apps"])


def _to_created(app: App, token: str) -> AppCreated:
    return AppCreated(
        id=app.id,
        name=app.name,
        token_prefix=app.token_prefix,
        frontend_url=app.frontend_url,
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
    app = App(
        owner_id=user.id,
        name=payload.name,
        token_hash=token_hash,
        token_prefix=prefix,
        frontend_url=payload.frontend_url,
    )
    db.add(app)
    await db.commit()
    await db.refresh(app)
    await log_event(db, "user", "app_created", actor_id=user.id, app_id=app.id)
    return _to_created(app, token)


@router.get("", response_model=list[AppRead])
async def list_apps(
    mine: bool = False, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    # Un admin voit toutes les apps par défaut ; ?mine=true restreint aux siennes.
    # Un non-admin ne voit toujours que les siennes, quel que soit ce paramètre.
    query = (
        select(App)
        if user.is_admin and not mine
        else select(App).where(App.owner_id == user.id)
    )
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


@router.patch("/{app_id}", response_model=AppRead)
async def update_app(
    app_id: uuid.UUID,
    payload: AppUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    app = await _get_owned_app(app_id, user, db)

    if payload.name is not None:
        app.name = payload.name
    if payload.frontend_url is not None:
        app.frontend_url = payload.frontend_url or None

    await db.commit()
    await db.refresh(app)
    await log_event(db, "user", "app_updated", actor_id=user.id, app_id=app.id)
    return app


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
async def delete_app(
    app_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    app = await _get_owned_app(app_id, user, db)
    app_id_for_log = app.id
    await db.delete(app)
    await db.commit()
    await log_event(db, "user", "app_deleted", actor_id=user.id, app_id=app_id_for_log)


@router.post("/{app_id}/activate", response_model=AppRead)
async def activate_app(
    app_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    app = await _get_owned_app(app_id, user, db)
    app.is_active = True
    await db.commit()
    await db.refresh(app)
    await log_event(db, "user", "app_activated", actor_id=user.id, app_id=app.id)
    return app


@router.post("/{app_id}/deactivate", response_model=AppRead)
async def deactivate_app(
    app_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    app = await _get_owned_app(app_id, user, db)
    app.is_active = False
    await db.commit()
    await db.refresh(app)
    await log_event(db, "user", "app_deactivated", actor_id=user.id, app_id=app.id)
    return app
