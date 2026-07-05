from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user, get_owned_app
from app.core.security import generate_app_token
from app.db.session import get_db
from app.models.app import App
from app.models.enums import ActorType, AuditEventType
from app.models.user import User
from app.schemas.app import AppCreate, AppCreated, AppRead, AppUpdate
from app.schemas.pagination import DEFAULT_LIMIT, MAX_LIMIT, Page
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
    await log_event(db, ActorType.USER, AuditEventType.APP_CREATED, actor_id=user.id, app_id=app.id)
    return _to_created(app, token)


@router.get("", response_model=Page[AppRead])
async def list_apps(
    mine: bool = False,
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # An admin sees all apps by default; ?mine=true restricts to their own.
    # A non-admin always sees only their own apps, regardless of this parameter.
    scoped = not (user.is_admin and not mine)

    count_query = select(func.count()).select_from(App)
    query = select(App)
    if scoped:
        count_query = count_query.where(App.owner_id == user.id)
        query = query.where(App.owner_id == user.id)

    total = (await db.execute(count_query)).scalar_one()
    result = await db.execute(query.order_by(App.created_at).limit(limit).offset(offset))
    await log_event(db, ActorType.USER, AuditEventType.APP_LIST, actor_id=user.id)
    return Page(items=result.scalars().all(), total=total, limit=limit, offset=offset)


@router.get("/{app_id}", response_model=AppRead)
async def get_app(
    app: App = Depends(get_owned_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await log_event(db, ActorType.USER, AuditEventType.APP_READ, actor_id=user.id, app_id=app.id)
    return app


@router.patch("/{app_id}", response_model=AppRead)
async def update_app(
    payload: AppUpdate,
    app: App = Depends(get_owned_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if payload.name is not None:
        app.name = payload.name
    if payload.frontend_url is not None:
        app.frontend_url = payload.frontend_url or None

    await db.commit()
    await db.refresh(app)
    await log_event(db, ActorType.USER, AuditEventType.APP_UPDATED, actor_id=user.id, app_id=app.id)
    return app


@router.post("/{app_id}/rotate-token", response_model=AppCreated)
async def rotate_token(
    app: App = Depends(get_owned_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    token, prefix, token_hash = generate_app_token()
    app.token_hash = token_hash
    app.token_prefix = prefix
    await db.commit()
    await db.refresh(app)
    await log_event(db, ActorType.USER, AuditEventType.APP_TOKEN_ROTATED, actor_id=user.id, app_id=app.id)
    return _to_created(app, token)


@router.delete("/{app_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_app(
    app: App = Depends(get_owned_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    app_id_for_log = app.id
    await db.delete(app)
    await db.commit()
    await log_event(db, ActorType.USER, AuditEventType.APP_DELETED, actor_id=user.id, app_id=app_id_for_log)


@router.post("/{app_id}/activate", response_model=AppRead)
async def activate_app(
    app: App = Depends(get_owned_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    app.is_active = True
    await db.commit()
    await db.refresh(app)
    await log_event(db, ActorType.USER, AuditEventType.APP_ACTIVATED, actor_id=user.id, app_id=app.id)
    return app


@router.post("/{app_id}/deactivate", response_model=AppRead)
async def deactivate_app(
    app: App = Depends(get_owned_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    app.is_active = False
    await db.commit()
    await db.refresh(app)
    await log_event(db, ActorType.USER, AuditEventType.APP_DEACTIVATED, actor_id=user.id, app_id=app.id)
    return app
