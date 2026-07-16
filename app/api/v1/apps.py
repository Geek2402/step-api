from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_app, get_current_user, get_owned_app
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
        owner_id=app.owner_id,
        name=app.name,
        token_prefix=app.token_prefix,
        frontend_url=app.frontend_url,
        is_active=app.is_active,
        created_at=app.created_at,
        token=token,
    )


@router.post("", response_model=AppCreated, status_code=status.HTTP_201_CREATED, summary="Create a new App")
async def create_app(
    payload: AppCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Creates a new App owned by the authenticated User, with a fresh secret token.

    Requires a valid User JWT. The generated token (prefixed `app_live_`) is returned in
    clear text **only in this response** — only its SHA-256 hash is stored, so it cannot be
    retrieved again later (use `POST /{app_id}/rotate-token` to issue a new one if lost).
    This token must be sent as the `X-App-Token` header on every `/v1/end-users/*` request.
    Logs an `APP_CREATED` audit event.
    """
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


@router.get("", response_model=Page[AppRead], summary="List Apps")
async def list_apps(
    mine: bool = False,
    search: str | None = Query(default=None, description="Search by App name"),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns a paginated list of Apps.

    Requires a valid User JWT. An admin sees every App on the platform by default, and can
    pass `mine=true` to restrict the list to Apps they personally own. A non-admin always sees
    only the Apps they own, regardless of the `mine` parameter. Supports an optional
    case-insensitive partial-match `search` on the App name. Paginated via `limit`
    (default 20, max 100) and `offset`; the response envelope includes `total`. Logs an
    `APP_LIST` audit event.
    """
    # An admin sees all apps by default; ?mine=true restricts to their own.
    # A non-admin always sees only their own apps, regardless of this parameter.
    scoped = not (user.is_admin and not mine)

    filters = []
    if scoped:
        filters.append(App.owner_id == user.id)
    if search:
        filters.append(App.name.ilike(f"%{search}%"))

    count_query = select(func.count()).select_from(App).where(*filters)
    query = select(App).where(*filters)

    total = (await db.execute(count_query)).scalar_one()
    result = await db.execute(query.order_by(App.created_at).limit(limit).offset(offset))
    await log_event(db, ActorType.USER, AuditEventType.APP_LIST, actor_id=user.id)
    return Page(items=result.scalars().all(), total=total, limit=limit, offset=offset)


@router.get("/by-token", response_model=AppRead, summary="Get the App identified by its X-App-Token")
async def get_app_by_token(
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
):
    """Returns the App's own public metadata, authenticated by its secret token.

    Requires the `X-App-Token` header (no User JWT needed) — intended for an App's backend
    to self-identify or verify its token is still valid/active. Logs an `APP_READ` audit event.

    Errors: 401 if the header is missing or the token is unknown/inactive.
    """
    await log_event(db, ActorType.APP, AuditEventType.APP_READ, app_id=app.id)
    return app


@router.get("/{app_id}", response_model=AppRead, summary="Get an App by id (owner or admin)")
async def get_app(
    app: App = Depends(get_owned_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns the App's public metadata.

    Requires a valid User JWT; restricted to the App's creator or an admin. Logs an
    `APP_READ` audit event.

    Errors: 404 if the App does not exist or is not owned by the caller (an admin can
    still access it) — a non-owner never learns whether the App exists.
    """
    await log_event(db, ActorType.USER, AuditEventType.APP_READ, actor_id=user.id, app_id=app.id)
    return app


@router.patch("/{app_id}", response_model=AppRead, summary="Update an App's name or frontend URL (owner or admin)")
async def update_app(
    payload: AppUpdate,
    app: App = Depends(get_owned_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Partially updates the App's name and/or frontend URL.

    Requires a valid User JWT; restricted to the App's creator or an admin. Only the fields
    provided in the request body are changed. The frontend URL is used to build password
    reset links sent to that App's end users. Logs an `APP_UPDATED` audit event.

    Errors: 404 if the App does not exist or is not owned by the caller.
    """
    if payload.name is not None:
        app.name = payload.name
    if payload.frontend_url is not None:
        app.frontend_url = payload.frontend_url or None

    await db.commit()
    await db.refresh(app)
    await log_event(db, ActorType.USER, AuditEventType.APP_UPDATED, actor_id=user.id, app_id=app.id)
    return app


@router.post("/{app_id}/rotate-token", response_model=AppCreated, summary="Rotate an App's secret token (owner or admin)")
async def rotate_token(
    app: App = Depends(get_owned_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generates a brand-new secret token for the App, immediately invalidating the previous one.

    Requires a valid User JWT; restricted to the App's creator or an admin. The new token is
    returned in clear text **only in this response** — as with creation, only its hash is
    stored. Any client still using the old `X-App-Token` will start receiving 401s. Logs an
    `APP_TOKEN_ROTATED` audit event.

    Errors: 404 if the App does not exist or is not owned by the caller.
    """
    token, prefix, token_hash = generate_app_token()
    app.token_hash = token_hash
    app.token_prefix = prefix
    await db.commit()
    await db.refresh(app)
    await log_event(db, ActorType.USER, AuditEventType.APP_TOKEN_ROTATED, actor_id=user.id, app_id=app.id)
    return _to_created(app, token)


@router.delete(
    "/{app_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete an App (owner or admin)"
)
async def delete_app(
    app: App = Depends(get_owned_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Permanently deletes the App and, via cascade, all of its EndUsers.

    Requires a valid User JWT; restricted to the App's creator or an admin. This is a hard
    delete and cannot be undone — the App's `X-App-Token` becomes invalid immediately. Logs
    an `APP_DELETED` audit event before returning 204 with no body.

    Errors: 404 if the App does not exist or is not owned by the caller.
    """
    app_id_for_log = app.id
    await db.delete(app)
    await db.commit()
    await log_event(db, ActorType.USER, AuditEventType.APP_DELETED, actor_id=user.id, app_id=app_id_for_log)


@router.post("/{app_id}/activate", response_model=AppRead, summary="Reactivate a disabled App (owner or admin)")
async def activate_app(
    app: App = Depends(get_owned_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Sets `is_active` back to true on the App, restoring its `X-App-Token` — while inactive,
    every `/v1/end-users/*` request for this App is rejected with 401.

    Requires a valid User JWT; restricted to the App's creator or an admin. Logs an
    `APP_ACTIVATED` audit event.

    Errors: 404 if the App does not exist or is not owned by the caller.
    """
    app.is_active = True
    await db.commit()
    await db.refresh(app)
    await log_event(db, ActorType.USER, AuditEventType.APP_ACTIVATED, actor_id=user.id, app_id=app.id)
    return app


@router.post("/{app_id}/deactivate", response_model=AppRead, summary="Disable an App (owner or admin)")
async def deactivate_app(
    app: App = Depends(get_owned_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Sets `is_active` to false on the App. While inactive, its `X-App-Token` is rejected on
    every `/v1/end-users/*` route (including its EndUsers' login), effectively suspending the
    App without deleting any data.

    Requires a valid User JWT; restricted to the App's creator or an admin. Logs an
    `APP_DEACTIVATED` audit event.

    Errors: 404 if the App does not exist or is not owned by the caller.
    """
    app.is_active = False
    await db.commit()
    await db.refresh(app)
    await log_event(db, ActorType.USER, AuditEventType.APP_DEACTIVATED, actor_id=user.id, app_id=app.id)
    return app
