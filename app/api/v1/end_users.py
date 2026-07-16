import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import func, or_, select
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
from app.models.audit_log import AuditLog
from app.models.end_user import EndUser
from app.models.enums import ActorType, AuditEventType
from app.models.user import User
from app.schemas.end_user import EndUserCreate, EndUserRead, EndUserUpdate
from app.schemas.pagination import DEFAULT_LIMIT, MAX_LIMIT, Page
from app.services.audit_service import log_event

# Tag distinct from "end-user-auth" so that Swagger groups the CRUD routes
# and the auth flow separately, while keeping both visible in the public
# /docs (see the PUBLIC_TAGS list in main.py).
router = APIRouter(prefix="/end-users", tags=["end-users"])


async def _fetch_activity(
    db: AsyncSession, app_id: uuid.UUID, end_user_ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[datetime, datetime]]:
    """Returns {end_user_id: (first_login, last_active)} inferred from successful GET /me calls
    (END_USER_READ self-reads by the EndUser themselves in the audit trail)."""
    if not end_user_ids:
        return {}
    result = await db.execute(
        select(AuditLog.actor_id, func.min(AuditLog.created_at), func.max(AuditLog.created_at))
        .where(
            AuditLog.actor_type == ActorType.END_USER.value,
            AuditLog.app_id == app_id,
            AuditLog.event_type == AuditEventType.END_USER_READ.value,
            AuditLog.actor_id.in_(end_user_ids),
        )
        .group_by(AuditLog.actor_id)
    )
    return {row[0]: (row[1], row[2]) for row in result.all()}


def _to_read(end_user: EndUser, activity: tuple[datetime, datetime] | None) -> EndUserRead:
    first_login, last_active = activity or (None, None)
    return EndUserRead(
        id=end_user.id,
        app_id=end_user.app_id,
        first_name=end_user.first_name,
        last_name=end_user.last_name,
        email=end_user.email,
        is_verified=end_user.is_verified,
        is_active=end_user.is_active,
        first_login=first_login,
        last_active=last_active,
    )


async def _get_owned_end_user(end_user_id: uuid.UUID, app: App, db: AsyncSession) -> EndUser:
    end_user = await db.get(EndUser, end_user_id)
    if not end_user or end_user.app_id != app.id:
        if end_user:
            await log_event(
                db, ActorType.APP, AuditEventType.ACCESS_DENIED, app_id=app.id,
                metadata={"reason": "not_owner", "target_end_user_id": str(end_user_id)},
            )
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return end_user


@router.post(
    "", response_model=EndUserRead, status_code=status.HTTP_201_CREATED, summary="Register a new EndUser"
)
async def register(
    payload: EndUserCreate,
    app: App = Depends(get_current_app),
    db: AsyncSession = Depends(get_db),
):
    """Creates a new EndUser (the App's own end user) scoped to the calling App.

    Requires the `X-App-Token` header identifying the App. The email only needs to be unique
    within this App — the same email can be registered for a different App. The account is
    created active but unverified; it becomes verified on first successful login (see
    `/end-users/auth/login` + `/verify-otp`). Logs an `END_USER_REGISTERED` audit event.

    Errors: 401 if the `X-App-Token` header is missing or invalid; 409 if an EndUser already
    exists with this email for this App.
    """
    existing = await db.execute(
        select(EndUser).where(EndUser.app_id == app.id, EndUser.email == payload.email)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status.HTTP_409_CONFLICT, "A user already exists with this email for this application"
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
    return _to_read(end_user, None)


@router.get("/me", response_model=EndUserRead, summary="Get the current authenticated EndUser's profile")
async def me(end_user: EndUser = Depends(get_current_end_user), db: AsyncSession = Depends(get_db)):
    """Returns the profile of the EndUser identified by the JWT in the `Authorization` header,
    including `first_login`/`last_active` timestamps inferred from their own past reads of
    this endpoint.

    Requires both the `X-App-Token` header and a valid EndUser JWT for that same App. Logs
    an `END_USER_READ` audit event (self-read) — this is precisely what powers the
    `first_login`/`last_active` activity tracking, so calling this endpoint is itself an
    "activity" signal.

    Errors: 401 if either header/token is missing, invalid, or the token belongs to a
    different App.
    """
    await log_event(
        db, ActorType.END_USER, AuditEventType.END_USER_READ, actor_id=end_user.id, app_id=end_user.app_id,
        metadata={"target_end_user_id": str(end_user.id), "self": True},
    )
    activity = await _fetch_activity(db, end_user.app_id, [end_user.id])
    return _to_read(end_user, activity.get(end_user.id))


@router.get("", response_model=Page[EndUserRead], summary="List the EndUsers of an App")
async def list_end_users(
    search: str | None = Query(default=None, description="Search by first name, last name, or email"),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    app: App = Depends(require_app_owner_or_admin),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns a paginated list of the EndUsers registered for the calling App.

    Requires both the `X-App-Token` header and a valid User JWT; restricted to that App's
    creator or an admin (this is a dev/admin-facing management endpoint, not something an
    EndUser can call for themselves). Supports an optional case-insensitive partial-match
    `search` across first name, last name, and email. Paginated via `limit` (default 20,
    max 100) and `offset`; the response envelope includes `total`. Each entry includes
    `first_login`/`last_active` activity timestamps. Logs an `END_USER_LIST` audit event.

    Errors: 401 if the `X-App-Token` header is missing/invalid; 403 if the User is neither
    this App's creator nor an admin.
    """
    filters = [EndUser.app_id == app.id]
    if search:
        pattern = f"%{search}%"
        filters.append(
            or_(
                EndUser.first_name.ilike(pattern),
                EndUser.last_name.ilike(pattern),
                EndUser.email.ilike(pattern),
            )
        )

    total = (await db.execute(select(func.count()).select_from(EndUser).where(*filters))).scalar_one()
    result = await db.execute(
        select(EndUser).where(*filters).order_by(EndUser.created_at).limit(limit).offset(offset)
    )
    end_users = result.scalars().all()

    activity = await _fetch_activity(db, app.id, [end_user.id for end_user in end_users])
    await log_event(db, ActorType.USER, AuditEventType.END_USER_LIST, actor_id=user.id, app_id=app.id)
    items = [_to_read(end_user, activity.get(end_user.id)) for end_user in end_users]
    return Page(items=items, total=total, limit=limit, offset=offset)


@router.get("/{end_user_id}", response_model=EndUserRead, summary="Get an EndUser by id")
async def get_end_user(
    end_user_id: uuid.UUID,
    app: App = Depends(get_current_app),
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Returns the EndUser's profile, including their activity timestamps.

    Requires the `X-App-Token` header, plus an `Authorization: Bearer` JWT that is either the
    EndUser's own token, or a User JWT belonging to this App's creator or an admin — the two
    JWT types are tried automatically, whichever matches is accepted. Logs an `END_USER_READ`
    audit event under the actor that was actually authorized (EndUser self-read, or the
    User that looked them up).

    Errors: 401 if the `X-App-Token` or JWT is missing/invalid; 403 if a User JWT is presented
    but that User is neither this App's creator nor an admin; 404 if the EndUser does not
    exist for this App.
    """
    end_user = await _get_owned_end_user(end_user_id, app, db)
    actor_type, actor_id = await authorize_end_user_access(end_user, app, authorization, db)
    await log_event(
        db, actor_type, AuditEventType.END_USER_READ, actor_id=actor_id, app_id=app.id,
        metadata={"target_end_user_id": str(end_user.id), "self": actor_id == end_user.id},
    )
    activity = await _fetch_activity(db, app.id, [end_user.id])
    return _to_read(end_user, activity.get(end_user.id))


@router.patch("/{end_user_id}", response_model=EndUserRead, summary="Update an EndUser's profile")
async def update_end_user(
    end_user_id: uuid.UUID,
    payload: EndUserUpdate,
    app: App = Depends(get_current_app),
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Partially updates an EndUser's email, first name, last name, and/or password.

    Requires the `X-App-Token` header, plus either the EndUser's own JWT or a User JWT
    belonging to this App's creator or an admin (same dual-authorization as `GET
    /{end_user_id}`). Only the fields provided in the request body are changed. Logs an
    `END_USER_UPDATED` audit event under whichever actor was authorized.

    Errors: 401/403 as in `GET /{end_user_id}`; 404 if the EndUser does not exist for this
    App; 409 if the new email is already used by another EndUser of this same App.
    """
    end_user = await _get_owned_end_user(end_user_id, app, db)
    actor_type, actor_id = await authorize_end_user_access(end_user, app, authorization, db)

    if payload.email is not None and payload.email != end_user.email:
        existing = await db.execute(
            select(EndUser).where(EndUser.app_id == app.id, EndUser.email == payload.email)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status.HTTP_409_CONFLICT, "A user already exists with this email for this application"
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
    activity = await _fetch_activity(db, app.id, [end_user.id])
    return _to_read(end_user, activity.get(end_user.id))


@router.delete(
    "/{end_user_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete an EndUser"
)
async def delete_end_user(
    end_user_id: uuid.UUID,
    app: App = Depends(get_current_app),
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Permanently deletes the EndUser account.

    Requires the `X-App-Token` header, plus either the EndUser's own JWT or a User JWT
    belonging to this App's creator or an admin (same dual-authorization as `GET
    /{end_user_id}`). This is a hard delete and cannot be undone. Logs an `END_USER_DELETED`
    audit event under whichever actor was authorized, then returns 204 with no body.

    Errors: 401/403 as in `GET /{end_user_id}`; 404 if the EndUser does not exist for this App.
    """
    end_user = await _get_owned_end_user(end_user_id, app, db)
    actor_type, actor_id = await authorize_end_user_access(end_user, app, authorization, db)
    end_user_id_for_log = end_user.id
    await db.delete(end_user)
    await db.commit()
    await log_event(
        db, actor_type, AuditEventType.END_USER_DELETED, actor_id=actor_id, app_id=app.id,
        metadata={"target_end_user_id": str(end_user_id_for_log)},
    )


@router.post(
    "/{end_user_id}/activate", response_model=EndUserRead, summary="Reactivate a disabled EndUser"
)
async def activate_end_user(
    end_user_id: uuid.UUID,
    app: App = Depends(require_app_owner_or_admin),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Sets `is_active` back to true on the EndUser, restoring their ability to log in.

    Requires both the `X-App-Token` header and a valid User JWT; restricted to that App's
    creator or an admin (management action, not available to the EndUser themselves).
    Logs an `END_USER_ACTIVATED` audit event.

    Errors: 401 if the `X-App-Token` header is missing/invalid; 403 if the User is neither
    this App's creator nor an admin; 404 if the EndUser does not exist for this App.
    """
    end_user = await _get_owned_end_user(end_user_id, app, db)
    end_user.is_active = True
    await db.commit()
    await db.refresh(end_user)
    await log_event(
        db, ActorType.USER, AuditEventType.END_USER_ACTIVATED, actor_id=user.id, app_id=app.id,
        metadata={"target_end_user_id": str(end_user.id)},
    )
    activity = await _fetch_activity(db, app.id, [end_user.id])
    return _to_read(end_user, activity.get(end_user.id))


@router.post(
    "/{end_user_id}/deactivate", response_model=EndUserRead, summary="Disable an EndUser"
)
async def deactivate_end_user(
    end_user_id: uuid.UUID,
    app: App = Depends(require_app_owner_or_admin),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Sets `is_active` to false on the EndUser, immediately preventing them from logging in
    (existing JWTs remain valid until they naturally expire — this does not blacklist tokens).

    Requires both the `X-App-Token` header and a valid User JWT; restricted to that App's
    creator or an admin. Logs an `END_USER_DEACTIVATED` audit event.

    Errors: 401 if the `X-App-Token` header is missing/invalid; 403 if the User is neither
    this App's creator nor an admin; 404 if the EndUser does not exist for this App.
    """
    end_user = await _get_owned_end_user(end_user_id, app, db)
    end_user.is_active = False
    await db.commit()
    await db.refresh(end_user)
    await log_event(
        db, ActorType.USER, AuditEventType.END_USER_DEACTIVATED, actor_id=user.id, app_id=app.id,
        metadata={"target_end_user_id": str(end_user.id)},
    )
    activity = await _fetch_activity(db, app.id, [end_user.id])
    return _to_read(end_user, activity.get(end_user.id))
