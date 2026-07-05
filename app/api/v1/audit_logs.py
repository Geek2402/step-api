import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user, get_owned_app, require_admin
from app.db.session import get_db
from app.models.app import App
from app.models.audit_log import AuditLog
from app.models.enums import ActorType, AuditEventType
from app.models.user import User
from app.schemas.audit_log import AuditLogRead
from app.schemas.pagination import DEFAULT_LIMIT, MAX_LIMIT, Page
from app.services.audit_service import log_event

# Read-only routes: no POST/PATCH/DELETE, AuditLog entries are only created by
# log_event() as system actions happen (see dependencies.py and the
# users/apps/end-users/*-auth routers).
router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])


def _apply_filters(
    query,
    actor_type: ActorType | None,
    event_type: AuditEventType | None,
    since: datetime | None,
    until: datetime | None,
):
    if actor_type is not None:
        query = query.where(AuditLog.actor_type == actor_type.value)
    if event_type is not None:
        query = query.where(AuditLog.event_type == event_type.value)
    if since is not None:
        query = query.where(AuditLog.created_at >= since)
    if until is not None:
        query = query.where(AuditLog.created_at <= until)
    return query


@router.get("", response_model=Page[AuditLogRead])
async def list_all_audit_logs(
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    actor_type: ActorType | None = None,
    event_type: AuditEventType | None = None,
    app_id: uuid.UUID | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Complete history, across all actors and all Apps — admins only."""
    count_query = select(func.count()).select_from(AuditLog)
    query = select(AuditLog)
    if app_id is not None:
        count_query = count_query.where(AuditLog.app_id == app_id)
        query = query.where(AuditLog.app_id == app_id)
    count_query = _apply_filters(count_query, actor_type, event_type, since, until)
    query = _apply_filters(query, actor_type, event_type, since, until)

    total = (await db.execute(count_query)).scalar_one()
    result = await db.execute(query.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset))
    await log_event(db, ActorType.USER, AuditEventType.AUDIT_LOG_LIST, actor_id=admin.id)
    return Page(items=result.scalars().all(), total=total, limit=limit, offset=offset)


@router.get("/apps/{app_id}", response_model=Page[AuditLogRead])
async def list_app_audit_logs(
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    actor_type: ActorType | None = None,
    event_type: AuditEventType | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    app: App = Depends(get_owned_app),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """History for a specific App — restricted to its creator or an admin."""
    count_query = select(func.count()).select_from(AuditLog).where(AuditLog.app_id == app.id)
    query = select(AuditLog).where(AuditLog.app_id == app.id)
    count_query = _apply_filters(count_query, actor_type, event_type, since, until)
    query = _apply_filters(query, actor_type, event_type, since, until)

    total = (await db.execute(count_query)).scalar_one()
    result = await db.execute(query.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset))
    await log_event(db, ActorType.USER, AuditEventType.AUDIT_LOG_LIST, actor_id=user.id, app_id=app.id)
    return Page(items=result.scalars().all(), total=total, limit=limit, offset=offset)
