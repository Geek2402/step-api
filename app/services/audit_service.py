import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


async def log_event(
    db: AsyncSession,
    actor_type: str,
    event_type: str,
    actor_id: uuid.UUID | None = None,
    app_id: uuid.UUID | None = None,
    metadata: dict | None = None,
) -> None:
    entry = AuditLog(
        actor_type=actor_type,
        actor_id=actor_id,
        app_id=app_id,
        event_type=event_type,
        event_metadata=metadata or {},
    )
    db.add(entry)
    await db.commit()
