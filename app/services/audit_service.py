import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.enums import ActorType, AuditEventType


async def log_event(
    db: AsyncSession,
    actor_type: ActorType,
    event_type: AuditEventType,
    actor_id: uuid.UUID | None = None,
    app_id: uuid.UUID | None = None,
    metadata: dict | None = None,
) -> None:
    entry = AuditLog(
        actor_type=ActorType(actor_type).value,
        actor_id=actor_id,
        app_id=app_id,
        event_type=AuditEventType(event_type).value,
        event_metadata=metadata or {},
    )
    db.add(entry)
    await db.commit()
