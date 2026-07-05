import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import ActorType, AuditEventType


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    actor_type: ActorType
    actor_id: uuid.UUID | None
    app_id: uuid.UUID | None
    event_type: AuditEventType
    event_metadata: dict
    created_at: datetime
