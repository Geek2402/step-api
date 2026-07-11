import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AppCreate(BaseModel):
    name: str
    frontend_url: str | None = None


class AppUpdate(BaseModel):
    name: str | None = None
    frontend_url: str | None = None


class AppRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    owner_id: uuid.UUID
    name: str
    token_prefix: str
    frontend_url: str | None
    is_active: bool
    created_at: datetime


class AppCreated(AppRead):
    token: str  # shown in clear text only once, at creation / rotation
