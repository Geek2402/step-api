import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AppCreate(BaseModel):
    name: str


class AppRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    token_prefix: str
    is_active: bool
    created_at: datetime


class AppCreated(AppRead):
    token: str  # affiché en clair une seule fois, à la création / rotation
