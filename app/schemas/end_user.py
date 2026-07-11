import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr


class EndUserCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: str


class EndUserUpdate(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    email: EmailStr | None = None
    password: str | None = None


class EndUserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    app_id: uuid.UUID
    first_name: str
    last_name: str
    email: EmailStr
    is_verified: bool
    is_active: bool
    first_login: datetime | None = None
    last_active: datetime | None = None
