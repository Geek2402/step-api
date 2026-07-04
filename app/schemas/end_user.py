import uuid

from pydantic import BaseModel, ConfigDict, EmailStr


class EndUserCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: str


class EndUserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    app_id: uuid.UUID
    first_name: str
    last_name: str
    email: EmailStr
    is_verified: bool
    is_active: bool
