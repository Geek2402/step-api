from pydantic import BaseModel

from app.schemas.end_user import EndUserRead
from app.schemas.user import UserRead


class UserTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserRead


class EndUserTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    email: str
    end_user: EndUserRead
