from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")

DEFAULT_LIMIT = 20
MAX_LIMIT = 100


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int
