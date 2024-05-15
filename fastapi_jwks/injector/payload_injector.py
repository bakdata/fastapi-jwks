from typing import Generic, TypeVar

from pydantic import BaseModel
from starlette.requests import Request

TypeT = TypeVar("TypeT", bound=BaseModel)


class JWTTokenInjector(Generic[TypeT]):
    async def __call__(self, request: Request) -> TypeT:
        return request.state.payload
