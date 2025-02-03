from typing import Generic, TypeVar

from pydantic import BaseModel
from starlette.requests import Request

from fastapi_jwks.models.types import JWTTokenInjectorConfig

TypeT = TypeVar("TypeT", bound=BaseModel)


class JWTTokenInjector(Generic[TypeT]):
    def __init__(self, config: JWTTokenInjectorConfig | None = None):
        self.config = config or JWTTokenInjectorConfig()

    async def __call__(self, request: Request) -> TypeT:
        return getattr(request.state, self.config.payload_field)


class JWTRawTokenInjector(Generic[TypeT]):
    def __init__(self, config: JWTTokenInjectorConfig | None = None):
        self.config = config or JWTTokenInjectorConfig()

    async def __call__(self, request: Request) -> TypeT:
        return getattr(request.state, self.config.token_field)
