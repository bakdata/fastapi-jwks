from pydantic import BaseModel
from starlette.requests import Request

from fastapi_jwks.models.types import JWTTokenInjectorConfig


class JWTTokenInjector[DataT: BaseModel]:
    def __init__(self, config: JWTTokenInjectorConfig | None = None):
        self.config: JWTTokenInjectorConfig = config or JWTTokenInjectorConfig()

    async def __call__(self, request: Request) -> DataT:
        return getattr(request.state, self.config.payload_field)


class JWTRawTokenInjector:
    def __init__(self, config: JWTTokenInjectorConfig | None = None):
        self.config: JWTTokenInjectorConfig = config or JWTTokenInjectorConfig()

    async def __call__(self, request: Request) -> str:
        return getattr(request.state, self.config.token_field)
