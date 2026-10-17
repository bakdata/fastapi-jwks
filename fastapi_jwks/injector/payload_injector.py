from typing import Any

from pydantic import BaseModel
from starlette.requests import Request

from fastapi_jwks.models.types import JWTTokenInjectorConfig


def _get_state(request: Request, field: str) -> Any:
    try:
        return getattr(request.state, field)
    except AttributeError:
        raise RuntimeError(
            f"Request state has no '{field}' field. Add JWKSAuth as a dependency of "
            "this route, e.g. via Security(jwks_auth), and make sure its state "
            "field names match the injector config."
        ) from None


class JWTTokenInjector[DataT: BaseModel]:
    def __init__(self, config: JWTTokenInjectorConfig | None = None):
        self.config: JWTTokenInjectorConfig = config or JWTTokenInjectorConfig()

    async def __call__(self, request: Request) -> DataT:
        return _get_state(request, self.config.payload_field)


class JWTRawTokenInjector:
    def __init__(self, config: JWTTokenInjectorConfig | None = None):
        self.config: JWTTokenInjectorConfig = config or JWTTokenInjectorConfig()

    async def __call__(self, request: Request) -> str:
        return _get_state(request, self.config.token_field)
