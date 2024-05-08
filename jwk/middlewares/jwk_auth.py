from typing import Any, Generic, TypeVar

import jwt
import requests
from cachetools import TTLCache, cached
from fastapi import HTTPException
from jwt import algorithms
from loguru import logger
from pydantic import BaseModel
from starlette.middleware.base import (
    BaseHTTPMiddleware,
    DispatchFunction,
    RequestResponseEndpoint,
)
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from jwk.middlewares.models.types import JWKSConfig, JWTDecodeConfig

DataT = TypeVar("DataT", bound=BaseModel)


class JWKSValidator(Generic[DataT]):
    def __init__(self, decode_config: JWTDecodeConfig, jwks_config: JWKSConfig):
        self.decode_config = decode_config
        self.jwks_config = jwks_config

    @cached(cache=TTLCache(ttl=600, maxsize=100))
    def jwks_data(self) -> dict[str, Any]:
        try:
            logger.debug("Fetching JWKS from %s", self.jwks_config.url)
            jwks_response = requests.get(self.jwks_config.url)
            jwks_response.raise_for_status()
        except requests.RequestException as e:
            logger.error("Invalid JWKS URI")
            raise HTTPException(status_code=503, detail="Invalid JWKS URI") from e
        jwks: dict[str, Any] = jwks_response.json()
        if "keys" not in jwks:
            logger.error("Invalid JWKS")
            raise HTTPException(status_code=503, detail="Invalid JWKS")
        return jwks

    @staticmethod
    def __extract_algorithms(jwks_response: dict[str, Any]) -> list[str]:
        if "keys" not in jwks_response:
            raise ValueError("JWKS response does not contain keys")
        keys = jwks_response["keys"]
        return [key["alg"] for key in keys]

    def validate_token(self, token: str) -> DataT:
        public_key = None
        try:
            header = jwt.get_unverified_header(token)
            kid = header["kid"]
            jwks_data = self.jwks_data()
            if header["alg"] not in self.__extract_algorithms(jwks_data):
                raise HTTPException(status_code=401, detail="Invalid token")
            for key in jwks_data["keys"]:
                if key["kid"] == kid:
                    public_key = algorithms.get_default_algorithms()[
                        header["alg"]
                    ].from_jwk(key)
                    break
            if public_key is None:
                raise HTTPException(status_code=401, detail="Invalid token")
            return self.__orig_class__.__args__[0].model_validate( # type: ignore
                jwt.decode(
                    token,
                    key=public_key,
                    **self.decode_config.model_dump(),
                    algorithms=[header["alg"]],
                )
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired") from None
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token") from None


class JWKAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        jwks_validator: JWKSValidator,
        dispatch: DispatchFunction | None = None,
    ) -> None:
        super().__init__(app, dispatch)
        self.jwk_validator = jwks_validator

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        bearer_token = request.headers.get("authorization") or request.headers.get(
            "Authorization"
        )
        if not bearer_token or not bearer_token.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid token")
        token = bearer_token[7:]
        request.state.payload = self.jwk_validator.validate_token(token)
        response = await call_next(request)
        return response
