from typing import final, override

from fastapi import HTTPException, Request, status
from fastapi.security.http import HTTPBase
from pydantic import BaseModel

from fastapi_jwks.models.types import JWKSAuthConfig, JWKSAuthCredentials
from fastapi_jwks.validators import JWKSValidator

UNAUTHORIZED_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid authorization token",
)


@final
class JWKSAuth[DataT: BaseModel](HTTPBase):
    def __init__(
        self,
        jwks_validator: JWKSValidator[DataT],
        config: JWKSAuthConfig | None = None,
        auth_header: str = "Authorization",
        auth_scheme: str = "Bearer",
        scheme_name: str | None = None,
    ):
        self.config = config or JWKSAuthConfig()
        self.jwks_validator = jwks_validator
        self.auth_header = auth_header
        self.auth_scheme = auth_scheme.lower()
        super().__init__(
            scheme=self.auth_scheme, scheme_name=scheme_name, auto_error=False
        )

    @override
    async def __call__(self, request: Request) -> JWKSAuthCredentials[DataT]:
        authorization = request.headers.get(self.auth_header)
        if not authorization:
            raise UNAUTHORIZED_ERROR

        try:
            scheme, _, token = authorization.partition(" ")
            if scheme.lower() != self.auth_scheme:
                raise UNAUTHORIZED_ERROR
        except ValueError as e:
            raise UNAUTHORIZED_ERROR from e

        try:
            payload = self.jwks_validator.validate_token(token)
            setattr(request.state, self.config.payload_field, payload)
            setattr(request.state, self.config.token_field, token)
        except Exception as e:
            raise UNAUTHORIZED_ERROR from e

        return JWKSAuthCredentials[DataT](
            scheme=scheme, credentials=token, payload=payload
        )
