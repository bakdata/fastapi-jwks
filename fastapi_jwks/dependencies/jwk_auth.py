import sys
from typing import final

from fastapi import HTTPException, Request, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
)
from fastapi.security.http import HTTPBase

from fastapi_jwks.models.types import JWKSAuthConfig
from fastapi_jwks.validators import JWKSValidator

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override  # pyright: ignore[reportUnreachable]

UNAUTHORIZED_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid authorization token",
)


@final
class JWKSAuth(HTTPBase):
    def __init__(
        self,
        jwks_validator: JWKSValidator,
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
    async def __call__(self, request: Request) -> HTTPAuthorizationCredentials:
        authorization = request.headers.get(self.auth_header)
        if not authorization:
            raise UNAUTHORIZED_ERROR

        try:
            scheme, token = authorization.split()
            if scheme.lower() != self.auth_scheme.lower():
                raise UNAUTHORIZED_ERROR
        except ValueError as e:
            raise UNAUTHORIZED_ERROR from e

        try:
            payload = self.jwks_validator.validate_token(token)
            setattr(request.state, self.config.payload_field, payload)
            setattr(request.state, self.config.token_field, token)
        except Exception as e:
            raise UNAUTHORIZED_ERROR from e

        return HTTPAuthorizationCredentials(scheme=scheme, credentials=token)
