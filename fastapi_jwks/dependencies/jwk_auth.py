from typing import final, override

from fastapi import HTTPException, status
from fastapi.security.http import HTTPBase
from pydantic import BaseModel
from starlette.requests import HTTPConnection

from fastapi_jwks.models.types import JWKSAuthConfig, JWKSAuthCredentials
from fastapi_jwks.validators import JWKSValidator


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
        self._challenge = auth_scheme
        super().__init__(
            scheme=self.auth_scheme, scheme_name=scheme_name, auto_error=False
        )

    def _unauthorized_error(
        self, detail: str = "Invalid authorization token"
    ) -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": self._challenge},
        )

    @override
    async def __call__(self, request: HTTPConnection) -> JWKSAuthCredentials[DataT]:
        authorization = request.headers.get(self.auth_header)
        if not authorization:
            raise self._unauthorized_error()

        scheme, _, token = authorization.partition(" ")
        token = token.strip()
        if scheme.lower() != self.auth_scheme or not token:
            raise self._unauthorized_error()

        try:
            payload = await self.jwks_validator.validate_token(token)
        except HTTPException as e:
            if e.status_code != status.HTTP_401_UNAUTHORIZED:
                raise
            raise self._unauthorized_error(e.detail) from None

        setattr(request.state, self.config.payload_field, payload)
        setattr(request.state, self.config.token_field, token)
        return JWKSAuthCredentials[DataT](
            scheme=scheme, credentials=token, payload=payload
        )
