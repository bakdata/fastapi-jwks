from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from fastapi_jwks.validators import JWKSValidator


class JWKSAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        jwks_validator: JWKSValidator,
        auth_header: str = "Authorization",
        auth_scheme: str = "Bearer",
        exclude_paths: list[str] | None = None,
    ):
        super().__init__(app)
        self.jwks_validator = jwks_validator
        self.auth_header = auth_header
        self.auth_scheme = auth_scheme
        self.exclude_paths = [] if exclude_paths is None else exclude_paths

    def unauthorized_response(self) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={
                "title": "Unauthorized",
                "detail": "Invalid authorization token",
            },
        )

    async def dispatch(self, request: Request, call_next) -> Response:
        if self.exclude_paths and request.url.path in self.exclude_paths:
            return await call_next(request)

        authorization: str | None = request.headers.get(self.auth_header)
        if not authorization:
            return self.unauthorized_response()

        try:
            scheme, token = authorization.split()
            if scheme.lower() != self.auth_scheme.lower():
                return self.unauthorized_response()
        except ValueError:
            return self.unauthorized_response()

        try:
            payload = self.jwks_validator.validate_token(token)
            request.state.payload = payload
        except Exception:
            return self.unauthorized_response()

        return await call_next(request)
