from typing import Optional, List

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from fastapi_jwks.validators import JWKSValidator


class JWKSAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        jwks_validator: JWKSValidator,
        auth_header: str = "Authorization",
        auth_scheme: str = "Bearer",
        exclude_paths: List[str] = [],
    ):
        super().__init__(app)
        self.jwks_validator = jwks_validator
        self.auth_header = auth_header
        self.auth_scheme = auth_scheme
        self.exclude_paths = exclude_paths

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        authorization: Optional[str] = request.headers.get(self.auth_header)
        if not authorization:
            return JSONResponse(
                status_code=401,
                content={"detail": "Authorization header missing"},
            )

        try:
            scheme, token = authorization.split()
            if scheme.lower() != self.auth_scheme.lower():
                return JSONResponse(
                    status_code=401,
                    content={"detail": f"Invalid authentication scheme. Expected {self.auth_scheme}"},
                )
        except ValueError:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid authorization header format"},
            )

        try:
            payload = self.jwks_validator.validate_token(token)
            request.state.payload = payload
        except Exception as e:
            return JSONResponse(
                status_code=401,
                content={"detail": str(e)},
            )

        return await call_next(request)
