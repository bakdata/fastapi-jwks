from datetime import timedelta
from typing import Any

from pydantic import BaseModel


class JWTDecodeConfig(BaseModel):
    audience: list[str] | None = None
    issuer: str | None = None
    leeway: float | timedelta | None = None
    options: dict[str, Any] | None = None
    verify: bool | None = None


class JWKSConfig(BaseModel):
    url: str
    ca_cert_path: str | None = None
