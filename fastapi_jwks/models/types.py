from datetime import timedelta
from typing import Any, Optional

from pydantic import BaseModel, HttpUrl


class JWTDecodeConfig(BaseModel):
    audience: list[str] | None = None
    issuer: str | None = None
    leeway: float | timedelta | None = None
    options: dict[str, Any] | None = None
    verify: bool | None = None


class JWKSConfig(BaseModel):
    url: HttpUrl
    ca_cert_path: Optional[str] = None
