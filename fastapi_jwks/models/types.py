from datetime import timedelta
from typing import Annotated, Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field


class JWTDecodeConfig(BaseModel):
    audience: list[str] | None = None
    issuer: str | None = None
    leeway: float | timedelta | None = None
    options: dict[str, Any] | None = None
    verify: bool | None = None


class JWKSMiddlewareConfig(BaseModel):
    payload_field: str = "payload"
    token_field: str = "raw_token"


class JWKSConfig(BaseModel):
    url: str
    ca_cert_path: str | None = None


class JWTTokenInjectorConfig(BaseModel):
    payload_field: str = "payload"
    token_field: str = "raw_token"


class JWTHeader(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow")

    alg: Annotated[str | None, Field(description="Algorithm used for signing")] = None
    typ: Annotated[
        str | None,
        Field(description="Type of token", examples=["JWT"]),
    ] = None
    cty: Annotated[str | None, Field(description="Content type")] = None
    kid: Annotated[str | None, Field(description="Key ID")] = None
    x5u: Annotated[str | None, Field(description="X.509 URL")] = None
    x5c: Annotated[list[str] | None, Field(description="X.509 Certificate Chain")] = (
        None
    )
    x5t: Annotated[
        str | None, Field(description="X.509 Certificate SHA-1 Thumbprint")
    ] = None
    x5tS256: Annotated[
        str | None, Field(description="X.509 Certificate SHA-256 Thumbprint")
    ] = None
