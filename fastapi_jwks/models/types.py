from datetime import timedelta
from typing import Annotated, Any, ClassVar

from fastapi.security import HTTPAuthorizationCredentials
from pydantic import AnyUrl, BaseModel, ConfigDict, Field


class JWTDecodeConfig(BaseModel):
    """Options passed to pyjwt's jwt.decode()"""

    audience: list[str] | None = None
    issuer: str | None = None
    leeway: float | timedelta = 0
    options: dict[str, Any] | None = None
    verify: bool | None = None


class JWKSAuthConfig(BaseModel):
    payload_field: str = "payload"
    token_field: str = "raw_token"


class JWKSConfig(BaseModel):
    url: str
    ca_cert_path: str | None = None


class JWTTokenInjectorConfig(BaseModel):
    payload_field: str = "payload"
    token_field: str = "raw_token"


class JWKSAuthCredentials[DataT: BaseModel](HTTPAuthorizationCredentials):
    payload: DataT


class JWTHeader(BaseModel):
    """JSON Web Token

    RFC: https://datatracker.ietf.org/doc/html/rfc7519
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow")

    alg: Annotated[str, Field(description="Algorithm used for signing")]
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
    x5t_s256: Annotated[
        str | None,
        Field(
            description="X.509 Certificate SHA-256 Thumbprint",
            validation_alias="x5t#S256",
        ),
    ] = None


class JWK(BaseModel):
    """JSON Web Key

    RFC: https://datatracker.ietf.org/doc/html/rfc7517#section-4
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", frozen=True)

    kty: Annotated[str, Field(description="Key Type")]
    use: Annotated[str | None, Field(description="Public key use")] = None
    key_ops: Annotated[list[str] | None, Field(description="Key operations")] = None
    alg: Annotated[str | None, Field(description="Algorithm intended for the key")] = (
        None
    )
    kid: Annotated[str | None, Field(description="Key ID")] = None
    x5u: Annotated[AnyUrl | None, Field(description="X.509 URL")] = None
    x5c: Annotated[list[str] | None, Field(description="X.509 Certificate Chain")] = (
        None
    )
    x5t: Annotated[
        str | None, Field(description="X.509 Certificate SHA-1 Thumbprint")
    ] = None
    x5t_s256: Annotated[
        str | None,
        Field(
            description="X.509 Certificate SHA-256 Thumbprint",
            validation_alias="x5t#S256",
        ),
    ] = None
    n: Annotated[str | None, Field(description="Modulus for RSA keys")] = None
    e: Annotated[str | None, Field(description="Exponent for RSA keys")] = None
    crv: Annotated[str | None, Field(description="Curve for EC keys")] = None
    x: Annotated[str | None, Field(description="X coordinate for EC keys")] = None
    y: Annotated[str | None, Field(description="Y coordinate for EC keys")] = None
    d: Annotated[
        str | None, Field(description="Private exponent for RSA or EC private key")
    ] = None
    k: Annotated[str | None, Field(description="Symmetric key value")] = None


class JWKS(BaseModel):
    keys: Annotated[list[JWK], Field(min_length=1)]

    @property
    def algorithms(self) -> list[str]:
        return [key.alg for key in self.keys if key.alg is not None]
