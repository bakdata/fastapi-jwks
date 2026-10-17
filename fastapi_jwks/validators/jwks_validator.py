import logging
from functools import cached_property
from typing import final, get_args

import jwt
import pydantic
from fastapi import HTTPException, status
from pydantic import BaseModel

from fastapi_jwks.models.types import (
    JWK,
    JWKS,
    JWKSConfig,
    JWTDecodeConfig,
    JWTHeader,
)
from fastapi_jwks.validators.jwks_fetcher import JWKSFetcher, JWKSUnavailableError

logger = logging.getLogger("fastapi-jwks")


class _InvalidTokenError(Exception):
    pass


def _is_signing_key(key: JWK) -> bool:
    # Symmetric ("oct") keys are skipped: the JWKS is fetched without
    # authentication, so anyone who can read such a key could forge tokens with it
    return key.use in ("sig", None) and key.kty != "oct"


@final
class JWKSValidator[DataT: BaseModel]:
    def __init__(self, decode_config: JWTDecodeConfig, jwks_config: JWKSConfig):
        self.decode_config = decode_config
        self.jwks_config = jwks_config
        self.fetcher = JWKSFetcher(jwks_config)

    async def jwks_data(self, *, force_refresh: bool = False) -> JWKS:
        return await self.fetcher.get_jwks(force_refresh=force_refresh)

    @cached_property
    def _payload_model(self) -> type[DataT]:
        args = get_args(getattr(self, "__orig_class__", None))
        if not args:
            raise ValueError(
                "Validator needs a model as generic value to decode payload"
            )
        return args[0]

    async def validate_token(self, token: str) -> DataT:
        payload_model = self._payload_model

        try:
            header = JWTHeader.model_validate(jwt.get_unverified_header(token))
            key = await self._find_key(header)
            signing_key = self._signing_key(key, header)
            allowed_algorithms = self._allowed_algorithms(signing_key)
            if (
                header.alg != signing_key.algorithm_name
                or header.alg not in allowed_algorithms
            ):
                logger.debug(
                    "Token algorithm '%s' does not match key algorithm '%s' or allowed algorithms %s",
                    header.alg,
                    signing_key.algorithm_name,
                    allowed_algorithms,
                )
                raise _InvalidTokenError
            payload = jwt.decode(
                token,
                key=signing_key,
                algorithms=allowed_algorithms,
                **self.decode_config.model_dump(exclude={"algorithms"}),
            )
            return payload_model.model_validate(payload)
        except JWKSUnavailableError:
            logger.debug("JWKS unavailable", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="JWKS unavailable",
            ) from None
        except jwt.ExpiredSignatureError:
            logger.debug("Expired token", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired"
            ) from None
        except (_InvalidTokenError, jwt.PyJWTError, pydantic.ValidationError):
            logger.debug("Invalid token", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            ) from None

    async def _find_key(self, header: JWTHeader) -> JWK:
        for force_refresh in (False, True):
            jwks = await self.jwks_data(force_refresh=force_refresh)
            for key in jwks.keys:
                if _is_signing_key(key) and key.kid == header.kid:
                    return key
            logger.debug("No signing key found for kid '%s'", header.kid)
        raise _InvalidTokenError

    def _signing_key(self, key: JWK, header: JWTHeader) -> jwt.PyJWK:
        algorithm = key.alg
        if algorithm is None and header.alg in (self.decode_config.algorithms or ()):
            algorithm = header.alg
        try:
            return jwt.PyJWK(
                key.model_dump(by_alias=True, exclude_none=True), algorithm=algorithm
            )
        except NotImplementedError as e:
            # Raised by algorithms such as "none" that cannot be built from a JWK
            raise _InvalidTokenError from e

    def _allowed_algorithms(self, signing_key: jwt.PyJWK) -> list[str]:
        if self.decode_config.algorithms is not None:
            return self.decode_config.algorithms
        return [signing_key.algorithm_name]
