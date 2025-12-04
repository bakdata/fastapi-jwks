import logging
from functools import cached_property
from typing import Any, final

import httpx
import jwt
import pydantic
from cachetools import TTLCache, cached
from fastapi import HTTPException, status
from jwt import algorithms
from pydantic import BaseModel

from fastapi_jwks.models.types import JWKS, JWKSConfig, JWTDecodeConfig, JWTHeader

logger = logging.getLogger("fastapi-jwks")


@final
class JWKSValidator[DataT: BaseModel]:
    def __init__(self, decode_config: JWTDecodeConfig, jwks_config: JWKSConfig):
        self.decode_config = decode_config
        self.jwks_config = jwks_config
        self.client = self._create_client()

    def _create_client(self) -> httpx.Client:
        client_kwargs: dict[str, Any] = {}
        if self.jwks_config.ca_cert_path:
            client_kwargs["verify"] = self.jwks_config.ca_cert_path
        return httpx.Client(**client_kwargs)

    @cached(cache=TTLCache(ttl=600, maxsize=1))
    def jwks_data(self) -> JWKS:
        try:
            logger.debug("Fetching JWKS from %s", self.jwks_config.url)
            jwks_response = self.client.get(self.jwks_config.url)
            jwks_response.raise_for_status()
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Invalid JWKS URI",
            ) from e
        try:
            return JWKS.model_validate(jwks_response.json())
        except pydantic.ValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Invalid JWKS"
            ) from e

    @cached_property
    def __is_generic_passed(self) -> bool:
        return getattr(self, "__orig_class__", None) is not None

    def validate_token(self, token: str) -> DataT:
        if not self.__is_generic_passed:
            raise ValueError(
                "Validator needs a model as generic value to decode payload"
            )

        public_key: bytes | None = None
        try:
            header = JWTHeader.model_validate(jwt.get_unverified_header(token))
            jwks_data = self.jwks_data()
            provided_algorithms = jwks_data.algorithms
            if provided_algorithms and header.alg not in provided_algorithms:
                logger.debug(
                    f"Could not find '{header.alg}' in provided algorithms: {provided_algorithms}"
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
                )
            for key in jwks_data.keys:
                if key.kid == header.kid:
                    public_key = algorithms.get_default_algorithms()[
                        header.alg
                    ].from_jwk(key.model_dump(exclude_none=True))
                    break
            if public_key is None:
                logger.debug(
                    f"No public key for provided algorithm '{header.alg}' found in JWKS data"
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
                )
            return self.__orig_class__.__args__[0].model_validate(  # pyright: ignore[reportAttributeAccessIssue]
                # This line gets the generic value in runtime to transform it to the correct pydantic model
                jwt.decode(
                    token,
                    key=public_key,
                    **self.decode_config.model_dump(),
                    algorithms=[header.alg],
                )
            )
        except jwt.ExpiredSignatureError:
            logger.debug("Expired token", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired"
            ) from None
        except (pydantic.ValidationError, jwt.InvalidTokenError):
            logger.debug("Invalid token", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            ) from None
