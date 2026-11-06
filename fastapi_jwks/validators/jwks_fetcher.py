import asyncio
import logging
import ssl
import time
from typing import final

import httpx

from fastapi_jwks.models.types import JWKS, JWKSConfig

logger = logging.getLogger("fastapi-jwks")


class JWKSUnavailableError(Exception):
    """Raised when no usable JWKS can be provided."""


@final
class JWKSFetcher:
    """Fetches a JWKS and caches it per instance.

    Concurrent refreshes are coalesced into a single request, forced refreshes
    and retries after a failed fetch are rate limited by
    ``JWKSConfig.refresh_cooldown``, and the last good JWKS is served when a
    refresh fails.
    """

    def __init__(
        self,
        config: JWKSConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.config = config
        self._transport = transport
        self._verify: ssl.SSLContext | bool = (
            ssl.create_default_context(cafile=config.ca_cert_path)
            if config.ca_cert_path
            else True
        )
        self._jwks: JWKS | None = None
        self._fetched_at: float = 0.0
        self._attempted_at: float | None = None
        self._last_failed = False
        self._attempts = 0
        self._lock: asyncio.Lock | None = None
        self._lock_loop: asyncio.AbstractEventLoop | None = None

    async def get_jwks(self, *, force_refresh: bool = False) -> JWKS:
        if (jwks := self._cached(force_refresh)) is not None:
            return jwks
        attempts = self._attempts
        async with self._get_lock():
            if self._attempts != attempts:
                # Another caller fetched while we were waiting for the lock
                return self._current()
            return await self._fetch()

    def _cached(self, force_refresh: bool) -> JWKS | None:
        """Return the JWKS to serve without I/O, or None if a fetch is due."""
        now = time.monotonic()
        cooling_down = (
            self._attempted_at is not None
            and now - self._attempted_at < self.config.refresh_cooldown
        )
        if self._jwks is None:
            if cooling_down:
                raise JWKSUnavailableError(
                    f"JWKS from {self.config.url} is unavailable, retrying after cooldown"
                )
            return None
        if not force_refresh and now - self._fetched_at < self.config.cache_ttl:
            return self._jwks
        if cooling_down and (force_refresh or self._last_failed):
            return self._jwks
        return None

    def _current(self) -> JWKS:
        if self._jwks is None:
            raise JWKSUnavailableError(f"JWKS from {self.config.url} is unavailable")
        return self._jwks

    def _get_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            self._lock, self._lock_loop = asyncio.Lock(), loop
        return self._lock

    async def _fetch(self) -> JWKS:
        try:
            jwks = await self._download()
        # ValueError covers invalid JSON and pydantic.ValidationError
        except (httpx.HTTPError, ValueError) as e:
            self._finish_attempt(failed=True)
            logger.warning("Failed to fetch JWKS from %s: %s", self.config.url, e)
            if self._jwks is None:
                raise JWKSUnavailableError(
                    f"Could not fetch JWKS from {self.config.url}"
                ) from e
            return self._jwks
        self._jwks = jwks
        self._fetched_at = self._finish_attempt(failed=False)
        return jwks

    def _finish_attempt(self, *, failed: bool) -> float:
        self._attempts += 1
        self._attempted_at = now = time.monotonic()
        self._last_failed = failed
        return now

    async def _download(self) -> JWKS:
        logger.debug("Fetching JWKS from %s", self.config.url)
        async with httpx.AsyncClient(
            verify=self._verify,
            timeout=self.config.timeout,
            transport=self._transport,
        ) as client:
            response = await client.get(self.config.url)
            response.raise_for_status()
        return JWKS.model_validate(response.json())
