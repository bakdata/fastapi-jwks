import asyncio
import ssl
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from fastapi_jwks.models.types import JWKSConfig
from fastapi_jwks.validators import JWKSFetcher, JWKSUnavailableError
from fastapi_jwks.validators import jwks_fetcher as jwks_fetcher_module

URL = "https://idp.example.com/jwks"
TTL = 600
COOLDOWN = 30


def jwks_body(kid: str) -> dict[str, Any]:
    return {"keys": [{"kty": "oct", "kid": kid, "k": "c2VjcmV0"}]}


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeIdP:
    """Mock JWKS endpoint returning a queue of responses (the last one repeats)."""

    def __init__(self, *responses: httpx.Response, delay: float = 0) -> None:
        self.responses = list(responses) or [httpx.Response(200, json=jwks_body("a"))]
        self.delay = delay
        self.requests = 0

    async def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if len(self.responses) > 1:
            return self.responses.pop(0)
        return self.responses[0]

    def fetcher(self) -> JWKSFetcher:
        return JWKSFetcher(
            JWKSConfig(url=URL, cache_ttl=TTL, refresh_cooldown=COOLDOWN),
            transport=httpx.MockTransport(self.handler),
        )


def ok(kid: str) -> httpx.Response:
    return httpx.Response(200, json=jwks_body(kid))


@pytest.fixture()
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    fake = FakeClock()
    monkeypatch.setattr(
        jwks_fetcher_module, "time", SimpleNamespace(monotonic=lambda: fake.now)
    )
    return fake


async def kid_of(fetcher: JWKSFetcher, **kwargs: bool) -> str | None:
    return (await fetcher.get_jwks(**kwargs)).keys[0].kid


@pytest.mark.asyncio()
async def test_fresh_cache_hit(clock: FakeClock):
    idp = FakeIdP()
    fetcher = idp.fetcher()
    for _ in range(5):
        assert await kid_of(fetcher) == "a"
        clock.advance(TTL / 10)
    assert idp.requests == 1


@pytest.mark.asyncio()
async def test_ttl_expiry_refetches(clock: FakeClock):
    idp = FakeIdP(ok("a"), ok("b"))
    fetcher = idp.fetcher()
    assert await kid_of(fetcher) == "a"
    clock.advance(TTL + 1)
    assert await kid_of(fetcher) == "b"
    assert idp.requests == 2


@pytest.mark.asyncio()
async def test_instances_do_not_share_cache(clock: FakeClock):
    idp_a, idp_b = FakeIdP(ok("a")), FakeIdP(ok("b"))
    fetcher_a, fetcher_b = idp_a.fetcher(), idp_b.fetcher()
    for _ in range(3):
        assert await kid_of(fetcher_a) == "a"
        assert await kid_of(fetcher_b) == "b"
    assert (idp_a.requests, idp_b.requests) == (1, 1)


@pytest.mark.asyncio()
async def test_force_refresh_respects_cooldown(clock: FakeClock):
    idp = FakeIdP(ok("a"), ok("b"))
    fetcher = idp.fetcher()
    assert await kid_of(fetcher) == "a"
    clock.advance(COOLDOWN - 1)
    assert await kid_of(fetcher, force_refresh=True) == "a"
    assert idp.requests == 1
    clock.advance(1)
    assert await kid_of(fetcher, force_refresh=True) == "b"
    assert idp.requests == 2


@pytest.mark.asyncio()
@pytest.mark.parametrize("force_refresh", [False, True])
async def test_concurrent_callers_single_request(clock: FakeClock, force_refresh: bool):
    idp = FakeIdP(ok("a"), ok("b"), delay=0.01)
    fetcher = idp.fetcher()
    if force_refresh:
        await fetcher.get_jwks()
        clock.advance(COOLDOWN)
    results = await asyncio.gather(
        *(fetcher.get_jwks(force_refresh=force_refresh) for _ in range(10))
    )
    assert {jwks.keys[0].kid for jwks in results} == {"b" if force_refresh else "a"}
    assert idp.requests == (2 if force_refresh else 1)


@pytest.mark.asyncio()
async def test_concurrent_callers_share_failure(clock: FakeClock):
    idp = FakeIdP(httpx.Response(500), delay=0.01)
    fetcher = idp.fetcher()
    results = await asyncio.gather(
        *(fetcher.get_jwks() for _ in range(5)), return_exceptions=True
    )
    assert all(isinstance(result, JWKSUnavailableError) for result in results)
    assert idp.requests == 1


@pytest.mark.asyncio()
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500),
        httpx.Response(404),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json={"keys": []}),
    ],
)
async def test_unavailable_without_cache(clock: FakeClock, response: httpx.Response):
    fetcher = FakeIdP(response).fetcher()
    with pytest.raises(JWKSUnavailableError) as exc_info:
        await fetcher.get_jwks()
    assert exc_info.value.__cause__ is not None


@pytest.mark.asyncio()
async def test_unavailable_on_connection_error(clock: FakeClock):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    fetcher = JWKSFetcher(JWKSConfig(url=URL), transport=httpx.MockTransport(handler))
    with pytest.raises(JWKSUnavailableError) as exc_info:
        await fetcher.get_jwks()
    assert isinstance(exc_info.value.__cause__, httpx.ConnectError)


@pytest.mark.asyncio()
@pytest.mark.parametrize(
    "failure",
    [
        httpx.Response(500),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json={"keys": [{"no": "kty"}]}),
    ],
)
async def test_stale_if_error(clock: FakeClock, failure: httpx.Response):
    idp = FakeIdP(ok("a"), failure, ok("b"))
    fetcher = idp.fetcher()
    assert await kid_of(fetcher) == "a"
    clock.advance(TTL + 1)
    assert await kid_of(fetcher) == "a"
    assert idp.requests == 2

    clock.advance(COOLDOWN - 1)
    assert await kid_of(fetcher) == "a"
    assert idp.requests == 2

    clock.advance(1)
    assert await kid_of(fetcher) == "b"
    assert idp.requests == 3


@pytest.mark.asyncio()
async def test_no_retry_within_cooldown_after_failure(clock: FakeClock):
    idp = FakeIdP(httpx.Response(503), ok("a"))
    fetcher = idp.fetcher()
    for _ in range(3):
        with pytest.raises(JWKSUnavailableError):
            await fetcher.get_jwks()
        clock.advance(COOLDOWN / 4)
    assert idp.requests == 1

    clock.advance(COOLDOWN)
    assert await kid_of(fetcher) == "a"
    assert idp.requests == 2


def test_works_across_event_loops(clock: FakeClock):
    idp = FakeIdP(ok("a"), ok("b"), delay=0.01)
    fetcher = idp.fetcher()

    def run(get: Callable[[], Any]) -> set[str | None]:
        async def gather() -> set[str | None]:
            results = await asyncio.gather(*(get() for _ in range(3)))
            return {jwks.keys[0].kid for jwks in results}

        return asyncio.run(gather())

    assert run(fetcher.get_jwks) == {"a"}
    clock.advance(TTL + 1)
    assert run(fetcher.get_jwks) == {"b"}
    assert idp.requests == 2


def test_ca_cert_path_builds_ssl_context():
    cafile = "/etc/ssl/certs/ca-certificates.crt"
    try:
        fetcher = JWKSFetcher(JWKSConfig(url=URL, ca_cert_path=cafile))
    except FileNotFoundError:
        pytest.skip("system CA bundle not available")
    assert isinstance(fetcher._verify, ssl.SSLContext)
