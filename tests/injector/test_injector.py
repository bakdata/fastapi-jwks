from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel

from fastapi_jwks.injector import JWTRawTokenInjector, JWTTokenInjector
from fastapi_jwks.models.types import JWTTokenInjectorConfig


class FakeUser(BaseModel):
    user: str


@pytest.mark.asyncio()
async def test_injector_return_call():
    user = FakeUser(user="my-fake-user")
    mock_request = MagicMock(state=MagicMock(payload=user))
    injector = JWTTokenInjector[FakeUser]()
    assert (await injector(mock_request)) == user


@pytest.mark.asyncio()
async def test_raw_token_injector_return_call():
    token = "my-fake-token"
    mock_request = MagicMock(state=MagicMock(raw_token=token))
    injector = JWTRawTokenInjector[str]()
    assert (await injector(mock_request)) == token


@pytest.mark.asyncio()
async def test_injector_with_custom_field():
    user = FakeUser(user="my-fake-user")
    mock_request = MagicMock(state=MagicMock(custom_payload=user))
    config = JWTTokenInjectorConfig(payload_field="custom_payload")
    injector = JWTTokenInjector[FakeUser](config=config)
    assert (await injector(mock_request)) == user


@pytest.mark.asyncio()
async def test_raw_token_injector_with_custom_field():
    token = "my-fake-token"
    mock_request = MagicMock(state=MagicMock(custom_token=token))
    config = JWTTokenInjectorConfig(token_field="custom_token")
    injector = JWTRawTokenInjector[str](config=config)
    assert (await injector(mock_request)) == token
