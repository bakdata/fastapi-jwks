from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel

from jwk.injector.payload_injector import JWTTokenInjector


class FakeUser(BaseModel):
    user: str


@pytest.mark.asyncio()
async def test_injector_return_call():
    user = FakeUser(user="my-fake-user")
    mock_request = MagicMock(state=MagicMock(payload=user))
    injector = JWTTokenInjector[FakeUser]()
    assert (await injector(mock_request)) == user
