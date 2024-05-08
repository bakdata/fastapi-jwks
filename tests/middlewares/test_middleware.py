import base64
from unittest.mock import patch

import jwt
import pytest
from fastapi import FastAPI
from pydantic import BaseModel
from starlette.requests import Request
from starlette.testclient import TestClient

from jwk.middlewares.jwk_auth import JWKAuthMiddleware, JWKSValidator
from jwk.middlewares.models.types import JWKSConfig, JWTDecodeConfig


class FakeToken(BaseModel):
    user: str


@pytest.fixture()
def jwks_fake_data():
    return {
        "keys": [
            {
                "kty": "oct",
                "use": "sig",
                "kid": "sYW9Qh23pPfbD06_F4UY6oAdi2FlNTwBAV6L6YMLY3o",
                "k": "b3NFUGVJR09BRW1JMzd6UTdYLUtaT0haci1ZUTZSVzhqaGd0QVhBdThKazZMSWFMclg3TXJsTHJ3YTZXenM3NWI4U1l3em1sQ0VLdXlJeXpVeXNDMmRLeVZ5RkVHSHZ5OWdtNk1PSGRTWjZXWDdWN3VIMHpaZmlkbDZhVV9LYTI0dnF3WHlYaXBKWHV5LWJoMVl4U0w4M0RRVnhmbk43X2NSMHNGbzVoSmFhUnJpT2NYWUt2SEJ2YXQ0dHFRMldJZnNTenJxdTA5alY0RFN4TjdXaTJ5NHJrU1dmVXY4cVV2ZU9OUHVUc3hQQURRb3RKdExsMUtEeGRjUHFIVkZPUTRmODhMZkZJb3ZreXZsNEZiSHM3Q05Uejh2Z0Etdml2cGhRNXJyVGVuUjUxaUd0c0lybC14V29KZXFzQ3lDVXdGdzl2SmxheFhqWXM0TDBsT3dLcGVR",
                "alg": "HS256",
            }
        ]
    }


@pytest.fixture()
def app(jwks_fake_data):
    test_app = FastAPI()

    @test_app.get("/test-endpoint", response_model=FakeToken)
    def get_test_route(request: Request):
        return request.state.payload

    jwks_verifier = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(url="http://my-fake-jwks-url/my-fake-endpoint"),
    )
    mocked_jwt = patch(
        "jwk.middlewares.jwk_auth.JWKSValidator.jwks_data", return_value=jwks_fake_data
    )
    mocked_jwt.start()

    mocked_jwt.return_value = jwks_fake_data
    test_app.add_middleware(JWKAuthMiddleware, jwks_validator=jwks_verifier)

    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def test_simple_example(client, jwks_fake_data):
    keys_definition = jwks_fake_data["keys"]
    key = keys_definition[0]["k"]
    algo = keys_definition[0]["alg"]
    kid = keys_definition[0]["kid"]

    claim = {"user": "my-fake-user"}
    signed_token = jwt.encode(
        claim, base64.urlsafe_b64decode(key), headers={"kid": kid}, algorithm=algo
    )

    response = client.get(
        "/test-endpoint", headers={"Authorization": f"Bearer {signed_token}"}
    )
    data = response.json()

    assert data["user"] == claim["user"]
    assert response.status_code == 200
