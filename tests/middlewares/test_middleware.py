import base64
import tempfile
from unittest.mock import MagicMock, patch

import jwt
import pytest
from fastapi import FastAPI
from pydantic import BaseModel
from starlette.requests import Request
from starlette.testclient import TestClient

from fastapi_jwks.middlewares.jwk_auth import JWKSAuthMiddleware
from fastapi_jwks.models.types import JWKSConfig, JWTDecodeConfig
from fastapi_jwks.validators import JWKSValidator


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
        "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
        return_value=jwks_fake_data,
    )
    mocked_jwt.start()
    test_app.add_middleware(JWKSAuthMiddleware, jwks_validator=jwks_verifier)
    yield test_app
    mocked_jwt.stop()


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


def test_custom_auth_header_and_scheme(jwks_fake_data):
    test_app = FastAPI()

    @test_app.get("/test-endpoint", response_model=FakeToken)
    def get_test_route(request: Request):
        return request.state.payload

    jwks_verifier = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(url="http://my-fake-jwks-url/my-fake-endpoint"),
    )
    mocked_jwt = patch(
        "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
        return_value=jwks_fake_data,
    )
    mocked_jwt.start()
    test_app.add_middleware(
        JWKSAuthMiddleware,
        jwks_validator=jwks_verifier,
        auth_header="X-Custom-Auth",
        auth_scheme="Token",
    )

    client = TestClient(test_app)

    keys_definition = jwks_fake_data["keys"]
    key = keys_definition[0]["k"]
    algo = keys_definition[0]["alg"]
    kid = keys_definition[0]["kid"]

    claim = {"user": "my-custom-user"}
    signed_token = jwt.encode(
        claim, base64.urlsafe_b64decode(key), headers={"kid": kid}, algorithm=algo
    )

    response = client.get(
        "/test-endpoint", headers={"X-Custom-Auth": f"Token {signed_token}"}
    )
    data = response.json()

    assert data["user"] == claim["user"]
    assert response.status_code == 200
    mocked_jwt.stop()


def test_invalid_auth_scheme(client, jwks_fake_data):
    keys_definition = jwks_fake_data["keys"]
    key = keys_definition[0]["k"]
    algo = keys_definition[0]["alg"]
    kid = keys_definition[0]["kid"]

    claim = {"user": "my-fake-user"}
    signed_token = jwt.encode(
        claim, base64.urlsafe_b64decode(key), headers={"kid": kid}, algorithm=algo
    )

    response = client.get(
        "/test-endpoint", headers={"Authorization": f"Invalid {signed_token}"}
    )
    assert response.status_code == 401
    assert "Invalid authentication scheme" in response.json()["detail"]


def test_missing_auth_header(client):
    response = client.get("/test-endpoint")
    assert response.status_code == 401
    assert "Authorization header missing" in response.json()["detail"]


def test_custom_ca_cert(jwks_fake_data):
    test_app = FastAPI()

    @test_app.get("/test-endpoint", response_model=FakeToken)
    def get_test_route(request: Request):
        return request.state.payload

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem") as ca_cert_file:
        ca_cert_file.write(
            "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"
        )
        ca_cert_file.flush()

        jwks_verifier = JWKSValidator[FakeToken](
            decode_config=JWTDecodeConfig(),
            jwks_config=JWKSConfig(
                url="http://my-fake-jwks-url/my-fake-endpoint",
                ca_cert_path=ca_cert_file.name,
            ),
        )

        with patch("httpx.Client") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_fake_data
            mock_response.raise_for_status.return_value = None
            mock_client.return_value.__enter__.return_value.get.return_value = (
                mock_response
            )

            test_app.add_middleware(JWKSAuthMiddleware, jwks_validator=jwks_verifier)
            client = TestClient(test_app)

            keys_definition = jwks_fake_data["keys"]
            key = keys_definition[0]["k"]
            algo = keys_definition[0]["alg"]
            kid = keys_definition[0]["kid"]

            claim = {"user": "my-custom-ca-user"}
            signed_token = jwt.encode(
                claim,
                base64.urlsafe_b64decode(key),
                headers={"kid": kid},
                algorithm=algo,
            )

            response = client.get(
                "/test-endpoint", headers={"Authorization": f"Bearer {signed_token}"}
            )
            data = response.json()

            assert data["user"] == claim["user"]
            assert response.status_code == 200
            mock_client.assert_called_once_with(verify=ca_cert_file.name)
            mock_client.return_value.__enter__.return_value.get.assert_called_once_with(
                "http://my-fake-jwks-url/my-fake-endpoint"
            )


def test_excluded_path(jwks_fake_data):
    test_app = FastAPI()

    @test_app.get("/public", response_model=dict)
    def public_route():
        return {"message": "This is a public route"}

    @test_app.get("/protected", response_model=FakeToken)
    def protected_route(request: Request):
        return request.state.payload

    jwks_verifier = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(url="http://my-fake-jwks-url/my-fake-endpoint"),
    )
    mocked_jwt = patch(
        "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
        return_value=jwks_fake_data,
    )
    mocked_jwt.start()
    test_app.add_middleware(
        JWKSAuthMiddleware, jwks_validator=jwks_verifier, exclude_paths=["/public"]
    )

    client = TestClient(test_app)

    # Test public route
    response = client.get("/public")
    assert response.status_code == 200
    assert response.json() == {"message": "This is a public route"}

    # Test protected route without token
    response = client.get("/protected")
    assert response.status_code == 401
    assert "Authorization header missing" in response.json()["detail"]

    # Test protected route with token
    keys_definition = jwks_fake_data["keys"]
    key = keys_definition[0]["k"]
    algo = keys_definition[0]["alg"]
    kid = keys_definition[0]["kid"]

    claim = {"user": "my-fake-user"}
    signed_token = jwt.encode(
        claim, base64.urlsafe_b64decode(key), headers={"kid": kid}, algorithm=algo
    )

    response = client.get(
        "/protected", headers={"Authorization": f"Bearer {signed_token}"}
    )
    data = response.json()

    assert data["user"] == claim["user"]
    assert response.status_code == 200

    mocked_jwt.stop()
