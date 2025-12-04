import base64
import tempfile
from collections.abc import Generator
from typing import Annotated
from unittest.mock import MagicMock, patch

import jwt
import pytest
from fastapi import FastAPI, Security, status
from pydantic import BaseModel
from starlette.requests import Request
from starlette.testclient import TestClient

from fastapi_jwks.dependencies.jwk_auth import JWKSAuth
from fastapi_jwks.injector.payload_injector import JWTRawTokenInjector, JWTTokenInjector
from fastapi_jwks.models.types import (
    JWKS,
    JWKSAuthConfig,
    JWKSAuthCredentials,
    JWKSConfig,
    JWTDecodeConfig,
    JWTTokenInjectorConfig,
)
from fastapi_jwks.validators import JWKSValidator


class FakeToken(BaseModel):
    user: str


@pytest.fixture()
def jwks_fake_data() -> JWKS:
    return JWKS.model_validate(
        {
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
    )


@pytest.fixture()
def jwks_auth(jwks_fake_data: JWKS) -> Generator[JWKSAuth[FakeToken]]:
    jwks_verifier = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(url="http://my-fake-jwks-url/my-fake-endpoint"),
    )
    mocked_jwt = patch(
        "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
        return_value=jwks_fake_data,
    )
    mocked_jwt.start()
    yield JWKSAuth(jwks_validator=jwks_verifier, scheme_name="AuthToken")
    mocked_jwt.stop()


@pytest.fixture()
def app(jwks_auth: JWKSAuth) -> FastAPI:
    test_app = FastAPI(dependencies=[Security(jwks_auth)])

    @test_app.get("/test-endpoint", response_model=FakeToken)
    def get_test_route(request: Request):
        return request.state.payload

    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def test_openapi_security_schema(app: FastAPI):
    openapi = app.openapi()
    assert openapi["components"]["securitySchemes"] == {
        "AuthToken": {"scheme": "bearer", "type": "http"}
    }
    assert openapi["paths"]["/test-endpoint"]["get"]["security"] == [{"AuthToken": []}]


@pytest.fixture()
def signed_token(jwks_fake_data: JWKS) -> str:
    jwk = jwks_fake_data.keys[0]
    key = jwk.k
    assert key
    algo = jwk.alg
    kid = jwk.kid

    claim = {"user": "my-fake-user"}
    signed_token = jwt.encode(
        claim, base64.urlsafe_b64decode(key), headers={"kid": kid}, algorithm=algo
    )
    return signed_token


def test_simple_example(client: TestClient, signed_token: str):
    response = client.get(
        "/test-endpoint", headers={"Authorization": f"Bearer {signed_token}"}
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["user"] == "my-fake-user"


def test_dependency_return_type(jwks_auth: JWKSAuth[FakeToken], signed_token: str):
    test_app = FastAPI()

    @test_app.get("/test-endpoint")
    def get_test_route(
        credentials: Annotated[JWKSAuthCredentials[FakeToken], Security(jwks_auth)],
    ) -> FakeToken:
        return credentials.payload

    client = TestClient(test_app)
    response = client.get(
        "/test-endpoint", headers={"Authorization": f"Bearer {signed_token}"}
    )
    assert response.is_success
    data = response.json()
    assert FakeToken.model_validate(data).user == "my-fake-user"


def test_custom_auth_header_and_scheme(jwks_fake_data: JWKS):
    jwks_verifier = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(url="http://my-fake-jwks-url/my-fake-endpoint"),
    )
    mocked_jwt = patch(
        "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
        return_value=jwks_fake_data,
    )
    mocked_jwt.start()
    jwks_auth = JWKSAuth(
        jwks_validator=jwks_verifier,
        auth_header="X-Custom-Auth",
        auth_scheme="Token",
    )

    test_app = FastAPI(dependencies=[Security(jwks_auth)])

    @test_app.get("/test-endpoint", response_model=FakeToken)
    def get_test_route(request: Request):
        return request.state.payload

    client = TestClient(test_app)

    jwk = jwks_fake_data.keys[0]
    key = jwk.k
    assert key
    algo = jwk.alg
    kid = jwk.kid

    claim = {"user": "my-custom-user"}
    signed_token = jwt.encode(
        claim, base64.urlsafe_b64decode(key), headers={"kid": kid}, algorithm=algo
    )

    response = client.get(
        "/test-endpoint", headers={"X-Custom-Auth": f"Token {signed_token}"}
    )
    data = response.json()

    assert data["user"] == claim["user"]
    assert response.status_code == status.HTTP_200_OK
    mocked_jwt.stop()


def test_invalid_auth_scheme(client, jwks_fake_data: JWKS):
    jwk = jwks_fake_data.keys[0]
    key = jwk.k
    assert key
    algo = jwk.alg
    kid = jwk.kid

    claim = {"user": "my-fake-user"}
    signed_token = jwt.encode(
        claim, base64.urlsafe_b64decode(key), headers={"kid": kid}, algorithm=algo
    )

    response = client.get(
        "/test-endpoint", headers={"Authorization": f"Invalid {signed_token}"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Invalid authorization token"


def test_missing_auth_header(client):
    response = client.get("/test-endpoint")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Invalid authorization token"


def test_custom_ca_cert(jwks_fake_data: JWKS):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem") as ca_cert_file:
        ca_cert_file.write(
            "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"
        )
        ca_cert_file.flush()

        with patch("httpx.Client") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_fake_data
            mock_response.raise_for_status.return_value = None
            mock_client.return_value.get.return_value = mock_response

            jwks_verifier = JWKSValidator[FakeToken](
                decode_config=JWTDecodeConfig(),
                jwks_config=JWKSConfig(
                    url="http://my-fake-jwks-url/my-fake-endpoint",
                    ca_cert_path=ca_cert_file.name,
                ),
            )

            jwks_auth = JWKSAuth(jwks_validator=jwks_verifier)
            test_app = FastAPI(dependencies=[Security(jwks_auth)])

            @test_app.get("/test-endpoint", response_model=FakeToken)
            def get_test_route(request: Request):
                return request.state.payload

            client = TestClient(test_app)

            jwk = jwks_fake_data.keys[0]
            key = jwk.k
            assert key
            algo = jwk.alg
            kid = jwk.kid

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
            assert response.status_code == status.HTTP_200_OK
            mock_client.assert_called_once_with(verify=ca_cert_file.name)
            mock_client.return_value.get.assert_called_once_with(
                "http://my-fake-jwks-url/my-fake-endpoint"
            )


def test_custom_state_fields(jwks_fake_data: JWKS):
    jwks_verifier = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(url="http://my-fake-jwks-url/my-fake-endpoint"),
    )
    mocked_jwt = patch(
        "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
        return_value=jwks_fake_data,
    )
    mocked_jwt.start()

    jwks_auth = JWKSAuth(
        jwks_validator=jwks_verifier,
        config=JWKSAuthConfig(
            payload_field="custom_payload", token_field="custom_token"
        ),
    )
    test_app = FastAPI(dependencies=[Security(jwks_auth)])

    @test_app.get("/test-endpoint", response_model=dict)
    def get_test_route(request: Request):
        return {
            "custom_payload": request.state.custom_payload.model_dump(),
            "custom_token": request.state.custom_token,
        }

    client = TestClient(test_app)

    # Test without token
    response = client.get("/test-endpoint")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Invalid authorization token"

    # Test with token
    jwk = jwks_fake_data.keys[0]
    key = jwk.k
    assert key
    algo = jwk.alg
    kid = jwk.kid

    claim = {"user": "custom-fields-user"}
    signed_token = jwt.encode(
        claim, base64.urlsafe_b64decode(key), headers={"kid": kid}, algorithm=algo
    )

    response = client.get(
        "/test-endpoint", headers={"Authorization": f"Bearer {signed_token}"}
    )
    data = response.json()

    assert data["custom_payload"]["user"] == claim["user"]
    assert data["custom_token"] == signed_token
    assert response.status_code == status.HTTP_200_OK
    mocked_jwt.stop()


@pytest.mark.asyncio()
async def test_token_injector_with_custom_fields(jwks_fake_data: JWKS):
    jwks_verifier = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(url="http://my-fake-jwks-url/my-fake-endpoint"),
    )
    mocked_jwt = patch(
        "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
        return_value=jwks_fake_data,
    )
    mocked_jwt.start()

    jwks_auth = JWKSAuth(
        jwks_validator=jwks_verifier,
        config=JWKSAuthConfig(
            payload_field="custom_payload", token_field="custom_token"
        ),
    )
    test_app = FastAPI(dependencies=[Security(jwks_auth)])

    @test_app.get("/test-endpoint", response_model=dict)
    async def get_test_route(request: Request):
        payload_injector = JWTTokenInjector[FakeToken](
            config=JWTTokenInjectorConfig(payload_field="custom_payload")
        )
        token_injector = JWTRawTokenInjector(
            config=JWTTokenInjectorConfig(token_field="custom_token")
        )
        payload = await payload_injector(request)
        token = await token_injector(request)
        return {"injected_payload": payload.model_dump(), "injected_token": token}

    client = TestClient(test_app)

    # Test without token
    response = client.get("/test-endpoint")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Invalid authorization token"

    # Test with token
    jwk = jwks_fake_data.keys[0]
    key = jwk.k
    assert key
    algo = jwk.alg
    kid = jwk.kid

    claim = {"user": "injector-custom-fields-user"}
    signed_token = jwt.encode(
        claim, base64.urlsafe_b64decode(key), headers={"kid": kid}, algorithm=algo
    )

    response = client.get(
        "/test-endpoint", headers={"Authorization": f"Bearer {signed_token}"}
    )
    data = response.json()

    assert data["injected_payload"]["user"] == claim["user"]
    assert data["injected_token"] == signed_token
    assert response.status_code == status.HTTP_200_OK
    mocked_jwt.stop()
