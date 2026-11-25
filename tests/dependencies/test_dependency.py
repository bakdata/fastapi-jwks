import base64
import ssl
from collections.abc import Generator
from pathlib import Path
from typing import Annotated
from unittest.mock import MagicMock, patch

import httpx2
import jwt
import pytest
from fastapi import FastAPI, HTTPException, Security, status
from pydantic import BaseModel
from pytest_mock import MockerFixture
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
    jwks_verifier = JWKSValidator(
        payload_model=FakeToken,
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
    jwks_verifier = JWKSValidator(
        payload_model=FakeToken,
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


@pytest.mark.asyncio()
async def test_unauthorized_errors_do_not_reuse_tracebacks():
    def traceback_length(exc: BaseException) -> int:
        traceback = exc.__traceback__
        length = 0
        while traceback is not None:
            length += 1
            traceback = traceback.tb_next
        return length

    jwks_verifier = MagicMock()
    jwks_verifier.validate_token.side_effect = ValueError("invalid token")
    jwks_auth = JWKSAuth(jwks_validator=jwks_verifier)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/test-endpoint",
            "headers": [(b"authorization", b"Bearer invalid")],
        }
    )

    exceptions = []
    traceback_lengths = []
    for _ in range(3):
        with pytest.raises(HTTPException) as exc_info:
            await jwks_auth(request)
        exceptions.append(exc_info.value)
        traceback_lengths.append(traceback_length(exc_info.value))

    assert len({id(exc) for exc in exceptions}) == len(exceptions)
    assert len(set(traceback_lengths)) == 1


def test_custom_ca_cert(
    jwks_fake_data: JWKS, ca_cert_path: Path, mocker: MockerFixture
):
    create_context = mocker.spy(ssl, "create_default_context")
    jwks_verifier = JWKSValidator(
        payload_model=FakeToken,
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(
            url="http://my-fake-jwks-url/my-fake-endpoint",
            ca_cert_path=str(ca_cert_path),
        ),
    )
    create_context.assert_called_once_with(cafile=str(ca_cert_path))

    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(200, json=jwks_fake_data.model_dump(exclude_none=True))

    jwks_verifier.client = httpx2.Client(transport=httpx2.MockTransport(handler))

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
    assert [str(r.url) for r in requests] == [
        "http://my-fake-jwks-url/my-fake-endpoint"
    ]


def test_custom_state_fields(jwks_fake_data: JWKS):
    jwks_verifier = JWKSValidator(
        payload_model=FakeToken,
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
    jwks_verifier = JWKSValidator(
        payload_model=FakeToken,
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
