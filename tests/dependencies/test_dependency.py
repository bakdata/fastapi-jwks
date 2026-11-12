import asyncio
import tempfile
from collections.abc import Generator
from typing import Annotated, Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI, HTTPException, Security, status
from jwt.algorithms import RSAAlgorithm
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
)
from fastapi_jwks.validators import JWKSValidator


class FakeToken(BaseModel):
    user: str


RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KID = "sYW9Qh23pPfbD06_F4UY6oAdi2FlNTwBAV6L6YMLY3o"


def sign_token(claims: dict[str, Any]) -> str:
    return jwt.encode(claims, RSA_PRIVATE_KEY, headers={"kid": KID}, algorithm="RS256")


@pytest.fixture()
def jwks_fake_data() -> JWKS:
    jwk = RSAAlgorithm.to_jwk(RSA_PRIVATE_KEY.public_key(), as_dict=True)
    return JWKS.model_validate(
        {"keys": [jwk | {"use": "sig", "kid": KID, "alg": "RS256"}]}
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
def signed_token() -> str:
    return sign_token({"user": "my-fake-user"})


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

    claim = {"user": "my-custom-user"}
    signed_token = sign_token(claim)

    response = client.get(
        "/test-endpoint", headers={"X-Custom-Auth": f"Token {signed_token}"}
    )
    data = response.json()

    assert data["user"] == claim["user"]
    assert response.status_code == status.HTTP_200_OK
    mocked_jwt.stop()


def test_invalid_auth_scheme(client, jwks_fake_data: JWKS):
    claim = {"user": "my-fake-user"}
    signed_token = sign_token(claim)

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
    jwks_verifier.validate_token = AsyncMock(
        side_effect=HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    )
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
    assert all(exc.headers == {"WWW-Authenticate": "Bearer"} for exc in exceptions)


def test_custom_ca_cert(jwks_fake_data: JWKS):
    ssl_context = MagicMock()
    client_kwargs: list[dict[str, Any]] = []
    requested_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(
            200, json=jwks_fake_data.model_dump(by_alias=True, exclude_none=True)
        )

    real_async_client = httpx.AsyncClient

    def async_client(**kwargs: Any) -> httpx.AsyncClient:
        client_kwargs.append(kwargs)
        return real_async_client(transport=httpx.MockTransport(handler))

    with (
        tempfile.NamedTemporaryFile(mode="w", suffix=".pem") as ca_cert_file,
        patch("ssl.create_default_context", return_value=ssl_context) as create_ctx,
        patch(
            "fastapi_jwks.validators.jwks_fetcher.httpx.AsyncClient",
            side_effect=async_client,
        ),
    ):
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

        claim = {"user": "my-custom-ca-user"}
        signed_token = sign_token(claim)

        response = client.get(
            "/test-endpoint", headers={"Authorization": f"Bearer {signed_token}"}
        )
        data = response.json()

        assert data["user"] == claim["user"]
        assert response.status_code == status.HTTP_200_OK
        create_ctx.assert_called_once_with(cafile=ca_cert_file.name)
        assert [kwargs["verify"] for kwargs in client_kwargs] == [ssl_context]
        assert requested_urls == ["http://my-fake-jwks-url/my-fake-endpoint"]


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
    claim = {"user": "custom-fields-user"}
    signed_token = sign_token(claim)

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
            config=JWKSAuthConfig(payload_field="custom_payload")
        )
        token_injector = JWTRawTokenInjector(
            config=JWKSAuthConfig(token_field="custom_token")
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
    claim = {"user": "injector-custom-fields-user"}
    signed_token = sign_token(claim)

    response = client.get(
        "/test-endpoint", headers={"Authorization": f"Bearer {signed_token}"}
    )
    data = response.json()

    assert data["injected_payload"]["user"] == claim["user"]
    assert data["injected_token"] == signed_token
    assert response.status_code == status.HTTP_200_OK
    mocked_jwt.stop()


def _app_with_validator(
    validate_token: AsyncMock, auth_scheme: str = "Bearer"
) -> FastAPI:
    jwks_verifier = MagicMock()
    jwks_verifier.validate_token = validate_token
    jwks_auth = JWKSAuth(jwks_validator=jwks_verifier, auth_scheme=auth_scheme)
    test_app = FastAPI(dependencies=[Security(jwks_auth)])

    @test_app.get("/test-endpoint", response_model=FakeToken)
    def get_test_route(request: Request):
        return request.state.payload

    return test_app


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer    "},
        {"Authorization": "Bearer not-a-jwt"},
    ],
    ids=["missing", "wrong-scheme", "no-token", "blank-token", "invalid-token"],
)
def test_unauthorized_has_www_authenticate(client: TestClient, headers: dict):
    response = client.get("/test-endpoint", headers=headers)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_www_authenticate_uses_custom_scheme():
    validate_token = AsyncMock(
        side_effect=HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    )
    client = TestClient(_app_with_validator(validate_token, auth_scheme="Token"))

    for headers in ({}, {"Authorization": "token abc"}):
        response = client.get("/test-endpoint", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.headers["WWW-Authenticate"] == "Token"


def test_validator_unavailable_propagates_503():
    validate_token = AsyncMock(
        side_effect=HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="JWKS unavailable"
        )
    )
    client = TestClient(_app_with_validator(validate_token))

    response = client.get("/test-endpoint", headers={"Authorization": "Bearer abc"})
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert response.json()["detail"] == "JWKS unavailable"
    assert "WWW-Authenticate" not in response.headers


def test_expired_token_detail(jwks_auth: JWKSAuth, jwks_fake_data: JWKS):
    test_app = FastAPI(dependencies=[Security(jwks_auth)])

    @test_app.get("/test-endpoint")
    def get_test_route():
        return {}

    expired_token = sign_token({"user": "my-fake-user", "exp": 1})

    response = TestClient(test_app).get(
        "/test-endpoint", headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Token has expired"
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_missing_generic_propagates(jwks_fake_data: JWKS, signed_token: str):
    jwks_verifier = JWKSValidator(
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(url="http://my-fake-jwks-url/my-fake-endpoint"),
    )
    test_app = FastAPI(dependencies=[Security(JWKSAuth(jwks_validator=jwks_verifier))])

    @test_app.get("/test-endpoint")
    def get_test_route():
        return {}

    with (
        patch(
            "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
            return_value=jwks_fake_data,
        ),
        pytest.raises(ValueError, match="generic"),
    ):
        TestClient(test_app).get(
            "/test-endpoint", headers={"Authorization": f"Bearer {signed_token}"}
        )


def test_extra_whitespace_before_token(client: TestClient, signed_token: str):
    response = client.get(
        "/test-endpoint", headers={"Authorization": f"Bearer   {signed_token} "}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["user"] == "my-fake-user"


def test_state_not_set_on_failed_validation():
    validate_token = AsyncMock(
        side_effect=HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    )
    jwks_verifier = MagicMock()
    jwks_verifier.validate_token = validate_token
    jwks_auth = JWKSAuth(jwks_validator=jwks_verifier)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/test-endpoint",
            "headers": [(b"authorization", b"Bearer invalid")],
        }
    )

    with pytest.raises(HTTPException):
        asyncio.run(jwks_auth(request))
    assert not hasattr(request.state, "payload")
    assert not hasattr(request.state, "raw_token")


def test_shared_state_config(jwks_fake_data: JWKS, signed_token: str):
    config = JWKSAuthConfig(payload_field="shared_payload", token_field="shared_token")
    jwks_auth = JWKSAuth(
        jwks_validator=JWKSValidator[FakeToken](
            decode_config=JWTDecodeConfig(),
            jwks_config=JWKSConfig(url="http://my-fake-jwks-url/my-fake-endpoint"),
        ),
        config=config,
    )
    payload_injector = JWTTokenInjector[FakeToken](config=config)
    token_injector = JWTRawTokenInjector(config=config)
    test_app = FastAPI(dependencies=[Security(jwks_auth)])

    @test_app.get("/test-endpoint")
    def get_test_route(
        payload: Annotated[FakeToken, Depends(payload_injector)],
        token: Annotated[str, Depends(token_injector)],
    ) -> dict[str, str]:
        return {"user": payload.user, "token": token}

    with patch(
        "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
        return_value=jwks_fake_data,
    ):
        response = TestClient(test_app).get(
            "/test-endpoint", headers={"Authorization": f"Bearer {signed_token}"}
        )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"user": "my-fake-user", "token": signed_token}
