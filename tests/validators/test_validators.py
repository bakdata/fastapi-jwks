import base64
import tempfile
from collections.abc import Callable
from unittest.mock import MagicMock, patch

import jwt
import pytest
from pydantic import BaseModel

from fastapi_jwks.models.types import JWKS, JWKSConfig, JWTDecodeConfig
from fastapi_jwks.validators import JWKSValidator


class FakeToken(BaseModel):
    user: str


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


def jwks_fake_data_no_alg() -> JWKS:
    return JWKS.model_validate(
        {
            "keys": [
                {
                    "kty": "oct",
                    "use": "sig",
                    "kid": "sYW9Qh23pPfbD06_F4UY6oAdi2FlNTwBAV6L6YMLY3o",
                    "k": "b3NFUGVJR09BRW1JMzd6UTdYLUtaT0haci1ZUTZSVzhqaGd0QVhBdThKazZMSWFMclg3TXJsTHJ3YTZXenM3NWI4U1l3em1sQ0VLdXlJeXpVeXNDMmRLeVZ5RkVHSHZ5OWdtNk1PSGRTWjZXWDdWN3VIMHpaZmlkbDZhVV9LYTI0dnF3WHlYaXBKWHV5LWJoMVl4U0w4M0RRVnhmbk43X2NSMHNGbzVoSmFhUnJpT2NYWUt2SEJ2YXQ0dHFRMldJZnNTenJxdTA5alY0RFN4TjdXaTJ5NHJrU1dmVXY4cVV2ZU9OUHVUc3hQQURRb3RKdExsMUtEeGRjUHFIVkZPUTRmODhMZkZJb3ZreXZsNEZiSHM3Q05Uejh2Z0Etdml2cGhRNXJyVGVuUjUxaUd0c0lybC14V29KZXFzQ3lDVXdGdzl2SmxheFhqWXM0TDBsT3dLcGVR",
                }
            ]
        }
    )


@pytest.fixture()
def signed_token() -> str:
    jwk = jwks_fake_data().keys[0]
    key = jwk.k
    assert key
    algo = jwk.alg
    kid = jwk.kid

    claim = {"user": "my-fake-user"}
    signed_token = jwt.encode(
        claim, base64.urlsafe_b64decode(key), headers={"kid": kid}, algorithm=algo
    )
    return signed_token


@pytest.mark.parametrize(
    "jwks_data_provider",
    [
        jwks_fake_data,
        jwks_fake_data_no_alg,
    ],
)
def test_simple_validate(
    monkeypatch: pytest.MonkeyPatch,
    signed_token: str,
    jwks_data_provider: Callable[[], JWKS],
):
    monkeypatch.setattr(
        "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
        lambda _: jwks_data_provider(),
    )
    validator = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(url="https://my-fake-jwks-endpoint/my-endpoint"),
    )

    fake_user = validator.validate_token(signed_token)
    assert isinstance(fake_user, FakeToken)


@patch("jwt.decode")
@patch(
    "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
    return_value=jwks_fake_data(),
)
def test_extra_config(
    data_mock: MagicMock,
    jwt_decode: MagicMock,
    signed_token: str,
):
    token = FakeToken(user="my-fake-user")
    jwt_decode.return_value = token
    validator = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(
            audience=["my-audience"],
            issuer="my-issuer",
            leeway=1.0,
            options={"extra_key": "extra_value"},
            verify=False,
        ),
        jwks_config=JWKSConfig(url="https://my-fake-jwks-endpoint/my-endpoint"),
    )
    jwks_data = jwks_fake_data()
    key = jwks_data.keys[0].k
    assert key
    algo = jwks_data.keys[0].alg

    validated_token = validator.validate_token(signed_token)
    assert validated_token.user == token.user
    jwt_decode.assert_called()
    jwt_decode.assert_called_with(
        signed_token,
        algorithms=[algo],
        key=base64.urlsafe_b64decode(key),
        audience=["my-audience"],
        issuer="my-issuer",
        leeway=1.0,
        options={"extra_key": "extra_value"},
        verify=False,
    )


@patch(
    "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
    return_value=jwks_fake_data(),
)
def test_generic_mandatory(data_mock, signed_token):
    validator = JWKSValidator(
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(url="https://my-fake-jwks-endpoint/my-endpoint"),
    )

    with pytest.raises(
        ValueError, match="Validator needs a model as generic value to decode payload"
    ):
        validator.validate_token(signed_token)


def test_custom_ca_cert():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem") as ca_cert_file:
        ca_cert_file.write(
            "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"
        )
        ca_cert_file.flush()

        with patch("httpx.Client") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_fake_data()
            mock_response.raise_for_status.return_value = None
            mock_client.return_value.get.return_value = mock_response

            jwks_verifier = JWKSValidator[FakeToken](
                decode_config=JWTDecodeConfig(),
                jwks_config=JWKSConfig(
                    url="https://my-fake-jwks-endpoint/my-endpoint",
                    ca_cert_path=ca_cert_file.name,
                ),
            )

            jwks_data = jwks_verifier.jwks_data()

            assert jwks_data == jwks_fake_data()
            mock_client.assert_called_with(verify=ca_cert_file.name)
            mock_client.return_value.get.assert_called_with(
                "https://my-fake-jwks-endpoint/my-endpoint"
            )
