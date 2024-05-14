import base64
from unittest.mock import MagicMock, patch

import jwt
import pytest
from pydantic import BaseModel

from jwk.models.types import JWKSConfig, JWTDecodeConfig
from jwk.validators import JWKSValidator


class FakeToken(BaseModel):
    user: str


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
def signed_token():
    keys_definition = jwks_fake_data()["keys"]
    key = keys_definition[0]["k"]
    algo = keys_definition[0]["alg"]
    kid = keys_definition[0]["kid"]

    claim = {"user": "my-fake-user"}
    signed_token = jwt.encode(
        claim, base64.urlsafe_b64decode(key), headers={"kid": kid}, algorithm=algo
    )
    return signed_token


@patch(
    "jwk.validators.jwks_validator.JWKSValidator.jwks_data",
    return_value=jwks_fake_data(),
)
def test_simple_validate(data_mock, signed_token):
    validator = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(url="https://my-fake-jwks-endpoint/my-endpoint"),
    )

    fake_user = validator.validate_token(signed_token)

    assert isinstance(fake_user, FakeToken)


@patch("jwt.decode")
@patch(
    "jwk.validators.jwks_validator.JWKSValidator.jwks_data",
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
    key = jwks_data["keys"][0]["k"]
    algo = jwks_data["keys"][0]["alg"]

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
    "jwk.validators.jwks_validator.JWKSValidator.jwks_data",
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
