import base64
import dataclasses
import datetime
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import jwt
import pytest
from fastapi import HTTPException, status
from jwt.algorithms import RSAAlgorithm
from pydantic import BaseModel

from fastapi_jwks.models.types import JWKS, JWKSConfig, JWTDecodeConfig
from fastapi_jwks.validators import JWKSValidator

RESOURCE_PATH = Path(__file__).parent / "resources"

KID = "secret"
"""KID used across all JWKS"""


class FakeToken(BaseModel):
    user: str


@dataclasses.dataclass
class JwksToken:
    jwks: JWKS
    signed_token: str


def create_signed_jwt(
    key: str | bytes, alg: str | None = None, kid: str | None = KID
) -> str:
    claim = {
        "user": "my-fake-user",
        "iat": datetime.datetime.now(datetime.UTC).timestamp(),
    }
    return jwt.encode(claim, key, headers={"kid": kid}, algorithm=alg)


def new_hs256_jwks(key: dict[str, Any]):
    decoded_key = base64.urlsafe_b64decode(key["k"])
    return JwksToken(
        JWKS.model_validate({"keys": [key]}),
        create_signed_jwt(decoded_key, alg=key.get("alg"), kid=key.get("kid")),
    )


def new_rsa_jwks():
    """Create a new RSA JWKS with the given public key and private key."""
    algo = RSAAlgorithm(RSAAlgorithm.SHA256)
    key = algo.prepare_key((RESOURCE_PATH / "public-key.pem").read_text())
    key = algo.to_jwk(key, as_dict=True) | {"alg": "RS256", "kid": KID}
    return JwksToken(
        JWKS.model_validate({"keys": [key]}),
        create_signed_jwt((RESOURCE_PATH / "private-key.pem").read_bytes(), key["alg"]),
    )


TEST_JWKS = {
    "HS256": new_hs256_jwks(
        {
            "kty": "oct",
            "use": "sig",
            "kid": KID,
            "k": "b3NFUGVJR09BRW1JMzd6UTdYLUtaT0haci1ZUTZSVzhqaGd0QVhBdThKazZMSWFMclg3TXJsTHJ3YTZXenM3NWI4U1l3em1sQ0VLdXlJeXpVeXNDMmRLeVZ5RkVHSHZ5OWdtNk1PSGRTWjZXWDdWN3VIMHpaZmlkbDZhVV9LYTI0dnF3WHlYaXBKWHV5LWJoMVl4U0w4M0RRVnhmbk43X2NSMHNGbzVoSmFhUnJpT2NYWUt2SEJ2YXQ0dHFRMldJZnNTenJxdTA5alY0RFN4TjdXaTJ5NHJrU1dmVXY4cVV2ZU9OUHVUc3hQQURRb3RKdExsMUtEeGRjUHFIVkZPUTRmODhMZkZJb3ZreXZsNEZiSHM3Q05Uejh2Z0Etdml2cGhRNXJyVGVuUjUxaUd0c0lybC14V29KZXFzQ3lDVXdGdzl2SmxheFhqWXM0TDBsT3dLcGVR",
            "alg": "HS256",
        }
    ),
    "NO_ALG": new_hs256_jwks(
        {
            "kty": "oct",
            "use": "sig",
            "kid": KID,
            "k": "b3NFUGVJR09BRW1JMzd6UTdYLUtaT0haci1ZUTZSVzhqaGd0QVhBdThKazZMSWFMclg3TXJsTHJ3YTZXenM3NWI4U1l3em1sQ0VLdXlJeXpVeXNDMmRLeVZ5RkVHSHZ5OWdtNk1PSGRTWjZXWDdWN3VIMHpaZmlkbDZhVV9LYTI0dnF3WHlYaXBKWHV5LWJoMVl4U0w4M0RRVnhmbk43X2NSMHNGbzVoSmFhUnJpT2NYWUt2SEJ2YXQ0dHFRMldJZnNTenJxdTA5alY0RFN4TjdXaTJ5NHJrU1dmVXY4cVV2ZU9OUHVUc3hQQURRb3RKdExsMUtEeGRjUHFIVkZPUTRmODhMZkZJb3ZreXZsNEZiSHM3Q05Uejh2Z0Etdml2cGhRNXJyVGVuUjUxaUd0c0lybC14V29KZXFzQ3lDVXdGdzl2SmxheFhqWXM0TDBsT3dLcGVR",
        }
    ),
    "RSA256": new_rsa_jwks(),
}


@pytest.mark.parametrize(
    "jwks_token",
    TEST_JWKS.values(),
)
def test_simple_validate(
    monkeypatch: pytest.MonkeyPatch,
    jwks_token: JwksToken,
):
    signed_token = jwks_token.signed_token
    monkeypatch.setattr(
        "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
        lambda _: jwks_token.jwks,
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
    return_value=TEST_JWKS["HS256"].jwks,
)
def test_extra_config(
    data_mock: MagicMock,
    jwt_decode: MagicMock,
):
    signed_token = TEST_JWKS["HS256"].signed_token
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
    jwks_data = TEST_JWKS["HS256"].jwks
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
    return_value=TEST_JWKS["HS256"].jwks,
)
def test_generic_mandatory(data_mock):
    signed_token = TEST_JWKS["HS256"].signed_token
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
            mock_response.json.return_value = TEST_JWKS["HS256"].jwks
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

            assert jwks_data == TEST_JWKS["HS256"].jwks
            mock_client.assert_called_with(verify=ca_cert_file.name)
            mock_client.return_value.get.assert_called_with(
                "https://my-fake-jwks-endpoint/my-endpoint"
            )


def test_cache_refresh_on_kid_mismatch():
    key1 = "secret1-at-least-32-characters-long-for-hs256"
    key2 = "secret2-at-least-32-characters-long-for-hs256"
    key1_b64 = base64.urlsafe_b64encode(key1.encode()).decode().rstrip("=")
    key2_b64 = base64.urlsafe_b64encode(key2.encode()).decode().rstrip("=")
    jwks_token1 = new_hs256_jwks(
        {
            "kty": "oct",
            "use": "sig",
            "kid": "kid1",
            "k": key1_b64,
            "alg": "HS256",
        }
    )
    jwks_token2 = new_hs256_jwks(
        {
            "kty": "oct",
            "use": "sig",
            "kid": "kid2",
            "k": key2_b64,
            "alg": "HS256",
        }
    )

    validator = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(url="https://fake-jwks/keys"),
    )

    mock_response1 = MagicMock()
    mock_response1.json.return_value = jwks_token1.jwks.model_dump()
    mock_response1.raise_for_status.return_value = None

    mock_response2 = MagicMock()
    mock_response2.json.return_value = jwks_token2.jwks.model_dump()
    mock_response2.raise_for_status.return_value = None

    with patch.object(
        validator.client, "get", side_effect=[mock_response1, mock_response2]
    ) as mock_get:
        # fetch jwks1 to cache it
        validator.jwks_data()
        assert mock_get.call_count == 1

        # simulate Keycloak restart (changed kid)
        # validating against cached jwks1 should fail, invalidate cache, refresh, and succeed with jwks2
        payload = validator.validate_token(jwks_token2.signed_token)

        assert payload.user == "my-fake-user"
        assert mock_get.call_count == 2
        mock_get.assert_called_with("https://fake-jwks/keys")


def test_unauthorized_after_refresh():
    key1 = "secret1-at-least-32-characters-long-for-hs256"
    key1_b64 = base64.urlsafe_b64encode(key1.encode()).decode().rstrip("=")
    jwks_token1 = new_hs256_jwks(
        {
            "kty": "oct",
            "use": "sig",
            "kid": "kid1",
            "k": key1_b64,
            "alg": "HS256",
        }
    )

    validator = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(url="https://fake-jwks/keys"),
    )

    mock_response = MagicMock()
    mock_response.json.return_value = jwks_token1.jwks.model_dump()
    mock_response.raise_for_status.return_value = None

    with patch.object(validator.client, "get", return_value=mock_response) as mock_get:
        token_unknown = create_signed_jwt(key1, alg="HS256", kid="unknown")
        with pytest.raises(HTTPException) as excinfo:
            validator.validate_token(token_unknown)

        assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert mock_get.call_count == 2  # check that it tried refreshing once
        mock_get.assert_called_with("https://fake-jwks/keys")
