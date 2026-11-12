import base64
import dataclasses
import datetime
import json
import logging
import warnings
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import HTTPException, status
from jwt.algorithms import ECAlgorithm, RSAAlgorithm
from pydantic import BaseModel

from fastapi_jwks.models.types import JWKS, JWKSConfig, JWTDecodeConfig
from fastapi_jwks.validators import JWKSFetcher, JWKSUnavailableError, JWKSValidator

RESOURCE_PATH = Path(__file__).parent / "resources"

KID = "secret"
"""KID used across all JWKS"""

URL = "https://my-fake-jwks-endpoint/my-endpoint"

RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())


class FakeToken(BaseModel):
    user: str


@dataclasses.dataclass
class JwksToken:
    jwks: JWKS
    signed_token: str
    decode_config: JWTDecodeConfig


def create_signed_jwt(
    key: Any,
    alg: str | None = None,
    kid: str | None = KID,
    claims: dict[str, Any] | None = None,
) -> str:
    claim = {
        "user": "my-fake-user",
        "iat": datetime.datetime.now(datetime.UTC).timestamp(),
    } | (claims or {})
    headers = {"kid": kid} if kid is not None else None
    return jwt.encode(claim, key, headers=headers, algorithm=alg)


def new_es256_jwks():
    key = ECAlgorithm.to_jwk(EC_PRIVATE_KEY.public_key(), as_dict=True) | {
        "alg": "ES256",
        "kid": KID,
    }
    return JwksToken(
        JWKS.model_validate({"keys": [key]}),
        create_signed_jwt(EC_PRIVATE_KEY, key["alg"]),
        JWTDecodeConfig(),
    )


def new_rsa_jwks():
    """Create a new RSA JWKS with the given public key and private key."""
    algo = RSAAlgorithm(RSAAlgorithm.SHA256)
    key = algo.prepare_key((RESOURCE_PATH / "public-key.pem").read_text())
    key = algo.to_jwk(key, as_dict=True) | {"alg": "RS256", "kid": KID}
    return JwksToken(
        JWKS.model_validate({"keys": [key]}),
        create_signed_jwt((RESOURCE_PATH / "private-key.pem").read_bytes(), key["alg"]),
        JWTDecodeConfig(),
    )


HS256_JWK = {
    "kty": "oct",
    "use": "sig",
    "kid": KID,
    "k": "b3NFUGVJR09BRW1JMzd6UTdYLUtaT0haci1ZUTZSVzhqaGd0QVhBdThKazZMSWFMclg3TXJsTHJ3YTZXenM3NWI4U1l3em1sQ0VLdXlJeXpVeXNDMmRLeVZ5RkVHSHZ5OWdtNk1PSGRTWjZXWDdWN3VIMHpaZmlkbDZhVV9LYTI0dnF3WHlYaXBKWHV5LWJoMVl4U0w4M0RRVnhmbk43X2NSMHNGbzVoSmFhUnJpT2NYWUt2SEJ2YXQ0dHFRMldJZnNTenJxdTA5alY0RFN4TjdXaTJ5NHJrU1dmVXY4cVV2ZU9OUHVUc3hQQURRb3RKdExsMUtEeGRjUHFIVkZPUTRmODhMZkZJb3ZreXZsNEZiSHM3Q05Uejh2Z0Etdml2cGhRNXJyVGVuUjUxaUd0c0lybC14V29KZXFzQ3lDVXdGdzl2SmxheFhqWXM0TDBsT3dLcGVR",
    "alg": "HS256",
}

TEST_JWKS = {
    "ES256": new_es256_jwks(),
    "RSA256": new_rsa_jwks(),
}


def rsa_jwk(
    private_key: rsa.RSAPrivateKey = RSA_PRIVATE_KEY, **extra: Any
) -> dict[str, Any]:
    return (
        RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
        | {"kid": KID}
        | extra
    )


def make_validator(
    jwks: JWKS | None = None, decode_config: JWTDecodeConfig | None = None
) -> JWKSValidator[FakeToken]:
    validator = JWKSValidator[FakeToken](
        decode_config=decode_config or JWTDecodeConfig(),
        jwks_config=JWKSConfig(url=URL),
    )
    if jwks is not None:
        validator.jwks_data = AsyncMock(return_value=jwks)
    return validator


def jwks_of(*keys: dict[str, Any]) -> JWKS:
    return JWKS.model_validate({"keys": list(keys)})


def unsigned_token(header: dict[str, Any]) -> str:
    def b64(data: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{b64(header)}.{b64({'user': 'attacker'})}.c2ln"


async def assert_unauthorized(
    validator: JWKSValidator[FakeToken], token: str, detail: str = "Invalid token"
) -> None:
    with pytest.raises(HTTPException) as exc_info:
        await validator.validate_token(token)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == detail


@pytest.mark.asyncio()
@pytest.mark.parametrize(
    "jwks_token",
    TEST_JWKS.values(),
)
async def test_simple_validate(
    monkeypatch: pytest.MonkeyPatch,
    jwks_token: JwksToken,
):
    signed_token = jwks_token.signed_token

    async def jwks_data(_, *, force_refresh: bool = False) -> JWKS:
        return jwks_token.jwks

    monkeypatch.setattr(
        "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
        jwks_data,
    )
    validator = JWKSValidator[FakeToken](
        decode_config=jwks_token.decode_config,
        jwks_config=JWKSConfig(url=URL),
    )

    fake_user = await validator.validate_token(signed_token)
    assert isinstance(fake_user, FakeToken)


@pytest.mark.asyncio()
@patch("jwt.decode")
@patch(
    "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
    return_value=TEST_JWKS["RSA256"].jwks,
)
async def test_extra_config(
    data_mock: MagicMock,
    jwt_decode: MagicMock,
):
    signed_token = TEST_JWKS["RSA256"].signed_token
    token = FakeToken(user="my-fake-user")
    jwt_decode.return_value = token.model_dump()
    validator = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(
            algorithms=["RS256"],
            audience=["my-audience"],
            issuer="my-issuer",
            leeway=1.0,
            options={"extra_key": "extra_value"},
            verify=False,
        ),
        jwks_config=JWKSConfig(url=URL),
    )
    jwk = TEST_JWKS["RSA256"].jwks.keys[0]

    validated_token = await validator.validate_token(signed_token)
    assert validated_token.user == token.user
    jwt_decode.assert_called_once()
    (called_token,), kwargs = jwt_decode.call_args
    signing_key = kwargs.pop("key")
    assert called_token == signed_token
    assert isinstance(signing_key, jwt.PyJWK)
    assert signing_key.algorithm_name == "RS256"
    assert RSAAlgorithm.to_jwk(signing_key.key, as_dict=True)["n"] == jwk.n
    assert kwargs == {
        "algorithms": ["RS256"],
        "audience": ["my-audience"],
        "issuer": "my-issuer",
        "leeway": 1.0,
        "options": {"extra_key": "extra_value"},
        "verify": False,
    }


@pytest.mark.asyncio()
async def test_audience_issuer_leeway_enforced():
    validator = make_validator(
        jwks_of(rsa_jwk(alg="RS256")),
        JWTDecodeConfig(audience=["my-audience"], issuer="my-issuer", leeway=60),
    )
    now = datetime.datetime.now(datetime.UTC).timestamp()
    valid = {"aud": "my-audience", "iss": "my-issuer", "exp": now - 30}
    assert (
        await validator.validate_token(
            create_signed_jwt(RSA_PRIVATE_KEY, "RS256", claims=valid)
        )
    ).user == "my-fake-user"

    for claims in (
        valid | {"aud": "other-audience"},
        valid | {"iss": "other-issuer"},
    ):
        await assert_unauthorized(
            validator, create_signed_jwt(RSA_PRIVATE_KEY, "RS256", claims=claims)
        )
    await assert_unauthorized(
        validator,
        create_signed_jwt(RSA_PRIVATE_KEY, "RS256", claims=valid | {"exp": now - 120}),
        detail="Token has expired",
    )


@pytest.mark.asyncio()
@patch(
    "fastapi_jwks.validators.jwks_validator.JWKSValidator.jwks_data",
    return_value=TEST_JWKS["RSA256"].jwks,
)
async def test_generic_mandatory(data_mock):
    signed_token = TEST_JWKS["RSA256"].signed_token
    validator = JWKSValidator(
        decode_config=JWTDecodeConfig(),
        jwks_config=JWKSConfig(url=URL),
    )

    with pytest.raises(
        ValueError, match="Validator needs a model as generic value to decode payload"
    ):
        await validator.validate_token(signed_token)


def test_custom_ca_cert():
    cafile = "/etc/ssl/certs/ca-certificates.crt"
    with patch("ssl.create_default_context") as create_default_context:
        validator = JWKSValidator[FakeToken](
            decode_config=JWTDecodeConfig(),
            jwks_config=JWKSConfig(url=URL, ca_cert_path=cafile),
        )
    create_default_context.assert_called_once_with(cafile=cafile)
    assert validator.fetcher.config.ca_cert_path == cafile


@pytest.mark.asyncio()
async def test_alg_less_rsa_key_infers_rs256():
    validator = make_validator(jwks_of(rsa_jwk()))
    token = create_signed_jwt(RSA_PRIVATE_KEY, "RS256")
    assert (await validator.validate_token(token)).user == "my-fake-user"


@pytest.mark.asyncio()
async def test_alg_less_rsa_key_rejects_other_rsa_algorithm_by_default():
    token = create_signed_jwt(RSA_PRIVATE_KEY, "PS256")
    await assert_unauthorized(make_validator(jwks_of(rsa_jwk())), token)

    validator = make_validator(
        jwks_of(rsa_jwk()), JWTDecodeConfig(algorithms=["PS256"])
    )
    assert (await validator.validate_token(token)).user == "my-fake-user"


@pytest.mark.asyncio()
@pytest.mark.parametrize("algorithms", [None, ["RS256", "PS256"]])
async def test_key_alg_takes_precedence_over_token_alg(algorithms: list[str] | None):
    validator = make_validator(
        jwks_of(rsa_jwk(alg="RS256")), JWTDecodeConfig(algorithms=algorithms)
    )
    await assert_unauthorized(validator, create_signed_jwt(RSA_PRIVATE_KEY, "PS256"))


@pytest.mark.asyncio()
async def test_key_alg_outside_allowlist_rejected():
    validator = make_validator(
        jwks_of(rsa_jwk(alg="RS256")), JWTDecodeConfig(algorithms=["ES256"])
    )
    await assert_unauthorized(validator, create_signed_jwt(RSA_PRIVATE_KEY, "RS256"))


@pytest.mark.asyncio()
@pytest.mark.parametrize(
    "jwk", [HS256_JWK, {k: v for k, v in HS256_JWK.items() if k != "alg"}]
)
@pytest.mark.parametrize("algorithms", [None, ["HS256"]])
async def test_hmac_key_rejected(jwk: dict[str, Any], algorithms: list[str] | None):
    token = create_signed_jwt(base64.urlsafe_b64decode(HS256_JWK["k"]), "HS256")
    validator = make_validator(jwks_of(jwk), JWTDecodeConfig(algorithms=algorithms))
    await assert_unauthorized(validator, token)


@pytest.mark.asyncio()
async def test_hmac_key_skipped_when_kid_is_shared():
    validator = make_validator(jwks_of(HS256_JWK, rsa_jwk(alg="RS256")))
    token = create_signed_jwt(RSA_PRIVATE_KEY, "RS256")
    assert (await validator.validate_token(token)).user == "my-fake-user"


@pytest.mark.asyncio()
@pytest.mark.parametrize("alg", ["none", "HS256", "FOO"])
@pytest.mark.parametrize("algorithms", [None, ["RS256"], ["none", "HS256", "FOO"]])
async def test_forged_header_algorithms_rejected(
    alg: str, algorithms: list[str] | None
):
    validator = make_validator(
        jwks_of(rsa_jwk()), JWTDecodeConfig(algorithms=algorithms)
    )
    await assert_unauthorized(validator, unsigned_token({"alg": alg, "kid": KID}))


@pytest.mark.asyncio()
@pytest.mark.parametrize(
    "token", ["not-a-jwt", unsigned_token({"kid": KID}), unsigned_token({"alg": 1})]
)
async def test_malformed_token_rejected(token: str):
    await assert_unauthorized(make_validator(jwks_of(rsa_jwk())), token)


@pytest.mark.asyncio()
async def test_wrong_signature_rejected():
    validator = make_validator(jwks_of(rsa_jwk(alg="RS256")))
    await assert_unauthorized(
        validator, create_signed_jwt(OTHER_RSA_PRIVATE_KEY, "RS256")
    )


@pytest.mark.asyncio()
async def test_encryption_keys_ignored():
    validator = make_validator(jwks_of(rsa_jwk(use="enc")))
    await assert_unauthorized(validator, create_signed_jwt(RSA_PRIVATE_KEY, "RS256"))


@pytest.mark.asyncio()
async def test_kid_less_token_matches_kid_less_key():
    jwk = {k: v for k, v in rsa_jwk().items() if k != "kid"}
    validator = make_validator(jwks_of(jwk))
    token = create_signed_jwt(RSA_PRIVATE_KEY, "RS256", kid=None)
    assert (await validator.validate_token(token)).user == "my-fake-user"


@pytest.mark.asyncio()
async def test_unknown_kid_triggers_single_forced_refresh():
    rotated = rsa_jwk(OTHER_RSA_PRIVATE_KEY, kid="rotated")
    jwks_data = AsyncMock(side_effect=[jwks_of(rsa_jwk()), jwks_of(rsa_jwk(), rotated)])
    validator = make_validator()
    validator.jwks_data = jwks_data

    token = create_signed_jwt(OTHER_RSA_PRIVATE_KEY, "RS256", kid="rotated")
    assert (await validator.validate_token(token)).user == "my-fake-user"
    assert [call.kwargs for call in jwks_data.call_args_list] == [
        {"force_refresh": False},
        {"force_refresh": True},
    ]


@pytest.mark.asyncio()
async def test_unknown_kid_still_missing_after_refresh():
    jwks_data = AsyncMock(return_value=jwks_of(rsa_jwk()))
    validator = make_validator()
    validator.jwks_data = jwks_data

    await assert_unauthorized(
        validator, create_signed_jwt(RSA_PRIVATE_KEY, "RS256", kid="unknown")
    )
    assert jwks_data.await_count == 2


@pytest.mark.asyncio()
async def test_key_rotation_through_fetcher():
    responses = [
        jwks_of(rsa_jwk()),
        jwks_of(rsa_jwk(), rsa_jwk(OTHER_RSA_PRIVATE_KEY, kid="rotated")),
    ]
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        jwks = responses[min(requests, len(responses) - 1)]
        requests += 1
        return httpx.Response(
            200, json=jwks.model_dump(by_alias=True, exclude_none=True)
        )

    config = JWKSConfig(url=URL, refresh_cooldown=0)
    validator = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(), jwks_config=config
    )
    validator.fetcher = JWKSFetcher(config, transport=httpx.MockTransport(handler))

    await validator.validate_token(create_signed_jwt(RSA_PRIVATE_KEY, "RS256"))
    assert requests == 1
    await validator.validate_token(
        create_signed_jwt(OTHER_RSA_PRIVATE_KEY, "RS256", kid="rotated")
    )
    assert requests == 2


@pytest.mark.asyncio()
async def test_jwks_unavailable():
    validator = make_validator()
    validator.jwks_data = AsyncMock(side_effect=JWKSUnavailableError("down"))
    with pytest.raises(HTTPException) as exc_info:
        await validator.validate_token(create_signed_jwt(RSA_PRIVATE_KEY, "RS256"))
    assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert exc_info.value.detail == "JWKS unavailable"


@pytest.mark.asyncio()
async def test_jwks_endpoint_error_through_fetcher():
    config = JWKSConfig(url=URL)
    validator = JWKSValidator[FakeToken](
        decode_config=JWTDecodeConfig(), jwks_config=config
    )
    validator.fetcher = JWKSFetcher(
        config, transport=httpx.MockTransport(lambda _: httpx.Response(500))
    )
    with pytest.raises(HTTPException) as exc_info:
        await validator.validate_token(create_signed_jwt(RSA_PRIVATE_KEY, "RS256"))
    assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


@pytest.mark.asyncio()
async def test_expired_token():
    validator = make_validator(jwks_of(rsa_jwk(alg="RS256")))
    past = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=5)
    token = create_signed_jwt(RSA_PRIVATE_KEY, "RS256", claims={"exp": past})
    await assert_unauthorized(validator, token, detail="Token has expired")


@pytest.mark.asyncio()
async def test_payload_validation_error():
    validator = make_validator(jwks_of(rsa_jwk(alg="RS256")))
    token = jwt.encode(
        {"name": "no-user-claim"}, RSA_PRIVATE_KEY, "RS256", headers={"kid": KID}
    )
    await assert_unauthorized(validator, token)


@pytest.mark.asyncio()
@pytest.mark.parametrize("jwks_token", TEST_JWKS.values())
async def test_no_warnings_during_validation(jwks_token: JwksToken):
    validator = make_validator(jwks_token.jwks, jwks_token.decode_config)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        await validator.validate_token(jwks_token.signed_token)


@pytest.mark.asyncio()
@pytest.mark.parametrize(
    "header",
    [
        {"alg": "RS256", "kid": "unknown\nforged log line"},
        {"alg": "RS256\nforged log line", "kid": KID},
    ],
)
async def test_token_values_cannot_forge_log_lines(
    caplog: pytest.LogCaptureFixture, header: dict[str, Any]
):
    validator = make_validator(jwks_of(rsa_jwk(alg="RS256")))

    with caplog.at_level(logging.DEBUG, logger="fastapi-jwks"):
        await assert_unauthorized(validator, unsigned_token(header))

    messages = [record.getMessage() for record in caplog.records]
    assert any("forged log line" in message for message in messages)
    assert not any("\n" in message for message in messages)
