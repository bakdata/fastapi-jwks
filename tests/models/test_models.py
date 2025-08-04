import json
from pathlib import Path

import pytest

from fastapi_jwks.models.types import JWKS

RESOURCE_PATH = Path(__file__).parent / "resources"


@pytest.mark.parametrize(
    "provider",
    [
        "google",  # https://www.googleapis.com/oauth2/v3/certs
        "apple",  # https://developer.apple.com/documentation/signinwithapplerestapi/fetch_apple_s_public_key_for_verifying_token_signature
        "microsoft",  # https://login.microsoftonline.com/common/discovery/v2.0/keys
        "botframework",  # https://login.botframework.com/v1/.well-known/keys
        "keycloak",  # Start a local keycloak and go to http://<keycloak>/realms/master/protocol/openid-connect/certs
    ],
)
def test_jwks_model(provider: str):
    """Test the JWKS model supports different providers"""
    with open(RESOURCE_PATH / f"{provider}.json") as file:
        jwks = json.loads(file.read())
    validate = JWKS.model_validate(jwks)
    assert len(validate.keys) > 0
