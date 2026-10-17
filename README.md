# fastapi-jwks

fastapi-jwks is a Python library designed to facilitate the integration of JSON Web Key Set (JWKS) with FastAPI applications. It provides a set of tools to automatically query the JWKS endpoint and verify the tokens sent over a request.

## Key Features

- **JWKS Endpoint Querying**: The library automatically queries the JWKS endpoint to fetch the necessary keys for token verification. Keys are cached and refreshed on key rotation.
- **Token Verification**: It verifies the tokens sent over a request with the JWKS endpoint, ensuring the authenticity and integrity of the data.
- **Dependency Integration**: The library includes a dependency that can be easily integrated into your FastAPI application to handle token validation on every request.
- **Pydantic Model Support**: It supports Pydantic models for token data extraction, providing a seamless way to work with the token data.
- **Customizable State Fields**: You can customize where the payload and raw token are stored in the request state.
- **Raw Token Access**: Access both the decoded payload and the original raw token through dependency injection.

## Installation

```sh
pip install fastapi_jwks
```

## Basic Usage

```python
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, Security
from pydantic import BaseModel

from fastapi_jwks.dependencies import JWKSAuth
from fastapi_jwks.injector import JWTTokenInjector
from fastapi_jwks.models.types import JWKSAuthCredentials, JWKSConfig, JWTDecodeConfig
from fastapi_jwks.validators import JWKSValidator


# The data we want to extract from the token
class UserToken(BaseModel):
    user: str


jwks_validator = JWKSValidator[UserToken](
    decode_config=JWTDecodeConfig(),
    jwks_config=JWKSConfig(url="https://my-idp.example.com/.well-known/jwks.json"),
)
jwks_auth = JWKSAuth(jwks_validator=jwks_validator)
payload_injector = JWTTokenInjector[UserToken]()

# global: protect all endpoints
app = FastAPI(dependencies=[Security(jwks_auth)])


@app.get("/me", response_model=UserToken)
def me(token: Annotated[UserToken, Depends(payload_injector)]) -> UserToken:
    return token


# specific API router
router = APIRouter(dependencies=[Security(jwks_auth)])
app.include_router(router)


# specific route: the dependency also returns the credentials and decoded payload
@app.get("/protected")
def protected(
    credentials: Annotated[JWKSAuthCredentials[UserToken], Security(jwks_auth)],
) -> UserToken:
    return credentials.payload
```

## Advanced Usage

### Custom State Fields

You can customize where the payload and raw token are stored in the request state:

```python
from fastapi_jwks.injector import JWTRawTokenInjector, JWTTokenInjector
from fastapi_jwks.models.types import JWKSAuthConfig

# Use the same field names for the dependency and the injectors
state_config = JWKSAuthConfig(
    payload_field="custom_payload", token_field="custom_token"
)
jwks_auth = JWKSAuth(jwks_validator=jwks_validator, config=state_config)
app = FastAPI(dependencies=[Security(jwks_auth)])

payload_injector = JWTTokenInjector[UserToken](config=state_config)
token_injector = JWTRawTokenInjector(config=state_config)


@app.get("/advanced-endpoint")
def advanced_endpoint(
    payload: Annotated[UserToken, Depends(payload_injector)],
    raw_token: Annotated[str, Depends(token_injector)],
):
    return {"user": payload.user, "token": raw_token}
```

## Contributing

We are happy if you want to contribute to this project. If you find any bugs or have suggestions for improvements, please open an issue. We are also happy to accept your PRs. Just open an issue beforehand and let us know what you want to do and why.

## License

fastapi-jwks is licensed under the MIT License.
