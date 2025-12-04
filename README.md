# fastapi-jwks

fastapi-jwks is a Python library designed to facilitate the integration of JSON Web Key Set (JWKS) with FastAPI applications. It provides a set of tools to automatically query the JWKS endpoint and verify the tokens sent over a request.

## Key Features

- **JWKS Endpoint Querying**: The library automatically queries the JWKS endpoint to fetch the necessary keys for token verification.
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
from fastapi import FastAPI
from fastapi import Depends, Security
from pydantic import BaseModel
from fastapi_jwks.injector import JWTTokenInjector
from fastapi_jwks.dependencies.jwk_auth import JWKSAuth
from fastapi_jwks.models.types import JWKSConfig, JWTDecodeConfig, JWKSAuthCredentials
from fastapi_jwks.validators import JWKSValidator

# The data we want to extract from the token
class FakeToken(BaseModel):
    user: str

app = FastAPI()

# Basic usage with default configuration
payload_injector = JWTTokenInjector[FakeToken]()

@app.get("/my-endpoint", response_model=FakeToken)
def my_endpoint(fake_token: FakeToken = Depends(payload_injector)):
    return fake_token

jwks_verifier = JWKSValidator[FakeToken](
    decode_config=JWTDecodeConfig(),
    jwks_config=JWKSConfig(url="http://my-fake-jwks-url/my-fake-endpoint"),
)
jwks_auth = JWKSAuth(jwks_validator=jwks_verifier)

# global: protect all endpoints
app = FastAPI(dependencies=[Security(jwks_auth)])

# specific API router
app.include_router(APIRouter(dependencies=[Security(jwks_auth)]))

# specific route
@app.get("/test")
def get_test_route(credentials: Annotated[JWKSAuthCredentials[FakeToken], Security(jwks_auth)]):
    ...
```

## Advanced Usage

### Custom State Fields

You can customize where the payload and raw token are stored in the request state:

```python
from fastapi_jwks.models.types import JWKSAuthConfig, JWTTokenInjectorConfig
from fastapi_jwks.injector import JWTTokenInjector, JWTRawTokenInjector

# Configure depdency with custom field names
auth_config = JWKSAuthConfig(
    payload_field="custom_payload",
    token_field="custom_token"
)
jwks_auth = JWKSAuth(jwks_validator=jwks_verifier, config=auth_config)
app = FastAPI(dependencies=[Security(jwks_auth)])

# Configure injectors to use the custom fields
payload_injector = JWTTokenInjector[FakeToken](
    config=JWTTokenInjectorConfig(payload_field="custom_payload")
)
token_injector = JWTRawTokenInjector[str](
    config=JWTTokenInjectorConfig(token_field="custom_token")
)

@app.get("/advanced-endpoint")
def advanced_endpoint(
    payload: FakeToken = Depends(payload_injector),
    raw_token: str = Depends(token_injector)
):
    return {
        "user": payload.user,
        "token": raw_token
    }
```

### Additional Configuration

The dependency also supports:

- Custom authorization header name (`auth_header`)
- Custom authorization scheme (`auth_scheme`)

```python
jwks_auth = JWKSAuth(
    jwks_validator=jwks_verifier, 
    auth_header="X-Custom-Auth", 
    auth_scheme="Token"
)
app = FastAPI(dependencies=[Security(jwks_auth)])
```

## Contributing

We are happy if you want to contribute to this project. If you find any bugs or have suggestions for improvements, please open an issue. We are also happy to accept your PRs. Just open an issue beforehand and let us know what you want to do and why.

## License

fastapi-jwks is licensed under the MIT License.
