# fastapi-jwks

fastapi-jwks is a Python library designed to facilitate the integration of JSON Web Key Set (JWKS) with FastAPI applications. It provides a set of tools to automatically query the JWKS endpoint and verify the tokens sent over a request.

## Key Features

- **JWKS Endpoint Querying**: The library automatically queries the JWKS endpoint to fetch the necessary keys for token verification.
- **Token Verification**: It verifies the tokens sent over a request with the JWKS endpoint, ensuring the authenticity and integrity of the data.
- **Middleware Integration**: The library includes a middleware that can be easily integrated into your FastAPI application to handle token validation on every request.
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
from fastapi import Depends
from pydantic import BaseModel
from fastapi_jwks.injector import JWTTokenInjector
from fastapi_jwks.middlewares.jwk_auth import JWKSAuthMiddleware
from fastapi_jwks.models.types import JWKSConfig, JWTDecodeConfig
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

app.add_middleware(JWKSAuthMiddleware, jwks_validator=jwks_verifier)
```

## Advanced Usage

### Custom State Fields

You can customize where the payload and raw token are stored in the request state:

```python
from fastapi_jwks.models.types import JWKSMiddlewareConfig, JWTTokenInjectorConfig
from fastapi_jwks.injector import JWTTokenInjector, JWTRawTokenInjector

# Configure middleware with custom field names
middleware_config = JWKSMiddlewareConfig(
    payload_field="custom_payload",
    token_field="custom_token"
)

app.add_middleware(
    JWKSAuthMiddleware,
    jwks_validator=jwks_verifier,
    config=middleware_config
)

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

The middleware also supports:
- Custom authorization header name (`auth_header`)
- Custom authorization scheme (`auth_scheme`)
- Path exclusion (`exclude_paths`)

```python
app.add_middleware(
    JWKSAuthMiddleware,
    jwks_validator=jwks_verifier,
    auth_header="X-Custom-Auth",
    auth_scheme="Token",
    exclude_paths=["/public", "/health"]
)
```
