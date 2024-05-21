# fastapi-jwks

fastapi-jwks is a Python library designed to facilitate the integration of JSON Web Key Set (JWKS) with FastAPI applications. It provides a set of tools to automatically query the JWKS endpoint and verify the tokens sent over a request.

## Key Features

- **JWKS Endpoint Querying**: The library automatically queries the JWKS endpoint to fetch the necessary keys for token verification.
- **Token Verification**: It verifies the tokens sent over a request with the JWKS endpoint, ensuring the authenticity and integrity of the data.
- **Middleware Integration**: The library includes a middleware that can be easily integrated into your FastAPI application to handle token validation on every request.
- **Pydantic Model Support**: It supports Pydantic models for token data extraction, providing a seamless way to work with the token data.

## Usage

```sh
pip install fastapi_jwks
```

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

payload_injector = JWTTokenInjector[FakeToken]()


@app.get("/my-endpoint", response_model=FakeToken)
def my_endpoint(fake_token: Depends(payload_injector)):
    return fake_token


jwks_verifier = JWKSValidator[FakeToken](
    decode_config=JWTDecodeConfig(),
    jwks_config=JWKSConfig(url="http://my-fake-jwks-url/my-fake-endpoint"),
)

app.add_middleware(JWKSAuthMiddleware, jwks_validator=jwks_verifier)

...
```
