# fastapi-jwks

fastapi-jwks is a Python library designed to facilitate the integration of JSON Web Key Set (JWKS) with FastAPI applications. It provides a set of tools to automatically query the JWKS endpoint and verify the tokens sent over a request.

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
