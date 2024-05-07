import pytest
from fastapi import FastAPI
from starlette.responses import Response
from starlette.testclient import TestClient


@pytest.fixture()
def app():

    test_app = FastAPI()

    @test_app.get("/test-endpoint")
    def get_test_route():
        return Response(status_code=200)
    return app

@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def test_middleware(client):


