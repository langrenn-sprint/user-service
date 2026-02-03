"""Integration test cases for the ready route."""

from http import HTTPStatus

import pytest
from fastapi.testclient import TestClient

from app import api


@pytest.fixture
def client() -> TestClient:
    """Fixture to create a test client for the FastAPI application."""
    return TestClient(api)


@pytest.mark.integration
async def test_ping(client: TestClient) -> None:
    """Should return OK."""
    resp = client.get("/ping")
    assert resp.status_code == HTTPStatus.OK
    text = resp.text
    assert "OK" in text


@pytest.mark.integration
async def test_ready(client: TestClient) -> None:
    """Should return OK."""
    resp = client.get("/ready")
    assert resp.status_code == HTTPStatus.OK
    text = resp.text
    assert "OK" in text
