"""Contract test cases for ping."""

import os
from http import HTTPStatus
from typing import Any

import jwt
import pytest
from httpx import AsyncClient
from pytest_mock import MockFixture


@pytest.fixture
def token() -> str:
    """Create a valid token."""
    secret = os.getenv("JWT_SECRET")
    algorithm = "HS256"
    payload = {"username": os.getenv("ADMIN_USERNAME"), "role": "admin"}
    return jwt.encode(payload, secret, algorithm)


@pytest.mark.contract
@pytest.mark.asyncio
async def test_authorize(http_service: Any, token: MockFixture) -> None:
    """Should return 200 OK and a valid token."""
    url = f"{http_service}/authorize"
    request_body = {"token": token, "roles": ["admin"]}

    headers = {
        "Content-Type": "application/json",
    }
    async with AsyncClient() as client:
        response = await client.post(url, headers=headers, json=request_body)

    assert response.status_code == HTTPStatus.NO_CONTENT


@pytest.mark.contract
@pytest.mark.asyncio
async def test_authorize_token_value_none(http_service: Any) -> None:
    """Should return 401 Unauthorized."""
    url = f"{http_service}/authorize"
    request_body = {"token": None, "roles": ["admin"]}

    headers = {
        "Content-Type": "application/json",
    }
    async with AsyncClient() as client:
        response = await client.post(url, headers=headers, json=request_body)
        body = response.json()

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert "application/json" in response.headers["Content-Type"]
    assert body.get("detail") == "Token is required input."


@pytest.mark.contract
@pytest.mark.asyncio
async def test_authorize_no_token(http_service: Any) -> None:
    """Should return 401 Unauthorized."""
    url = f"{http_service}/authorize"
    request_body = {"roles": ["admin"]}

    headers = {
        "Content-Type": "application/json",
    }
    async with AsyncClient() as client:
        response = await client.post(url, headers=headers, json=request_body)
        body = response.json()

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert "application/json" in response.headers["Content-Type"]
    assert body.get("detail") == "Token is required input."


@pytest.mark.contract
@pytest.mark.asyncio
async def test_authorize_wrong_role(http_service: Any, token: MockFixture) -> None:
    """Should return 403 Forbidden."""
    url = f"{http_service}/authorize"
    request_body = {"token": token, "roles": ["WRONG_ROLE"]}

    headers = {
        "Content-Type": "application/json",
    }

    async with AsyncClient() as client:
        response = await client.post(url, headers=headers, json=request_body)
        body = response.json()

    assert response.status_code == HTTPStatus.FORBIDDEN
    assert "application/json" in response.headers["Content-Type"]
    assert body.get("detail") == "User admin does not have sufficient role."
