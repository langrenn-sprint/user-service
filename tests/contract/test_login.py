"""Contract test cases for ping."""

import os
from http import HTTPStatus
from typing import Any

import pytest
from httpx import AsyncClient


@pytest.mark.contract
@pytest.mark.asyncio
async def test_login(http_service: Any) -> None:
    """Should return 200 OK and a valid token."""
    url = f"{http_service}/login"
    headers = {"Content-Type": "application/json"}
    request_body = {
        "username": os.getenv("ADMIN_USERNAME"),
        "password": os.getenv("ADMIN_PASSWORD"),
    }

    async with AsyncClient() as client:
        response = await client.post(url, headers=headers, json=request_body)
        body = response.json()

    assert response.status_code == HTTPStatus.OK
    assert "application/json" in response.headers["Content-Type"]
    assert body["token"]


@pytest.mark.contract
@pytest.mark.asyncio
async def test_login_wrong_password(http_service: Any) -> None:
    """Should return 401 Unauthorized."""
    url = f"{http_service}/login"
    headers = {"Content-Type": "application/json"}
    request_body = {
        "username": os.getenv("ADMIN_USERNAME"),
        "password": "WRONG_PASSWORD",
    }
    async with AsyncClient() as client:
        response = await client.post(url, headers=headers, json=request_body)
        body = response.json()

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert "application/json" in response.headers["Content-Type"]
    assert body["detail"] == "Incorrect username or password"
