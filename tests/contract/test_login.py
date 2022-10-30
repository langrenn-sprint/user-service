"""Contract test cases for ping."""
import os
from typing import Any

from aiohttp import ClientSession, hdrs
import pytest


@pytest.mark.contract
@pytest.mark.asyncio
async def test_login(http_service: Any) -> None:
    """Should return 200 OK and a valid token."""
    url = f"{http_service}/login"
    headers = {hdrs.CONTENT_TYPE: "application/json"}
    request_body = {
        "username": os.getenv("ADMIN_USERNAME"),
        "password": os.getenv("ADMIN_PASSWORD"),
    }
    session = ClientSession()
    async with session.post(url, headers=headers, json=request_body) as response:
        body = await response.json()
    await session.close()

    assert response.status == 200
    assert body["token"]


@pytest.mark.contract
@pytest.mark.asyncio
async def test_login_wrong_password(http_service: Any) -> None:
    """Should return 401."""
    url = f"{http_service}/login"
    headers = {hdrs.CONTENT_TYPE: "application/json"}
    request_body = {
        "username": os.getenv("ADMIN_USERNAME"),
        "password": "WRONG_PASSWORD",
    }
    session = ClientSession()
    async with session.post(url, headers=headers, json=request_body) as response:
        body = await response.json()
    await session.close()

    assert response.status == 401
    assert response.content_type == "application/json"
    assert body["detail"] == "Incorrect username or password"
