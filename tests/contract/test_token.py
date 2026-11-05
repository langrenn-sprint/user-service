"""Contract test cases for token renewal."""

import os
import time
from http import HTTPStatus
from typing import Any

import jwt
import pytest
from httpx import AsyncClient


async def login(client: AsyncClient, url: str) -> str:
    """Log in as admin and return the token."""
    response = await client.post(
        f"{url}/login",
        json={
            "username": os.getenv("ADMIN_USERNAME"),
            "password": os.getenv("ADMIN_PASSWORD"),
        },
    )
    assert response.status_code == HTTPStatus.OK
    return response.json()["token"]


def make_token(auth_time: int, exp: int) -> str:
    """Create an admin token with the given auth_time and exp."""
    payload = {
        "username": os.getenv("ADMIN_USERNAME"),
        "role": "admin",
        "auth_time": auth_time,
        "exp": exp,
    }
    return jwt.encode(payload, os.getenv("JWT_SECRET"), "HS256")


@pytest.mark.contract
@pytest.mark.asyncio
async def test_renew_token(http_service: Any) -> None:
    """Should return 200 OK and a new valid token keeping auth_time."""
    async with AsyncClient() as client:
        token = await login(client, http_service)
        response = await client.post(
            f"{http_service}/token/renew",
            headers={"Authorization": f"Bearer {token}"},
        )
        body = response.json()

    assert response.status_code == HTTPStatus.OK
    assert "application/json" in response.headers["Content-Type"]
    secret = os.getenv("JWT_SECRET")
    old = jwt.decode(token, secret, algorithms=["HS256"])
    new = jwt.decode(body["token"], secret, algorithms=["HS256"])
    assert new["auth_time"] == old["auth_time"]
    assert new["username"] == old["username"]
    assert new["role"] == old["role"]


@pytest.mark.contract
@pytest.mark.asyncio
async def test_renew_token_missing(http_service: Any) -> None:
    """Should return 401 Unauthorized."""
    async with AsyncClient() as client:
        response = await client.post(f"{http_service}/token/renew")

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert "application/json" in response.headers["Content-Type"]
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.contract
@pytest.mark.asyncio
async def test_renew_token_invalid(http_service: Any) -> None:
    """Should return 401 Unauthorized."""
    async with AsyncClient() as client:
        response = await client.post(
            f"{http_service}/token/renew",
            headers={"Authorization": "Bearer not-a-jwt"},
        )

    assert response.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.contract
@pytest.mark.asyncio
async def test_renew_token_expired(http_service: Any) -> None:
    """Should return 401 Unauthorized."""
    now = int(time.time())
    token = make_token(auth_time=now - 120, exp=now - 60)
    async with AsyncClient() as client:
        response = await client.post(
            f"{http_service}/token/renew",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.contract
@pytest.mark.asyncio
async def test_renew_token_session_too_old(http_service: Any) -> None:
    """Should return 401 when auth_time is older than JWT_MAX_SESSION_SECONDS."""
    now = int(time.time())
    max_session = int(os.getenv("JWT_MAX_SESSION_SECONDS") or "86400")
    token = make_token(auth_time=now - max_session - 60, exp=now + 60)
    async with AsyncClient() as client:
        response = await client.post(
            f"{http_service}/token/renew",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == HTTPStatus.UNAUTHORIZED
