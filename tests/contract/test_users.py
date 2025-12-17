"""Contract test cases for ping."""

import logging
import os
from collections.abc import AsyncGenerator
from http import HTTPStatus
from typing import Any

import jwt
import motor.motor_asyncio
import pytest
from aiohttp import ClientSession, hdrs
from pytest_mock import MockFixture

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "27017"))
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

logger = logging.getLogger("user_service.contract_tests.test_users")


@pytest.fixture
def token() -> str:
    """Create a valid token."""
    secret = os.getenv("JWT_SECRET")
    algorithm = "HS256"
    payload = {"username": os.getenv("ADMIN_USERNAME"), "role": "admin"}
    return jwt.encode(payload, secret, algorithm)


@pytest.fixture(scope="module")
async def clear_db() -> AsyncGenerator:
    """Delete all events before we start."""
    mongo = motor.motor_asyncio.AsyncIOMotorClient(
        host=DB_HOST, port=DB_PORT, username=DB_USER, password=DB_PASSWORD
    )
    try:
        await mongo.drop_database(f"{DB_NAME}")
    except Exception:
        logger.exception("Failed to drop database %s", DB_NAME)
        raise

    yield

    try:
        await mongo.drop_database(f"{DB_NAME}")
    except Exception:
        logger.exception("Failed to drop database %s", DB_NAME)
        raise


@pytest.mark.contract
@pytest.mark.asyncio
async def test_create_user(http_service: Any, token: MockFixture) -> None:
    """Should return 201 Created, location header and no body."""
    url = f"{http_service}/users"
    headers = {
        hdrs.CONTENT_TYPE: "application/json",
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }
    request_body = {
        "username": "user@example.com",
        "password": "secret",
        "role": "admin",
    }
    session = ClientSession()
    async with session.post(url, headers=headers, json=request_body) as response:
        status = response.status
    await session.close()

    assert status == HTTPStatus.CREATED
    assert "/users/" in response.headers[hdrs.LOCATION]


@pytest.mark.contract
@pytest.mark.asyncio
async def test_get_users(http_service: Any, token: MockFixture) -> None:
    """Should return 200 OK and a list of users as json."""
    url = f"{http_service}/users"
    headers = {
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    session = ClientSession()
    async with session.get(url, headers=headers) as response:
        users = await response.json()
    await session.close()

    assert response.status == HTTPStatus.OK
    assert "application/json" in response.headers[hdrs.CONTENT_TYPE]
    assert type(users) is list
    assert len(users) == 1
    for user in users:
        assert "password" not in user


@pytest.mark.contract
@pytest.mark.asyncio
async def test_get_user(http_service: Any, token: MockFixture) -> None:
    """Should return 200 OK and an user as json."""
    url = f"{http_service}/users"

    headers = {
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    async with ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            users = await response.json()
        _id = users[0]["id"]
        url = f"{url}/{_id}"
        async with session.get(url, headers=headers) as response:
            user = await response.json()

    assert response.status == HTTPStatus.OK
    assert "application/json" in response.headers[hdrs.CONTENT_TYPE]
    assert type(user) is dict
    assert user["id"]
    assert user["username"]
    assert "password" not in user


@pytest.mark.contract
@pytest.mark.asyncio
async def test_update_user(http_service: Any, token: MockFixture) -> None:
    """Should return 204 No Content."""
    url = f"{http_service}/users"
    headers = {
        hdrs.CONTENT_TYPE: "application/json",
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    async with ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            users = await response.json()
        _id = users[0]["id"]
        url = f"{url}/{_id}"
        request_body = {
            "id": _id,
            "username": "user@example.com updated",
            "role": "admin",
        }
        async with session.put(url, headers=headers, json=request_body) as response:
            pass

    assert response.status == HTTPStatus.NO_CONTENT


@pytest.mark.contract
@pytest.mark.asyncio
async def test_delete_user(http_service: Any, token: MockFixture) -> None:
    """Should return 204 No Content."""
    url = f"{http_service}/users"
    headers = {
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    async with ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            users = await response.json()
        _id = users[0]["id"]
        url = f"{url}/{_id}"
        async with session.delete(url, headers=headers) as response:
            pass

    assert response.status == HTTPStatus.NO_CONTENT
