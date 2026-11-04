"""Contract test cases for ping."""

import logging
import os
from collections.abc import AsyncGenerator
from http import HTTPStatus
from typing import Any

import jwt
import motor.motor_asyncio
import pytest
from argon2 import PasswordHasher
from httpx import AsyncClient
from pytest_mock import MockFixture

from app.services.passwords import PASSWORD_HASH_MONGO_REGEX

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "27017"))
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

logger = logging.getLogger("app.contract_tests.test_users")


@pytest.fixture
def token() -> str:
    """Create a valid token."""
    secret = os.getenv("JWT_SECRET")
    algorithm = "HS256"
    payload = {
        "username": os.getenv("ADMIN_USERNAME"),
        "role": "admin",
        "exp": 9999999999,
    }
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
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    request_body = {
        "username": "user@example.com",
        "password": "secret",
        "role": "admin",
    }

    async with AsyncClient() as client:
        response = await client.post(url, headers=headers, json=request_body)

    assert response.status_code == HTTPStatus.CREATED
    assert "/users/" in response.headers["Location"]


@pytest.mark.contract
@pytest.mark.asyncio
async def test_login_created_user_password_is_hashed(http_service: Any) -> None:
    """Should log in the new user, and store a hash, not the password."""
    async with AsyncClient() as client:
        response = await client.post(
            f"{http_service}/login",
            json={"username": "user@example.com", "password": "secret"},
        )
    assert response.status_code == HTTPStatus.OK, response.text

    mongo = motor.motor_asyncio.AsyncIOMotorClient(
        host=DB_HOST, port=DB_PORT, username=DB_USER, password=DB_PASSWORD
    )
    try:
        user = await mongo[f"{DB_NAME}"].users_collection.find_one(
            {"username": "user@example.com"}
        )
    finally:
        mongo.close()
    assert user
    assert user["password"].startswith("$argon2id$")
    assert "secret" not in user["password"]


@pytest.mark.contract
@pytest.mark.asyncio
async def test_get_users(http_service: Any, token: MockFixture) -> None:
    """Should return 200 OK and a list of users as json."""
    url = f"{http_service}/users"
    headers = {
        "Authorization": f"Bearer {token}",
    }

    async with AsyncClient() as client:
        response = await client.get(url, headers=headers)
        users = response.json()

    assert response.status_code == HTTPStatus.OK
    assert "application/json" in response.headers["Content-Type"]
    assert type(users) is list
    assert len(users) == 1


@pytest.mark.contract
@pytest.mark.asyncio
async def test_get_user(http_service: Any, token: MockFixture) -> None:
    """Should return 200 OK and an user as json."""
    url = f"{http_service}/users"

    headers = {
        "Authorization": f"Bearer {token}",
    }

    async with AsyncClient() as client:
        response = await client.get(url, headers=headers)
        assert response.status_code == HTTPStatus.OK, response.text
        users = response.json()
        assert len(users) > 0
        _id = users[0]["id"]
        url = f"{url}/{_id}"
        response = await client.get(url, headers=headers)
        user = response.json()

    assert response.status_code == HTTPStatus.OK
    assert "application/json" in response.headers["Content-Type"]
    assert type(user) is dict
    assert user["id"]
    assert user["username"]


@pytest.mark.contract
@pytest.mark.asyncio
async def test_update_user(http_service: Any, token: MockFixture) -> None:
    """Should return 204 No Content."""
    url = f"{http_service}/users"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    async with AsyncClient() as client:
        response = await client.get(url, headers=headers)
        assert response.status_code == HTTPStatus.OK, response.text
        users = response.json()
        assert len(users) > 0
        _id = users[0]["id"]
        url = f"{url}/{_id}"
        request_body = {
            "id": _id,
            "username": "user@example.com updated",
            "role": "admin",
            "password": "newsecret",
        }
        response = await client.put(url, headers=headers, json=request_body)

    assert response.status_code == HTTPStatus.NO_CONTENT, response.text


@pytest.mark.contract
@pytest.mark.asyncio
async def test_login_with_updated_password(http_service: Any) -> None:
    """Should log in with the new password, and not with the old one."""
    url = f"{http_service}/login"
    username = "user@example.com updated"
    async with AsyncClient() as client:
        new = await client.post(
            url, json={"username": username, "password": "newsecret"}
        )
        old = await client.post(url, json={"username": username, "password": "secret"})
    assert new.status_code == HTTPStatus.OK, new.text
    assert old.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.contract
@pytest.mark.asyncio
async def test_delete_user(http_service: Any, token: MockFixture) -> None:
    """Should return 204 No Content."""
    url = f"{http_service}/users"
    headers = {
        "Authorization": f"Bearer {token}",
    }

    async with AsyncClient() as client:
        response = await client.get(url, headers=headers)
        assert response.status_code == HTTPStatus.OK, response.text
        users = response.json()
        assert len(users) > 0
        _id = users[0]["id"]
        url = f"{url}/{_id}"
        response = await client.delete(url, headers=headers)
    assert response.status_code == HTTPStatus.NO_CONTENT, response.text


@pytest.mark.contract
@pytest.mark.asyncio
async def test_plaintext_password_query_in_mongodb(http_service: Any) -> None:
    """Should select plain-text passwords, also those resembling a hash, in MongoDB."""
    _ = http_service  # starts the services, including MongoDB
    password_hash = PasswordHasher().hash("secret")
    mongo = motor.motor_asyncio.AsyncIOMotorClient(
        host=DB_HOST, port=DB_PORT, username=DB_USER, password=DB_PASSWORD
    )
    collection = mongo[f"{DB_NAME}"].password_regex_test
    try:
        await collection.insert_many(
            [
                {"password": password_hash},
                {"password": "secret"},
                {"password": "$argon2-my-password"},
                {"password": password_hash + "\n"},
            ]
        )
        cursor = collection.find(
            {"password": {"$not": {"$regex": PASSWORD_HASH_MONGO_REGEX}}},
            {"_id": 0, "password": 1},
        )
        found = [doc["password"] for doc in await cursor.to_list(length=None)]
    finally:
        await collection.drop()
        mongo.close()

    assert sorted(found) == sorted(
        ["secret", "$argon2-my-password", password_hash + "\n"]
    )
