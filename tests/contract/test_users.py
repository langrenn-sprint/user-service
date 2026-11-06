"""Contract test cases for ping."""

import logging
import os
from collections.abc import AsyncGenerator
from http import HTTPStatus
from typing import Any

import jwt
import pytest
from argon2 import PasswordHasher
from httpx import AsyncClient
from pymongo import AsyncMongoClient
from pytest_mock import MockFixture

from app.adapters import UsersAdapter
from app.services.passwords import PASSWORD_HASH_MONGO_REGEX

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
async def clear_db(db_address: dict[str, Any]) -> AsyncGenerator:
    """Delete all events before we start."""
    mongo = AsyncMongoClient(**db_address, username=DB_USER, password=DB_PASSWORD)
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
    finally:
        await mongo.close()


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
        "password": "secret-1234",
        "role": "admin",
    }

    async with AsyncClient() as client:
        response = await client.post(url, headers=headers, json=request_body)

    assert response.status_code == HTTPStatus.CREATED
    assert "/users/" in response.headers["Location"]


@pytest.mark.contract
@pytest.mark.asyncio
async def test_login_created_user_password_is_hashed(
    http_service: Any, db_address: dict[str, Any]
) -> None:
    """Should log in the new user, and store a hash, not the password."""
    async with AsyncClient() as client:
        response = await client.post(
            f"{http_service}/login",
            json={"username": "user@example.com", "password": "secret-1234"},
        )
    assert response.status_code == HTTPStatus.OK, response.text

    mongo = AsyncMongoClient(**db_address, username=DB_USER, password=DB_PASSWORD)
    try:
        user = await mongo[f"{DB_NAME}"].users_collection.find_one(
            {"username": "user@example.com"}
        )
    finally:
        await mongo.close()
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
            "password": "newsecret-1234",
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
            url, json={"username": username, "password": "newsecret-1234"}
        )
        old = await client.post(
            url, json={"username": username, "password": "secret-1234"}
        )
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
async def test_plaintext_password_query_in_mongodb(
    http_service: Any, db_address: dict[str, Any]
) -> None:
    """Should select plain-text passwords, also those resembling a hash.

    Users without password (not activated) have nothing to hash, and must not
    be selected: hashing None would stop user-service from starting.
    """
    _ = http_service  # starts the services, including MongoDB
    password_hash = PasswordHasher().hash("secret")
    mongo = AsyncMongoClient(
        **db_address,
        username=DB_USER,
        password=DB_PASSWORD,
        uuidRepresentation="standard",
    )
    database = mongo["password_regex_test"]
    try:
        await database.users_collection.insert_many(
            [
                {"id": 1, "password": password_hash},
                {"id": 2, "password": "secret"},
                {"id": 3, "password": "$argon2-my-password"},
                {"id": 4, "password": password_hash + "\n"},
                {"id": 5, "password": None},
                {"id": 6},
            ]
        )
        await UsersAdapter.init(database)
        found = await UsersAdapter.get_users_with_plaintext_password(
            PASSWORD_HASH_MONGO_REGEX
        )
    finally:
        await mongo.drop_database("password_regex_test")
        await mongo.close()

    assert sorted(user["password"] for user in found) == sorted(
        ["secret", "$argon2-my-password", password_hash + "\n"]
    )
