"""Contract test cases for activation (event-service-gui#222).

Runs against user-service and MongoDB in docker compose: admin creates a user
without password, the user sets the password with the activation code, and
admin makes a new code to reset the password.
"""

import hashlib
import os
import secrets
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import Any

import jwt
import pytest
from httpx import AsyncClient
from pymongo import AsyncMongoClient

DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")


@pytest.fixture
def admin() -> dict:
    """Return the Authorization header for admin."""
    payload = {
        "username": os.getenv("ADMIN_USERNAME"),
        "role": "admin",
        "exp": 9999999999,
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET"), "HS256")
    return {"Authorization": f"Bearer {token}"}


async def stored_user(db_address: dict[str, Any], username: str) -> dict:
    """Return the user as stored in MongoDB."""
    mongo = AsyncMongoClient(
        **db_address,
        username=DB_USER,
        password=DB_PASSWORD,
        uuidRepresentation="standard",
    )
    try:
        user = await mongo[f"{DB_NAME}"].users_collection.find_one(
            {"username": username}
        )
    finally:
        await mongo.close()
    assert user
    return user


async def expire_code(db_address: dict[str, Any], username: str) -> None:
    """Let the user's activation code expire."""
    mongo = AsyncMongoClient(
        **db_address,
        username=DB_USER,
        password=DB_PASSWORD,
        uuidRepresentation="standard",
    )
    try:
        await mongo[f"{DB_NAME}"].users_collection.update_one(
            {"username": username},
            {"$set": {"activation_expires": datetime.now(UTC) - timedelta(minutes=1)}},
        )
    finally:
        await mongo.close()


async def login(client: AsyncClient, url: str, username: str, password: str) -> int:
    """Log in and return the status."""
    response = await client.post(
        f"{url}/login", json={"username": username, "password": password}
    )
    return response.status_code


async def activate(client: AsyncClient, url: str, code: str, password: str) -> int:
    """Set the password with the code and return the status."""
    response = await client.post(
        f"{url}/activate", json={"code": code, "password": password}
    )
    return response.status_code


async def create_user(client: AsyncClient, url: str, admin: dict, username: str):  # noqa: ANN201
    """Create a user without password and return the response."""
    response = await client.post(
        f"{url}/users",
        headers=admin,
        json={"username": username, "role": "event-admin"},
    )
    assert response.status_code == HTTPStatus.CREATED, response.text
    return response


@pytest.mark.contract
@pytest.mark.asyncio
async def test_user_sets_own_password(
    http_service: str, db_address: dict[str, Any], admin: dict
) -> None:
    """Admin creates a user without password; the user activates once."""
    username = f"ny-{secrets.token_hex(4)}@example.com"
    password = secrets.token_urlsafe(16)
    async with AsyncClient() as client:
        response = await create_user(client, http_service, admin, username)
        activation = response.json()
        code = activation["code"]
        user_id = activation["user_id"]
        assert response.headers["Location"] == f"/users/{user_id}"

        # only a hash of the code is stored:
        stored = await stored_user(db_address, username)
        assert stored["password"] is None
        assert (
            stored["activation_code_hash"] == hashlib.sha256(code.encode()).hexdigest()
        )
        assert code not in str(stored)

        # admin sees that the user is not activated:
        info = (
            await client.get(f"{http_service}/users/{user_id}", headers=admin)
        ).json()
        assert info["activated"] is False
        assert info["activation_expires"] == activation["expires"].replace(
            "+00:00", "Z"
        )

        # the user cannot log in before the password is set:
        assert await login(client, http_service, username, "") == HTTPStatus.FORBIDDEN
        assert await login(client, http_service, username, password) == (
            HTTPStatus.FORBIDDEN
        )

        # the password must have at least 10 characters:
        assert await activate(client, http_service, code, "kort") == (
            HTTPStatus.UNPROCESSABLE_ENTITY
        )
        assert await activate(client, http_service, "feil-kode", password) == (
            HTTPStatus.BAD_REQUEST
        )
        assert await activate(client, http_service, code, password) == (
            HTTPStatus.NO_CONTENT
        )
        # the code can only be used once:
        assert await activate(client, http_service, code, "et-annet-passord") == (
            HTTPStatus.BAD_REQUEST
        )

        assert await login(client, http_service, username, password) == HTTPStatus.OK
        info = (
            await client.get(f"{http_service}/users/{user_id}", headers=admin)
        ).json()
        assert info["activated"] is True
        assert info["activation_expires"] is None
        stored = await stored_user(db_address, username)
        assert stored["password"].startswith("$argon2id$")
        assert "activation_code_hash" not in stored


@pytest.mark.contract
@pytest.mark.asyncio
async def test_admin_resets_password(http_service: str, admin: dict) -> None:
    """A new code replaces earlier ones; the old password works until the new is set."""
    username = f"glemsk-{secrets.token_hex(4)}@example.com"
    async with AsyncClient() as client:
        response = await create_user(client, http_service, admin, username)
        user_id = response.json()["user_id"]
        first = response.json()["code"]
        assert await activate(client, http_service, first, "gammelt-passord") == (
            HTTPStatus.NO_CONTENT
        )

        url = f"{http_service}/users/{user_id}/activation"
        second = (await client.post(url, headers=admin)).json()["code"]
        third_response = await client.post(url, headers=admin)
        assert third_response.status_code == HTTPStatus.CREATED, third_response.text
        third = third_response.json()["code"]

        # the old password works until the new one is set:
        assert await login(client, http_service, username, "gammelt-passord") == (
            HTTPStatus.OK
        )
        # only the newest code works:
        assert await activate(client, http_service, second, "nytt-passord!") == (
            HTTPStatus.BAD_REQUEST
        )
        assert await activate(client, http_service, third, "nytt-passord!") == (
            HTTPStatus.NO_CONTENT
        )
        assert await login(client, http_service, username, "nytt-passord!") == (
            HTTPStatus.OK
        )
        assert await login(client, http_service, username, "gammelt-passord") == (
            HTTPStatus.UNAUTHORIZED
        )


@pytest.mark.contract
@pytest.mark.asyncio
async def test_expired_code(
    http_service: str, db_address: dict[str, Any], admin: dict
) -> None:
    """An expired code gives the same answer as an unknown one."""
    username = f"treg-{secrets.token_hex(4)}@example.com"
    async with AsyncClient() as client:
        response = await create_user(client, http_service, admin, username)
        await expire_code(db_address, username)

        status = await activate(
            client, http_service, response.json()["code"], "et-langt-passord"
        )

    assert status == HTTPStatus.BAD_REQUEST


@pytest.mark.contract
@pytest.mark.asyncio
async def test_activate_with_username(http_service: str, admin: dict) -> None:
    """With a username, the code only works for the user it was given to."""
    username = f"navn-{secrets.token_hex(4)}@example.com"
    password = secrets.token_urlsafe(16)
    async with AsyncClient() as client:
        code = (await create_user(client, http_service, admin, username)).json()["code"]
        wrong = await client.post(
            f"{http_service}/activate",
            json={"code": code, "password": password, "username": "en-annen"},
        )
        right = await client.post(
            f"{http_service}/activate",
            json={"code": code, "password": password, "username": username},
        )

    assert wrong.status_code == HTTPStatus.BAD_REQUEST, wrong.text
    assert right.status_code == HTTPStatus.NO_CONTENT, right.text


@pytest.mark.contract
@pytest.mark.asyncio
async def test_admin_cannot_delete_self(http_service: str, admin: dict) -> None:
    """An admin user cannot delete the user they are logged in as."""
    username = f"admin-{secrets.token_hex(4)}@example.com"
    password = secrets.token_urlsafe(16)
    async with AsyncClient() as client:
        response = await client.post(
            f"{http_service}/users",
            headers=admin,
            json={"username": username, "role": "admin", "password": password},
        )
        assert response.status_code == HTTPStatus.CREATED, response.text
        user_url = f"{http_service}{response.headers['Location']}"
        login = await client.post(
            f"{http_service}/login", json={"username": username, "password": password}
        )
        own = {"Authorization": f"Bearer {login.json()['token']}"}

        refused = await client.delete(user_url, headers=own)
        deleted = await client.delete(user_url, headers=admin)

    assert refused.status_code == HTTPStatus.CONFLICT, refused.text
    assert deleted.status_code == HTTPStatus.NO_CONTENT, deleted.text
