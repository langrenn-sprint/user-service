"""Contract test cases for the role model (event-service-gui#215).

A user is created with each role and logs in, so the tests use real tokens.
They check that only admin may read and change users, that the token carries
the user's role, and how a role change reaches the token:
- /authorize rejects a token whose role no longer matches the user.
- /token/renew puts the new role in the new token.
"""

import os
import re
import secrets
from collections.abc import AsyncGenerator
from http import HTTPStatus
from typing import Any

import jwt
import pytest
from httpx import AsyncClient, Response
from pymongo import AsyncMongoClient

from tests.role_model import (
    ADMIN,
    CONTESTANT_ADMIN,
    REMOVED_ROLES,
    RESULT_ADMIN,
    ROLES,
    access_cases,
)

DB_NAME = os.environ["DB_NAME"]
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
# Password for the users the tests create:
PASSWORD = secrets.token_urlsafe(16)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _check(response: Response, expected: HTTPStatus, action: str) -> Response:
    assert response.status_code == expected, (
        f"{action}: got {response.status_code}, {response.text[:500]}"
    )
    return response


def _role_in(token: str) -> str:
    return jwt.decode(token, os.environ["JWT_SECRET"], algorithms=["HS256"])["role"]


async def _login(
    client: AsyncClient, http_service: str, username: str, password: str
) -> str:
    response = await client.post(
        f"{http_service}/login", json={"username": username, "password": password}
    )
    return _check(response, HTTPStatus.OK, f"login {username}").json()["token"]


async def _create_user(
    client: AsyncClient, http_service: str, admin_token: str, username: str, role: str
) -> str:
    """Create a user as admin, and return its id."""
    response = await client.post(
        f"{http_service}/users",
        headers=_auth(admin_token),
        json={"username": username, "password": PASSWORD, "role": role},
    )
    _check(response, HTTPStatus.CREATED, f"create user with role {role}")
    return response.headers["Location"].split("/")[-1]


@pytest.fixture(scope="module", autouse=True)
async def clear_db(db_address: dict[str, Any]) -> AsyncGenerator:
    """Clear db before and after tests."""
    mongo = AsyncMongoClient(**db_address, username=DB_USER, password=DB_PASSWORD)
    await mongo.drop_database(DB_NAME)
    yield
    await mongo.drop_database(DB_NAME)
    await mongo.close()


@pytest.fixture(scope="module")
async def admin_token(http_service: str, clear_db: Any) -> str:
    """Log in as admin."""
    _ = clear_db  # the db is cleared first
    async with AsyncClient() as client:
        return await _login(
            client,
            http_service,
            os.environ["ADMIN_USERNAME"],
            os.environ["ADMIN_PASSWORD"],
        )


@pytest.fixture(scope="module")
async def tokens(http_service: str, admin_token: str) -> dict[str, str]:
    """Create a user for each other role, and log in as them."""
    tokens = {ADMIN: admin_token}
    async with AsyncClient() as client:
        for role in ROLES:
            if role == ADMIN:
                continue
            username = f"{role}@example.com"
            await _create_user(client, http_service, admin_token, username, role)
            tokens[role] = await _login(client, http_service, username, PASSWORD)
    return tokens


# --- The role model, with real tokens -------------------------------------------


@pytest.mark.contract
@pytest.mark.asyncio(scope="module")
@pytest.mark.parametrize(("method", "path", "role", "allowed"), access_cases(ROLES))
async def test_access(  # noqa: PLR0913
    http_service: str,
    tokens: dict[str, str],
    method: str,
    path: str,
    role: str,
    *,
    allowed: bool,
) -> None:
    """Only admin may read and change users, the others get 403.

    The role check runs before validation, so with an invalid id and an empty
    body nothing is changed.
    """
    url = http_service + re.sub(r"\{\w+\}", "not-a-uuid", path)
    async with AsyncClient() as client:
        response = await client.request(
            method,
            url,
            headers=_auth(tokens[role]),
            json={} if method in ("POST", "PUT") else None,
        )
    if allowed:
        assert response.status_code not in (
            HTTPStatus.UNAUTHORIZED,
            HTTPStatus.FORBIDDEN,
        ), f"{method} {path} as {role}: got {response.status_code}"
    else:
        _check(response, HTTPStatus.FORBIDDEN, f"{method} {path} as {role}")


@pytest.mark.contract
@pytest.mark.asyncio(scope="module")
async def test_token_has_the_users_role(tokens: dict[str, str]) -> None:
    """The token from login carries the user's role."""
    for role, token in tokens.items():
        assert _role_in(token) == role


@pytest.mark.contract
@pytest.mark.asyncio(scope="module")
@pytest.mark.parametrize("role", REMOVED_ROLES)
async def test_removed_roles_cannot_be_given(
    http_service: str, admin_token: str, role: str
) -> None:
    """A user cannot be created with a role that no longer exists."""
    async with AsyncClient() as client:
        response = await client.post(
            f"{http_service}/users",
            headers=_auth(admin_token),
            json={
                "username": f"{role}@example.com",
                "password": PASSWORD,
                "role": role,
            },
        )
    _check(response, HTTPStatus.UNPROCESSABLE_ENTITY, f"create with role {role}")


# --- Scenarios ------------------------------------------------------------------


@pytest.mark.contract
@pytest.mark.asyncio(scope="module")
async def test_user_cannot_change_own_role(http_service: str, admin_token: str) -> None:
    """A contestant-admin cannot make itself admin."""
    username = "selvbetjent@example.com"
    async with AsyncClient() as client:
        user_id = await _create_user(
            client, http_service, admin_token, username, CONTESTANT_ADMIN
        )
        token = await _login(client, http_service, username, PASSWORD)
        response = await client.put(
            f"{http_service}/users/{user_id}",
            headers=_auth(token),
            json={
                "id": user_id,
                "username": username,
                "password": PASSWORD,
                "role": ADMIN,
            },
        )
        _check(response, HTTPStatus.FORBIDDEN, "change own role")

        response = await client.get(
            f"{http_service}/users/{user_id}", headers=_auth(admin_token)
        )
        assert _check(response, HTTPStatus.OK, "get user").json()["role"] == (
            CONTESTANT_ADMIN
        )


@pytest.mark.contract
@pytest.mark.asyncio(scope="module")
async def test_role_change_reaches_the_token(
    http_service: str, admin_token: str
) -> None:
    """Admin changes a user's role.

    /authorize then rejects the old token, as its role no longer matches, and
    /token/renew gives a token with the new role.
    """
    username = "rollebytte@example.com"
    async with AsyncClient() as client:
        user_id = await _create_user(
            client, http_service, admin_token, username, CONTESTANT_ADMIN
        )
        token = await _login(client, http_service, username, PASSWORD)

        response = await client.post(
            f"{http_service}/authorize",
            json={"token": token, "target_roles": [CONTESTANT_ADMIN]},
        )
        _check(response, HTTPStatus.NO_CONTENT, "authorize with own role")
        response = await client.post(
            f"{http_service}/authorize",
            json={"token": token, "target_roles": [ADMIN, RESULT_ADMIN]},
        )
        _check(response, HTTPStatus.FORBIDDEN, "authorize with other roles")

        response = await client.put(
            f"{http_service}/users/{user_id}",
            headers=_auth(admin_token),
            json={
                "id": user_id,
                "username": username,
                "password": PASSWORD,
                "role": RESULT_ADMIN,
            },
        )
        _check(response, HTTPStatus.NO_CONTENT, "change role as admin")

        response = await client.post(
            f"{http_service}/authorize",
            json={"token": token, "target_roles": [CONTESTANT_ADMIN]},
        )
        _check(response, HTTPStatus.FORBIDDEN, "authorize with the old token")

        response = await client.post(
            f"{http_service}/token/renew", headers=_auth(token)
        )
        new_token = _check(response, HTTPStatus.OK, "renew token").json()["token"]
        assert _role_in(new_token) == RESULT_ADMIN
