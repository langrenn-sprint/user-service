"""Integration test cases for the token route."""

import os
import time
from http import HTTPStatus
from typing import Any
from uuid import UUID

import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pytest_mock import MockFixture

from app.main import api
from app.models import Role, User

ID = UUID("290e70d5-0933-4af0-bb53-1d705ba7eb95")
JWT_SECRET = os.getenv("JWT_SECRET")
MAX_SESSION_SECONDS = int(os.getenv("JWT_MAX_SESSION_SECONDS", "86400"))


@pytest.fixture
def client() -> TestClient:
    """Fixture to create a test client for the FastAPI application."""
    return TestClient(api)


def make_token(**claims: Any) -> str:
    """Create a token with sensible defaults, overridden by the given claims."""
    now = int(time.time())
    payload = {
        "username": "test",
        "role": Role.EVENT_ADMIN.value,
        "auth_time": now,
        "exp": now + 60,
        **claims,
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    return jwt.encode(payload, JWT_SECRET, "HS256")


def decode(token: str) -> dict:
    """Decode and validate a token."""
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])


def renew(client: TestClient, token: str) -> Any:
    """Post to /token/renew with the given token."""
    return client.post("/token/renew", headers={"Authorization": f"Bearer {token}"})


@pytest.mark.integration
async def test_renew_token(client: TestClient, mocker: MockFixture) -> None:
    """Should return 200 OK and a new token with the role from the db."""
    user = User(
        id=ID, username="test", password=SecretStr("hash"), role=Role.CONTESTANT_ADMIN
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=user,
    )
    auth_time = int(time.time()) - 3600
    token = make_token(auth_time=auth_time, exp=int(time.time()) + 5)

    resp = renew(client, token)
    assert resp.status_code == HTTPStatus.OK, resp.text
    claims = decode(resp.json()["token"])
    assert claims["username"] == "test"
    # The role is read again, so a changed role is put in the new token:
    assert claims["role"] == Role.CONTESTANT_ADMIN.value
    # auth_time is kept, the lifetime is full again:
    assert claims["auth_time"] == auth_time
    assert claims["exp"] >= int(time.time()) + 60 - 1


@pytest.mark.integration
async def test_renew_token_admin(client: TestClient, mocker: MockFixture) -> None:
    """Should renew the admin's token without looking it up in the db."""
    get_user = mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
    )
    token = make_token(username=os.getenv("ADMIN_USERNAME"), role="admin")

    resp = renew(client, token)
    assert resp.status_code == HTTPStatus.OK, resp.text
    claims = decode(resp.json()["token"])
    assert claims["username"] == os.getenv("ADMIN_USERNAME")
    assert claims["role"] == Role.ADMIN.value
    get_user.assert_not_awaited()


@pytest.mark.integration
async def test_renew_token_from_login(client: TestClient) -> None:
    """Should renew a token from /login, keeping its auth_time."""
    login = client.post(
        "/login",
        json={
            "username": os.getenv("ADMIN_USERNAME"),
            "password": os.getenv("ADMIN_PASSWORD"),
        },
    )
    token = login.json()["token"]

    resp = renew(client, token)
    assert resp.status_code == HTTPStatus.OK, resp.text
    assert decode(resp.json()["token"])["auth_time"] == decode(token)["auth_time"]


# Bad cases


@pytest.mark.integration
async def test_renew_token_deleted_user(
    client: TestClient, mocker: MockFixture
) -> None:
    """Should return 401 when the user no longer exists."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=None,
    )
    resp = renew(client, make_token())
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    assert resp.json()["detail"] == "Not authenticated"


@pytest.mark.integration
async def test_renew_token_session_too_old(
    client: TestClient, mocker: MockFixture
) -> None:
    """Should return 401 when auth_time is older than JWT_MAX_SESSION_SECONDS."""
    get_user = mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
    )
    token = make_token(auth_time=int(time.time()) - MAX_SESSION_SECONDS - 1)

    resp = renew(client, token)
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    get_user.assert_not_awaited()


@pytest.mark.integration
@pytest.mark.parametrize(
    "claims",
    [
        {"exp": int(time.time()) - 1},  # expired
        {"exp": None},  # no exp
        {"auth_time": None},  # no auth_time, e.g. issued before auth_time existed
        {"username": None},
        {"auth_time": "yesterday"},
        {"auth_time": True},
    ],
)
async def test_renew_token_bad_claims(
    client: TestClient, mocker: MockFixture, claims: dict
) -> None:
    """Should return 401 for an expired token or one missing required claims."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
    )
    resp = renew(client, make_token(**claims))
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.integration
async def test_renew_token_wrong_signature(client: TestClient) -> None:
    """Should return 401 for a token not signed by us."""
    token = jwt.encode(
        {"username": "test", "auth_time": int(time.time()), "exp": time.time() + 60},
        "another-secret-that-is-at-least-32-bytes-long",
        "HS256",
    )
    resp = renew(client, token)
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.integration
async def test_renew_token_garbage(client: TestClient) -> None:
    """Should return 401 for a token that cannot be decoded."""
    resp = renew(client, "not-a-jwt")
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.integration
@pytest.mark.parametrize("headers", [{}, {"Authorization": "Basic dXNlcjpwYXNz"}])
async def test_renew_token_missing(client: TestClient, headers: dict) -> None:
    """Should return 401 when there is no bearer token."""
    resp = client.post("/token/renew", headers=headers)
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.headers["WWW-Authenticate"] == "Bearer"
