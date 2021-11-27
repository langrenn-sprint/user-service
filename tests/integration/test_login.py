"""Integration test cases for the login route."""
import os
from typing import Any

from aiohttp import hdrs
from aiohttp.test_utils import TestClient as _TestClient
import jwt
import pytest
from pytest_mock import MockFixture

from user_service.models import User


ID = "290e70d5-0933-4af0-bb53-1d705ba7eb95"


async def mock_test_user(db: Any, username: str) -> User:
    """Create a mock user object."""
    return User(  # noqa: S106
        id=ID, username="test", password="test", role="user-admin"
    )


@pytest.mark.integration
async def test_login_admin_user_password(
    client: _TestClient, mocker: MockFixture
) -> None:
    """Should return 200 OK and a valid token."""
    request_body = {
        "username": os.getenv("ADMIN_USERNAME"),
        "password": os.getenv("ADMIN_PASSWORD"),
    }
    headers = {
        hdrs.CONTENT_TYPE: "application/json",
    }

    resp = await client.post("/login", headers=headers, json=request_body)
    assert resp.status == 200
    body = await resp.json()
    assert type(body) is dict
    assert body["token"]
    jwt.decode(body["token"], os.getenv("JWT_SECRET"), algorithms="HS256")  # type: ignore


@pytest.mark.integration
async def test_login_valid_user_password(
    client: _TestClient, mocker: MockFixture
) -> None:
    """Should return 200 OK and a valid token."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_test_user,
    )

    request_body = {
        "username": "test",
        "password": "test",
    }
    headers = {
        hdrs.CONTENT_TYPE: "application/json",
    }

    resp = await client.post("/login", headers=headers, json=request_body)
    assert resp.status == 200
    body = await resp.json()
    assert type(body) is dict
    assert body["token"]
    jwt.decode(body["token"], os.getenv("JWT_SECRET"), algorithms="HS256")  # type: ignore


# Bad cases


@pytest.mark.integration
async def test_login_invalid_user(client: _TestClient, mocker: MockFixture) -> None:
    """Should return 401 Unauthorized."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=None,
    )

    request_body = {
        "username": "NON_EXISTENT_USER",
        "password": os.getenv("ADMIN_PASSWORD"),
    }
    headers = {
        hdrs.CONTENT_TYPE: "application/json",
    }

    resp = await client.post("/login", headers=headers, json=request_body)
    assert resp.status == 401


@pytest.mark.integration
async def test_login_wrong_password(client: _TestClient, mocker: MockFixture) -> None:
    """Should return 401 Unauthorized."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_test_user,
    )
    request_body = {
        "username": "test",
        "password": "WRONG_PASSWORD",
    }
    headers = {
        hdrs.CONTENT_TYPE: "application/json",
    }

    resp = await client.post("/login", headers=headers, json=request_body)
    assert resp.status == 401


@pytest.mark.integration
async def test_login_no_body_in_request(
    client: _TestClient, mocker: MockFixture
) -> None:
    """Should return 400 Bad Request."""
    headers = {
        hdrs.CONTENT_TYPE: "application/json",
    }

    resp = await client.post("/login", headers=headers)
    assert resp.status == 400
