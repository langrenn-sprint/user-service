"""Integration test cases for the authorize route."""
import os
from typing import Any, Dict

from aiohttp import hdrs
from aiohttp.test_utils import TestClient as _TestClient
import jwt
from multidict import MultiDict
import pytest
from pytest_mock import MockFixture


ID = "290e70d5-0933-4af0-bb53-1d705ba7eb95"


@pytest.fixture
def token() -> str:
    """Create a valid token."""
    secret = os.getenv("JWT_SECRET")
    algorithm = "HS256"
    payload = {"username": os.getenv("ADMIN_USERNAME"), "role": "admin"}
    return jwt.encode(payload, secret, algorithm)  # type: ignore


@pytest.fixture
def incomplete_token() -> str:
    """Create a token missing role-key."""
    secret = os.getenv("JWT_SECRET")
    algorithm = "HS256"
    payload = {"username": os.getenv("ADMIN_USERNAME")}
    return jwt.encode(payload, secret, algorithm)  # type: ignore


@pytest.fixture
def token_nonprivileged_user() -> str:
    """Create a valid token."""
    secret = os.getenv("JWT_SECRET")
    algorithm = "HS256"
    payload = {"username": "nonprivileged@example.com", "role": "nonprivileged"}
    return jwt.encode(payload, secret, algorithm)  # type: ignore


@pytest.fixture
def token_invalid() -> str:
    """Create a valid token."""
    return "invalid_token"


async def mock_user_with_admin_role(db: Any, username: str) -> dict:
    """Create a mock user object."""
    return {  # noqa: S106
        "id": ID,
        "username": "admin-user@example.com",
        "password": "password",
        "role": "admin",
    }


async def mock_nonpriviledged_user(db: Any, username: str) -> dict:
    """Create a mock user object."""
    return {  # noqa: S106
        "id": ID,
        "username": "nonprivileged@example.com",
        "password": "password",
        "role": "nonprivileged",
    }


async def mock_inconsistent_user(db: Any, username: str) -> dict:
    """Create a mock user object."""
    return {  # noqa: S106
        "id": ID,
        "username": "nonprivileged@example.com",
        "password": "password",
        "role": "inconsistent",
    }


@pytest.mark.integration
async def test_authorize(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 204 No content."""
    request_body = {"token": token, "roles": ["admin"]}

    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
        },
    )

    resp = await client.post("/authorize", headers=headers, json=request_body)
    assert resp.status == 204


@pytest.mark.integration
async def test_authorize_incomplete_token(
    client: _TestClient, mocker: MockFixture, incomplete_token: MockFixture
) -> None:
    """Should return 400 Bad Request."""
    request_body = {"token": incomplete_token, "roles": ["admin"]}

    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
        },
    )

    resp = await client.post("/authorize", headers=headers, json=request_body)
    assert resp.status == 400


@pytest.mark.integration
async def test_authorize_non_priviledge_user(
    client: _TestClient, mocker: MockFixture, token_nonprivileged_user: MockFixture
) -> None:
    """Should return 403 Forbidden."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_nonpriviledged_user,
    )

    request_body = {"token": token_nonprivileged_user, "roles": ["admin"]}

    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
        },
    )

    resp = await client.post("/authorize", headers=headers, json=request_body)
    assert resp.status == 403


# Bad cases:
@pytest.mark.integration
async def test_authorize_no_body(
    client: _TestClient, mocker: MockFixture, token_nonprivileged_user: MockFixture
) -> None:
    """Should return 400 Bad Request."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_inconsistent_user,
    )

    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
        },
    )

    resp = await client.post("/authorize", headers=headers)
    assert resp.status == 400


@pytest.mark.integration
async def test_authorize_invalid_body(
    client: _TestClient, mocker: MockFixture, token_nonprivileged_user: MockFixture
) -> None:
    """Should return 400 Bad Request."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_inconsistent_user,
    )

    invalid_body: Dict[Any, Any] = {"blabla": "bladibla"}

    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
        },
    )

    resp = await client.post("/authorize", headers=headers, json=invalid_body)
    assert resp.status == 400


@pytest.mark.integration
async def test_authorize_body_missing_required_input(
    client: _TestClient, mocker: MockFixture, token_nonprivileged_user: MockFixture
) -> None:
    """Should return 400 Bad Request."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_inconsistent_user,
    )

    request_body = {"token": token_nonprivileged_user}

    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
        },
    )

    resp = await client.post("/authorize", headers=headers, json=request_body)
    assert resp.status == 400


@pytest.mark.integration
async def test_authorize_token_role_does_not_match_user_role(
    client: _TestClient, mocker: MockFixture, token_nonprivileged_user: MockFixture
) -> None:
    """Should return 400 Bad Request."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_inconsistent_user,
    )

    request_body = {"token": token_nonprivileged_user, "roles": ["admin"]}

    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
        },
    )

    resp = await client.post("/authorize", headers=headers, json=request_body)
    assert resp.status == 400


@pytest.mark.integration
async def test_authorize_invalid_token(
    client: _TestClient, mocker: MockFixture, token_invalid: MockFixture
) -> None:
    """Should return 401 Unauthorized."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user_with_admin_role,
    )

    request_body = {"token": token_invalid, "roles": ["admin"]}

    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
        },
    )

    resp = await client.post("/authorize", headers=headers, json=request_body)
    assert resp.status == 401
