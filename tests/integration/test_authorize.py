"""Integration test cases for the authorize route."""

import os
from http import HTTPStatus
from typing import Any
from uuid import UUID

import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pytest_mock import MockFixture

from app import api
from app.models import Role, User

USER_ID = UUID("290e70d5-0933-4af0-bb53-1d705ba7eb95")


@pytest.fixture
def client() -> TestClient:
    """Fixture to create a test client for the FastAPI application."""
    return TestClient(api)


@pytest.fixture
def token_admin_user() -> str:
    """Create a valid token."""
    secret = os.getenv("JWT_SECRET")
    algorithm = "HS256"
    payload = {"username": os.getenv("ADMIN_USERNAME"), "role": "admin"}
    return jwt.encode(payload, secret, algorithm)


@pytest.fixture
def token_non_admin_user() -> str:
    """Create a valid token."""
    secret = os.getenv("JWT_SECRET")
    algorithm = "HS256"
    payload = {"username": "non-admin-user@example.com", "role": "event-admin"}
    return jwt.encode(payload, secret, algorithm)


@pytest.fixture
def incomplete_token() -> str:
    """Create a token missing role-key."""
    secret = os.getenv("JWT_SECRET")
    algorithm = "HS256"
    payload = {"username": os.getenv("ADMIN_USERNAME")}
    return jwt.encode(payload, secret, algorithm)


@pytest.fixture
def token_nonprivileged_user() -> str:
    """Create a valid token."""
    secret = os.getenv("JWT_SECRET")
    algorithm = "HS256"
    payload = {"username": "nonprivileged@example.com", "role": "nonprivileged"}
    return jwt.encode(payload, secret, algorithm)


@pytest.fixture
def token_invalid() -> str:
    """Create a valid token."""
    return "invalid_token"


@pytest.fixture
async def mock_user_with_admin_role() -> User:
    """Create a mock user object."""
    return User(
        id=USER_ID,
        username="admin-user@example.com",
        password=SecretStr("password"),
        role=Role.ADMIN,
    )


@pytest.fixture
async def mock_user_with_event_admin_role() -> User:
    """Create a mock user object."""
    return User(
        id=USER_ID,
        username="nonprivileged@example.com",
        password=SecretStr("password"),
        role=Role.EVENT_ADMIN,
    )


@pytest.fixture
async def mock_inconsistent_user() -> User:
    """Create a mock user object."""
    return User(
        id=USER_ID,
        username="nonprivileged@example.com",
        password=SecretStr("password"),
        role=Role.USER_ADMIN,
    )


@pytest.mark.integration
async def test_authorize(
    client: TestClient, token_admin_user: MockFixture, mocker: MockFixture
) -> None:
    """Should return 204 No content."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user_with_admin_role,
    )
    request_body = {"token": token_admin_user, "target_roles": ["admin"]}

    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/authorize", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.NO_CONTENT, resp.text


@pytest.mark.integration
async def test_authorize_incomplete_token(
    client: TestClient, incomplete_token: MockFixture
) -> None:
    """Should return 401 Unauthorized."""
    request_body = {"token": incomplete_token, "target_roles": ["admin"]}

    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/authorize", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.integration
async def test_authorize_non_priviledge_user(
    client: TestClient,
    mocker: MockFixture,
    token_nonprivileged_user: MockFixture,
    mock_user_with_event_admin_role: User,
) -> None:
    """Should return 403 Forbidden."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user_with_event_admin_role,
    )

    request_body = {"token": token_nonprivileged_user, "target_roles": ["admin"]}

    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/authorize", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.FORBIDDEN


# Bad cases:
@pytest.mark.integration
async def test_authorize_no_body(client: TestClient) -> None:
    """Should return 422 Unprocessable entity."""
    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/authorize", headers=headers)
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


@pytest.mark.integration
async def test_authorize_invalid_body(client: TestClient) -> None:
    """Should return 422 Unprocessable entity."""
    invalid_body: dict[Any, Any] = {"blabla": "bladibla"}

    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/authorize", headers=headers, json=invalid_body)
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


@pytest.mark.integration
async def test_authorize_body_missing_required_input(
    client: TestClient,
    token_nonprivileged_user: MockFixture,
) -> None:
    """Should return 422 Unprocessable entity."""
    request_body = {"token": token_nonprivileged_user}

    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/authorize", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


@pytest.mark.integration
async def test_authorize_token_role_does_not_match_user_role(
    client: TestClient,
    mocker: MockFixture,
    token_nonprivileged_user: MockFixture,
    mock_inconsistent_user: User,
) -> None:
    """Should return 403 Forbidden."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_inconsistent_user,
    )

    request_body = {"token": token_nonprivileged_user, "target_roles": ["admin"]}

    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/authorize", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.integration
async def test_authorize_invalid_token(
    client: TestClient,
    mocker: MockFixture,
    token_invalid: MockFixture,
    mock_user_with_admin_role: User,
) -> None:
    """Should return 401 Unauthorized."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user_with_admin_role,
    )

    request_body = {"token": token_invalid, "target_roles": ["admin"]}

    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/authorize", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.integration
async def test_authorize_no_token(client: TestClient) -> None:
    """Should return 422 Unprocessable entity."""
    request_body = {"token": None, "target_roles": ["admin"]}

    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/authorize", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


@pytest.mark.integration
async def test_authorize_user_does_not_exist(
    client: TestClient, token_non_admin_user: MockFixture, mocker: MockFixture
) -> None:
    """Should return 204 No content."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=None,
    )
    request_body = {"token": token_non_admin_user, "target_roles": ["admin"]}

    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/authorize", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.integration
async def test_authorize_user_does_not_have_role(
    client: TestClient,
    token_non_admin_user: MockFixture,
    mocker: MockFixture,
    mock_user_with_event_admin_role: User,
) -> None:
    """Should return 204 No content."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user_with_event_admin_role,
    )
    request_body = {"token": token_non_admin_user, "target_roles": ["admin"]}

    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/authorize", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.FORBIDDEN
