"""Integration test cases for the login route."""

import os
from http import HTTPStatus
from uuid import UUID

import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pytest_mock import MockFixture

from app.main import api
from app.models import Role, User

ID = UUID("290e70d5-0933-4af0-bb53-1d705ba7eb95")


@pytest.fixture
def client() -> TestClient:
    """Fixture to create a test client for the FastAPI application."""
    return TestClient(api)


@pytest.fixture
async def mock_test_user() -> User:
    """Create a mock user object."""
    return User(id=ID, username="test", password=SecretStr("test"), role=Role.ADMIN)


@pytest.mark.integration
async def test_login_admin_user_password(client: TestClient) -> None:
    """Should return 200 OK and a valid token."""
    request_body = {
        "username": os.getenv("ADMIN_USERNAME"),
        "password": os.getenv("ADMIN_PASSWORD"),
    }
    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/login", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.OK, resp.text
    body = resp.json()
    assert type(body) is dict
    assert body["token"]
    jwt.decode(body["token"], os.getenv("JWT_SECRET"), algorithms=["HS256"])


@pytest.mark.integration
async def test_login_valid_user_password(
    client: TestClient, mocker: MockFixture, mock_test_user: User
) -> None:
    """Should return 200 OK and a valid token."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_test_user,
    )

    request_body = {
        "username": "test",
        "password": "test",
    }
    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/login", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.OK
    body = resp.json()
    assert type(body) is dict
    assert body["token"]
    jwt.decode(body["token"], os.getenv("JWT_SECRET"), algorithms=["HS256"])


# Bad cases


@pytest.mark.integration
async def test_login_invalid_user(client: TestClient, mocker: MockFixture) -> None:
    """Should return 401 Unauthorized."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=None,
    )

    request_body = {
        "username": "NON_EXISTENT_USER",
        "password": os.getenv("ADMIN_PASSWORD"),
    }
    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/login", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.integration
async def test_login_wrong_password(
    client: TestClient, mocker: MockFixture, mock_test_user: User
) -> None:
    """Should return 401 Unauthorized."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_test_user,
    )
    request_body = {
        "username": "test",
        "password": "WRONG_PASSWORD",
    }
    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/login", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.integration
async def test_login_no_body_in_request(client: TestClient) -> None:
    """Should return 422 UNPROCESSABLE_ENTITY."""
    headers = {
        "Content-Type": "application/json",
    }

    resp = client.post("/login", headers=headers)
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
