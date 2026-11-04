"""Integration test cases for the login route."""

import os
from http import HTTPStatus
from uuid import UUID

import jwt
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pytest_mock import MockFixture

from app.main import api
from app.models import Role, User
from app.services.passwords import hash_password

ID = UUID("290e70d5-0933-4af0-bb53-1d705ba7eb95")


@pytest.fixture
def client() -> TestClient:
    """Fixture to create a test client for the FastAPI application."""
    return TestClient(api)


@pytest.fixture
async def mock_test_user() -> User:
    """Create a mock user object."""
    return User(
        id=ID,
        username="test",
        password=SecretStr(await hash_password("test")),
        role=Role.ADMIN,
    )


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


@pytest.mark.integration
async def test_login_does_not_rehash_current_hash(
    client: TestClient, mocker: MockFixture, mock_test_user: User
) -> None:
    """Should not update the stored hash when it uses the current parameters."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_test_user,
    )
    update_password = mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.update_password",
    )

    resp = client.post("/login", json={"username": "test", "password": "test"})
    assert resp.status_code == HTTPStatus.OK
    update_password.assert_not_awaited()


@pytest.mark.integration
async def test_login_rehashes_outdated_hash(
    client: TestClient, mocker: MockFixture
) -> None:
    """Should replace a hash made with outdated parameters on login."""
    outdated_hash = PasswordHasher(time_cost=1, memory_cost=8192).hash("test")
    user = User(
        id=ID, username="test", password=SecretStr(outdated_hash), role=Role.ADMIN
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=user,
    )
    update_password = mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.update_password",
    )

    resp = client.post("/login", json={"username": "test", "password": "test"})
    assert resp.status_code == HTTPStatus.OK
    update_password.assert_awaited_once()
    user_id, old_hash, new_hash = update_password.await_args_list[0].args
    assert user_id == ID
    assert old_hash == outdated_hash
    assert new_hash != outdated_hash
    assert PasswordHasher().verify(new_hash, "test")
    assert not PasswordHasher().check_needs_rehash(new_hash)


# Bad cases


@pytest.mark.integration
async def test_login_plaintext_stored_password(
    client: TestClient, mocker: MockFixture
) -> None:
    """Should return 401: a stored password must be a hash, not plain text."""
    user = User(id=ID, username="test", password=SecretStr("test"), role=Role.ADMIN)
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=user,
    )

    resp = client.post("/login", json={"username": "test", "password": "test"})
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


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


@pytest.mark.integration
@pytest.mark.parametrize(
    "body",
    [
        {"username": "admin", "password": None},
        {"username": "admin", "password": 123},
        {"username": None, "password": "secret"},
        {"username": "admin"},
        {"password": "secret"},
    ],
)
async def test_login_invalid_body(client: TestClient, body: dict) -> None:
    """Should return 422 UNPROCESSABLE_ENTITY, not 500, for a malformed body."""
    resp = client.post("/login", json=body)
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
