"""Integration test cases for the users route."""

import os
from http import HTTPStatus
from uuid import UUID, uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pytest_mock import MockFixture

from app import api
from app.models import Role, User

USER_ID = UUID("2330b904efcc4ac08c01375b19c12a44")


@pytest.fixture
def client() -> TestClient:
    """Fixture to create a test client for the FastAPI application."""
    return TestClient(api)


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


@pytest.fixture
def token_nonprivileged_user() -> str:
    """Create a valid token."""
    secret = os.getenv("JWT_SECRET")
    algorithm = "HS256"
    payload = {"username": "nonprivileged", "role": "event-admin", "exp": 9999999999}
    return jwt.encode(payload, secret, algorithm)


@pytest.fixture
async def mock_user() -> User:
    """Create a mock user object."""
    return User(
        id=USER_ID,
        username="admin",
        password=SecretStr("password"),
        role=Role.ADMIN,
    )


@pytest.fixture
async def mock_user_insufficent_role() -> User:
    """Create a mock user object."""
    return User(
        id=USER_ID,
        username="nonprivileged",
        password=SecretStr("password"),
        role=Role.EVENT_ADMIN,
    )


@pytest.mark.integration
async def test_create_user(
    client: TestClient, mocker: MockFixture, token: MockFixture, mock_user: User
) -> None:
    """Should return Created, location header."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.create_user",
        return_value=mock_user.id,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )

    request_body = {
        "id": mock_user.id.hex,
        "username": "user@example.com",
        "password": "secret",
        "role": "admin",
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    resp = client.post("/users", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.CREATED, resp.text
    assert f"/users/{mock_user.id}" in resp.headers["Location"]


@pytest.mark.integration
async def test_get_user_by_id(
    client: TestClient,
    mocker: MockFixture,
    token: MockFixture,
    mock_user: User,
) -> None:
    """Should return OK, and a body containing one user."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=mock_user,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )

    headers = {
        "Authorization": f"Bearer {token}",
    }

    resp = client.get(f"/users/{mock_user.id}", headers=headers)
    assert resp.status_code == HTTPStatus.OK
    assert "application/json" in resp.headers["Content-Type"]
    user = resp.json()
    assert type(user) is dict
    assert user["id"] == str(mock_user.id)
    assert user["username"] == mock_user.username


@pytest.mark.integration
async def test_update_user_by_id(
    client: TestClient, mocker: MockFixture, token: MockFixture, mock_user: User
) -> None:
    """Should return No Content."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=mock_user,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.update_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    request_body = {
        "id": str(mock_user.id),
        "username": "updated.user@example.com",
        "password": "secret",
        "role": "admin",
    }

    resp = client.put(f"/users/{USER_ID}", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.NO_CONTENT, resp.text


@pytest.mark.integration
async def test_list_users(
    client: TestClient, mocker: MockFixture, token: MockFixture, mock_user: User
) -> None:
    """Should return OK and a valid json body."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_all_users",
        return_value=[mock_user],
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )

    headers = {
        "Authorization": f"Bearer {token}",
    }

    resp = client.get("/users", headers=headers)
    assert resp.status_code == HTTPStatus.OK
    assert "application/json" in resp.headers["Content-Type"]
    users = resp.json()
    assert type(users) is list
    assert len(users) > 0


@pytest.mark.integration
async def test_delete_user_by_id(
    client: TestClient, mocker: MockFixture, token: MockFixture, mock_user: User
) -> None:
    """Should return No Content."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=mock_user,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.delete_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )

    headers = {
        "Authorization": f"Bearer {token}",
    }

    resp = client.delete(f"/users/{USER_ID}", headers=headers)
    assert resp.status_code == HTTPStatus.NO_CONTENT


# Bad cases


@pytest.mark.integration
async def test_create_user_invalid_input(
    client: TestClient, mocker: MockFixture, token: MockFixture, mock_user: User
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.create_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )

    request_body_lacks_role = {
        "username": "user@example.com",
        "password": "secret",
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    resp = client.post("/users", headers=headers, json=request_body_lacks_role)
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


@pytest.mark.integration
async def test_create_user_with_id(
    client: TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 201 Created."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.create_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )

    request_body_with_id = {
        "id": str(USER_ID),
        "username": "user@example.com",
        "password": "secret",
        "role": "admin",
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    resp = client.post("/users", headers=headers, json=request_body_with_id)
    assert resp.status_code == HTTPStatus.CREATED, resp.text
    assert f"/users/{request_body_with_id['id']}" in resp.headers["Location"]


@pytest.mark.integration
async def test_create_user_with_username_admin(
    client: TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.create_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )

    request_body = {
        "username": "admin",
        "password": "secret",
        "role": "admin",
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    resp = client.post("/users", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.integration
async def test_create_user_returns_none(
    client: TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 400 Bad Request."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.create_user",
        return_value=None,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )

    request_body_lacks_role = {
        "username": "user@example.com",
        "role": "admin",
        "password": "secret",
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    resp = client.post("/users", headers=headers, json=request_body_lacks_role)
    assert resp.status_code == HTTPStatus.BAD_REQUEST, resp.text


@pytest.mark.integration
async def test_update_user_invalid_input(
    client: TestClient, mocker: MockFixture, token: MockFixture, mock_user: User
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=mock_user,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.update_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    request_body_lacks_role = {
        "id": str(USER_ID),
        "username": "updated.user@example.com",
        "password": "secret",
    }

    resp = client.put(
        f"/users/{USER_ID}", headers=headers, json=request_body_lacks_role
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


@pytest.mark.integration
async def test_update_user_set_username_to_admin(
    client: TestClient, mocker: MockFixture, token: MockFixture, mock_user: User
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=mock_user,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.update_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    request_body = {
        "id": str(USER_ID),
        "username": "admin",
        "password": "secret",
        "role": "admin",
    }

    resp = client.put(f"/users/{USER_ID}", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


@pytest.mark.integration
async def test_update_user_change_id(
    client: TestClient, mocker: MockFixture, token: MockFixture, mock_user: User
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=mock_user,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.update_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    request_body = {
        "id": str(uuid4()),
        "username": "some.user@example.com",
        "password": "secret",
        "role": "admin",
    }

    resp = client.put(f"/users/{USER_ID}", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


# NOT FOUND CASES:


@pytest.mark.integration
async def test_get_user_not_found(
    client: TestClient, mocker: MockFixture, token: MockFixture, mock_user: User
) -> None:
    """Should return 404 Not found."""
    user_id = str(uuid4())
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=None,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )
    headers = {
        "Authorization": f"Bearer {token}",
    }

    resp = client.get(f"/users/{user_id}", headers=headers)
    assert resp.status_code == HTTPStatus.NOT_FOUND, resp.text


@pytest.mark.integration
async def test_update_user_not_found(
    client: TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 404 Not found."""
    user_id = str(uuid4())
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=None,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.update_user",
        return_value=None,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    request_body = {
        "id": str(USER_ID),
        "username": "updated.user@example.com",
        "password": "secret",
        "role": "admin",
    }

    resp = client.put(f"/users/{user_id}", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.NOT_FOUND, resp.text


@pytest.mark.integration
async def test_delete_user_not_found(
    client: TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 404 Not found."""
    user_id = str(uuid4())
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=None,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.delete_user",
        return_value=None,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user,
    )

    headers = {
        "Authorization": f"Bearer {token}",
    }

    resp = client.delete(f"/users/{user_id}", headers=headers)
    assert resp.status_code == HTTPStatus.NOT_FOUND

    # UNAUTHORIZED CASES:


@pytest.mark.integration
async def test_create_user_unauthorized(
    client: TestClient,
    mocker: MockFixture,
    token_nonprivileged_user: str,
    mock_user_insufficent_role: User,
) -> None:
    """Should return 403 Forbidden."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.create_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user_insufficent_role,
    )

    request_body = {
        "username": "user@example.com",
        "password": "secret",
        "role": "admin",
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token_nonprivileged_user}",
    }

    resp = client.post("/users", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.integration
async def test_get_user_by_id_unauthorized(
    client: TestClient,
    mocker: MockFixture,
    token_nonprivileged_user: MockFixture,
    mock_user_insufficent_role: User,
) -> None:
    """Should return 403 Forbidden."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=mock_user_insufficent_role,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user_insufficent_role,
    )

    headers = {
        "Authorization": f"Bearer {token_nonprivileged_user}",
    }

    resp = client.get(f"/users/{USER_ID}", headers=headers)
    assert resp.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.integration
async def test_update_user_by_id_unauthorized(
    client: TestClient,
    mocker: MockFixture,
    token_nonprivileged_user: MockFixture,
    mock_user_insufficent_role: User,
) -> None:
    """Should return 403 Forbidden."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=mock_user_insufficent_role,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.update_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user_insufficent_role,
    )

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token_nonprivileged_user}",
    }

    request_body = {
        "id": str(USER_ID),
        "username": "updated.user@example.com",
        "password": "secret",
        "role": "admin",
    }

    resp = client.put(f"/users/{USER_ID}", headers=headers, json=request_body)
    assert resp.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.integration
async def test_list_users_unauthorized(
    client: TestClient,
    mocker: MockFixture,
    token_nonprivileged_user: str,
    mock_user_insufficent_role: User,
) -> None:
    """Should return 403 Forbidden."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_all_users",
        return_value=[mock_user_insufficent_role],
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user_insufficent_role,
    )

    headers = {
        "Authorization": f"Bearer {token_nonprivileged_user}",
    }

    resp = client.get("/users", headers=headers)
    assert resp.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.integration
async def test_delete_user_by_id_unauthorized(
    client: TestClient,
    mocker: MockFixture,
    token_nonprivileged_user: str,
    mock_user_insufficent_role: User,
) -> None:
    """Should return 403 Forbidden."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=mock_user_insufficent_role,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.delete_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_user_by_username",
        return_value=mock_user_insufficent_role,
    )

    headers = {
        "Authorization": f"Bearer {token_nonprivileged_user}",
    }

    resp = client.delete(f"/users/{USER_ID}", headers=headers)
    assert resp.status_code == HTTPStatus.FORBIDDEN
