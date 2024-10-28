"""Integration test cases for the users route."""

import os
from http import HTTPStatus
from typing import Any

import jwt
import pytest
from aiohttp import hdrs
from aiohttp.test_utils import TestClient as _TestClient
from pytest_mock import MockFixture

from user_service.services import AuthorizationError

USER_ID = "290e70d5-0933-4af0-bb53-1d705ba7eb95"


@pytest.fixture
def token() -> str:
    """Create a valid token."""
    secret = os.getenv("JWT_SECRET")
    algorithm = "HS256"
    payload = {"username": os.getenv("ADMIN_USERNAME"), "role": "admin"}
    return jwt.encode(payload, secret, algorithm)


@pytest.fixture
def token_nonprivileged_user() -> str:
    """Create a valid token."""
    secret = os.getenv("JWT_SECRET")
    algorithm = "HS256"
    payload = {"username": "nonprivileged", "role": "nonprivileged"}
    return jwt.encode(payload, secret, algorithm)


async def mock_user(db: str, username: str) -> dict:
    """Create a mock user object."""
    _ = (db, username)
    return {
        "id": USER_ID,
        "username": "admin",
        "password": "password",
        "role": "admin",
    }


async def mock_user_insufficent_role(db: str, username: str) -> dict:
    """Create a mock user object."""
    _ = (db, username)
    return {
        "id": USER_ID,
        "username": "nonprivileged",
        "password": "password",
        "role": "event-admin",
    }


async def mock_user_object(db: str, username: str) -> dict:
    """Create a mock user object."""
    _ = (db, username)
    return {
        "id": USER_ID,
        "username": "some.user@example.com",
        "password": "secret",
        "role": "test",
    }


async def mock_authorize(db: str, token: Any, roles: Any) -> None:
    """Pass autorization."""


@pytest.mark.integration
async def test_create_user(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return Created, location header."""
    mocker.patch(
        "user_service.services.users_service.create_id",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.create_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    request_body = {
        "username": "user@example.com",
        "password": "secret",
        "role": "test",
    }
    headers = {
        hdrs.CONTENT_TYPE: "application/json",
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    resp = await client.post("/users", headers=headers, json=request_body)
    assert resp.status == HTTPStatus.CREATED
    assert f"/users/{USER_ID}" in resp.headers[hdrs.LOCATION]


@pytest.mark.integration
async def test_get_user_by_id(
    client: _TestClient,
    mocker: MockFixture,
    token: MockFixture,
) -> None:
    """Should return OK, and a body containing one user."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_id",
        side_effect=mock_user_object,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    headers = {
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    resp = await client.get(f"/users/{USER_ID}", headers=headers)
    assert resp.status == HTTPStatus.OK
    assert "application/json" in resp.headers[hdrs.CONTENT_TYPE]
    user = await resp.json()
    assert type(user) is dict
    assert user["id"] == USER_ID


@pytest.mark.integration
async def test_update_user_by_id(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return No Content."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_id",
        side_effect=mock_user_object,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.update_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    headers = {
        hdrs.CONTENT_TYPE: "application/json",
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    request_body = {
        "id": USER_ID,
        "username": "updated.user@example.com",
        "password": "secret",
        "role": "test",
    }

    resp = await client.put(f"/users/{USER_ID}", headers=headers, json=request_body)
    assert resp.status == HTTPStatus.NO_CONTENT


@pytest.mark.integration
async def test_list_users(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return OK and a valid json body."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_all_users",
        return_value=[
            {"id": USER_ID, "username": "Oslo Skagen Sprint", "role": "test"}
        ],
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    headers = {
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    resp = await client.get("/users", headers=headers)
    assert resp.status == HTTPStatus.OK
    assert "application/json" in resp.headers[hdrs.CONTENT_TYPE]
    users = await resp.json()
    assert type(users) is list
    assert len(users) > 0


@pytest.mark.integration
async def test_delete_user_by_id(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return No Content."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_id",
        side_effect=mock_user_object,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.delete_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    headers = {
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    resp = await client.delete(f"/users/{USER_ID}", headers=headers)
    assert resp.status == HTTPStatus.NO_CONTENT


# Bad cases


@pytest.mark.integration
async def test_create_user_invalid_input(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "user_service.services.users_service.create_id",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.create_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    request_body_lacks_role = {
        "username": "user@example.com",
        "password": "secret",
    }
    headers = {
        hdrs.CONTENT_TYPE: "application/json",
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    resp = await client.post("/users", headers=headers, json=request_body_lacks_role)
    assert resp.status == HTTPStatus.UNPROCESSABLE_ENTITY


@pytest.mark.integration
async def test_create_user_with_id(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "user_service.services.users_service.create_id",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.create_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    request_body_with_id = {
        "id": USER_ID,
        "username": "user@example.com",
        "password": "secret",
        "role": "test_role",
    }
    headers = {
        hdrs.CONTENT_TYPE: "application/json",
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    resp = await client.post("/users", headers=headers, json=request_body_with_id)
    assert resp.status == HTTPStatus.UNPROCESSABLE_ENTITY


@pytest.mark.integration
async def test_create_user_with_username_admin(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "user_service.services.users_service.create_id",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.create_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    request_body = {
        "username": "admin",
        "password": "secret",
        "role": "test_role",
    }
    headers = {
        hdrs.CONTENT_TYPE: "application/json",
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    resp = await client.post("/users", headers=headers, json=request_body)
    assert resp.status == HTTPStatus.UNPROCESSABLE_ENTITY


@pytest.mark.integration
async def test_create_user_returns_none(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 400 Bad Request."""
    mocker.patch(
        "user_service.services.users_service.create_id",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.create_user",
        return_value=None,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    request_body_lacks_role = {
        "username": "user@example.com",
        "role": "test_role",
        "password": "secret",
    }
    headers = {
        hdrs.CONTENT_TYPE: "application/json",
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    resp = await client.post("/users", headers=headers, json=request_body_lacks_role)
    assert resp.status == HTTPStatus.BAD_REQUEST


@pytest.mark.integration
async def test_update_user_invalid_input(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_id",
        side_effect=mock_user_object,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.update_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    headers = {
        hdrs.CONTENT_TYPE: "application/json",
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    request_body_lacks_role = {
        "id": USER_ID,
        "username": "updated.user@example.com",
        "password": "secret",
    }

    resp = await client.put(
        f"/users/{USER_ID}", headers=headers, json=request_body_lacks_role
    )
    assert resp.status == HTTPStatus.UNPROCESSABLE_ENTITY


@pytest.mark.integration
async def test_update_user_set_username_to_admin(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_id",
        side_effect=mock_user_object,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.update_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    headers = {
        hdrs.CONTENT_TYPE: "application/json",
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    request_body = {
        "id": USER_ID,
        "username": "admin",
        "password": "secret",
        "role": "test_role",
    }

    resp = await client.put(f"/users/{USER_ID}", headers=headers, json=request_body)
    assert resp.status == HTTPStatus.UNPROCESSABLE_ENTITY


@pytest.mark.integration
async def test_update_user_change_id(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_id",
        side_effect=mock_user_object,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.update_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    headers = {
        hdrs.CONTENT_TYPE: "application/json",
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    request_body = {
        "id": "DifferentId",
        "username": "some.user@example.com",
        "password": "secret",
        "role": "test_role",
    }

    resp = await client.put(f"/users/{USER_ID}", headers=headers, json=request_body)
    assert resp.status == HTTPStatus.UNPROCESSABLE_ENTITY


# NOT FOUND CASES:


@pytest.mark.integration
async def test_get_user_not_found(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 404 Not found."""
    user_id = "does-not-exist"
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=None,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    headers = {
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    resp = await client.get(f"/users/{user_id}", headers=headers)
    assert resp.status == HTTPStatus.NOT_FOUND


@pytest.mark.integration
async def test_update_user_not_found(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 404 Not found."""
    user_id = "does-not-exist"
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=None,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.update_user",
        return_value=None,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )

    headers = {
        hdrs.CONTENT_TYPE: "application/json",
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    request_body = {
        "id": user_id,
        "username": "updated.user@example.com",
        "password": "secret",
        "role": "test",
    }

    user_id = "does-not-exist"
    resp = await client.put(f"/users/{user_id}", headers=headers, json=request_body)
    assert resp.status == HTTPStatus.NOT_FOUND


@pytest.mark.integration
async def test_delete_user_not_found(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 404 Not found."""
    user_id = "does-not-exist"
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=None,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.delete_user",
        return_value=None,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )

    headers = {
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    resp = await client.delete(f"/users/{user_id}", headers=headers)
    assert resp.status == HTTPStatus.NOT_FOUND

    # UNAUTHORIZED CASES:


@pytest.mark.integration
async def test_create_user_unauthorized(
    client: _TestClient, mocker: MockFixture
) -> None:
    """Should return 403 Forbidden."""
    mocker.patch(
        "user_service.services.users_service.create_id",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.create_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=AuthorizationError("Unauthorized"),
    )

    request_body = {
        "username": "user@example.com",
        "password": "secret",
        "role": "test",
    }
    headers = {
        hdrs.CONTENT_TYPE: "application/json",
        hdrs.AUTHORIZATION: "Bearer BAD_TOKEN",
    }

    resp = await client.post("/users", headers=headers, json=request_body)
    assert resp.status == HTTPStatus.FORBIDDEN


@pytest.mark.integration
async def test_get_user_by_id_unauthorized(
    client: _TestClient,
    mocker: MockFixture,
    token: MockFixture,
) -> None:
    """Should return 403 Forbidden."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_id",
        side_effect=mock_user_object,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=AuthorizationError("Unauthorized"),
    )

    headers = {
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    resp = await client.get(f"/users/{USER_ID}", headers=headers)
    assert resp.status == HTTPStatus.FORBIDDEN


@pytest.mark.integration
async def test_update_user_by_id_unauthorized(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 403 Forbidden."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_id",
        side_effect=mock_user_object,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.update_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=AuthorizationError("Unauthorized"),
    )

    headers = {
        hdrs.CONTENT_TYPE: "application/json",
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    request_body = {
        "id": USER_ID,
        "username": "updated.user@example.com",
        "password": "secret",
        "role": "test",
    }

    resp = await client.put(f"/users/{USER_ID}", headers=headers, json=request_body)
    assert resp.status == HTTPStatus.FORBIDDEN


@pytest.mark.integration
async def test_list_users_unauthorized(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 403 Forbidden."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_all_users",
        return_value=[
            {"id": USER_ID, "username": "Oslo Skagen Sprint", "role": "test"}
        ],
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=AuthorizationError("Unauthorized"),
    )

    headers = {
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    resp = await client.get("/users", headers=headers)
    assert resp.status == HTTPStatus.FORBIDDEN


@pytest.mark.integration
async def test_delete_user_by_id_unauthorized(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 403 Forbidden."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_id",
        side_effect=mock_user_object,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.delete_user",
        return_value=USER_ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=AuthorizationError("Unauthorized"),
    )

    headers = {
        hdrs.AUTHORIZATION: f"Bearer {token}",
    }

    resp = await client.delete(f"/users/{USER_ID}", headers=headers)
    assert resp.status == HTTPStatus.FORBIDDEN
