"""Integration test cases for the users route."""
import os
from typing import Any

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
def token_nonprivileged_user() -> str:
    """Create a valid token."""
    secret = os.getenv("JWT_SECRET")
    algorithm = "HS256"
    payload = {"username": "nonprivileged", "role": "nonprivileged"}
    return jwt.encode(payload, secret, algorithm)  # type: ignore


async def mock_user(db: Any, username: str) -> dict:
    """Create a mock user object."""
    return {  # noqa: S106
        "id": ID,
        "username": "admin",
        "password": "password",
        "role": "admin",
    }


async def mock_user_insufficent_role(db: Any, username: str) -> dict:
    """Create a mock user object."""
    return {  # noqa: S106
        "id": ID,
        "username": "nonprivileged",
        "password": "password",
        "role": "event-admin",
    }


async def mock_user_object(db: Any, username: str) -> dict:
    """Create a mock user object."""
    return {  # noqa: S106
        "id": ID,
        "username": "some.user@example.com",
        "password": "secret",
        "role": "test",
    }


async def mock_authorize(db: Any, token: Any, roles: Any) -> None:
    """Pass autorization."""
    pass


@pytest.mark.integration
async def test_create_user(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return Created, location header."""
    mocker.patch(
        "user_service.services.users_service.create_id",
        return_value=ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.create_user",
        return_value=ID,
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
    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )

    resp = await client.post("/users", headers=headers, json=request_body)
    assert resp.status == 201
    assert f"/users/{ID}" in resp.headers[hdrs.LOCATION]


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

    headers = MultiDict(
        {
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )

    resp = await client.get(f"/users/{ID}", headers=headers)
    assert resp.status == 200
    assert "application/json" in resp.headers[hdrs.CONTENT_TYPE]
    user = await resp.json()
    assert type(user) is dict
    assert user["id"] == ID


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
        return_value=ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )
    request_body = {
        "id": ID,
        "username": "updated.user@example.com",
        "password": "secret",
        "role": "test",
    }

    resp = await client.put(f"/users/{ID}", headers=headers, json=request_body)
    assert resp.status == 204


@pytest.mark.integration
async def test_list_users(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return OK and a valid json body."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_all_users",
        return_value=[{"id": ID, "username": "Oslo Skagen Sprint"}],
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    headers = MultiDict(
        {
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )
    resp = await client.get("/users", headers=headers)
    assert resp.status == 200
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
        return_value=ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    headers = MultiDict(
        {
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )

    resp = await client.delete(f"/users/{ID}", headers=headers)
    assert resp.status == 204


# Bad cases


@pytest.mark.integration
async def test_create_user_invalid_input(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "user_service.services.users_service.create_id",
        return_value=ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.create_user",
        return_value=ID,
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
    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )

    resp = await client.post("/users", headers=headers, json=request_body_lacks_role)
    assert resp.status == 422


@pytest.mark.integration
async def test_create_user_with_id(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "user_service.services.users_service.create_id",
        return_value=ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.create_user",
        return_value=ID,
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
        "id": ID,
        "username": "user@example.com",
        "password": "secret",
        "role": "test_role",
    }
    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )

    resp = await client.post("/users", headers=headers, json=request_body_with_id)
    assert resp.status == 422


@pytest.mark.integration
async def test_create_user_with_username_admin(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "user_service.services.users_service.create_id",
        return_value=ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.create_user",
        return_value=ID,
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
    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )

    resp = await client.post("/users", headers=headers, json=request_body)
    assert resp.status == 422


@pytest.mark.integration
async def test_create_user_returns_none(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 400 Bad Request."""
    mocker.patch(
        "user_service.services.users_service.create_id",
        return_value=ID,
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
    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )

    resp = await client.post("/users", headers=headers, json=request_body_lacks_role)
    assert resp.status == 400


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
        return_value=ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )
    request_body_lacks_role = {
        "id": ID,
        "username": "updated.user@example.com",
        "password": "secret",
    }

    resp = await client.put(
        f"/users/{ID}", headers=headers, json=request_body_lacks_role
    )
    assert resp.status == 422


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
        return_value=ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )
    request_body = {
        "id": ID,
        "username": "admin",
        "password": "secret",
        "role": "test_role",
    }

    resp = await client.put(f"/users/{ID}", headers=headers, json=request_body)
    assert resp.status == 422


@pytest.mark.integration
async def test_update_user_change_ID(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 422 Unprocessable Entity."""
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_id",
        side_effect=mock_user_object,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.update_user",
        return_value=ID,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    mocker.patch(
        "user_service.services.AuthorizationService.authorize",
        side_effect=mock_authorize,
    )

    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )
    request_body = {
        "id": "DifferentId",
        "username": "some.user@example.com",
        "password": "secret",
        "role": "test_role",
    }

    resp = await client.put(f"/users/{ID}", headers=headers, json=request_body)
    assert resp.status == 422


# NOT FOUND CASES:


@pytest.mark.integration
async def test_get_user_not_found(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 404 Not found."""
    ID = "does-not-exist"
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_id",
        return_value=None,
    )
    mocker.patch(
        "user_service.adapters.users_adapter.UsersAdapter.get_user_by_username",
        side_effect=mock_user,
    )
    headers = MultiDict(
        {
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )

    resp = await client.get(f"/users/{ID}", headers=headers)
    assert resp.status == 404


@pytest.mark.integration
async def test_update_user_not_found(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 404 Not found."""
    ID = "does-not-exist"
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

    headers = MultiDict(
        {
            hdrs.CONTENT_TYPE: "application/json",
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )
    request_body = {
        "id": ID,
        "username": "updated.user@example.com",
        "password": "secret",
        "role": "test",
    }

    ID = "does-not-exist"
    resp = await client.put(f"/users/{ID}", headers=headers, json=request_body)
    assert resp.status == 404


@pytest.mark.integration
async def test_delete_user_not_found(
    client: _TestClient, mocker: MockFixture, token: MockFixture
) -> None:
    """Should return 404 Not found."""
    ID = "does-not-exist"
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

    headers = MultiDict(
        {
            hdrs.AUTHORIZATION: f"Bearer {token}",
        },
    )
    resp = await client.delete(f"/users/{ID}", headers=headers)
    assert resp.status == 404
