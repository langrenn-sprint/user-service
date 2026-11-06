"""Integration test cases for activation (event-service-gui#222).

Admin creates a user without password and gets an activation code, which the
user uses once to set the password. Only a hash of the code is stored. A user
without password cannot log in. Admin can make a new code, e.g. to reset a
forgotten password.
"""

import os
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from uuid import UUID

import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pytest_mock import MockFixture

from app import api
from app.models import Role, User
from app.services.activation import hash_activation_code
from app.services.passwords import is_password_hash, verify_password

USER_ID = UUID("2330b904efcc4ac08c01375b19c12a44")
ADAPTER = "app.adapters.users_adapter.UsersAdapter"


@pytest.fixture
def client() -> TestClient:
    """Fixture to create a test client for the FastAPI application."""
    return TestClient(api)


def make_token(role: str) -> str:
    """Return a valid token for a user with the role."""
    payload = {"username": f"{role}@example.com", "role": role, "exp": 9999999999}
    return jwt.encode(payload, os.getenv("JWT_SECRET"), "HS256")


def auth(role: str = "admin") -> dict:
    """Return the Authorization header for a user with the role."""
    return {"Authorization": f"Bearer {make_token(role)}"}


# --- Creating a user without password -------------------------------------------------


@pytest.mark.integration
@pytest.mark.parametrize("password", [None, ""])
def test_create_user_without_password_gives_activation_code(
    client: TestClient, mocker: MockFixture, password: str | None
) -> None:
    """Should return 201 with the code, and store only a hash of it."""
    create_user = mocker.patch(f"{ADAPTER}.create_user", return_value=USER_ID)
    body = {"id": USER_ID.hex, "username": "ny@example.com", "role": "event-admin"}
    if password is not None:
        body["password"] = password

    resp = client.post("/users", headers=auth(), json=body)

    assert resp.status_code == HTTPStatus.CREATED, resp.text
    assert resp.headers["Location"] == f"/users/{USER_ID}"
    activation = resp.json()
    assert activation["user_id"] == str(USER_ID)
    expires = datetime.fromisoformat(activation["expires"])
    assert abs(expires - (datetime.now(UTC) + timedelta(hours=48))) < timedelta(
        seconds=5
    )
    user, stored = create_user.await_args_list[0].args
    assert user.password is None
    assert stored["activation_code_hash"] == hash_activation_code(activation["code"])
    assert activation["code"] not in str(stored)


@pytest.mark.integration
def test_create_user_with_password_gives_no_code(
    client: TestClient, mocker: MockFixture
) -> None:
    """Should work as before: 201, no body, and the password hash stored."""
    create_user = mocker.patch(f"{ADAPTER}.create_user", return_value=USER_ID)
    body = {"username": "test@example.com", "role": "admin", "password": "a" * 10}

    resp = client.post("/users", headers=auth(), json=body)

    assert resp.status_code == HTTPStatus.CREATED, resp.text
    assert resp.content == b""
    user, stored = create_user.await_args_list[0].args
    assert is_password_hash(user.password.get_secret_value())
    assert stored is None


@pytest.mark.integration
def test_create_user_with_too_short_password(
    client: TestClient, mocker: MockFixture
) -> None:
    """Should return 422 for a password shorter than 10 characters."""
    create_user = mocker.patch(f"{ADAPTER}.create_user", return_value=USER_ID)
    body = {"username": "test@example.com", "role": "admin", "password": "a" * 9}

    resp = client.post("/users", headers=auth(), json=body)

    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY, resp.text
    assert "at least 10 characters" in resp.json()["detail"]
    create_user.assert_not_awaited()


# --- Updating a user ------------------------------------------------------------------


@pytest.mark.integration
def test_update_user_without_password_keeps_it(
    client: TestClient, mocker: MockFixture
) -> None:
    """Should not change the stored password when none is given."""
    old = User(id=USER_ID, username="u", role=Role.ADMIN, password=SecretStr("h"))
    mocker.patch(f"{ADAPTER}.get_user_by_id", return_value=old)
    update_user = mocker.patch(f"{ADAPTER}.update_user", return_value=USER_ID)
    body = {"id": str(USER_ID), "username": "nytt-navn", "role": "event-admin"}

    resp = client.put(f"/users/{USER_ID}", headers=auth(), json=body)

    assert resp.status_code == HTTPStatus.NO_CONTENT, resp.text
    assert update_user.await_args_list[0].args[1].password is None


@pytest.mark.integration
def test_update_user_with_too_short_password(
    client: TestClient, mocker: MockFixture
) -> None:
    """Should return 422 for a password shorter than 10 characters."""
    old = User(id=USER_ID, username="u", role=Role.ADMIN, password=SecretStr("h"))
    mocker.patch(f"{ADAPTER}.get_user_by_id", return_value=old)
    update_user = mocker.patch(f"{ADAPTER}.update_user", return_value=USER_ID)
    body = {"id": str(USER_ID), "username": "u", "role": "admin", "password": "kort"}

    resp = client.put(f"/users/{USER_ID}", headers=auth(), json=body)

    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY, resp.text
    update_user.assert_not_awaited()


# --- New activation code (reset password) ---------------------------------------------


@pytest.mark.integration
def test_create_activation(client: TestClient, mocker: MockFixture) -> None:
    """Should return 201 with a new code, and store only its hash."""
    set_activation = mocker.patch(f"{ADAPTER}.set_activation", return_value=True)

    resp = client.post(f"/users/{USER_ID}/activation", headers=auth())

    assert resp.status_code == HTTPStatus.CREATED, resp.text
    activation = resp.json()
    user_id, code_hash, _ = set_activation.await_args_list[0].args
    assert user_id == USER_ID
    assert code_hash == hash_activation_code(activation["code"])


@pytest.mark.integration
def test_create_activation_user_not_found(
    client: TestClient, mocker: MockFixture
) -> None:
    """Should return 404 for an unknown user."""
    mocker.patch(f"{ADAPTER}.set_activation", return_value=False)

    resp = client.post(f"/users/{USER_ID}/activation", headers=auth())

    assert resp.status_code == HTTPStatus.NOT_FOUND, resp.text


@pytest.mark.integration
@pytest.mark.parametrize("role", ["event-admin", "result-admin", "contestant-admin"])
def test_create_activation_only_for_admin(
    client: TestClient, mocker: MockFixture, role: str
) -> None:
    """Should return 403 for other roles than admin, and 401 without token."""
    set_activation = mocker.patch(f"{ADAPTER}.set_activation", return_value=True)

    forbidden = client.post(f"/users/{USER_ID}/activation", headers=auth(role))
    no_token = client.post(f"/users/{USER_ID}/activation")

    assert forbidden.status_code == HTTPStatus.FORBIDDEN, forbidden.text
    assert no_token.status_code == HTTPStatus.UNAUTHORIZED, no_token.text
    set_activation.assert_not_awaited()


# --- Activating -----------------------------------------------------------------------


@pytest.mark.integration
async def test_activate(client: TestClient, mocker: MockFixture) -> None:
    """Should set a hash of the password for the code, without a token."""
    activate = mocker.patch(f"{ADAPTER}.activate", return_value=True)

    resp = client.post("/activate", json={"code": "kode", "password": "a" * 10})

    assert resp.status_code == HTTPStatus.NO_CONTENT, resp.text
    code_hash, now, password_hash, username = activate.await_args_list[0].args
    assert code_hash == hash_activation_code("kode")
    assert username is None
    assert abs(now - datetime.now(UTC)) < timedelta(seconds=5)
    assert await verify_password(password_hash, "a" * 10)


@pytest.mark.integration
def test_activate_with_invalid_code(client: TestClient, mocker: MockFixture) -> None:
    """Should return 400 for an unknown, used or expired code."""
    mocker.patch(f"{ADAPTER}.activate", return_value=False)

    resp = client.post("/activate", json={"code": "ukjent", "password": "a" * 10})

    assert resp.status_code == HTTPStatus.BAD_REQUEST, resp.text
    assert resp.json()["detail"] == "The activation code is invalid or has expired."


@pytest.mark.integration
def test_activate_with_too_short_password(
    client: TestClient, mocker: MockFixture
) -> None:
    """Should return 422, and not use the code."""
    activate = mocker.patch(f"{ADAPTER}.activate", return_value=True)

    resp = client.post("/activate", json={"code": "kode", "password": "a" * 9})

    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY, resp.text
    activate.assert_not_awaited()


# --- Login and listing ----------------------------------------------------------------


@pytest.mark.integration
def test_login_not_activated(client: TestClient, mocker: MockFixture) -> None:
    """Should return 403 with a clear message for a user without password."""
    user = User(id=USER_ID, username="ny@example.com", role=Role.EVENT_ADMIN)
    mocker.patch(f"{ADAPTER}.get_user_by_username", return_value=user)

    resp = client.post(
        "/login", json={"username": "ny@example.com", "password": "hva-som-helst"}
    )

    assert resp.status_code == HTTPStatus.FORBIDDEN, resp.text
    assert resp.json()["detail"] == "User is not activated. Use the activation link."


@pytest.mark.integration
def test_list_users_shows_activation_status(
    client: TestClient, mocker: MockFixture
) -> None:
    """Should show whether each user is activated, and never the code."""
    expires = datetime(2026, 11, 8, 12, 0)  # noqa: DTZ001 - naive UTC, as from MongoDB
    mocker.patch(
        f"{ADAPTER}.get_all_users",
        return_value=[
            {
                "id": USER_ID,
                "username": "ny@example.com",
                "role": "event-admin",
                "password": None,
                "activation_code_hash": "hash",
                "activation_expires": expires,
            }
        ],
    )

    resp = client.get("/users", headers=auth())

    assert resp.status_code == HTTPStatus.OK, resp.text
    assert resp.json() == [
        {
            "id": str(USER_ID),
            "username": "ny@example.com",
            "role": "event-admin",
            "activated": False,
            "activation_expires": "2026-11-08T12:00:00Z",
        }
    ]


@pytest.mark.integration
def test_activate_with_username(client: TestClient, mocker: MockFixture) -> None:
    """Should pass the username on, so only the user with the code matches."""
    activate = mocker.patch(f"{ADAPTER}.activate", return_value=True)

    resp = client.post(
        "/activate",
        json={"code": "kode", "password": "a" * 10, "username": "ny@example.com"},
    )

    assert resp.status_code == HTTPStatus.NO_CONTENT, resp.text
    assert activate.await_args_list[0].args[3] == "ny@example.com"


# --- Deleting yourself -----------------------------------------------------------


@pytest.mark.integration
def test_cannot_delete_yourself(client: TestClient, mocker: MockFixture) -> None:
    """Should return 409 when admin deletes the user they are logged in as."""
    me = User(id=USER_ID, username="admin@example.com", role=Role.ADMIN)
    mocker.patch(f"{ADAPTER}.get_user_by_id", return_value=me)
    delete_user = mocker.patch(f"{ADAPTER}.delete_user")
    token = jwt.encode(
        {"username": "admin@example.com", "role": "admin", "exp": 9999999999},
        os.getenv("JWT_SECRET"),
        "HS256",
    )

    resp = client.delete(
        f"/users/{USER_ID}", headers={"Authorization": f"Bearer {token}"}
    )

    assert resp.status_code == HTTPStatus.CONFLICT, resp.text
    assert resp.json()["detail"] == "You cannot delete the user you are logged in as."
    delete_user.assert_not_awaited()
