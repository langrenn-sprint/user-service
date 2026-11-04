"""Integration test cases for hashing passwords stored in plain text."""

import uuid

import pytest
from pytest_mock import MockFixture

from app.services import UsersService
from app.services.passwords import PASSWORD_HASH_MONGO_REGEX, verify_password


@pytest.mark.integration
async def test_hash_plaintext_passwords(mocker: MockFixture) -> None:
    """Should replace each plain-text password with a hash of it."""
    first_id = uuid.uuid4()
    second_id = uuid.uuid4()
    get_users = mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_users_with_plaintext_password",
        return_value=[
            {"id": first_id, "password": "secret"},
            {"id": second_id, "password": "$argon2-my-password"},
        ],
    )
    update_password = mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.update_password",
        return_value=True,
    )

    count = await UsersService.hash_plaintext_passwords()

    calls = [c.args for c in update_password.await_args_list]
    assert count == len(calls)
    assert [(user_id, old) for user_id, old, _ in calls] == [
        (first_id, "secret"),
        (second_id, "$argon2-my-password"),
    ]
    assert await verify_password(calls[0][2], "secret")
    assert await verify_password(calls[1][2], "$argon2-my-password")
    get_users.assert_awaited_once_with(PASSWORD_HASH_MONGO_REGEX)


@pytest.mark.integration
async def test_hash_plaintext_passwords_changed_meanwhile(mocker: MockFixture) -> None:
    """Should not count a password that was changed before it could be replaced."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_users_with_plaintext_password",
        return_value=[{"id": uuid.uuid4(), "password": "secret"}],
    )
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.update_password",
        return_value=False,
    )

    assert await UsersService.hash_plaintext_passwords() == 0


@pytest.mark.integration
async def test_hash_plaintext_passwords_nothing_to_do(mocker: MockFixture) -> None:
    """Should not update anything when no password is stored in plain text."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_users_with_plaintext_password",
        return_value=[],
    )
    update_password = mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.update_password",
    )

    assert await UsersService.hash_plaintext_passwords() == 0
    update_password.assert_not_awaited()
