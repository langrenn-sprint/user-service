"""Unit test cases for hashing passwords stored in plain text."""

import uuid

import pytest
from pytest_mock import MockFixture

from app.services import UsersService
from app.services.passwords import hash_password, verify_password


@pytest.mark.integration
async def test_hash_plaintext_passwords(mocker: MockFixture) -> None:
    """Should hash plain-text passwords and leave hashed passwords alone."""
    plaintext_id = uuid.uuid4()
    hashed_id = uuid.uuid4()
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_all_users",
        return_value=[
            {"id": plaintext_id, "username": "a", "password": "secret"},
            {"id": hashed_id, "username": "b", "password": hash_password("other")},
        ],
    )
    update_password = mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.update_password",
    )

    count = await UsersService.hash_plaintext_passwords()

    assert count == 1
    update_password.assert_awaited_once()
    user_id, password_hash = update_password.await_args_list[0].args
    assert user_id == plaintext_id
    assert verify_password(password_hash, "secret")


@pytest.mark.integration
async def test_hash_plaintext_passwords_nothing_to_do(mocker: MockFixture) -> None:
    """Should not update anything when all passwords are hashed."""
    mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.get_all_users",
        return_value=[
            {"id": uuid.uuid4(), "username": "b", "password": hash_password("x")}
        ],
    )
    update_password = mocker.patch(
        "app.adapters.users_adapter.UsersAdapter.update_password",
    )

    assert await UsersService.hash_plaintext_passwords() == 0
    update_password.assert_not_awaited()
