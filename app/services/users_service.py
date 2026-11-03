"""Module for users service."""

import logging
from typing import Any
from uuid import UUID

from pydantic import SecretStr

from app.adapters import UsersAdapter
from app.models import User

from .passwords import hash_password, is_password_hash

logger = logging.getLogger(__name__)


class IllegalValueError(Exception):
    """Class representing custom exception for fetch method."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class UserNotFoundError(Exception):
    """Class representing custom exception for fetch method."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class UsersService:
    """Class representing a service for users."""

    @classmethod
    async def create_user(cls: Any, user: User) -> UUID | None:
        """Create user function.

        Args:
            user (User): a user instanse to be created

        Returns:
            Optional[str]: The id of the created user. None otherwise.

        Raises:
            IllegalValueError: input object has illegal values

        """
        # Validation:
        if user.username == "admin":
            msg = 'Cannot create user with username "admin".'
            raise IllegalValueError(msg) from None
        # Store a hash of the password, never the password itself:
        user.password = SecretStr(hash_password(user.password.get_secret_value()))
        # insert new user
        result = await UsersAdapter.create_user(user)
        logger.debug("inserted user with id: %s", user.id)
        if result:
            return user.id
        return None

    @classmethod
    async def update_user(cls: Any, user_id: UUID, user: User) -> UUID | None:
        """Get user function."""
        # Validation:
        if user.username == "admin":
            msg = 'Cannot change username to "admin".'
            raise IllegalValueError(msg) from None
        # get old document
        old_user = await UsersAdapter.get_user_by_id(user_id)
        # update the user if found:
        if old_user:
            if user.id != old_user.id:
                msg = "Cannot change id for user."
                raise IllegalValueError(msg) from None
            # Store a hash of the password, never the password itself:
            user.password = SecretStr(hash_password(user.password.get_secret_value()))
            return await UsersAdapter.update_user(user_id, user)
        msg = f"User with id {user_id} not found."
        raise UserNotFoundError(msg) from None

    @classmethod
    async def hash_plaintext_passwords(cls: Any) -> int:
        """Replace every password stored in plain text with a hash of it.

        Users stored before passwords were hashed have their password in plain
        text. This runs on startup, and does nothing for passwords that are
        already hashed, so it is safe to run repeatedly.

        Returns:
            int: The number of passwords that were hashed.

        """
        count = 0
        for user in await UsersAdapter.get_all_users():
            password = user["password"]
            if not is_password_hash(password):
                await UsersAdapter.update_password(user["id"], hash_password(password))
                count += 1
        return count

    @classmethod
    async def delete_user(cls: Any, user_id: UUID) -> None:
        """Delete user."""
        # get old document
        user = await UsersAdapter.get_user_by_id(user_id)
        # delete the document if found:
        if user:
            await UsersAdapter.delete_user(user.id)
        else:
            msg = f"User with id {user_id} not found"
            raise UserNotFoundError(msg) from None
