"""Module for users service."""

import logging
from typing import Any
from uuid import UUID

from app.adapters import UsersAdapter
from app.models import User


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

    logger = logging.getLogger("app.users_service.UsersService")

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
        # insert new user
        result = await UsersAdapter.create_user(user)
        cls.logger.debug("inserted user with id: %s", user.id)
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
            return await UsersAdapter.update_user(user_id, user)
        msg = f"User with id {user_id} not found."
        raise UserNotFoundError(msg) from None

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
