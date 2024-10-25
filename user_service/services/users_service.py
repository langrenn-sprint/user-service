"""Module for users service."""

import logging
import uuid
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from user_service.adapters import UsersAdapter
from user_service.models import User


def create_id() -> str:
    """Create an uuid."""
    return str(uuid.uuid4())  # pragma: no cover


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
    async def get_all_users(cls: Any, db: AsyncIOMotorDatabase) -> list[User]:
        """Get all users function."""
        users: list[User] = []
        _users = await UsersAdapter.get_all_users(db)
        for _user in _users:
            user = User.from_dict(_user)
            users.append(user)
        return users

    @classmethod
    async def create_user(cls: Any, db: AsyncIOMotorDatabase, user: User) -> str | None:
        """Create user function.

        Args:
            db (Any): the db
            user (User): a user instanse to be created

        Returns:
            Optional[str]: The id of the created user. None otherwise.

        Raises:
            IllegalValueError: input object has illegal values

        """
        # Validation:
        if user.id:
            msg = "Cannot create user with input id-"
            raise IllegalValueError(msg) from None
        if user.username == "admin":
            msg = 'Cannot create user with username "admin".'
            raise IllegalValueError(msg) from None
        # create id
        user_id = create_id()
        user.id = user_id
        # insert new user
        new_user = user.to_dict()
        result = await UsersAdapter.create_user(db, new_user)
        logging.debug("inserted user with id: %s", user_id)
        if result:
            return user_id
        return None

    @classmethod
    async def get_user_by_id(cls: Any, db: AsyncIOMotorDatabase, user_id: str) -> User:
        """Get user function."""
        user = await UsersAdapter.get_user_by_id(db, user_id)
        # return the document if found:
        if user:
            return User.from_dict(user)
        msg = f"User with id {user_id} not found"
        raise IllegalValueError(msg) from None

    @classmethod
    async def update_user(
        cls: Any, db: AsyncIOMotorDatabase, user_id: str, user: User
    ) -> str | None:
        """Get user function."""
        # Validation:
        if user.username == "admin":
            msg = 'Cannot change username to "admin".'
            raise IllegalValueError(msg) from None
        # get old document
        old_user = await UsersAdapter.get_user_by_id(db, user_id)
        # update the user if found:
        if old_user:
            if user.id != old_user["id"]:
                msg = "Cannot change id for user."
                raise IllegalValueError(msg) from None
            new_user = user.to_dict()
            return await UsersAdapter.update_user(db, user_id, new_user)
        msg = f"User with id {user_id} not found."
        raise UserNotFoundError(msg) from None

    @classmethod
    async def delete_user(cls: Any, db: AsyncIOMotorDatabase, user_id: str) -> None:
        """Delete user."""
        # get old document
        user = await UsersAdapter.get_user_by_id(db, user_id)
        # delete the document if found:
        if user:
            await UsersAdapter.delete_user(db, user_id)
        else:
            msg = f"User with id {user_id} not found"
            raise UserNotFoundError(msg) from None
