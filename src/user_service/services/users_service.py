"""Module for users service."""
import logging
from typing import Any, List, Optional
import uuid

from user_service.adapters import UsersAdapter
from user_service.models import User


def create_id() -> str:  # pragma: no cover
    """Creates an uuid."""
    return str(uuid.uuid4())


class UserNotFoundException(Exception):
    """Class representing custom exception for fetch method."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class IllegalValueException(Exception):
    """Class representing custom exception for create method."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class UsersService:
    """Class representing a service for users."""

    @classmethod
    async def get_all_users(cls: Any, db: Any) -> List[User]:
        """Get all users function."""
        users = await UsersAdapter.get_all_users(db)
        return users

    @classmethod
    async def create_user(cls: Any, db: Any, user: User) -> Optional[str]:
        """Create user function.

        Args:
            db (Any): the db
            user (User): a user instanse to be created

        Returns:
            Optional[str]: The id of the created user. None otherwise.

        Raises:
            IllegalValueException: input object has illegal values
        """
        # Validation:
        if user.id:
            raise IllegalValueException("Cannot create user with input id-")
        if user.username == "admin":
            raise IllegalValueException('Cannot create user with username "admin".')
        # create id
        id = create_id()
        user.id = id
        # insert new user
        new_user = user.to_dict()
        result = await UsersAdapter.create_user(db, new_user)
        logging.debug(f"inserted user with id: {id}")
        if result:
            return id
        return None

    @classmethod
    async def get_user_by_id(cls: Any, db: Any, id: str) -> User:
        """Get user function."""
        user = await UsersAdapter.get_user_by_id(db, id)
        # return the document if found:
        if user:
            return User.from_dict(user)
        raise UserNotFoundException(f"User with id {id} not found")

    @classmethod
    async def update_user(cls: Any, db: Any, id: str, user: User) -> Optional[str]:
        """Get user function."""
        # Validation:
        if user.username == "admin":
            raise IllegalValueException('Cannot change username to "admin".')
        # get old document
        old_user = await UsersAdapter.get_user_by_id(db, id)
        # update the user if found:
        if old_user:
            if user.id != old_user["id"]:
                raise IllegalValueException("Cannot change id for user.")
            new_user = user.to_dict()
            result = await UsersAdapter.update_user(db, id, new_user)
            return result
        raise UserNotFoundException(f"User with id {id} not found.")

    @classmethod
    async def delete_user(cls: Any, db: Any, id: str) -> Optional[str]:
        """Get user function."""
        # get old document
        user = await UsersAdapter.get_user_by_id(db, id)
        # delete the document if found:
        if user:
            result = await UsersAdapter.delete_user(db, id)
            return result
        raise UserNotFoundException(f"User with id {id} not found")
