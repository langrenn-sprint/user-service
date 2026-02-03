"""Module for user adapter."""

import logging
from typing import Any
from uuid import UUID

from app.models import User


class UsersAdapter:
    """Class representing an adapter for users."""

    database: Any
    logger: logging.Logger

    @classmethod
    async def init(cls, database: Any) -> None:  # pragma: no cover
        """Initialize class properties."""
        cls.database = database
        cls.logger = logging.getLogger(__name__)

    @classmethod
    async def get_all_users(cls: Any) -> list:
        """Get all users function."""
        users: list = []
        cursor = cls.database.users_collection.find()
        for user in await cursor.to_list(length=100):
            users.append(user)
            cls.logger.debug(user)
        return users

    @classmethod
    async def create_user(cls: Any, user: User) -> UUID:
        """Create user function and return id."""
        # We need to deserialize the secretstr password before inserting to db:
        user_dict = user.model_dump()
        user_dict["password"] = user.password.get_secret_value()
        _result = await cls.database.users_collection.insert_one(user_dict)
        return _result.inserted_id

    @classmethod
    async def get_user_by_id(cls: Any, user_id: UUID) -> User | None:
        """Get user function."""
        result = await cls.database.users_collection.find_one({"id": user_id})
        return User.model_validate(result) if result else None

    @classmethod
    async def get_user_by_username(cls: Any, username: str) -> User | None:
        """Get user function."""
        result = await cls.database.users_collection.find_one({"username": username})
        return User.model_validate(result) if result else None

    @classmethod
    async def update_user(cls: Any, user_id: UUID, user: User) -> UUID | None:
        """Update user function and return id of updated document."""
        # We need to deserialize the secretstr password before inserting to db:
        user_dict = user.model_dump()
        user_dict["password"] = user.password.get_secret_value()
        _result = await cls.database.users_collection.replace_one(
            {"id": user_id}, user_dict
        )
        return _result.upserted_id

    @classmethod
    async def delete_user(cls: Any, user_id: UUID) -> None:
        """Delete user function."""
        _user = await cls.database.users_collection.find_one({"id": user_id})
        if _user is None:
            return
        await cls.database.users_collection.delete_one({"id": user_id})
