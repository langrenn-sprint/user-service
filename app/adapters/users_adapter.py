"""Module for user adapter."""

import logging
from typing import Any
from uuid import UUID

from app.models import User

logger = logging.getLogger(__name__)


class UsersAdapter:
    """Class representing an adapter for users."""

    database: Any

    @classmethod
    async def init(cls, database: Any) -> None:  # pragma: no cover
        """Initialize class properties."""
        cls.database = database

    @classmethod
    async def get_all_users(cls: Any) -> list:
        """Get all users function."""
        cursor = cls.database.users_collection.find()
        return await cursor.to_list(length=100)

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
    async def get_users_with_plaintext_password(
        cls: Any, hash_regex: str
    ) -> list[dict]:
        """Get the id and password of every user whose password is not a hash.

        Args:
            hash_regex (str): a MongoDB regex that matches a complete password hash.

        """
        cursor = cls.database.users_collection.find(
            {"password": {"$not": {"$regex": hash_regex}}},
            {"_id": 0, "id": 1, "password": 1},
        )
        return await cursor.to_list(length=None)

    @classmethod
    async def update_password(
        cls: Any, user_id: UUID, old_password: str, new_password: str
    ) -> bool:
        """Replace the stored password, if it is still old_password.

        The new value is derived from the old one, so it must not overwrite a
        password that was changed in the meantime.

        Returns:
            bool: True if the password was replaced.

        """
        result = await cls.database.users_collection.update_one(
            {"id": user_id, "password": old_password},
            {"$set": {"password": new_password}},
        )
        return result.modified_count == 1

    @classmethod
    async def delete_user(cls: Any, user_id: UUID) -> None:
        """Delete user function."""
        _user = await cls.database.users_collection.find_one({"id": user_id})
        if _user is None:
            return
        await cls.database.users_collection.delete_one({"id": user_id})
