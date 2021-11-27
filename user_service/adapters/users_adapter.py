"""Module for user adapter."""
import logging
from typing import Any, List, Optional

from .adapter import Adapter


class UsersAdapter(Adapter):
    """Class representing an adapter for users."""

    @classmethod
    async def get_all_users(cls: Any, db: Any) -> List:  # pragma: no cover
        """Get all users function."""
        users: List = []
        cursor = db.users_collection.find()
        for user in await cursor.to_list(length=100):
            users.append(user)
            logging.debug(user)
        return users

    @classmethod
    async def create_user(cls: Any, db: Any, user: dict) -> str:  # pragma: no cover
        """Create user function."""
        result = await db.users_collection.insert_one(user)
        return result

    @classmethod
    async def get_user_by_id(cls: Any, db: Any, id: str) -> dict:  # pragma: no cover
        """Get user function."""
        result = await db.users_collection.find_one({"id": id})
        return result

    @classmethod
    async def get_user_by_username(
        cls: Any, db: Any, username: str
    ) -> dict:  # pragma: no cover
        """Get user function."""
        result = await db.users_collection.find_one({"username": username})
        return result

    @classmethod
    async def update_user(
        cls: Any, db: Any, id: str, user: dict
    ) -> Optional[str]:  # pragma: no cover
        """Get user function."""
        result = await db.users_collection.replace_one({"id": id}, user)
        return result

    @classmethod
    async def delete_user(
        cls: Any, db: Any, id: str
    ) -> Optional[str]:  # pragma: no cover
        """Get user function."""
        result = await db.users_collection.delete_one({"id": id})
        return result
