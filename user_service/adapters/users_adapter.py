"""Module for user adapter."""

import logging
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from .adapter import Adapter


class UsersAdapter(Adapter):
    """Class representing an adapter for users."""

    logger = logging.getLogger("user_service.users_adapter.UsersAdapter")

    @classmethod
    async def get_all_users(cls: Any, db: AsyncIOMotorDatabase) -> list:
        """Get all users function."""
        users: list = []
        cursor = db.users_collection.find()
        for user in await cursor.to_list(length=100):
            users.append(user)
            cls.logger.debug(user)
        return users

    @classmethod
    async def create_user(cls: Any, db: AsyncIOMotorDatabase, user: dict) -> str:
        """Create user function and return id."""
        _result = await db.users_collection.insert_one(user)
        return _result.inserted_id

    @classmethod
    async def get_user_by_id(
        cls: Any, db: AsyncIOMotorDatabase, user_id: str
    ) -> dict | None:
        """Get user function."""
        return await db.users_collection.find_one({"id": user_id})

    @classmethod
    async def get_user_by_username(
        cls: Any, db: AsyncIOMotorDatabase, username: str
    ) -> dict | None:
        """Get user function."""
        return await db.users_collection.find_one({"username": username})

    @classmethod
    async def update_user(
        cls: Any, db: AsyncIOMotorDatabase, user_id: str, user: dict
    ) -> str | None:
        """Update user function and return id of updated document."""
        _result = await db.users_collection.replace_one({"id": user_id}, user)
        return _result.upserted_id

    @classmethod
    async def delete_user(cls: Any, db: AsyncIOMotorDatabase, user_id: str) -> None:
        """Delete user function."""
        _user = await db.users_collection.find_one({"id": user_id})
        if _user is None:
            return
        await db.users_collection.delete_one({"id": user_id})
