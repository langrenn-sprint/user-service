"""Module for user adapter."""

from abc import ABC, abstractmethod
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase


class Adapter(ABC):
    """Class representing an adapter interface."""

    @classmethod
    @abstractmethod
    async def get_all_users(cls: Any, db: AsyncIOMotorDatabase) -> list:
        """Get all users function."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    async def create_user(cls: Any, db: AsyncIOMotorDatabase, user: dict) -> str:
        """Create user function and return id."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    async def get_user_by_id(
        cls: Any, db: AsyncIOMotorDatabase, user_id: str
    ) -> dict | None:
        """Get user by id function."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    async def get_user_by_username(
        cls: Any, db: AsyncIOMotorDatabase, username: str
    ) -> dict | None:
        """Get user by name function."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    async def update_user(
        cls: Any, db: AsyncIOMotorDatabase, user_id: str, user: dict
    ) -> str | None:
        """Update user and return id."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    async def delete_user(
        cls: Any, db: AsyncIOMotorDatabase, user_id: str
    ) -> str | None:
        """Delete user function."""
        raise NotImplementedError
