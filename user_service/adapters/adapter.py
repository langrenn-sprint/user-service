"""Module for user adapter."""

from abc import ABC, abstractmethod
from typing import Any, List, Optional


class Adapter(ABC):
    """Class representing an adapter interface."""

    @classmethod
    @abstractmethod
    async def get_all_users(cls: Any, db: Any) -> List:  # pragma: no cover
        """Get all users function."""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    async def create_user(cls: Any, db: Any, user: dict) -> str:  # pragma: no cover
        """Create user function."""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    async def get_user_by_id(cls: Any, db: Any, id: str) -> dict:  # pragma: no cover
        """Get user by id function."""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    async def get_user_by_username(
        cls: Any, db: Any, username: str
    ) -> dict:  # pragma: no cover
        """Get user function."""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    async def update_user(
        cls: Any, db: Any, id: str, user: dict
    ) -> Optional[str]:  # pragma: no cover
        """Get user function."""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    async def delete_user(
        cls: Any, db: Any, id: str
    ) -> Optional[str]:  # pragma: no cover
        """Get user function."""
        raise NotImplementedError()
