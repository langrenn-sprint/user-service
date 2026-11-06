"""Module for user adapter."""

import logging
from datetime import datetime
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
    async def create_user(cls: Any, user: User, activation: dict | None = None) -> UUID:
        """Create user function and return id.

        Args:
            user (User): the user, with a password hash or no password
            activation (dict | None): activation_code_hash and
                activation_expires, for a user without password

        """
        # We need to deserialize the secretstr password before inserting to db:
        user_dict = user.model_dump()
        user_dict["password"] = (
            user.password.get_secret_value() if user.password else None
        )
        user_dict.update(activation or {})
        _result = await cls.database.users_collection.insert_one(user_dict)
        return _result.inserted_id

    @classmethod
    async def get_user_by_id(cls: Any, user_id: UUID) -> User | None:
        """Get user function."""
        result = await cls.database.users_collection.find_one({"id": user_id})
        return User.model_validate(result) if result else None

    @classmethod
    async def get_user_document(cls: Any, user_id: UUID) -> dict | None:
        """Get the stored user, including the activation fields."""
        return await cls.database.users_collection.find_one({"id": user_id})

    @classmethod
    async def get_user_by_username(cls: Any, username: str) -> User | None:
        """Get user function."""
        result = await cls.database.users_collection.find_one({"username": username})
        return User.model_validate(result) if result else None

    @classmethod
    async def update_user(cls: Any, user_id: UUID, user: User) -> UUID | None:
        """Update username, role and, if given, password.

        Without a password in user, the stored password is kept. A pending
        activation code is kept in both cases.

        Returns:
            UUID | None: user_id if the user was found, None otherwise.

        """
        fields: dict[str, Any] = {"username": user.username, "role": user.role}
        if user.password is not None:
            # deserialize the secretstr password before storing it:
            fields["password"] = user.password.get_secret_value()
        result = await cls.database.users_collection.update_one(
            {"id": user_id}, {"$set": fields}
        )
        return user_id if result.matched_count == 1 else None

    @classmethod
    async def set_activation(
        cls: Any, user_id: UUID, code_hash: str, expires: datetime
    ) -> bool:
        """Store a new activation code for the user, replacing any earlier one.

        Returns:
            bool: True if the user was found.

        """
        result = await cls.database.users_collection.update_one(
            {"id": user_id},
            {
                "$set": {
                    "activation_code_hash": code_hash,
                    "activation_expires": expires,
                }
            },
        )
        return result.matched_count == 1

    @classmethod
    async def activate(
        cls: Any,
        code_hash: str,
        now: datetime,
        password_hash: str,
        username: str | None = None,
    ) -> bool:
        """Set the password of the user with this unexpired code, and remove the code.

        Done in one update, so a code can only be used once.

        Returns:
            bool: True if a user had the code and it had not expired.

        """
        query: dict[str, Any] = {
            "activation_code_hash": code_hash,
            "activation_expires": {"$gt": now},
        }
        if username is not None:
            query["username"] = username
        result = await cls.database.users_collection.update_one(
            query,
            {
                "$set": {"password": password_hash},
                "$unset": {"activation_code_hash": "", "activation_expires": ""},
            },
        )
        return result.modified_count == 1

    @classmethod
    async def get_users_with_plaintext_password(
        cls: Any, hash_regex: str
    ) -> list[dict]:
        """Get the id and password of every user whose password is not a hash.

        Args:
            hash_regex (str): a MongoDB regex that matches a complete password hash.

        """
        # Users without password (not activated) have no password to hash:
        cursor = cls.database.users_collection.find(
            {"password": {"$type": "string", "$not": {"$regex": hash_regex}}},
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
