"""Module for login functions."""

import os
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from motor.motor_asyncio import AsyncIOMotorDatabase

from user_service.adapters import UsersAdapter
from user_service.models import Role, User

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

JWT_SECRET: str | None = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = int(os.getenv("JWT_EXP_DELTA_SECONDS", "60"))


class WrongPasswordError(Exception):
    """Class representing custom exception for authorization."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class UnknownUserError(Exception):
    """Class representing custom exception for authorization."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class LoginService:
    """Class representing a service for users."""

    @classmethod
    async def login(
        cls: Any, db: AsyncIOMotorDatabase, username: str, password: str
    ) -> str:
        """Check username and passord.

        Args:
            db (Any): the db
            username (str): the username of the user trying to log in
            password (str): the users password

        Returns:
            str: A jwt token.

        Raises:
            UnknownUserError: If the user is unknown to us
            WrongPasswordError: If the password does not match our records

        """
        # First we see if it is the admin trying to log in.
        # Then we need to check if we have the user in our db,
        user = None
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            user = User(
                username=ADMIN_USERNAME, password=ADMIN_PASSWORD, role=Role.ADMIN
            )
        else:
            _user = await UsersAdapter.get_user_by_username(db, username)
            if _user:
                user = User.from_dict(_user)

        # Evaluate what we have in the user-object:
        if not user:
            msg = f"Username {username} not found."
            raise UnknownUserError(msg) from None
        if password != user.password:
            msg = f"Password for {username} did not match."
            raise WrongPasswordError(msg) from None

        return await create_access_token(user)


async def create_access_token(user: User) -> str:
    """Create a jwt based on username."""
    payload = {
        "username": user.username,
        "role": user.role,
        "exp": datetime.now(UTC) + timedelta(seconds=JWT_EXP_DELTA_SECONDS),
    }
    return jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
