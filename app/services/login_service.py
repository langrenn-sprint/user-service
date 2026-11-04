"""Module for login functions."""

import hmac
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from pydantic import SecretStr

from app.adapters import UsersAdapter
from app.models import Role, User

from .passwords import (
    hash_password,
    needs_rehash,
    verify_dummy_password,
    verify_password,
)

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if ADMIN_PASSWORD is None:  # pragma: no cover
    msg = "ADMIN_PASSWORD environment variable is not set."
    raise ValueError(msg) from None

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
    async def login(cls: Any, username: str, password: str) -> str:
        """Check username and passord.

        Args:
            username (str): the username of the user trying to log in
            password (str): the users password

        Returns:
            str: A jwt token.

        Raises:
            UnknownUserError: If the user is unknown to us
            WrongPasswordError: If the password does not match our records

        """
        # First we see if it is the admin trying to log in.
        # The admin password is configured in the environment, not stored:
        if username == ADMIN_USERNAME and hmac.compare_digest(
            password.encode(), str(ADMIN_PASSWORD).encode()
        ):
            admin = User(
                username=ADMIN_USERNAME,
                password=SecretStr(str(ADMIN_PASSWORD)),
                role=Role.ADMIN,
            )
            return await create_access_token(admin)

        # Then we need to check if we have the user in our db:
        user = await UsersAdapter.get_user_by_username(username)
        if not user:
            # Spend the same time as for a known user, so that the response
            # time does not reveal whether the username exists:
            await verify_dummy_password(password)
            msg = f"Username {username} not found."
            raise UnknownUserError(msg) from None
        password_hash = user.password.get_secret_value()
        if not await verify_password(password_hash, password):
            msg = f"Password for {username} did not match."
            raise WrongPasswordError(msg) from None
        # Upgrade the hash if the hashing parameters have changed since it was made.
        # Only replaces the hash if the password has not been changed meanwhile:
        if needs_rehash(password_hash):
            await UsersAdapter.update_password(
                user.id, password_hash, await hash_password(password)
            )

        return await create_access_token(user)


async def create_access_token(user: User) -> str:
    """Create a jwt based on username."""
    payload = {
        "username": user.username,
        "role": user.role,
        "exp": datetime.now(UTC) + timedelta(seconds=JWT_EXP_DELTA_SECONDS),
    }
    return jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
