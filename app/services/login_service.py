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
# A token can be renewed until this many seconds after the user logged in.
# An empty value means the default, as docker-compose passes unset variables as "":
JWT_MAX_SESSION_SECONDS = int(os.getenv("JWT_MAX_SESSION_SECONDS") or "86400")


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


class TokenRenewalError(Exception):
    """Class representing custom exception for token renewal."""

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
            return await create_access_token(_admin_user())

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

    @classmethod
    async def renew(cls: Any, token: str) -> str:
        """Renew a valid token.

        The user is read again, so that a deleted user cannot renew and a
        changed role is put in the new token. The auth_time claim is kept, so
        that a session cannot be renewed beyond JWT_MAX_SESSION_SECONDS.

        Args:
            token (str): a valid, unexpired token issued by us

        Returns:
            str: A new jwt token with full lifetime.

        Raises:
            TokenRenewalError: If the token is invalid or expired, the session
                is too old, or the user no longer exists

        """
        try:
            claims = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
                options={"require": ["exp", "auth_time", "username"]},
            )
        except jwt.InvalidTokenError as e:
            msg = f"Token is invalid: {e}"
            raise TokenRenewalError(msg) from e

        auth_time = claims["auth_time"]
        if not isinstance(auth_time, int) or isinstance(auth_time, bool):
            msg = "Token has an invalid auth_time claim."
            raise TokenRenewalError(msg) from None
        if datetime.now(UTC).timestamp() - auth_time > JWT_MAX_SESSION_SECONDS:
            msg = "Session has exceeded the maximum length."
            raise TokenRenewalError(msg) from None

        username = claims["username"]
        if username == ADMIN_USERNAME:
            return await create_access_token(_admin_user(), auth_time=auth_time)

        user = await UsersAdapter.get_user_by_username(username)
        if not user:
            msg = f"Username {username} not found."
            raise TokenRenewalError(msg) from None
        return await create_access_token(user, auth_time=auth_time)


def _admin_user() -> User:
    """Return the admin user, which is configured in the environment."""
    return User(
        username=ADMIN_USERNAME,
        password=SecretStr(str(ADMIN_PASSWORD)),
        role=Role.ADMIN,
    )


async def create_access_token(user: User, auth_time: int | None = None) -> str:
    """Create a jwt based on username.

    Args:
        user (User): the user the token is issued to
        auth_time (int | None): when the user logged in with password, in
            seconds since the epoch. Defaults to now, i.e. a new login.

    Returns:
        str: A jwt token.

    """
    now = datetime.now(UTC)
    payload = {
        "username": user.username,
        "role": user.role,
        "auth_time": int(now.timestamp()) if auth_time is None else auth_time,
        "exp": now + timedelta(seconds=JWT_EXP_DELTA_SECONDS),
    }
    return jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
