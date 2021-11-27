"""Module for login functions."""
from datetime import datetime, timedelta
import os
from typing import Any, Optional

import jwt

from user_service.adapters import UsersAdapter
from user_service.models import Role, User

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

JWT_SECRET: Optional[str] = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = int(os.getenv("JWT_EXP_DELTA_SECONDS", 60))


class WrongPasswordException(Exception):
    """Class representing custom exception for authorization."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class UnknownUserException(Exception):
    """Class representing custom exception for authorization."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class LoginService:
    """Class representing a service for users."""

    @classmethod
    async def login(cls: Any, db: Any, username: str, password: str) -> str:
        """Check username and passord.

        Args:
            db (Any): the db
            username (str): the username of the user trying to log in
            password (str): the users password

        Returns:
            str: A jwt token.

        Raises:
            UnknownUserException: If the user is unknown to us
            WrongPasswordException: If the password does not match our records
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
            raise UnknownUserException(f"Username {username} not found.") from None
        if password != user.password:
            raise WrongPasswordException(
                f"Password for {username} did not match."
            ) from None

        jwt_token = await create_access_token(user)
        return jwt_token


async def create_access_token(user: User) -> str:
    """Create a jwt based on username."""
    payload = {
        "username": user.username,
        "role": user.role,
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS),
    }
    jwt_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)  # type: ignore

    return jwt_token
