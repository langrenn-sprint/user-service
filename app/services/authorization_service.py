"""Module for authorize functions."""

import logging
import os
from typing import Any

import jwt

from app.adapters import UsersAdapter
from app.models import AuthorizationRequest

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")

JWT_SECRET: str | None = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"

logger = logging.getLogger("app.authorization_service")


class AuthorizationError(Exception):
    """Class representing custom exception for authorization."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class UserNotAuthorizedError(AuthorizationError):
    """Class representing custom exception for authorization."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class InvalidTokenError(AuthorizationError):
    """Class representing custom exception for token validation."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class InconsistentTokenError(AuthorizationError):
    """Class representing custom exception for token verification."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class IncompleteTokenError(AuthorizationError):
    """Class representing custom exception for token verification."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class AuthorizationService:
    """Class representing a service for users."""

    logger = logging.getLogger("app.authorization_service.AuthorizationService")

    @classmethod
    async def authorize(cls: Any, autorization_request: AuthorizationRequest) -> None:
        """Check token and check role against role in token.

        Args:
            autorization_request (AuthorizationRequest): authorization request data
        Raises:
            UserNotAuthorizedError: user's role does not match target role
            IncompleteTokenError: token lacks mandatory attributes
            InconsistentTokenError: role in token is different from users role

        """
        # Decode token:
        decoded_token = await decode_token(autorization_request.token)
        try:
            username = decoded_token["username"]
            token_role = decoded_token["role"]
        except KeyError as e:
            msg = f"Mandatory property in token {e.args[0]} is missing."
            raise IncompleteTokenError(msg) from e

        # Check username:
        # admin user is good
        if username == "admin":
            pass
        else:
            # Check if user given by username exists in our records:
            logger.debug("Trying to verify user with username: %s", username)
            user = await UsersAdapter.get_user_by_username(username)
            if not user:
                msg = f"User with username {username} not found."
                raise UserNotAuthorizedError(msg) from None
            # Verify that user has role given in token:
            if user.role != token_role:
                msg = (
                    f"Inconsistent roles: user.role is {user.role} "
                    f"vs token_role {token_role}"
                )
                raise InconsistentTokenError(msg) from None

        # We authorize if username is "admin" or if the user has sufficient role:
        if token_role in autorization_request.target_roles:
            pass
        else:
            msg = f"User {username} does not have sufficient role."
            raise UserNotAuthorizedError(msg) from None


async def decode_token(token: str) -> dict:
    """Decode token."""
    logger.debug("Got jwt_token %s", token)
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except (jwt.DecodeError, jwt.ExpiredSignatureError) as e:
        logger.debug("Got excpetion %s", e)
        msg = f"Token is invalid: {type(e)}"
        raise InvalidTokenError(msg) from e
