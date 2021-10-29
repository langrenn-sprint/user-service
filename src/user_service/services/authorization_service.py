"""Module for authorize functions."""
import logging
import os
from typing import Any, List, Optional

import jwt

from user_service.adapters import UsersAdapter
from user_service.models import User

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")

JWT_SECRET: Optional[str] = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"


class InvalidInputException(Exception):
    """Class representing custom exception for authorization."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class UserNotAuthorizedException(Exception):
    """Class representing custom exception for authorization."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class InvalidTokenException(Exception):
    """Class representing custom exception for token validation."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class InconsistentTokenException(Exception):
    """Class representing custom exception for token verification."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class IncompleteTokenException(Exception):
    """Class representing custom exception for token verification."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class AuthorizationService:
    """Class representing a service for users."""

    @classmethod
    async def authorize(
        cls: Any, db: Any, token: Optional[str], target_roles: List[str]
    ) -> None:
        """Check token and check role against role in token.

        Args:
            db (Any): the db
            token (str): the jwt to be checked
            target_roles (List[str]): the roles to be checked against

        Raises:
            UserNotAuthorizedException: user's role does not match target role
            IncompleteTokenException: token lacks mandatory attributes
            InconsistentTokenException: role in token is different from users role
            InvalidInputException: required input parameter is missing
        """
        # Validate input:
        if not token:
            raise InvalidInputException("Token is required input.") from None
        if not target_roles:
            raise InvalidInputException("Roles is required input.") from None

        # Decode token:
        decoded_token = await decode_token(token)
        try:
            username = decoded_token["username"]
            token_role = decoded_token["role"]
        except KeyError as e:
            raise IncompleteTokenException(
                f"Mandatory property in token {e.args[0]} is missing."
            ) from e

        # Check username:
        # admin user is good
        if username == "admin":
            pass
        else:
            # Check if user given by username exists in our records:
            logging.debug(f"Trying to verify user with username: {username}")
            _user = await UsersAdapter.get_user_by_username(db, username)
            user = User.from_dict(_user)
            # Verify that user has role given in token:
            if user.role != token_role:
                raise InconsistentTokenException(
                    f"Inconsistent roles: user.role is {user.role} vs token_role {token_role}"
                ) from None

        # We authorize if username is "admin" or if the user has sufficient role:
        if token_role in target_roles:
            pass
        else:
            raise UserNotAuthorizedException(
                f"User {username} does not have sufficient role."
            ) from None


async def decode_token(token: Optional[str]) -> dict:
    """Decode token."""
    logging.debug(f"Got jwt_token {token}")
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])  # type: ignore
        return decoded
    except (jwt.DecodeError, jwt.ExpiredSignatureError) as e:
        logging.debug(f"Got excpetion {e}")
        raise InvalidTokenException(f"Token is invalid: {type(e)}") from e
